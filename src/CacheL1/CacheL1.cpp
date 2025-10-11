    // === src/CacheManager/CacheManager.cpp ===
    #include "CacheL1.hpp"
    #include <ctime>
    #include <iostream>
    #include <sys/stat.h>
    #include <string>
    #include <vector>
    #include <algorithm>
    #include <cmath>


    // Desc: check if cache size in dbstat tables is below limit
    // In: sqlite3* db, uint64_t max_bytes
    // Out: bool (true if within limit, false if exceeded)
    bool check_cache_capacity(sqlite3* db, uint64_t max_bytes) {
        if (!db) return true;
        uint64_t live_bytes = 0;

        const char* sql =
            "SELECT SUM(pgsize - unused) "
            "FROM dbstat "
            "WHERE name IN ("
            "'cache_entries',"
            "'sqlite_autoindex_cache_entries_1',"
            "'idx_cache_version',"
            "'idx_cache_last_access'"
            ");";

        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_type(stmt, 0) != SQLITE_NULL) {
                live_bytes = static_cast<uint64_t>(sqlite3_column_int64(stmt, 0));
            }
            (void)sqlite3_finalize(stmt);
        }

        if (live_bytes >= max_bytes) {
            #ifdef DEBUG
            std::cerr << "[cache] size limit exceeded (dbstat): "
                    << live_bytes << " >= " << max_bytes << " bytes\n";
            #endif
            return false;
        }
        return true;
    }


    // Desc: evict entries using size-aware LFU (age-decayed) scoring
    // In: sqlite3* db, int max_rows_to_evict, double beta, int candidate_limit
    // Out: void (deletes up to max_rows_to_evict rows)
    #ifdef LFU_SIZE
    static void evict_lfu_size(sqlite3* db, int max_rows_to_evict, double beta, int candidate_limit) {
        if (!db || max_rows_to_evict <= 0) return;
        if (candidate_limit <= 0) candidate_limit = 256;
        const double tau_seconds = 3600.0; 
        const long long now_sec = static_cast<long long>(time(nullptr));
        const char* sel_sql =
            "SELECT dev, ino, hit_count, size, last_access_ts "
            "FROM cache_entries "
            "ORDER BY hit_count ASC, last_access_ts ASC "
            "LIMIT ?;";

            sqlite3_stmt* sel = nullptr;
            if (sqlite3_prepare_v2(db, sel_sql, -1, &sel, nullptr) != SQLITE_OK) return;
            sqlite3_bind_int(sel, 1, candidate_limit);

            struct Row { long long dev, ino; long long hits; long long sz; long long last_ts; double score; };
            std::vector<Row> rows;
            while (sqlite3_step(sel) == SQLITE_ROW) {
                Row r;
                r.dev     = sqlite3_column_int64(sel, 0);
                r.ino     = sqlite3_column_int64(sel, 1);
                r.hits    = sqlite3_column_int64(sel, 2);
                r.sz      = sqlite3_column_int64(sel, 3);
                r.last_ts = sqlite3_column_int64(sel, 4);
                double sbytes = static_cast<double>(r.sz);
                double h      = static_cast<double>(r.hits);
                double age = (now_sec > r.last_ts) ? double(now_sec - r.last_ts) : 0.0;
                double eff_hits = h / (1.0 + age / tau_seconds);
                r.score = eff_hits * (beta * std::log1p(sbytes));
                rows.push_back(r);
            }
            (void)sqlite3_finalize(sel);
            if (rows.empty()) return;

            std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b){
                if (a.score != b.score) return a.score < b.score;
                return a.last_ts < b.last_ts;
            });

            if (static_cast<size_t>(max_rows_to_evict) < rows.size())
                rows.resize(static_cast<size_t>(max_rows_to_evict));

            char* err = nullptr;
            (void)sqlite3_exec(db, "BEGIN IMMEDIATE;", nullptr, nullptr, &err);
            const char* del_sql = "DELETE FROM cache_entries WHERE dev=? AND ino=?;";
            sqlite3_stmt* del = nullptr;
            if (sqlite3_prepare_v2(db, del_sql, -1, &del, nullptr) == SQLITE_OK) {
                for (auto& r : rows) {
                    sqlite3_bind_int64(del, 1, r.dev);
                    sqlite3_bind_int64(del, 2, r.ino);
                    (void)sqlite3_step(del);
                    (void)sqlite3_reset(del);
                }
                (void)sqlite3_finalize(del);
            }
            (void)sqlite3_exec(db, "COMMIT;", nullptr, nullptr, &err);
    }
    #endif


    // Desc: evict oldest entries using LRU strategy
    // In: sqlite3* db, int max_rows_to_evict
    // Out: void (deletes rows)
    #ifdef LRU
    static void evict_lru(sqlite3* db, int max_rows_to_evict) {
        if (!db || max_rows_to_evict <= 0) return;

        // Select oldest entries by last_access_ts
        const char* sel_sql =
            "SELECT dev, ino FROM cache_entries "
            "ORDER BY last_access_ts ASC "
            "LIMIT ?;";

        sqlite3_stmt* sel = nullptr;
        if (sqlite3_prepare_v2(db, sel_sql, -1, &sel, nullptr) != SQLITE_OK) {
            return;
        }
        sqlite3_bind_int(sel, 1, max_rows_to_evict);

        // Collect keys to delete
        std::vector<std::pair<long long,long long>> keys;
        while (sqlite3_step(sel) == SQLITE_ROW) {
            long long dev = sqlite3_column_int64(sel, 0);
            long long ino = sqlite3_column_int64(sel, 1);
            keys.emplace_back(dev, ino);
        }
        (void)sqlite3_finalize(sel);
        if (keys.empty()) return;

        // Delete in a transaction
        char* err = nullptr;
        (void)sqlite3_exec(db, "BEGIN IMMEDIATE;", nullptr, nullptr, &err);
        const char* del_sql =
            "DELETE FROM cache_entries WHERE dev=? AND ino=?;";
        sqlite3_stmt* del = nullptr;
        if (sqlite3_prepare_v2(db, del_sql, -1, &del, nullptr) == SQLITE_OK) {
            for (auto& k : keys) {
                sqlite3_bind_int64(del, 1, k.first);
                sqlite3_bind_int64(del, 2, k.second);
                (void)sqlite3_step(del);
                (void)sqlite3_reset(del);
            }
            (void)sqlite3_finalize(del);
        }
        (void)sqlite3_exec(db, "COMMIT;", nullptr, nullptr, &err);
    }
    #endif

    // Desc: evict least-frequently-used entries with age decay
    // In: sqlite3* db, int max_rows_to_evict
    // Out: void (deletes rows)
    #ifdef LFU
    static void evict_lfu(sqlite3* db, int max_rows_to_evict) {
        if (!db || max_rows_to_evict <= 0) return;

        const double tau_seconds = 3600.0; 
        const long long now_sec = static_cast<long long>(time(nullptr));
        const char* sel_sql =
            "SELECT dev, ino FROM cache_entries "
            "ORDER BY (CAST(hit_count AS REAL) / (1.0 + "
            "         (MAX(?1 - last_access_ts, 0) / ?2))) ASC, "
            "         last_access_ts ASC "
            "LIMIT ?3;";

        sqlite3_stmt* sel = nullptr;
        if (sqlite3_prepare_v2(db, sel_sql, -1, &sel, nullptr) != SQLITE_OK) return;
        sqlite3_bind_int64(sel, 1, now_sec);                 // ?1 = now
        sqlite3_bind_double(sel, 2, tau_seconds);            // ?2 = τ
        sqlite3_bind_int(sel, 3, max_rows_to_evict);         // ?3 = LIMIT

        std::vector<std::pair<long long,long long>> keys;
        while (sqlite3_step(sel) == SQLITE_ROW) {
            keys.emplace_back(sqlite3_column_int64(sel, 0), sqlite3_column_int64(sel, 1));
        }
        (void)sqlite3_finalize(sel);
        if (keys.empty()) return;

        char* err = nullptr;
        (void)sqlite3_exec(db, "BEGIN IMMEDIATE;", nullptr, nullptr, &err);
        const char* del_sql = "DELETE FROM cache_entries WHERE dev=? AND ino=?;";
        sqlite3_stmt* del = nullptr;
        if (sqlite3_prepare_v2(db, del_sql, -1, &del, nullptr) == SQLITE_OK) {
            for (auto& k : keys) {
                sqlite3_bind_int64(del, 1, k.first);
                sqlite3_bind_int64(del, 2, k.second);
                (void)sqlite3_step(del);
                (void)sqlite3_reset(del);
            }
            (void)sqlite3_finalize(del);
        }
        (void)sqlite3_exec(db, "COMMIT;", nullptr, nullptr, &err);
    }
    #endif

    // Desc: check cache for file and fetch decision if metadata matches
    // In: const struct stat& st, uint64_t ruleset_version, int& decision
    // Out: bool (true=hit, false=miss)
    bool CacheL1::get(const struct stat& st, uint64_t ruleset_version, int& decision) {
    if (!db_) return false;

    const char* sql =
    "SELECT mtime_ns, size, ruleset_version, decision, ctime_ns "
    "FROM cache_entries WHERE dev=? AND ino=?;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_int64(stmt, 1, static_cast<long long>(st.st_dev));
    sqlite3_bind_int64(stmt, 2, static_cast<long long>(st.st_ino));

    bool hit = false;

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const long long row_mtime_ns    = sqlite3_column_int64(stmt, 0);
        const long long row_size        = sqlite3_column_int64(stmt, 1);
        const long long row_ruleset_ver = sqlite3_column_int64(stmt, 2);
        const int       row_decision    = sqlite3_column_int(stmt,   3);
        const long long row_ctime_ns    = sqlite3_column_int64(stmt, 4);

        const long long cur_mtime_ns =
            static_cast<long long>(st.st_mtim.tv_sec) * 1000000000LL + st.st_mtim.tv_nsec;
        const long long cur_ctime_ns =
            static_cast<long long>(st.st_ctim.tv_sec) * 1000000000LL + st.st_ctim.tv_nsec;

        if (row_ruleset_ver == static_cast<long long>(ruleset_version) &&
            row_mtime_ns    == cur_mtime_ns &&
            row_size        == static_cast<long long>(st.st_size) &&
            row_ctime_ns    == cur_ctime_ns) {
            decision = row_decision;
            hit = true;
        }
    }

    (void)sqlite3_finalize(stmt);


    if (hit) {
        const char* upd =
            "UPDATE cache_entries "
            "SET hit_count = hit_count + 1, last_access_ts = ? "
            "WHERE dev=? AND ino=?;";
        sqlite3_stmt* upd_stmt = nullptr;
        if (sqlite3_prepare_v2(db_, upd, -1, &upd_stmt, nullptr) == SQLITE_OK) {
            const long long now = static_cast<long long>(time(nullptr));
            sqlite3_bind_int64(upd_stmt, 1, now);
            sqlite3_bind_int64(upd_stmt, 2, static_cast<long long>(st.st_dev));
            sqlite3_bind_int64(upd_stmt, 3, static_cast<long long>(st.st_ino));
            (void)sqlite3_step(upd_stmt);
            (void)sqlite3_finalize(upd_stmt);
        }
    }

    return hit;
    }


    // Desc: upsert cache entry; may evict if over capacity
    // In: const struct stat& st, uint64_t ruleset_version, int decision, uint64_t max_bytes
    // Out: void
    void CacheL1::put(const struct stat& st, uint64_t ruleset_version, int decision, uint64_t max_bytes) {
        if (!db_) return;

        #ifdef DEBUG
        std::cout << "[cache] put: dev=" << st.st_dev
                << " ino=" << st.st_ino
                << " size=" << st.st_size
                << " mtime=" << st.st_mtim.tv_sec
                << " ctime=" << st.st_ctim.tv_sec
                << " ver=" << ruleset_version
                << " decision=" << decision
                << std::endl;
        #endif

        if (!check_cache_capacity(db_, max_bytes)) {
            #ifdef LFU_SIZE
            std::cout << "\033[31m"
                    << "[cache][evict] Cache full. Removing based on f(hit_count , size) item"
                    << "\033[0m" << std::endl;
            evict_lfu_size(db_, 10, 5, 1000);
            #endif

            #ifdef LRU
            std::cout << "\033[31m"
                    << "[cache][evict] Cache full. Removing least recently used item"
                    << "\033[0m" << std::endl;
            evict_lru(db_, 10);
            #endif

            #ifdef LFU
            std::cout << "\033[31m"
                    << "[cache][evict] Cache full. Removing least frequently used item"
                    << "\033[0m" << std::endl;
            evict_lfu(db_, 10);
            #endif
        }

        const char* sql =
            "INSERT OR REPLACE INTO cache_entries "
            "(dev, ino, mtime_ns, ctime_ns, size, ruleset_version, decision, last_access_ts, hit_count) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0);";

        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return;
        }

        const long long mtime_ns =
            static_cast<long long>(st.st_mtim.tv_sec) * 1000000000LL + st.st_mtim.tv_nsec;
        const long long ctime_ns =
            static_cast<long long>(st.st_ctim.tv_sec) * 1000000000LL + st.st_ctim.tv_nsec;
        const long long now = static_cast<long long>(time(nullptr));

        sqlite3_bind_int64(stmt, 1, static_cast<long long>(st.st_dev));
        sqlite3_bind_int64(stmt, 2, static_cast<long long>(st.st_ino));
        sqlite3_bind_int64(stmt, 3, mtime_ns);
        sqlite3_bind_int64(stmt, 4, ctime_ns);
        sqlite3_bind_int64(stmt, 5, static_cast<long long>(st.st_size));
        sqlite3_bind_int64(stmt, 6, static_cast<long long>(ruleset_version));
        sqlite3_bind_int(stmt,   7, decision);
        sqlite3_bind_int64(stmt, 8, now);

        (void)sqlite3_step(stmt);
        (void)sqlite3_finalize(stmt);
    }


