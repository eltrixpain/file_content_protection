    // === src/CacheManager/CacheManager.cpp ===
    #include "CacheManager.hpp"
    #include <ctime>
    #include <iostream>
    #include <sys/stat.h>
    #include <string>
    #include <vector>


    // check cache size (dbstat-based only)
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



    // LRU implementaion
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

    //LFU implemention
    static void evict_lfu(sqlite3* db, int max_rows_to_evict) {
        if (!db || max_rows_to_evict <= 0) return;

        const char* sel_sql =
            "SELECT dev, ino FROM cache_entries "
            "ORDER BY hit_count ASC, last_access_ts ASC "
            "LIMIT ?;";

        sqlite3_stmt* sel = nullptr;
        if (sqlite3_prepare_v2(db, sel_sql, -1, &sel, nullptr) != SQLITE_OK) return;
        sqlite3_bind_int(sel, 1, max_rows_to_evict);

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




    // check cache table result ---> hit or miss
    bool CacheManager::get(const struct stat& st, uint64_t ruleset_version, int& decision) {
    if (!db_) return false;

    const char* sql =
        "SELECT mtime_ns, size, ruleset_version, decision "
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

        const long long cur_mtime_ns =
            static_cast<long long>(st.st_mtim.tv_sec) * 1000000000LL + st.st_mtim.tv_nsec;

        if (row_ruleset_ver == static_cast<long long>(ruleset_version) &&
            row_mtime_ns    == cur_mtime_ns &&
            row_size        == static_cast<long long>(st.st_size)) {
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


    // put new record into the hash table
    void CacheManager::put(const struct stat& st, uint64_t ruleset_version, int decision ,uint64_t max_bytes) {
    if (!db_) return;

   #ifdef DEBUG
    std::cout << "[cache] put: dev=" << st.st_dev
              << " ino=" << st.st_ino
              << " size=" << st.st_size
              << " mtime=" << st.st_mtim.tv_sec
              << " ver=" << ruleset_version
              << " decision=" << decision
              << std::endl;
    #endif

    if (!check_cache_capacity(db_, max_bytes)){
        //#ifdef DEBUG
        std::cout << "\033[31m"
          << "[cache][evict] Cache full. Removing least frequently used item"
          << "\033[0m" << std::endl;
        //#endif
        evict_lfu(db_, 100);
    }
    const char* sql =
        "INSERT OR REPLACE INTO cache_entries "
        "(dev, ino, mtime_ns, size, ruleset_version, decision, last_access_ts, hit_count) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 0);";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return;
    }

    const long long mtime_ns =
        static_cast<long long>(st.st_mtim.tv_sec) * 1000000000LL + st.st_mtim.tv_nsec;
    const long long now = static_cast<long long>(time(nullptr));

    sqlite3_bind_int64(stmt, 1, static_cast<long long>(st.st_dev));
    sqlite3_bind_int64(stmt, 2, static_cast<long long>(st.st_ino));
    sqlite3_bind_int64(stmt, 3, mtime_ns);
    sqlite3_bind_int64(stmt, 4, static_cast<long long>(st.st_size));
    sqlite3_bind_int64(stmt, 5, static_cast<long long>(ruleset_version));
    sqlite3_bind_int(stmt,   6, decision);
    sqlite3_bind_int64(stmt, 7, now);

    (void)sqlite3_step(stmt);
    (void)sqlite3_finalize(stmt);
    }

