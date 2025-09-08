// === src/CacheManager/CacheManager.cpp ===
#include "CacheManager.hpp"
#include <ctime>
#include <iostream> 

// === src/CacheManager/CacheManager.cpp ===
// replace the current get(...) stub with this:
bool CacheManager::get(const struct stat& st, uint64_t ruleset_version, int& decision, uint64_t& matched_mask) {
    if (!db_) return false;

    const char* sql =
        "SELECT mtime_ns, size, ruleset_version, decision, matched_mask "
        "FROM cache_entries WHERE dev=? AND ino=?;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_int64(stmt, 1, static_cast<long long>(st.st_dev));
    sqlite3_bind_int64(stmt, 2, static_cast<long long>(st.st_ino));

    bool hit = false;

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const long long row_mtime_ns     = sqlite3_column_int64(stmt, 0);
        const long long row_size         = sqlite3_column_int64(stmt, 1);
        const long long row_ruleset_ver  = sqlite3_column_int64(stmt, 2);
        const int        row_decision    = sqlite3_column_int(stmt,   3);
        const long long row_mask         = sqlite3_column_int64(stmt, 4);

        const long long cur_mtime_ns =
            static_cast<long long>(st.st_mtim.tv_sec) * 1000000000LL + st.st_mtim.tv_nsec;

        if (row_ruleset_ver == static_cast<long long>(ruleset_version) &&
            row_mtime_ns    == cur_mtime_ns &&
            row_size        == static_cast<long long>(st.st_size)) {
            decision     = row_decision;                // 0=ALLOW,1=BLOCK
            matched_mask = static_cast<uint64_t>(row_mask);
            hit = true;
        }
    }

    (void)sqlite3_finalize(stmt);
    return hit;
}

void CacheManager::put(const struct stat& st, uint64_t ruleset_version, int decision, uint64_t matched_mask) {
    if (!db_) return;

    std::cout << "[cache] put: dev=" << st.st_dev
              << " ino=" << st.st_ino
              << " size=" << st.st_size
              << " mtime=" << st.st_mtim.tv_sec
              << " ver=" << ruleset_version
              << " decision=" << decision
              << " mask=" << matched_mask
              << std::endl;

    const char* sql =
        "INSERT OR REPLACE INTO cache_entries "
        "(dev, ino, mtime_ns, size, ruleset_version, decision, matched_mask, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?);";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return;
    }

    const long long mtime_ns =
        static_cast<long long>(st.st_mtim.tv_sec) * 1000000000LL + st.st_mtim.tv_nsec;
    const long long now = static_cast<long long>(time(nullptr));

    // bind params
    sqlite3_bind_int64(stmt, 1, static_cast<long long>(st.st_dev));
    sqlite3_bind_int64(stmt, 2, static_cast<long long>(st.st_ino));
    sqlite3_bind_int64(stmt, 3, mtime_ns);
    sqlite3_bind_int64(stmt, 4, static_cast<long long>(st.st_size));
    sqlite3_bind_int64(stmt, 5, static_cast<long long>(ruleset_version));
    sqlite3_bind_int(stmt,   6, decision); // 0=ALLOW,1=BLOCK
    sqlite3_bind_int64(stmt, 7, static_cast<long long>(matched_mask));
    sqlite3_bind_int64(stmt, 8, now);

    (void)sqlite3_step(stmt);   // ignore result; best-effort
    (void)sqlite3_finalize(stmt);
}
