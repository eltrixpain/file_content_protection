// === include/CacheManager.hpp ===
#pragma once
#include <cstdint>
#include <sys/stat.h>
#include <sqlite3.h>
#include <iostream>

class CacheManager {
public:
    explicit CacheManager(sqlite3* db) : db_(db) {}  // store db handle
    bool get(const struct stat& st, uint64_t ruleset_version, int& decision);
    void put(const struct stat& st, uint64_t ruleset_version, int decision , uint64_t max_bytes);

private:
    sqlite3* db_{nullptr};
    
};
