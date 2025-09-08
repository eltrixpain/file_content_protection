// === main.cpp ===
#include "CoreEngine.hpp"
#include "ConfigManager.hpp"
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <sqlite3.h>

static const char* kSchemaSQL = R"SQL(
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS cache_entries (
  dev             INTEGER NOT NULL,
  ino             INTEGER NOT NULL,
  mtime_ns        INTEGER NOT NULL,
  size            INTEGER NOT NULL,
  ruleset_version INTEGER NOT NULL,
  decision        INTEGER NOT NULL,     -- 0=ALLOW, 1=BLOCK
  updated_at      INTEGER NOT NULL,
  PRIMARY KEY (dev, ino)
);

CREATE INDEX IF NOT EXISTS idx_cache_version ON cache_entries(ruleset_version);
CREATE INDEX IF NOT EXISTS idx_cache_updated ON cache_entries(updated_at);
)SQL";

// returns opened handle or nullptr on error
sqlite3* init_cache_db(const std::string& db_path) {
    // open (creates file if missing)
    sqlite3* db = nullptr;
    if (sqlite3_open_v2(db_path.c_str(), &db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK) {
        std::cerr << "[cache] sqlite open failed: " << sqlite3_errmsg(db) << "\n";
        if (db) sqlite3_close(db);
        return nullptr;
    }

    // apply schema
    char* err = nullptr;
    if (sqlite3_exec(db, kSchemaSQL, nullptr, nullptr, &err) != SQLITE_OK) {
        std::cerr << "[cache] schema exec failed: " << (err ? err : "") << "\n";
        if (err) sqlite3_free(err);
        sqlite3_close(db);
        return nullptr;
    }
    return db;
}

// config log helper
static void cfglog(const std::string& msg) {
    int fd = open("logs/config.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd != -1) {
        // timestamp
        time_t now = time(nullptr);
        char buf[64];
        ctime_r(&now, buf);
        buf[strlen(buf) - 1] = '\0'; // remove newline

        std::string line = "[" + std::string(buf) + "] " + msg + "\n";
        write(fd, line.c_str(), line.size());
        close(fd);
    }
}

// pre-run config validation
static bool validate_config(const ConfigManager& config) {
    const std::string wp = config.getWatchPath();

    // path checks
    struct stat st{};
    if (wp.empty()) {
        cfglog("[config] watch_path is empty");
        return false;
    }
    if (stat(wp.c_str(), &st) == -1) {
        cfglog(std::string("[config] path not found: ") + wp + " (" + strerror(errno) + ")");
        return false;
    }
    if (!S_ISDIR(st.st_mode)) {
        cfglog(std::string("[config] path is not a directory: ") + wp);
        return false;
    }
    if (access(wp.c_str(), R_OK | X_OK) != 0) {
        cfglog(std::string("[config] insufficient access: ") + wp + " (" + strerror(errno) + ")");
        return false;
    }

    // pattern checks
    if (config.patternCount() == 0) {
        cfglog("[config] no valid patterns loaded");
        return false;
    }

    return true;
}



int main() {
    ConfigManager config;
    if (!config.loadFromFile("./config.json")) {
        cfglog("[config] failed to load ./config.json");
        std::cerr << "[Main] aborted due to config error (see logs/config.log for details)\n";
        return 1;
    }
    if (!validate_config(config)) {
        cfglog("[config] validation failed, aborting");
        std::cerr << "[Main] aborted due to config error (see logs/config.log for details)\n";
        return 1;
    }
    sqlite3* cache_db = init_cache_db("cache/cache.sqlite"); // keep under project logs/
    if (!cache_db) {
        std::cerr << "[Main] aborted due to cache DB init error\n";
        return 1;
    }
    start_core_engine(config, cache_db);
    return 0;
}

