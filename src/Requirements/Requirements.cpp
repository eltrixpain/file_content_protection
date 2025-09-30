// requirements.cpp
#include "requirements.hpp"
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <ctime>


// Cerate tables query
static const char* kSchemaSQL = R"SQL(
CREATE TABLE IF NOT EXISTS cache_entries (
  dev             INTEGER NOT NULL,
  ino             INTEGER NOT NULL,
  mtime_ns        INTEGER NOT NULL,
  ctime_ns        INTEGER NOT NULL,
  size            INTEGER NOT NULL,
  ruleset_version INTEGER NOT NULL,
  decision        INTEGER NOT NULL,
  last_access_ts  INTEGER NOT NULL,
  hit_count       INTEGER DEFAULT 0,
  PRIMARY KEY (dev, ino)
);

CREATE INDEX IF NOT EXISTS idx_cache_version ON cache_entries(ruleset_version);
CREATE INDEX IF NOT EXISTS idx_cache_last_access ON cache_entries(last_access_ts);

CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

INSERT OR IGNORE INTO meta(key, value) VALUES ('ruleset_version','1');
INSERT OR IGNORE INTO meta(key, value) VALUES ('scope_hash','');
INSERT OR IGNORE INTO meta(key, value) VALUES ('patterns_hash','');
)SQL";



// Desc: append a timestamped line to config log file
// In: const std::string& msg
// Out: void
void Requirements::fileLog(const std::string& msg) {
    int fd = ::open("logs/config.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd == -1) return;
    time_t now = ::time(nullptr);
    char buf[64];
    ctime_r(&now, buf);
    buf[std::strlen(buf) - 1] = '\0';
    std::string line = "[" + std::string(buf) + "] " + msg + "\n";
    ssize_t _wr = ::write(fd, line.c_str(), line.size());
    (void)_wr;  
    ::close(fd);
}

// Desc: create directory if missing and record status
// In: const char* path, StartupResult& out
// Out: void    
void Requirements::ensureDir(const char* path, StartupResult& out) {
    ::mkdir(path, 0755);
    out.logs.push_back(std::string("[ensureDir] ok: ") + path);
}

// Desc: load JSON config into StartupResult::config
// In: const std::string& config_path, StartupResult& out
// Out: bool (true on success)
bool Requirements::loadConfig(const std::string& config_path, StartupResult& out) {
    if (!out.config.loadFromFile(config_path)) {
        out.error = "[config] failed to load " + config_path;
        out.logs.push_back(out.error);
        return false;
    }
    out.logs.push_back(std::string("[config] loaded: ") + config_path);
    return true;
}

// Desc: validate key config fields and permissions
// In: const ConfigManager& cfg, StartupResult& out
// Out: bool (true if valid)
bool Requirements::validateConfig(const ConfigManager& cfg, StartupResult& out) {
    std::string mode = cfg.getWatchMode();
    if (mode != "path" && mode != "mount") {
        out.logs.push_back("[config] watch_mode missing/invalid -> defaulting to 'path'");
        mode = "path";
    }

    const std::string target = cfg.getWatchTarget();
    if (target.empty()) {
        out.error = "[config] watch_target is empty";
        out.logs.push_back(out.error);
        return false;
    }

    struct stat st{};
    if (::stat(target.c_str(), &st) == -1) {
        out.error = "[config] target not found: " + target + " (" + std::string(::strerror(errno)) + ")";
        out.logs.push_back(out.error);
        return false;
    }
    if (!S_ISDIR(st.st_mode)) {
        out.error = "[config] target is not a directory: " + target;
        out.logs.push_back(out.error);
        return false;
    }
    if (::access(target.c_str(), R_OK | X_OK) != 0) {
        out.error = "[config] insufficient access on target: " + target + " (" + std::string(::strerror(errno)) + ")";
        out.logs.push_back(out.error);
        return false;
    }

    if (cfg.patternCount() == 0) {
        out.error = "[config] no valid patterns loaded";
        out.logs.push_back(out.error);
        return false;
    }
    const uint64_t max_bytes = cfg.max_cache_bytes();
    const uint64_t MIN_BYTES = 1 * 1024ULL;                              // 5KB
    const uint64_t MAX_BYTES = 1ULL * 1024ULL * 1024ULL * 1024ULL; // 1GB

    if (max_bytes == 0) {
        out.error = "[config] cache_max_size missing/invalid (expect like \"512MB\" or \"200KB\")";
        out.logs.push_back(out.error);
        return false;
    }
    if (max_bytes < MIN_BYTES) {
        out.error = "[config] cache_max_size too small (<64KB)";
        out.logs.push_back(out.error);
        return false;
    }
    if (max_bytes > MAX_BYTES) {
        out.error = "[config] cache_max_size too large (>1TB)";
        out.logs.push_back(out.error);
        return false;
    }
    out.logs.push_back("[config] cache_max_size: " + std::to_string(max_bytes) + " bytes");
    out.logs.push_back("[config] watch_mode: " + mode);
    out.logs.push_back("[config] watch_target: " + target);
    out.logs.push_back("[config] patterns loaded: " + std::to_string(cfg.patternCount()));
    out.logs.push_back("[config] validation ok");
    return true;
}

// Desc: open/init SQLite cache DB and apply schema
// In: const std::string& db_path, StartupResult& out
// Out: bool (true on success)
bool Requirements::initCacheDb(const std::string& db_path, StartupResult& out) {
    sqlite3* raw = nullptr;
    int rc = sqlite3_open_v2(db_path.c_str(), &raw,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
    if (rc != SQLITE_OK) {
        out.error = std::string("[cache] sqlite open failed: ") + (raw ? sqlite3_errmsg(raw) : "unknown");
        out.logs.push_back(out.error);
        if (raw) sqlite3_close(raw);
        return false;
    }
   sqlite3_busy_timeout(raw, 5000);
    sqlite3_exec(raw, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(raw, "PRAGMA synchronous=NORMAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(raw, "PRAGMA foreign_keys=ON;", nullptr, nullptr, nullptr);
    sqlite3_wal_autocheckpoint(raw, 512);


    out.db.reset(raw); 

    char* err = nullptr;
    rc = sqlite3_exec(out.db.get(), kSchemaSQL, nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        out.error = std::string("[cache] schema exec failed: ") + (err ? err : "");
        out.logs.push_back(out.error);
        if (err) sqlite3_free(err);
        return false;
    }
    out.logs.push_back("[cache] schema ok (tables/indexes)");
    return true;
}


// Desc: initialize/bump ruleset version in DB meta
// In: StartupResult& out
// Out: bool (true on success)
bool Requirements::initRulesetVersion(StartupResult& out) {
    if (!out.config.initRulesetVersion(out.db.get())) {
        out.error = "[cache] failed to init ruleset version in meta";
        out.logs.push_back(out.error);
        return false;
    }
    out.logs.push_back("[cache] ruleset_version ready");
    return true;
}


// Desc: delete cache entries with outdated ruleset_version
// In: sqlite3* db
// Out: void
static void invalidate_to_meta_ruleset(sqlite3* db) {
    if (!db) return;
    char* err = nullptr;
    sqlite3_exec(db, "BEGIN IMMEDIATE;", nullptr, nullptr, &err);

    const char* del_sql =
        "DELETE FROM cache_entries "
        "WHERE ruleset_version <> ("
        "  SELECT CAST(value AS INTEGER) "
        "  FROM meta WHERE key='ruleset_version' LIMIT 1"
        ");";

    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, del_sql, -1, &st, nullptr) == SQLITE_OK) {
        (void)sqlite3_step(st);
        (void)sqlite3_finalize(st);
    }
    sqlite3_exec(db, "COMMIT;", nullptr, nullptr, &err);
}



// Desc: orchestrate startup: dirs, config, DB, ruleset; log results
// In: const std::string& config_path, const std::string& db_path
// Out: StartupResult
StartupResult Requirements::run(const std::string& config_path,
                                const std::string& db_path) {
    StartupResult res;

    // 1) dirs
    ensureDir("logs", res);
    ensureDir("cache", res);
    ensureDir("statistical_result", res);

    // 2) config load + validate
    if (!loadConfig(config_path, res)) {
        for (auto& l : res.logs) fileLog(l);
        return res;
    }
    if (!validateConfig(res.config, res)) {
        for (auto& l : res.logs) fileLog(l);
        return res;
    }

    // 3) DB init + schema
    if (!initCacheDb(db_path, res)) {
        for (auto& l : res.logs) fileLog(l);
        return res;
    }

    // 4) ruleset version
    if (!initRulesetVersion(res)) {
        for (auto& l : res.logs) fileLog(l);
        return res;
    }
    invalidate_to_meta_ruleset(res.db.get());
    // Ok
    res.ok = true;
    for (auto& l : res.logs) fileLog(l);
    return res;
}
