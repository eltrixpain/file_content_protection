// requirements.cpp
#include "requirements.hpp"
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <ctime>


// Cerate tables query
static const char* kSchemaSQL = R"SQL(
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS cache_entries (
  dev             INTEGER NOT NULL,
  ino             INTEGER NOT NULL,
  mtime_ns        INTEGER NOT NULL,
  size            INTEGER NOT NULL,
  ruleset_version INTEGER NOT NULL,
  decision        INTEGER NOT NULL,     
  updated_at      INTEGER NOT NULL,
  PRIMARY KEY (dev, ino)
);

CREATE INDEX IF NOT EXISTS idx_cache_version ON cache_entries(ruleset_version);
CREATE INDEX IF NOT EXISTS idx_cache_updated ON cache_entries(updated_at);

CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

INSERT OR IGNORE INTO meta(key, value) VALUES ('ruleset_version','1');
INSERT OR IGNORE INTO meta(key, value) VALUES ('ruleset_hash','');
)SQL";

// Config log
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

// Create directory if it is not exist
void Requirements::ensureDir(const char* path, StartupResult& out) {
    ::mkdir(path, 0755);
    out.logs.push_back(std::string("[ensureDir] ok: ") + path);
}

// Parse the config field
bool Requirements::loadConfig(const std::string& config_path, StartupResult& out) {
    if (!out.config.loadFromFile(config_path)) {
        out.error = "[config] failed to load " + config_path;
        out.logs.push_back(out.error);
        return false;
    }
    out.logs.push_back(std::string("[config] loaded: ") + config_path);
    return true;
}

// Validate config file and check crusial fields correctness
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

    out.logs.push_back("[config] watch_mode: " + mode);
    out.logs.push_back("[config] watch_target: " + target);
    out.logs.push_back("[config] patterns loaded: " + std::to_string(cfg.patternCount()));
    out.logs.push_back("[config] validation ok");
    return true;
}

// Create tables in DB
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
    out.db.reset(raw);

    char* err = nullptr;
    rc = sqlite3_exec(out.db.get(), kSchemaSQL, nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        out.error = std::string("[cache] schema exec failed: ") + (err ? err : "");
        out.logs.push_back(out.error);
        if (err) sqlite3_free(err);
        return false;
    }
    out.logs.push_back("[cache] schema ok (PRAGMA + tables/indexes)");
    return true;
}

// check the rule set version
bool Requirements::initRulesetVersion(StartupResult& out) {
    if (!out.config.initRulesetVersion(out.db.get())) {
        out.error = "[cache] failed to init ruleset version in meta";
        out.logs.push_back(out.error);
        return false;
    }
    out.logs.push_back("[cache] ruleset_version ready");
    return true;
}


StartupResult Requirements::run(const std::string& config_path,
                                const std::string& db_path) {
    StartupResult res;

    // 1) dirs
    ensureDir("logs", res);
    ensureDir("cache", res);

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

    // Ok
    res.ok = true;
    for (auto& l : res.logs) fileLog(l);
    return res;
}
