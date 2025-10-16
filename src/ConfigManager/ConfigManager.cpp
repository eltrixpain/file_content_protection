// === ConfigManager.cpp (hardened) ===
#include "ConfigManager.hpp"

#include <fstream>
#include <algorithm>
#include <cctype>
#include <iostream>
#include <regex>
#include <stdexcept>
#include <filesystem>
#include <nlohmann/json.hpp>
using nlohmann::json;

// sqlite
#include <sqlite3.h>
#ifdef USE_OPENSSL_SHA256
#include <openssl/sha.h>
#endif

// Desc: normalize a filesystem path to canonical form
// In: const std::string& path
// Out: std::string (normalized path)
static std::string normalizePath(const std::string& path) {
    namespace fs = std::filesystem;
    try {
        fs::path p(path);
        fs::path norm = fs::weakly_canonical(p);
        std::string result = norm.string();
        if (result.size() > 1 && result.back() == '/')
            result.pop_back();
        return result;
    } catch (...) {
        return path;
    }
}

// Desc: convert string to lowercase
// In: std::string s
// Out: std::string (lowercased)
static inline std::string toLower(std::string s) {
    for (char& c : s) c = (char)std::tolower((unsigned char)c);
    return s;
}

// Desc: trim leading and trailing spaces inplace
// In: std::string& t
// Out: void
static inline void trim_inplace(std::string& t) {
    t.erase(t.begin(), std::find_if(t.begin(), t.end(), [](unsigned char c){ return !std::isspace(c); }));
    t.erase(std::find_if(t.rbegin(), t.rend(), [](unsigned char c){ return !std::isspace(c); }).base(), t.end());
}


// Desc: parse size string (KB/MB) into bytes
// In: const std::string& raw
// Out: std::uint64_t (bytes); throws on invalid input
std::uint64_t ConfigManager::parse_size_kb_mb(const std::string& raw) {
    std::string in = raw;
    trim_inplace(in);

    static const std::regex re(R"(^([0-9]+)\s*([kKmM][bB]?)$)");
    std::smatch m;
    if (!std::regex_match(in, m, re)) {
        throw std::runtime_error("invalid format (only KB/MB allowed): '" + raw + "'");
    }

    std::uint64_t n = 0;
    try {
        n = std::stoull(m[1].str());
    } catch (...) {
        throw std::runtime_error("invalid number : '" + raw + "'");
    }

    std::string unit = m[2].str();
    for (auto& c : unit) c = (char)std::toupper((unsigned char)c);

    if (unit == "K" || unit == "KB") return n * 1024ULL;
    if (unit == "M" || unit == "MB") return n * 1024ULL * 1024ULL;
    throw std::runtime_error("unreachable unit");
}


// Desc: ensure 'meta' table exists in SQLite DB
// In: sqlite3* db
// Out: void; throws on SQLite error
static void ensure_meta_table(sqlite3* db) {
    char* err = nullptr;
    const char* sql =
        "CREATE TABLE IF NOT EXISTS meta ("
        "  key   TEXT PRIMARY KEY,"
        "  value TEXT"
        ");";
    if (sqlite3_exec(db, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        std::string e = err ? err : "unknown";
        if (err) sqlite3_free(err);
        throw std::runtime_error("ensure_meta_table: " + e);
    }
}


bool ConfigManager::loadFromFile(const std::string& config_path) {
    std::ifstream file(config_path);
    if (!file.is_open()) {
        std::cerr << "[ConfigManager] cannot open file: " << config_path << "\n";
        return false;
    }

    json j;
    try { file >> j; }
    catch (const std::exception& e) { std::cerr << "[ConfigManager] invalid JSON: " << e.what() << "\n"; return false; }
    catch (...) { std::cerr << "[ConfigManager] invalid JSON (unknown error)\n"; return false; }

    // watch_mode
    if (j.contains("watch_mode") && j["watch_mode"].is_string()) {
        watch_mode_ = [](std::string s){ for (char& c: s) c = (char)std::tolower((unsigned char)c); return s; }(j["watch_mode"].get<std::string>());
        if (watch_mode_ != "path" && watch_mode_ != "mount") {
            std::cerr << "[ConfigManager] watch_mode must be 'path' or 'mount', got: " << watch_mode_ << "\n";
            return false;
        }
    } else { std::cerr << "[ConfigManager] missing or invalid 'watch_mode'\n"; return false; }

    // watch_target
    if (j.contains("watch_target") && j["watch_target"].is_string()) {
        watch_target_ = j["watch_target"].get<std::string>();
        if (watch_target_.empty()) { std::cerr << "[ConfigManager] 'watch_target' must be non-empty\n"; return false; }
    } else { std::cerr << "[ConfigManager] missing or invalid 'watch_target'\n"; return false; }

    // patterns (strings only)
    pattern_strings_.clear();
    auto add_pat = [&](const std::string& pat) {
        // Accept as-is; Hyperscan will compile/validate later
        pattern_strings_.push_back(pat);
    };
    if (j.contains("patterns")) {
        if (j["patterns"].is_array()) {
            for (const auto& p : j["patterns"]) if (p.is_string()) add_pat(p.get<std::string>());
        } else if (j["patterns"].is_string()) {
            add_pat(j["patterns"].get<std::string>());
        } else {
            std::cerr << "[ConfigManager] 'patterns' must be string or array of strings\n";
            return false;
        }
    }

    // sizes
    cache_capacity_bytes_ = 0;
    if (j.contains("cache_capacity_bytes") && j["cache_capacity_bytes"].is_string()) {
        try { cache_capacity_bytes_ = parse_size_kb_mb(j["cache_capacity_bytes"].get<std::string>()); }
        catch (...) { std::cerr << "[ConfigManager] 'cache_capacity_bytes' must be like '80KB' or '10MB'\n"; return false; }
    }
    max_file_size_sync_scan_ = 0;
    if (j.contains("max_file_size_sync_scan") && j["max_file_size_sync_scan"].is_string()) {
        try { max_file_size_sync_scan_ = parse_size_kb_mb(j["max_file_size_sync_scan"].get<std::string>()); }
        catch (...) { std::cerr << "[ConfigManager] 'max_file_size_sync_scan' must be like '10MB'\n"; return false; }
    }

    duration_sec_ = 0;
    if (j.contains("statistical") && j["statistical"].is_object()) {
        const auto& s = j["statistical"];
        if (s.contains("duration_sec") && s["duration_sec"].is_number_integer()) {
            try {
                duration_sec_ = s["duration_sec"].get<uint64_t>();
                if (duration_sec_ == 0) { std::cerr << "[ConfigManager] 'statistical.duration_sec' must be > 0\n"; return false; }
            } catch (...) { std::cerr << "[ConfigManager] 'statistical.duration_sec' must be integer\n"; return false; }
        } else { std::cerr << "[ConfigManager] missing or invalid 'statistical.duration_sec'\n"; return false; }
    } else { std::cerr << "[ConfigManager] missing or invalid 'statistical' object\n"; return false; }

    return true;
}


// Desc: build canonical JSON of rules (sorted patterns)
// In: (none)
// Out: std::string (JSON)
std::string ConfigManager::canonicalRulesJson() const {
    std::vector<std::string> sorted = pattern_strings_;
    std::sort(sorted.begin(), sorted.end());
    json c;
    c["patterns"] = sorted;
    return c.dump();
}

// Desc: hash data into hex (SHA-256 if available, else FNV-based)
// In: const std::string& data
// Out: std::string (hex digest)
std::string ConfigManager::hashCanonical(const std::string& data) {
#ifdef USE_OPENSSL_SHA256
    unsigned char out[32];
    SHA256((const unsigned char*)data.data(), data.size(), out);
    static const char* hex = "0123456789abcdef";
    std::string h(64, '0');
    for (int i = 0; i < 32; i++) {
        h[2*i]   = hex[(out[i]>>4) & 0xF];
        h[2*i+1] = hex[out[i] & 0xF];
    }
    return h;
#else

    const std::uint64_t FNV_OFFSET = 1469598103934665603ULL, FNV_PRIME = 1099511628211ULL;
    std::uint64_t hash = FNV_OFFSET;
    for (unsigned char c : data) {
        hash ^= c;
        hash *= FNV_PRIME;
    }
    static const char* hex = "0123456789abcdef";
    std::string h(16, '0');
    for (int i = 15; i >= 0; --i) {
        h[i] = hex[hash & 0xF];
        hash >>= 4;
    }
    return h;
#endif
}

// Desc: init/bump ruleset version based on scope/pattern changes
// In: sqlite3* db
// Out: bool (true on success)
bool ConfigManager::initRulesetVersion(sqlite3* db) {
    if (!db) return false;

    try {
        ensure_meta_table(db); // must ensure keys: scope_hash, patterns_hash, ruleset_version
    } catch (const std::exception& e) {
        std::cerr << "[ConfigManager] " << e.what() << "\n";
        return false;
    }

    // 1) compute current scope & patterns hashes
    const std::string tgt_norm          = normalizePath(getWatchTarget());
    const std::string scope_mat         = "watch_mode=" + getWatchMode() + "\nwatch_target=" + tgt_norm;
    const std::string cur_scope_hash    = hashCanonical(scope_mat);

    // canonicalRulesJson() must include only patterns/options (no watch target/mode)
    const std::string patterns_json     = canonicalRulesJson();
    const std::string cur_patterns_hash = hashCanonical(patterns_json);

    // 2) read previous hashes & version
    std::string last_scope_hash;
    std::string last_patterns_hash;
    std::uint64_t last_ver = 0;

    {
        sqlite3_stmt* s = nullptr;
        if (sqlite3_prepare_v2(db, "SELECT value FROM meta WHERE key='scope_hash'", -1, &s, nullptr) == SQLITE_OK) {
            if (sqlite3_step(s) == SQLITE_ROW) {
                const unsigned char* t = sqlite3_column_text(s, 0);
                if (t) last_scope_hash = (const char*)t;
            }
            sqlite3_finalize(s);
        }
    }
    {
        sqlite3_stmt* s = nullptr;
        if (sqlite3_prepare_v2(db, "SELECT value FROM meta WHERE key='patterns_hash'", -1, &s, nullptr) == SQLITE_OK) {
            if (sqlite3_step(s) == SQLITE_ROW) {
                const unsigned char* t = sqlite3_column_text(s, 0);
                if (t) last_patterns_hash = (const char*)t;
            }
            sqlite3_finalize(s);
        }
    }
    {
        sqlite3_stmt* s = nullptr;
        if (sqlite3_prepare_v2(db, "SELECT value FROM meta WHERE key='ruleset_version'", -1, &s, nullptr) == SQLITE_OK) {
            if (sqlite3_step(s) == SQLITE_ROW) {
                const unsigned char* t = sqlite3_column_text(s, 0);
                if (t) last_ver = std::strtoull((const char*)t, nullptr, 10);
            }
            sqlite3_finalize(s);
        }
    }

    if (last_ver == 0) last_ver = 1; // safety seed

    const bool scope_changed    = (cur_scope_hash    != last_scope_hash);
    const bool patterns_changed = (cur_patterns_hash != last_patterns_hash);

    // 3) handle first-time init
    if (last_scope_hash.empty() && last_patterns_hash.empty()) {
        sqlite3_exec(db, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr);
        {
            sqlite3_stmt* u = nullptr;
            sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO meta(key,value) VALUES('ruleset_version',?)", -1, &u, nullptr);
            const std::string v = std::to_string(last_ver);
            sqlite3_bind_text(u, 1, v.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(u); sqlite3_finalize(u);
        }
        {
            sqlite3_stmt* u = nullptr;
            sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO meta(key,value) VALUES('scope_hash',?)", -1, &u, nullptr);
            sqlite3_bind_text(u, 1, cur_scope_hash.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(u); sqlite3_finalize(u);
        }
        {
            sqlite3_stmt* u = nullptr;
            sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO meta(key,value) VALUES('patterns_hash',?)", -1, &u, nullptr);
            sqlite3_bind_text(u, 1, cur_patterns_hash.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(u); sqlite3_finalize(u);
        }
        sqlite3_exec(db, "COMMIT", nullptr, nullptr, nullptr);

        ruleset_version_ = last_ver;
        // no ruleset_hash_ anymore
        #ifdef DEBUG
        std::cerr << "[ruleset] initialized. version=" << ruleset_version_
                  << " scope_changed=false patterns_changed=false\n";
        #endif
        return true;
    }

    // 4) unchanged
    if (!scope_changed && !patterns_changed) {
        ruleset_version_ = last_ver;
        #ifdef DEBUG
        std::cerr << "[ruleset] no change. version=" << ruleset_version_ << "\n";
        #endif
        return true;
    }

    // 5) changed cases (split into two clear branches)

    // Branch A: scope changed OR both changed => treat as full change
    if (scope_changed) {
        const std::uint64_t new_ver = last_ver + 1;
        sqlite3_exec(db, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr);
        {
            sqlite3_stmt* u = nullptr;
            sqlite3_prepare_v2(db, "UPDATE meta SET value=? WHERE key='ruleset_version'", -1, &u, nullptr);
            const std::string v = std::to_string(new_ver);
            sqlite3_bind_text(u, 1, v.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(u); sqlite3_finalize(u);
        }
        {
            sqlite3_stmt* u = nullptr;
            sqlite3_prepare_v2(db, "UPDATE meta SET value=? WHERE key='scope_hash'", -1, &u, nullptr);
            sqlite3_bind_text(u, 1, cur_scope_hash.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(u); sqlite3_finalize(u);
        }
        {
            sqlite3_stmt* u = nullptr;
            sqlite3_prepare_v2(db, "UPDATE meta SET value=? WHERE key='patterns_hash'", -1, &u, nullptr);
            sqlite3_bind_text(u, 1, cur_patterns_hash.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(u); sqlite3_finalize(u);
        }
        sqlite3_exec(db, "COMMIT", nullptr, nullptr, nullptr);

        ruleset_version_ = new_ver;
        #ifdef DEBUG
        std::cerr << "[ruleset] scope changed (or both). bumped version to " << ruleset_version_ << "\n";
        #endif
        return true;
    }

    // Branch B: only patterns changed => lighter path (still bump version)
    {
        const std::uint64_t new_ver = last_ver + 1;
        sqlite3_exec(db, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr);
        {
            sqlite3_stmt* u = nullptr;
            sqlite3_prepare_v2(db, "UPDATE meta SET value=? WHERE key='ruleset_version'", -1, &u, nullptr);
            const std::string v = std::to_string(new_ver);
            sqlite3_bind_text(u, 1, v.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(u); sqlite3_finalize(u);
        }
        {
            // update only patterns_hash; scope_hash stays the same
            sqlite3_stmt* u = nullptr;
            sqlite3_prepare_v2(db, "UPDATE meta SET value=? WHERE key='patterns_hash'", -1, &u, nullptr);
            sqlite3_bind_text(u, 1, cur_patterns_hash.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(u); sqlite3_finalize(u);
        }
        sqlite3_exec(db, "COMMIT", nullptr, nullptr, nullptr);

        ruleset_version_ = new_ver;
        #ifdef DEBUG
        std::cerr << "[ruleset] patterns changed (scope unchanged). bumped version to " << ruleset_version_ << "\n";
        #endif
        return true;
    }
}
