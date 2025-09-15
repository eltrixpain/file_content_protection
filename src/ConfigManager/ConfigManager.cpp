// === ConfigManager.cpp (hardened) ===
#include "ConfigManager.hpp"

#include <fstream>
#include <algorithm>
#include <cctype>
#include <iostream>
#include <regex>
#include <stdexcept>

// JSON (header-only)
#include <nlohmann/json.hpp>
using nlohmann::json;

// sqlite
#include <sqlite3.h>

// اختیاری: اگر OpenSSL داری، این رو فعال کن و به لینکرت -lcrypto بده
// #define USE_OPENSSL_SHA256
#ifdef USE_OPENSSL_SHA256
#include <openssl/sha.h>
#endif

// -------- helpers --------
static inline std::string toLower(std::string s) {
    for (char& c : s) c = (char)std::tolower((unsigned char)c);
    return s;
}

static inline void trim_inplace(std::string& t) {
    t.erase(t.begin(), std::find_if(t.begin(), t.end(), [](unsigned char c){ return !std::isspace(c); }));
    t.erase(std::find_if(t.rbegin(), t.rend(), [](unsigned char c){ return !std::isspace(c); }).base(), t.end());
}

uint64_t ConfigManager::parse_size_kb_mb(const std::string& raw) {
    std::string in = raw;
    trim_inplace(in);

    static const std::regex re(R"(^([0-9]+)\s*([kKmM][bB]?)$)");
    std::smatch m;
    if (!std::regex_match(in, m, re)) {
        throw std::runtime_error("invalid cache_max_size (only KB/MB allowed): '" + raw + "'");
    }

    uint64_t n = 0;
    try {
        n = std::stoull(m[1].str());
    } catch (...) {
        throw std::runtime_error("invalid number in cache_max_size: '" + raw + "'");
    }

    std::string unit = m[2].str();
    for (auto& c : unit) c = (char)std::toupper((unsigned char)c);

    if (unit == "K" || unit == "KB") return n * 1024ULL;
    if (unit == "M" || unit == "MB") return n * 1024ULL * 1024ULL;

    // به اینجا نباید برسیم چون regex محدود کرده
    throw std::runtime_error("unreachable unit in cache_max_size");
}


// تضمین وجود جدول meta
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


// load config file from json format and fill the class attribute
bool ConfigManager::loadFromFile(const std::string& config_path) {
    std::ifstream file(config_path);
    if (!file.is_open()) {
        std::cerr << "[ConfigManager] cannot open file: " << config_path << "\n";
        return false;
    }

    json j;
    try {
        file >> j;
    } catch (const std::exception& e) {
        std::cerr << "[ConfigManager] invalid JSON: " << e.what() << "\n";
        return false;
    } catch (...) {
        std::cerr << "[ConfigManager] invalid JSON (unknown error)\n";
        return false;
    }

    // --- watch_mode (اجباری: path | mount)
    if (j.contains("watch_mode") && j["watch_mode"].is_string()) {
        watch_mode_ = toLower(j["watch_mode"].get<std::string>());
        if (watch_mode_ != "path" && watch_mode_ != "mount") {
            std::cerr << "[ConfigManager] watch_mode must be 'path' or 'mount', got: " << watch_mode_ << "\n";
            return false;
        }
    } else {
        std::cerr << "[ConfigManager] missing or invalid 'watch_mode'\n";
        return false;
    }

    // --- watch_target (اجباری: رشته غیر خالی)
    if (j.contains("watch_target") && j["watch_target"].is_string()) {
        watch_target_ = j["watch_target"].get<std::string>();
        if (watch_target_.empty()) {
            std::cerr << "[ConfigManager] 'watch_target' must be non-empty\n";
            return false;
        }
    } else {
        std::cerr << "[ConfigManager] missing or invalid 'watch_target'\n";
        return false;
    }

    // --- patterns (اختیاری)
    patterns.clear();
    pattern_strings_.clear();
    auto add_pat = [&](const std::string& pat) {
        pattern_strings_.push_back(pat);
        try {
            patterns.emplace_back(pat, std::regex::ECMAScript | std::regex::icase);
        } catch (const std::exception& e) {
            std::cerr << "[ConfigManager] invalid regex pattern skipped: '" << pat << "' error=" << e.what() << "\n";
        } catch (...) {
            std::cerr << "[ConfigManager] invalid regex pattern skipped: '" << pat << "' (unknown error)\n";
        }
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

    // --- cache_max_size (اجباری / فقط KB یا MB)
    max_cache_bytes_ = 0;
    if (j.contains("cache_max_size") && j["cache_max_size"].is_string()) {
        try {
            max_cache_bytes_ = parse_size_kb_mb(j["cache_max_size"].get<std::string>());
        } catch (...) {
            max_cache_bytes_ = 0; // نامعتبر → بعداً validate رد می‌کند
        }
    }

    return true;
}


// Check the content against the patterns in config file
bool ConfigManager::matches(const std::string& text) const {
    for (const auto& re : patterns) {
        if (std::regex_search(text, re)) return true;
    }
    return false;
}

// return number of patterns
size_t ConfigManager::patternCount() const { return patterns.size(); }

// Get canonical rules json for hash calculation (سفارش: فقط الگوها)
std::string ConfigManager::canonicalRulesJson() const {
    // ترتیب مهم نیست → مرتب‌سازی
    std::vector<std::string> sorted = pattern_strings_;
    std::sort(sorted.begin(), sorted.end());
    json c;
    c["patterns"] = sorted;
    return c.dump();
}

// hash calculator
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
    // FNV-1a 64 (برای نسخه‌بندی کافی است؛ امنیتی نیست)
    const uint64_t FNV_OFFSET = 1469598103934665603ULL, FNV_PRIME = 1099511628211ULL;
    uint64_t hash = FNV_OFFSET;
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

// initialize & bump ruleset version if patterns changed
bool ConfigManager::initRulesetVersion(sqlite3* db) {
    if (!db) return false;

    try {
        ensure_meta_table(db);
    } catch (const std::exception& e) {
        std::cerr << "[ConfigManager] " << e.what() << "\n";
        return false;
    }

    // 1 compute current canonical hash
    const std::string canonical = canonicalRulesJson();
    const std::string cur_hash  = hashCanonical(canonical);

    // 2 read old hash & version
    std::string last_hash;
    uint64_t last_ver = 0;

    {
        sqlite3_stmt* s = nullptr;
        if (sqlite3_prepare_v2(db, "SELECT value FROM meta WHERE key='ruleset_hash'", -1, &s, nullptr) == SQLITE_OK) {
            if (sqlite3_step(s) == SQLITE_ROW) {
                const unsigned char* t = sqlite3_column_text(s, 0);
                if (t) last_hash = (const char*)t;
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

    // 3 compare & update (transactional)
    if (last_hash.empty()) {
        // first time
        sqlite3_exec(db, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr);
        {
            sqlite3_stmt* u = nullptr;
            sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO meta(key,value) VALUES('ruleset_version',?)", -1, &u, nullptr);
            std::string v = std::to_string(last_ver);
            sqlite3_bind_text(u, 1, v.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(u); sqlite3_finalize(u);
        }
        {
            sqlite3_stmt* u = nullptr;
            sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO meta(key,value) VALUES('ruleset_hash',?)", -1, &u, nullptr);
            sqlite3_bind_text(u, 1, cur_hash.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(u); sqlite3_finalize(u);
        }
        sqlite3_exec(db, "COMMIT", nullptr, nullptr, nullptr);
        ruleset_version_ = last_ver;
        ruleset_hash_    = cur_hash;
        return true;
    }

    if (cur_hash == last_hash) {
        // unchanged
        ruleset_version_ = last_ver;
        ruleset_hash_    = last_hash;
        return true;
    }

    // changed → bump
    uint64_t new_ver = last_ver + 1;
    sqlite3_exec(db, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr);
    {
        sqlite3_stmt* u = nullptr;
        sqlite3_prepare_v2(db, "UPDATE meta SET value=? WHERE key='ruleset_version'", -1, &u, nullptr);
        std::string v = std::to_string(new_ver);
        sqlite3_bind_text(u, 1, v.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(u); sqlite3_finalize(u);
    }
    {
        sqlite3_stmt* u = nullptr;
        sqlite3_prepare_v2(db, "UPDATE meta SET value=? WHERE key='ruleset_hash'", -1, &u, nullptr);
        sqlite3_bind_text(u, 1, cur_hash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(u); sqlite3_finalize(u);
    }
    sqlite3_exec(db, "COMMIT", nullptr, nullptr, nullptr);

    ruleset_version_ = new_ver;
    ruleset_hash_    = cur_hash;
    return true;
}
