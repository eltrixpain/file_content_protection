// requirements.hpp
#pragma once
#include "ConfigManager.hpp"
#include <memory>
#include <string>
#include <vector>
#include <sqlite3.h>

struct StartupResult {
    bool ok = false;
    std::string error;              // خلاصه خطای نهایی برای stderr
    std::vector<std::string> logs;  // لاگ‌های مرحله‌ای (برای نوشتن در فایل)
    ConfigManager config;
    std::unique_ptr<sqlite3, void(*)(sqlite3*)> db{nullptr, [](sqlite3* p){ if (p) sqlite3_close(p); }};
};

// یک کلاس ساده برای اجرای همه‌ی pre-run checks
class Requirements {
public:
    // مسیر config.json و مسیر cache.sqlite را می‌گیرد و همه‌ی بررسی‌ها را انجام می‌دهد
    static StartupResult run(const std::string& config_path,
                             const std::string& db_path);

private:
    static void ensureDir(const char* path, StartupResult& out);
    static void fileLog(const std::string& msg);
    static bool loadConfig(const std::string& config_path,
                           StartupResult& out);
    static bool validateConfig(const ConfigManager& cfg,
                               StartupResult& out);
    static bool initCacheDb(const std::string& db_path,
                            StartupResult& out);
    static bool initRulesetVersion(StartupResult& out);
};
