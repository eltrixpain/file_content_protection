// requirements.hpp
#pragma once
#include "ConfigManager.hpp"
#include <memory>
#include <string>
#include <vector>
#include <sqlite3.h>

struct StartupResult {
    bool ok = false;
    std::string error;              
    std::vector<std::string> logs;
    ConfigManager config;
    std::unique_ptr<sqlite3, void(*)(sqlite3*)> db{nullptr, [](sqlite3* p){ if (p) sqlite3_close(p); }};
};

class Requirements {
public:
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
