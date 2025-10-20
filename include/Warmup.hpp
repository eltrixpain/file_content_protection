#pragma once
#include <string>
#include <sqlite3.h>
class ConfigManager;

namespace Warmup {
void pattern_warmup(sqlite3* db, const ConfigManager& cfg);
void scope_warmup_on_access(const std::string& path);
}
