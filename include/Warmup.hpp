#pragma once
#include <string>
#include <sqlite3.h>
class ConfigManager;

namespace Warmup {
void pattern_warmup(sqlite3* db, const ConfigManager& cfg, size_t max_hit_candidates,
                    double l2_fill_ratio);  
void scope_warmup_on_access(const std::string& path);
}
