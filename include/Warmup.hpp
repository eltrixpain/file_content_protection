#pragma once
#include <string>
#include <sqlite3.h>
class ConfigManager;

namespace Warmup {
void scope_warmup_on_access(const std::string& path);
}
