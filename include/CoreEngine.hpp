#ifndef CORE_ENGINE_HPP
#define CORE_ENGINE_HPP
#pragma once
#include <sys/fanotify.h>
#include <unistd.h>
#include <sqlite3.h>

#include "ConfigManager.hpp"

void start_core_engine_blocking(const ConfigManager& config, sqlite3* cache_db);
void start_core_engine_statistic(const ConfigManager& config);
void start_core_engine_simulation(const ConfigManager& config);

#endif // CORE_ENGINE_HPP
