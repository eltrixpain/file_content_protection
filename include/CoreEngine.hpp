#ifndef CORE_ENGINE_HPP
#define CORE_ENGINE_HPP
#pragma once
#include <sys/fanotify.h>
#include <unistd.h>
#include <sqlite3.h>

#include "ConfigManager.hpp"

void start_core_engine(const ConfigManager& config, sqlite3* cache_db);

#endif // CORE_ENGINE_HPP
