#ifndef CORE_ENGINE_HPP
#define CORE_ENGINE_HPP
#pragma once
#include <sys/fanotify.h>
#include <unistd.h>

#include "ConfigManager.hpp"

void start_core_engine(const ConfigManager& config);

#endif // CORE_ENGINE_HPP
