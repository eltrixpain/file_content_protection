// === include/StatisticStoreIO.hpp ===
#pragma once
#include "StatisticStore.hpp"
#include <string>

bool save_statistic_store(const StatisticStore& store, const std::string& path);
bool load_statistic_store(StatisticStore& store, const std::string& path);
