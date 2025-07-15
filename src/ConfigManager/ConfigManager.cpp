#include "ConfigManager.hpp"
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

bool ConfigManager::loadFromFile(const std::string& config_path) {
    std::ifstream file(config_path);
    if (!file.is_open()) return false;

    json j;
    file >> j;

    // Parse watch_path
    if (!j.contains("watch_path") || !j["watch_path"].is_string()) return false;
    watch_path = j["watch_path"];

    // Parse regex patterns
    if (!j.contains("patterns") || !j["patterns"].is_array()) return false;

    for (const auto& p : j["patterns"]) {
        if (!p.is_string()) continue;
        try {
            patterns.emplace_back(p.get<std::string>(), std::regex::ECMAScript | std::regex::icase);
        } catch (const std::regex_error& e) {
            std::cerr << "[ConfigManager] Invalid regex: " << p << "\n";
        }
    }

    return true;
}

const std::string& ConfigManager::getWatchPath() const {
    return watch_path;
}

bool ConfigManager::matches(const std::string& text) const {
    for (const auto& pattern : patterns) {
        if (std::regex_search(text, pattern)) return true;
    }
    return false;
}
