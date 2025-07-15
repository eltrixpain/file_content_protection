#include "RegexConfigManager.hpp"
#include <fstream>
#include <iostream>

bool RegexConfigManager::loadFromFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return false;

    std::string line;
    while (std::getline(file, line)) {
        try {
            patterns.emplace_back(line, std::regex::ECMAScript | std::regex::icase);
        } catch (const std::regex_error& e) {
            std::cerr << "[RegexConfigManager] Invalid regex: " << line << "\n";
        }
    }
    return true;
}

bool RegexConfigManager::matches(const std::string& text) const {
    for (const auto& pattern : patterns) {
        if (std::regex_search(text, pattern)) return true;
    }
    return false;
}
