#ifndef REGEX_CONFIG_MANAGER_HPP
#define REGEX_CONFIG_MANAGER_HPP

#include <vector>
#include <regex>
#include <string>

class ConfigManager {
public:
    bool loadFromFile(const std::string& path);
    bool matches(const std::string& text) const;
    const std::string& getWatchPath() const;


private:
    std::string watch_path;
    std::vector<std::regex> patterns;
};

#endif // REGEX_CONFIG_MANAGER_HPP
