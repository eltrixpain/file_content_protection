#ifndef REGEX_CONFIG_MANAGER_HPP
#define REGEX_CONFIG_MANAGER_HPP

#include <vector>
#include <regex>
#include <string>

class RegexConfigManager {
public:
    bool loadFromFile(const std::string& path);
    bool matches(const std::string& text) const;

private:
    std::vector<std::regex> patterns;
};

#endif // REGEX_CONFIG_MANAGER_HPP
