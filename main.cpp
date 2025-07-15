// === main.cpp ===
#include "CoreEngine.hpp"
#include "ConfigManager.hpp" 
#include <iostream>

int main() {
    ConfigManager config;
    if (!config.loadFromFile("./config.json")) {
        std::cerr << "[Main] Failed to load configuration file.\n";
        return 1;
    }
    start_core_engine(config);
    return 0;
}
