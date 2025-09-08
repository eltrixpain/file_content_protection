// === main.cpp ===
#include "CoreEngine.hpp"
#include "ConfigManager.hpp"
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>

// config log helper
static void cfglog(const std::string& msg) {
    int fd = open("logs/config.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd != -1) {
        // timestamp
        time_t now = time(nullptr);
        char buf[64];
        ctime_r(&now, buf);
        buf[strlen(buf) - 1] = '\0'; // remove newline

        std::string line = "[" + std::string(buf) + "] " + msg + "\n";
        write(fd, line.c_str(), line.size());
        close(fd);
    }
}

// pre-run config validation
static bool validate_config(const ConfigManager& config) {
    const std::string wp = config.getWatchPath();

    // path checks
    struct stat st{};
    if (wp.empty()) {
        cfglog("[config] watch_path is empty");
        return false;
    }
    if (stat(wp.c_str(), &st) == -1) {
        cfglog(std::string("[config] path not found: ") + wp + " (" + strerror(errno) + ")");
        return false;
    }
    if (!S_ISDIR(st.st_mode)) {
        cfglog(std::string("[config] path is not a directory: ") + wp);
        return false;
    }
    if (access(wp.c_str(), R_OK | X_OK) != 0) {
        cfglog(std::string("[config] insufficient access: ") + wp + " (" + strerror(errno) + ")");
        return false;
    }

    // pattern checks
    if (config.patternCount() == 0) {
        cfglog("[config] no valid patterns loaded");
        return false;
    }

    return true;
}

int main() {
    ConfigManager config;
    if (!config.loadFromFile("./config.json")) {
        cfglog("[config] failed to load ./config.json");
        std::cerr << "[Main] aborted due to config error (see logs/config.log for details)\n";
        return 1;
    }
    if (!validate_config(config)) {
        cfglog("[config] validation failed, aborting");
        std::cerr << "[Main] aborted due to config error (see logs/config.log for details)\n";
        return 1;
    }
    start_core_engine(config);
    return 0;
}

