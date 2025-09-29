// main.cpp
#include "CoreEngine.hpp"
#include "requirements.hpp"
#include <iostream>
#include <string>

int main(int argc, char** argv) {
    auto boot = Requirements::run("./config.json", "cache/cache.sqlite");
    if (!boot.ok) {
        std::cerr << "[Main] aborted: " << boot.error << "\n";
        return 1;
    }

    //"statistic" mode
    if (argc > 1 && std::string(argv[1]) == "statistic") {
        start_core_engine_statistic(boot.config);
        return 0;
    }
    // blocking mode
    start_core_engine_blocking(boot.config, boot.db.get());
    return 0;
}
