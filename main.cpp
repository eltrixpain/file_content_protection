// main.cpp
#include "CoreEngine.hpp"
#include "requirements.hpp"
#include <iostream>

int main() {
    auto boot = Requirements::run("./config.json", "cache/cache.sqlite");
    if (!boot.ok) {
        std::cerr << "[Main] aborted: " << boot.error << "\n";
        return 1;
    }
    start_core_engine(boot.config, boot.db.get());
    return 0;
}
