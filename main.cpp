// main.cpp
#include "CoreEngine.hpp"
#include "requirements.hpp"
#include <iostream>
#include <string>

void print_help() {
    std::cout << "Usage:\n"
              << "  ./filegaurde                Run in blocking mode (default)\n"
              << "  ./filegaurde statistic      Run in statistic gathering mode\n"
              << "  ./filegaurde simulation     Run in simulation mode\n"
              << "  ./filegaurde -h, --help     Show this help message\n";
}

int main(int argc, char** argv) {
    // Handle help flag early
    if (argc > 1 && (std::string(argv[1]) == "-h" || std::string(argv[1]) == "--help")) {
        print_help();
        return 0;
    }
    const char* cache_env = std::getenv("FILEGUARD_CACHE");
    std::string cache_path = cache_env ? cache_env : "cache/cache.sqlite";
    
    auto boot = Requirements::run("./config.json", cache_path.c_str());
    if (!boot.ok) {
        std::cerr << "[Main] aborted: " << boot.error << "\n";
        return 1;
    }

    // "statistic" mode
    if (argc > 1 && std::string(argv[1]) == "statistic") {
        start_core_engine_statistic(boot.config);
        return 0;
    }

    // "simulation" mode
    if (argc > 1 && std::string(argv[1]) == "simulation") {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " simulation <trace_file.bin>\n";
            return 1;
        }
        std::string filename = argv[2];
        start_core_engine_simulation(boot.config, filename);
        return 0;
    }

    // default: blocking mode
    start_core_engine_blocking(boot.config, boot.db.get());
    return 0;
}
