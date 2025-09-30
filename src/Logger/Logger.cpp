// === src/Logger/Logger.cpp ===
#include "Logger.hpp"
#include <cstdio>
#include <unistd.h>

#define LOG_PATH "logs/fileguard.log"


// Desc: logger loop to read from pipe and append to log file
// In: int pipe_read_fd
// Out: void
void logger_loop(int pipe_read_fd) {
    char buf[1024];
    // [Main loop of logger thread]
    while (true) {
        ssize_t len = read(pipe_read_fd, buf, sizeof(buf) - 1);
        if (len > 0) {
            buf[len] = '\0';
            FILE* f = fopen(LOG_PATH, "a");
            if (f) {
                fwrite(buf, 1, len, f);
                fclose(f);
            }
        }
    }
}
