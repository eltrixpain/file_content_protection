// === src/CoreEngine/CoreEngine.cpp ===
#include "CoreEngine.hpp"
#include "Logger.hpp"
#include "ConfigManager.hpp" 
#include "RuleEvaluator.hpp"


#include <iostream>
#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <cstring>
#include <cstdlib>


#define BUF_SIZE 4096
#define LOG_PATH "/tmp/fileguard.log"



void start_core_engine(const ConfigManager& config) {
    std::string watch_path = config.getWatchPath();
    int fan_fd = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK, O_RDONLY | O_LARGEFILE);
    if (fan_fd == -1) { perror("fanotify_init"); exit(1); }

    if (fanotify_mark(fan_fd, FAN_MARK_ADD, FAN_OPEN_PERM | FAN_EVENT_ON_CHILD, AT_FDCWD, watch_path.c_str()) == -1) {
        perror("fanotify_mark"); exit(1);
    }

    int log_pipe[2];
    if (pipe(log_pipe) == -1) { perror("pipe"); exit(1); }

    pid_t logger_pid = fork();
    if (logger_pid == -1) { perror("fork"); exit(1); }

    if (logger_pid == 0) {
        close(log_pipe[1]);
        logger_loop(log_pipe[0]);
        exit(0);
    }

    RuleEvaluator evaluator(config);
    std::cout << "[CoreEngine] Watching " << watch_path << " for access events...\n";

    char buffer[BUF_SIZE];
    struct fanotify_event_metadata* metadata;

    while (true) {
        ssize_t len = read(fan_fd, buffer, sizeof(buffer));
        if (len <= 0) continue;
        metadata = (struct fanotify_event_metadata*)buffer;
        while (FAN_EVENT_OK(metadata, len)) {
            if (metadata->vers != FANOTIFY_METADATA_VERSION) {
                std::cerr << "Mismatched fanotify version!" << std::endl;
                exit(1);
            }
            evaluator.handle_event(fan_fd, metadata, logger_pid, log_pipe[1]);
            metadata = FAN_EVENT_NEXT(metadata, len);
        }
    }
}
