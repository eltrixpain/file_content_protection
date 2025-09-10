// === src/CoreEngine/CoreEngine.cpp ===
#include "CoreEngine.hpp"
#include "Logger.hpp"
#include "ConfigManager.hpp" 
#include "RuleEvaluator.hpp"
#include "CacheManager.hpp"


#include <iostream>
#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <cstring>
#include <cstdlib>


#define BUF_SIZE 4096
#define LOG_PATH "/tmp/fileguard.log"



void start_core_engine(const ConfigManager& config, sqlite3* cache_db) {
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

    CacheManager cache(cache_db);                   
    const uint64_t RULESET_VERSION = config.getRulesetVersion();

    while (true) {
        ssize_t len = read(fan_fd, buffer, sizeof(buffer));
        if (len <= 0) continue;
        metadata = (struct fanotify_event_metadata*)buffer;

        while (FAN_EVENT_OK(metadata, len)) {
            if (metadata->vers != FANOTIFY_METADATA_VERSION) {
                std::cerr << "Mismatched fanotify version!" << std::endl;
                exit(1);
            }

            // try cache first (only for permission events with a valid fd)
            if (metadata->mask & FAN_OPEN_PERM) {
                struct stat st{};
                if (fstat(metadata->fd, &st) == 0) {
                    int decision = 0;
                    // try cache
                    if (cache.get(st, RULESET_VERSION, decision)) {

                        std::cout << "[cache] hit: dev=" << st.st_dev
                                  << " ino=" << st.st_ino
                                  << " decision=" << decision
                                  << std::endl;

                        struct fanotify_response resp{};
                        resp.fd = metadata->fd;
                        resp.response = (decision == 0) ? FAN_ALLOW : FAN_DENY;
                        // If block
                        if (decision != 0) {
                            // find path of file
                            char path_buf[512];
                            snprintf(path_buf, sizeof(path_buf), "/proc/self/fd/%d", metadata->fd);
                            char realpath_buf[512];
                            ssize_t r = readlink(path_buf, realpath_buf, sizeof(realpath_buf) - 1);
                            if (r > 0) {
                                realpath_buf[r] = '\0';
                                // timestamp
                                std::time_t now = std::time(nullptr);
                                char* date_time = std::ctime(&now);
                                date_time[strlen(date_time) - 1] = '\0';
                            
                                std::string log_line = "[" + std::string(date_time) + "] BLOCKED: " +
                                                       realpath_buf + " for PID [" +
                                                       std::to_string(metadata->pid) + "]\n";
                                (void)write(log_pipe[1], log_line.c_str(), log_line.size());
                            }
                        }
                        // fanotify answer
                        (void)write(fan_fd, &resp, sizeof(resp));
                        close(metadata->fd);
                        metadata = FAN_EVENT_NEXT(metadata, len);
                        continue;
                        }


                    // miss → evaluate, then cache.put
                    evaluator.handle_event(fan_fd, metadata, logger_pid, log_pipe[1], decision);
                    cache.put(st, RULESET_VERSION, decision);
                    metadata = FAN_EVENT_NEXT(metadata, len);
                    continue;
                }
            }

        }
    }
}
