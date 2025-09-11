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
#include <unistd.h>     // getpid

#define BUF_SIZE 4096

void start_core_engine(const ConfigManager& config, sqlite3* cache_db) {
    const std::string mode   = config.getWatchMode();
    const std::string target = config.getWatchTarget();

    int fan_fd = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK,
                               O_RDONLY | O_LARGEFILE);
    if (fan_fd == -1) { perror("fanotify_init"); exit(1); }

    uint64_t mask  = FAN_OPEN_PERM | FAN_EVENT_ON_CHILD;
    uint64_t flags = FAN_MARK_ADD;

    if (mode == "mount") {
        flags |= FAN_MARK_MOUNT;
    }

    if (fanotify_mark(fan_fd, flags, mask, AT_FDCWD, target.c_str()) == -1) {
        perror("fanotify_mark");
        exit(1);
    }

    int log_pipe[2];
    if (pipe(log_pipe) == -1) { perror("pipe"); exit(1); }

    pid_t logger_pid = fork();
    if (logger_pid == -1) { perror("fork"); exit(1); }

    if (logger_pid == 0) {
        close(log_pipe[1]);
        logger_loop(log_pipe[0]);
        _exit(0);
    }

    // === NEW: record our own pid for self-filtering
    pid_t self_pid = getpid();

    RuleEvaluator evaluator(config);
    std::cout << "[CoreEngine] Watching " << target << " for access events...\n"; // fixed

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

            // فقط روی permission events کار می‌کنیم
            if ((metadata->mask & FAN_OPEN_PERM) == 0) {
                metadata = FAN_EVENT_NEXT(metadata, len);
                continue;
            }

            // === NEW: Self-filter (قبل از cache/evaluator)
            if (metadata->pid == self_pid || metadata->pid == logger_pid) {
                std::cout << "self" << std::endl ;
                struct fanotify_response resp{};
                resp.fd = metadata->fd;
                resp.response = FAN_ALLOW;
                (void)write(fan_fd, &resp, sizeof(resp));
                close(metadata->fd);
                metadata = FAN_EVENT_NEXT(metadata, len);
                continue;
            }

            // حالا می‌توانیم cache/evaluator را اجرا کنیم
            struct stat st{};
            if (fstat(metadata->fd, &st) == 0) {
                int decision = 0;

                // 1) cache try
                if (cache.get(st, RULESET_VERSION, decision)) {
                    std::cout << "[cache] hit: dev=" << st.st_dev
                              << " ino=" << st.st_ino
                              << " decision=" << decision
                              << std::endl;

                    struct fanotify_response resp{};
                    resp.fd = metadata->fd;
                    resp.response = (decision == 0) ? FAN_ALLOW : FAN_DENY;

                    // اگر block شد، برای لاگ یک پیام هم بفرستیم
                    if (decision != 0) {
                        char link[64]; snprintf(link, sizeof(link), "/proc/self/fd/%d", metadata->fd);
                        char realpath_buf[512];
                        ssize_t r = readlink(link, realpath_buf, sizeof(realpath_buf) - 1);
                        if (r > 0) {
                            realpath_buf[r] = '\0';
                            std::time_t now = std::time(nullptr);
                            char* dt = std::ctime(&now);
                            if (dt) {
                                dt[std::strlen(dt) - 1] = '\0';
                                std::string log_line = "[" + std::string(dt) + "] BLOCKED: " +
                                                       realpath_buf + " for PID [" +
                                                       std::to_string(metadata->pid) + "]\n";
                                (void)write(log_pipe[1], log_line.c_str(), log_line.size());
                            }
                        }
                    }

                    (void)write(fan_fd, &resp, sizeof(resp));
                    close(metadata->fd);
                    metadata = FAN_EVENT_NEXT(metadata, len);
                    continue;
                }

                // 2) cache miss → evaluate + cache.put
                evaluator.handle_event(fan_fd, metadata, logger_pid, log_pipe[1], decision);
                cache.put(st, RULESET_VERSION, decision);
                metadata = FAN_EVENT_NEXT(metadata, len);
                continue;
            }

            // fallback: اگر fstat نشد، امن‌ترین کار: allow و رد شو
            {
                struct fanotify_response resp{};
                resp.fd = metadata->fd;
                resp.response = FAN_ALLOW;
                (void)write(fan_fd, &resp, sizeof(resp));
                close(metadata->fd);
                metadata = FAN_EVENT_NEXT(metadata, len);
            }
        }
    }
}
