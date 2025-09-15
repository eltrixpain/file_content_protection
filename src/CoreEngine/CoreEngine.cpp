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
#include <unistd.h>
#include <chrono>


#define BUF_SIZE 4096

#include <chrono>
using SteadyClock = std::chrono::steady_clock;


static uint64_t decisions = 0;
static uint64_t hits = 0;
static uint64_t total_us = 0;        // مجموع میکروثانیه کل تصمیم‌ها
static uint64_t total_hit_us = 0;    // اختیاری: میانگین مخصوص hit
static uint64_t total_miss_us = 0;   // اختیاری: میانگین مخصوص miss

auto report_every = [](uint64_t n) {
    if (decisions % n == 0 && decisions > 0) {
        double avg_ms = (double)total_us / decisions / 1000.0;
        double hit_rate = (double)hits * 100.0 / (double)decisions;
        std::cout << "[metrics] decisions=" << decisions
                  << " hit_rate=" << hit_rate << "% "
                  << "avg_decision=" << avg_ms << " ms"
                  << std::endl;
    }
};


void start_core_engine(const ConfigManager& config, sqlite3* cache_db) {
    // [Fanotify registration]
    // get data for register fanotify from config file
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

    // [Create new thread for logging]
    int log_pipe[2];
    if (pipe(log_pipe) == -1) { perror("pipe"); exit(1); }

    pid_t logger_pid = fork();
    if (logger_pid == -1) { perror("fork"); exit(1); }

    if (logger_pid == 0) {
        close(log_pipe[1]);
        logger_loop(log_pipe[0]);
        _exit(0);
    }

    // [Initialize and assignment for prepration]
    pid_t self_pid = getpid();
    RuleEvaluator evaluator(config);
    char buffer[BUF_SIZE];
    struct fanotify_event_metadata* metadata;
    CacheManager cache(cache_db);
    const uint64_t RULESET_VERSION = config.getRulesetVersion();

    //[Start main loop of program]
    std::cout << "[CoreEngine] Watching " << target << " for access events...\n"; 
    while (true) {
        ssize_t len = read(fan_fd, buffer, sizeof(buffer));
        if (len <= 0) continue;
        metadata = (struct fanotify_event_metadata*)buffer;
        while (FAN_EVENT_OK(metadata, len)) {
            if (metadata->vers != FANOTIFY_METADATA_VERSION) {
                std::cerr << "Mismatched fanotify version!" << std::endl;
                exit(1);
            }

            //  Only montior on open request
            if ((metadata->mask & FAN_OPEN_PERM) == 0) {
                metadata = FAN_EVENT_NEXT(metadata, len);
                continue;
            }

            //  Exclude progarm pid and logger pid from checking
            if (metadata->pid == self_pid || metadata->pid == logger_pid) {
                // std::cout << "[Access] By program itself" << std::endl ;
                struct fanotify_response resp{};
                resp.fd = metadata->fd;
                resp.response = FAN_ALLOW;
                ssize_t _wr = ::write(fan_fd, &resp, sizeof(resp));
                (void)_wr;
                close(metadata->fd);
                metadata = FAN_EVENT_NEXT(metadata, len);
                continue;
            }
            auto t0 = SteadyClock::now();
            struct stat st{};
            if (fstat(metadata->fd, &st) == 0) {
                int decision = 0;

                //Cache path
                if (cache.get(st, RULESET_VERSION, decision)) {
                    hits++;  // برای Hit Rate
                    // پاسخ دادن...
                    struct fanotify_response resp{};
                    resp.fd = metadata->fd;
                    resp.response = (decision == 0) ? FAN_ALLOW : FAN_DENY;
                    ssize_t _wr = ::write(fan_fd, &resp, sizeof(resp));
                    (void)_wr;
                    // زمان را جمع بزن:
                    auto dt_us = (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(SteadyClock::now() - t0).count();
                    total_us += dt_us;
                    total_hit_us += dt_us; // اختیاری
                    decisions++;
                    report_every(1000);

                    close(metadata->fd);
                    metadata = FAN_EVENT_NEXT(metadata, len);
                    continue;
                }

                // Miss path: evaluate + put
                evaluator.handle_event(fan_fd, metadata, log_pipe[1], decision);
                cache.put(st, RULESET_VERSION, decision);

                // پایان اندازه‌گیری برای miss:
                auto dt_us = (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(SteadyClock::now() - t0).count();
                total_us += dt_us;
                total_miss_us += dt_us; // اختیاری
                decisions++;
                report_every(100);

                metadata = FAN_EVENT_NEXT(metadata, len);
                continue;
            }


            // Allow file if fstat failed due to priventing of deadlock
            {
                std::cout << "whyyyyyyyyy!!!!!!" << std::endl;
                struct fanotify_response resp{};
                resp.fd = metadata->fd;
                resp.response = FAN_ALLOW;
                ssize_t _wr = ::write(fan_fd, &resp, sizeof(resp));
                (void)_wr;
                close(metadata->fd);
                metadata = FAN_EVENT_NEXT(metadata, len);
            }
        }
    }
}
