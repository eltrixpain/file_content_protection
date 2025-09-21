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
#include <fstream>



#define BUF_SIZE 4096

#include <chrono>
using SteadyClock = std::chrono::steady_clock;


static uint64_t decisions = 0;
static uint64_t hits = 0;
static uint64_t total_us = 0;     
static uint64_t total_bytes = 0;   
static uint64_t hit_bytes = 0;   

auto report_every = [](uint64_t n) {
    if (decisions % n == 0 && decisions > 0) {
        double avg_ms = (double)total_us / decisions / 1000.0;
        double hit_rate = (double)hits * 100.0 / (double)decisions;
        double byte_hit_rate = total_bytes ? (double)hit_bytes * 100.0 / (double)total_bytes : 0.0;
        std::cout << "\033[32m"
          << "[metrics] decisions=" << decisions
          << " hit_rate=" << hit_rate << "% "
          << "byte_hit_rate=" << byte_hit_rate << "% "
          << "avg_decision=" << avg_ms << " ms"
          << "\033[0m" << std::endl;
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
                #ifdef DEBUG
                std::cout << "[Access] By program itself" << std::endl ;
                #endif
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

                #ifdef DEBUG
                pid_t pid = metadata->pid;
                char proc_comm[256] = {0};
                std::string comm_path = "/proc/" + std::to_string(pid) + "/comm";
                std::ifstream comm_file(comm_path);
                if (comm_file.is_open()) {
                    comm_file.getline(proc_comm, sizeof(proc_comm));
                    comm_file.close();
                } else {
                    strncpy(proc_comm, "unknown", sizeof(proc_comm)-1);
                }
                char fd_link[64];
                snprintf(fd_link, sizeof(fd_link), "/proc/self/fd/%d", metadata->fd);
                char path_buf[512];
                ssize_t n = readlink(fd_link, path_buf, sizeof(path_buf) - 1);
                path_buf[n] = '\0';

                std::cout << "[CoreEngine] Access: dev=" << st.st_dev
                << " ino=" << st.st_ino
                << " size=" << st.st_size
                << " mtime=" << st.st_mtim.tv_sec
                << " path=" << path_buf
                << " PID=" << pid
                << " PROC=" << proc_comm
                << std::endl;
                #endif


                //Cache path
                if (cache.get(st, RULESET_VERSION, decision)) {
                    hits++;
                    total_bytes += (uint64_t)st.st_size;
                    hit_bytes   += (uint64_t)st.st_size; 
                    struct fanotify_response resp{};
                    resp.fd = metadata->fd;
                    resp.response = (decision == 0) ? FAN_ALLOW : FAN_DENY;
                    ssize_t _wr = ::write(fan_fd, &resp, sizeof(resp));
                    (void)_wr;
                    // زمان را جمع بزن:
                    auto dt_us = (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(SteadyClock::now() - t0).count();
                    total_us += dt_us;
                    decisions++;
                    //#ifdef DEBUG
                    report_every(100);
                    //#endif
                    close(metadata->fd);
                    metadata = FAN_EVENT_NEXT(metadata, len);
                    continue;
                }

                // Miss path: evaluate + put
                evaluator.handle_event(fan_fd, metadata, log_pipe[1], decision);
                cache.put(st, RULESET_VERSION, decision,config.max_cache_bytes());

                // پایان اندازه‌گیری برای miss:
                auto dt_us = (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(SteadyClock::now() - t0).count();
                total_us += dt_us;
                decisions++;
                total_bytes += (uint64_t)st.st_size; 
                //#ifdef DEBUG
                report_every(100);
                //#endif

                metadata = FAN_EVENT_NEXT(metadata, len);
                continue;
            }


            // Allow file if fstat failed due to priventing of deadlock
            {
                #ifdef DEBUG
                std::cout << "fstat doesn't work" << std::endl;
                #endif
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
