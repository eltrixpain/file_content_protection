// === src/CoreEngine/CoreEngine.cpp ===
#include "CoreEngine.hpp"
#include "Logger.hpp"
#include "ConfigManager.hpp"
#include "RuleEvaluator.hpp"
#include "CacheL1.hpp"
#include "CacheL2.hpp"
#include "StatisticStore.hpp"
#include "AsyncScanQueue.hpp"
#include "Warmup.hpp"
#include "ContentParser.hpp"
#include "SimpleSemaphore.hpp"

#include <iostream>
#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <cstring>
#include <fcntl.h>
#include <cstdlib>
#include <unistd.h>
#include <chrono>
#include <fstream>
#include <thread>
#include <functional>
#include <filesystem>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <math.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sched.h>
#include <errno.h>
#include <string.h>

#define BUF_SIZE 4096
#define REPORT_PER_CYCLE 300
#define COLOR_GREEN "\033[1;32m"
#define COLOR_CYAN  "\033[1;36m"
#define COLOR_RED   "\033[1;31m"
#define COLOR_RESET "\033[0m"

using SteadyClock = std::chrono::steady_clock;

// Global metrics (atomic because workers update them)
static std::atomic<uint64_t> decisions{0};
static std::atomic<uint64_t> hits{0};
static std::atomic<uint64_t> total_us{0};
static std::atomic<uint64_t> total_bytes{0};
static std::atomic<uint64_t> hit_bytes{0};


// tune this based on CPU / IO
unsigned int cores = std::thread::hardware_concurrency();
unsigned int max_concurrency = std::max(cores * 2, 8u);
static SimpleSemaphore g_worker_slots(max_concurrency);


// Desc: periodically print metrics every n decisions
// In: uint64_t n (report interval)
// Out: void
auto report_every = [](uint64_t n) {
    uint64_t d = decisions.load(std::memory_order_relaxed);
    if (d % n == 0 && d > 0) {
        double avg_ms = (double)total_us.load(std::memory_order_relaxed) / (double)d / 1000.0;
        double hit_rate = (double)hits.load(std::memory_order_relaxed) * 100.0 / (double)d;
        uint64_t tb = total_bytes.load(std::memory_order_relaxed);
        double byte_hit_rate = tb ? (double)hit_bytes.load(std::memory_order_relaxed) * 100.0 / (double)tb : 0.0;
        std::cout << COLOR_RED
          << "[metrics] decisions=" << d
          << " hit_rate=" << hit_rate << "% "
          << "byte_hit_rate=" << byte_hit_rate << "% "
          << "avg_decision=" << avg_ms << " ms"
          << COLOR_RESET << std::endl;
    }
};

// Desc: run blocking fanotify loop with logging, cache, and rule evaluation
// In: const ConfigManager& config, sqlite3* cache_db
// Out: void
void start_core_engine_blocking(const ConfigManager& config, sqlite3* cache_db) {
    // [Fanotify registration]
    const std::string mode   = config.getWatchMode();
    const std::string target = config.getWatchTarget();

    int fan_fd = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC,
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

    // [Initialize and assignment for preparation]
    pid_t self_pid = getpid();
    PatternMatcherHS hs;
    hs.buildFromConfig(config);
    RuleEvaluator evaluator(config, hs);
    char buffer[BUF_SIZE];
    struct fanotify_event_metadata* metadata;
    CacheL1 l1(cache_db);
    CacheL2 l2(l1);
    const uint64_t RULESET_VERSION = config.getRulesetVersion();

    // [Starting thread pool] (kept for other async parts if used)
    start_async_workers(log_pipe[1], config, &hs, l2, /*num_workers=*/1);

    if (config.getWarmupMode() == WarmupMode::Pattern) {
        std::cout << "[CoreEngine] engine will start after pattern warmup…\n";
        std::thread warm_thr([&](){
            const size_t top_k = 20000;     // max candidates by hit
            const double ratio = 0.80;      // fill L2 up to 80% of capacity
            Warmup::pattern_warmup(cache_db, config, top_k, ratio);
        });
        warm_thr.join();
        std::cout << "[CoreEngine] pattern warmup finished. starting engine…\n";
    }

    // [Start main loop of program]
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

            // Only monitor on open request
            if ((metadata->mask & FAN_OPEN_PERM) == 0) {
                metadata = FAN_EVENT_NEXT(metadata, len);
                continue;
            }

            // Exclude program pid and logger pid from checking
            if (metadata->pid == self_pid || metadata->pid == logger_pid) {
                #ifdef DEBUG
                std::cout << "[Access] By program itself" << std::endl;
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
                if (n >= 0) path_buf[n] = '\0'; else path_buf[0] = '\0';

                std::cout << "[CoreEngine] Access: dev=" << st.st_dev
                << " ino=" << st.st_ino
                << " size=" << st.st_size
                << " mtime=" << st.st_mtim.tv_sec
                << " path=" << path_buf
                << " PID=" << pid
                << " PROC=" << proc_comm
                << std::endl;
                #endif

                // Cache path (fast path, handled synchronously)
                int resp_cache = l2.get(st, RULESET_VERSION, decision, config.max_cache_bytes());
                if (resp_cache != 0) {
                    if (resp_cache == 2) {
                        hits.fetch_add(1, std::memory_order_relaxed);
                        hit_bytes.fetch_add((uint64_t)st.st_size, std::memory_order_relaxed);
                    }
                    total_bytes.fetch_add((uint64_t)st.st_size, std::memory_order_relaxed);

                    struct fanotify_response resp{};
                    resp.fd = metadata->fd;
                    resp.response = (decision == 0) ? FAN_ALLOW : FAN_DENY;
                    ssize_t _wr = ::write(fan_fd, &resp, sizeof(resp));
                    (void)_wr;

                    auto dt_us = (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(
                                     SteadyClock::now() - t0).count();
                    total_us.fetch_add(dt_us, std::memory_order_relaxed);
                    decisions.fetch_add(1, std::memory_order_relaxed);

                    report_every(REPORT_PER_CYCLE);

                    close(metadata->fd);
                    metadata = FAN_EVENT_NEXT(metadata, len);
                    continue;
                }

                // Miss path: offload everything to a worker so the main loop never blocks
                {
                    // Transfer ownership of the fd to the worker
                    int event_fd = metadata->fd;

                    // Snapshot what the worker needs
                    int fan_fd_local = fan_fd;
                    int log_fd = log_pipe[1];
                    struct stat st_copy = st;
                    uint64_t ruleset = RULESET_VERSION;
                    uint64_t cap_bytes = config.max_cache_bytes();
                    auto t0_copy = t0;

                    // Limit concurrency
                    g_worker_slots.acquire();

                    std::thread([&, fan_fd_local, log_fd, event_fd, st_copy, ruleset, cap_bytes, t0_copy]() {
                        #ifdef DEBUG
                            {
                                pid_t tid = (pid_t)syscall(SYS_gettid);
                                char path_buf[512];
                                snprintf(path_buf, sizeof(path_buf), "/proc/self/fd/%d", event_fd);
                                char resolved[512];
                                ssize_t n = readlink(path_buf, resolved, sizeof(resolved) - 1);
                                if (n >= 0) resolved[n] = '\0'; else strcpy(resolved, "unknown");

                                std::cout << COLOR_CYAN
                                        << "[Worker] TID=" << tid
                                        << " checking file=" << resolved
                                        << COLOR_RESET << std::endl;
                            }
                        #endif
                        int decision_local = 0;

                        // Minimal metadata carrying just the fd for evaluator
                        struct fanotify_event_metadata md_min{};
                        md_min.fd = event_fd;

                        // 1) Heavy decision. Contract: this writes fanotify response.
                        evaluator.handle_event(fan_fd_local, &md_min, log_fd, decision_local);

                        // If handle_event doesn't close the fd internally, uncomment:
                        // close(event_fd);

                        // 2) Cache put (CacheL2 is internally synchronized)
                        if (decision_local != 2) {
                            l2.put(st_copy, ruleset, decision_local, cap_bytes);
                        }

                        // 3) Metrics (asynchronous)
                        auto dt_us = (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(
                                         SteadyClock::now() - t0_copy).count();
                        total_us.fetch_add(dt_us, std::memory_order_relaxed);
                        decisions.fetch_add(1, std::memory_order_relaxed);
                        total_bytes.fetch_add((uint64_t)st_copy.st_size, std::memory_order_relaxed);

                        report_every(REPORT_PER_CYCLE);

                        g_worker_slots.release();
                    }).detach();

                    // Important: the main thread must not touch/close event_fd now
                    char fd_link_opened[64];
                    snprintf(fd_link_opened, sizeof(fd_link_opened), "/proc/self/fd/%d", metadata->fd);
                    char opened_path_buf[512];
                    ssize_t opened_n = readlink(fd_link_opened, opened_path_buf, sizeof(opened_path_buf) - 1);
                    std::string opened_path = (opened_n >= 0) ? std::string(opened_path_buf, opened_n) : std::string();

                    if (config.getWarmupMode() == WarmupMode::Scope && !opened_path.empty()) {
                        Warmup::scope_warmup_on_access(opened_path);
                    }
                    metadata = FAN_EVENT_NEXT(metadata, len);
                    continue;
                }
            }

            // Allow file if fstat failed to prevent deadlock
            {
                #ifdef DEBUG
                std::cout << "fstat failed; allowing to prevent deadlock" << std::endl;
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
