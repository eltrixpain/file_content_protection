// === src/CoreEngine/CoreEngine.cpp ===
#include "CoreEngine.hpp"
#include "Logger.hpp"
#include "ConfigManager.hpp" 
#include "RuleEvaluator.hpp"
#include "CacheManager.hpp"
#include "StatisticStore.hpp"

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
#include <filesystem>



#define BUF_SIZE 4096
#define REPORT_PER_CYCLE 50

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


void start_core_engine_blocking(const ConfigManager& config, sqlite3* cache_db) {
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
                    report_every(REPORT_PER_CYCLE);
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
                report_every(REPORT_PER_CYCLE);
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
namespace fs = std::filesystem;

static StatisticStore g_stats;

static inline int64_t now_ns() {
    struct timespec ts{};
    clock_gettime(CLOCK_REALTIME, &ts); // wall-clock for reporting
    return (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
}


// CSV dump: size distribution per file
// Columns: dev,ino,size_bytes
static void dump_size_distribution_csv(std::ostream& os) {
    os << "dev,ino,size_bytes\n";
    for (const auto& [key, sz] : g_stats.sizes.sizes) {
        os << key.dev << ',' << key.ino << ',' << sz << '\n';
    }
}

// CSV dump: access distribution per file
// Columns: dev,ino,open_hits
static void dump_access_distribution_csv(std::ostream& os) {
    os << "dev,ino,open_hits\n";
    for (const auto& [key, hits] : g_stats.access.open_hits) {
        os << key.dev << ',' << key.ino << ',' << hits << '\n';
    }
}


// Scan /home recursively and populate sizes distribution
// Fills: g_stats.sizes.sizes[key] = file_size
static void pre_scan_home_sizes(const std::string& root_path) {
    std::error_code ec;
    uint64_t scanned = 0;
    std::cout << "[stat] pre-scan: scanning " << root_path << " ...\n";

    for (fs::recursive_directory_iterator it(root_path, fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) {
            // skip entries we cannot access
            ec.clear();
            continue;
        }
        const fs::directory_entry& de = *it;
        // only regular files
        if (!de.is_regular_file(ec) || ec) {
            if (ec) ec.clear();
            continue;
        }
        // obtain native path and stat to get dev/ino/size (stat is robust)
        struct stat st{};
        if (stat(de.path().c_str(), &st) != 0) {
            // couldn't stat — skip
            continue;
        }
        FileKey key{ (uint64_t)st.st_dev, (uint64_t)st.st_ino };
        uint64_t fsize = (uint64_t)st.st_size;
        // fill sizes map
        g_stats.sizes.sizes[key] = fsize; // populate size distribution
        scanned++;
        #ifdef DEBUG
        if ((scanned & 0x3FFF) == 0) {
            std::cout << "[stat] pre-scan: scanned " << scanned << " files...\n";
        }
        #endif
    }

    std::cout << "[stat] pre-scan done, scanned " << scanned << " files, sizes populated.\n";
}

void start_core_engine_statistic() {
    // 1) pre-scan /home to build size distribution
    pre_scan_home_sizes("/home");
    std::ofstream ofs1("statistical_result/sizes.csv");
    dump_size_distribution_csv(ofs1);
    ofs1.close();

    // 2) start fanotify loop to collect access distribution and trace
    int fan_fd = fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK,
                               O_RDONLY | O_LARGEFILE);
    if (fan_fd == -1) {
        perror("fanotify_init");
        return;
    }

    uint64_t mask  = FAN_OPEN;                   // only OPEN events
    uint64_t flags = FAN_MARK_ADD | FAN_MARK_MOUNT;

    if (fanotify_mark(fan_fd, flags, mask, AT_FDCWD, "/home") == -1) {
        perror("fanotify_mark");
        close(fan_fd);
        return;
    }

    std::cout << "[CoreEngine] statistic: listening for OPEN on /home (mount)\n";

    char buffer[4096];
    while (true) {
        struct pollfd pfd { fan_fd, POLLIN, 0 };
        int pret = poll(&pfd, 1, 1000); // 1s timeout to avoid busy loop
        if (pret <= 0) continue;

        ssize_t len = read(fan_fd, buffer, sizeof(buffer));
        if (len <= 0) continue;

        struct fanotify_event_metadata* metadata =
            (struct fanotify_event_metadata*)buffer;

        while (FAN_EVENT_OK(metadata, len)) {
            if (metadata->vers != FANOTIFY_METADATA_VERSION) {
                std::cerr << "[stat] fanotify version mismatch\n";
                close(fan_fd);
                return;
            }

            if (metadata->mask & FAN_OPEN) {
                // event timestamp
                const int64_t ts = now_ns();

                // stat the supplied fd to get (dev, ino, size)
                struct stat st{};
                if (fstat(metadata->fd, &st) == 0) {
                    FileKey key{ (uint64_t)st.st_dev, (uint64_t)st.st_ino };
                    uint64_t fsize = (uint64_t)st.st_size;

                    // 1) update access.open_hits
                    g_stats.access.open_hits[key] += 1; // increment open count

                    // 2) update sizes.sizes (store/refresh current size if changed)
                    // size map was initially populated by pre-scan; refresh in case of changes
                    g_stats.sizes.sizes[key] = fsize;

                    // 3) append to trace.events
                    g_stats.trace.events.push_back(TraceEvent{
                        ts, key, fsize, OpType::Open
                    });

                    // debug print (path is just for visibility)
                    char fd_link[64];
                    snprintf(fd_link, sizeof(fd_link), "/proc/self/fd/%d", metadata->fd);
                    char path_buf[512];
                    ssize_t n = readlink(fd_link, path_buf, sizeof(path_buf) - 1);
                    if (n >= 0) {
                        path_buf[n] = '\0';
                        std::cout << "[stat] OPEN dev=" << st.st_dev
                                  << " ino=" << st.st_ino
                                  << " size=" << st.st_size
                                  << " path=" << path_buf
                                  << " hits=" << g_stats.access.open_hits[key]
                                  << std::endl;
                    } else {
                        std::cout << "[stat] OPEN dev=" << st.st_dev
                                  << " ino=" << st.st_ino
                                  << " size=" << st.st_size
                                  << " path=?"
                                  << " hits=" << g_stats.access.open_hits[key]
                                  << std::endl;
                    }
                } else {
                    std::cout << "[stat] OPEN (fstat failed)\n";
                }

                // always close the supplied FD
                close(metadata->fd);
            } else {
                if (metadata->fd >= 0) close(metadata->fd);
            }

            metadata = FAN_EVENT_NEXT(metadata, len);
        }
    }
}
