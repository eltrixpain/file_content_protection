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
#define COLOR_GREEN "\033[1;32m"
#define COLOR_CYAN  "\033[1;36m"
#define COLOR_RESET "\033[0m"


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

static inline int64_t now_ns_realtime() {
    struct timespec ts{};
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
}

static inline int64_t now_ns_monotonic() {
    struct timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
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

static uint64_t compute_max_file_size_95(const AccessDistribution& acc,
                                         const SizeDistribution& sz)
{
    std::vector<std::pair<uint64_t, uint64_t>> items;
    items.reserve(acc.open_hits.size());
    unsigned __int128 total_hits = 0;

    for (const auto& [key, hits] : acc.open_hits) {
        auto it = sz.sizes.find(key);
        if (it == sz.sizes.end()) continue;
        items.emplace_back(it->second, hits);
        total_hits += hits;
    }
    if (items.empty() || total_hits == 0) return 0;

    std::sort(items.begin(), items.end(),
              [](auto& a, auto& b){ return a.first < b.first; });

    unsigned __int128 target = (total_hits * 95 + 99) / 100; // ceil(0.95 * total)
    unsigned __int128 cum = 0;
    for (const auto& [size, hits] : items) {
        cum += hits;
        if (cum >= target) {
            double coverage = (double)(unsigned long long)cum /
                              (double)(unsigned long long)total_hits * 100.0;
            std::cout << COLOR_GREEN
                      << "[stat] max_file_size_sync_scan = " << size
                      << " bytes"
                      << COLOR_RESET << "  "
                      << COLOR_CYAN << "(covers ~"
                      << std::fixed << std::setprecision(2)
                      << coverage << "% of accesses)"
                      << COLOR_RESET << std::endl;
            return size;
        }
    }
    std::cout << COLOR_GREEN
              << "[stat] max_file_size_sync_scan = " << items.back().first
              << " bytes"
              << COLOR_RESET << "  "
              << COLOR_CYAN << "(covers 100% of accesses)"
              << COLOR_RESET << std::endl;

    return items.back().first;
}



void start_core_engine_statistic(const ConfigManager& config) {
    // read test duration (seconds) from config
    const uint64_t duration_sec = config.getStatisticDurationSeconds(); // must exist in ConfigManager
    const int64_t  t_start_ns   = now_ns_monotonic();
    // 1) pre-scan sizes and write sizes.csv once
    pre_scan_home_sizes("/home");
    std::ofstream ofs1("statistical_result/sizes.csv");
    dump_size_distribution_csv(ofs1);
    ofs1.close(); 

    // 2) start fanotify loop (collect access + trace)
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
        // check time budget at loop head
        const int64_t elapsed_ns = now_ns_monotonic() - t_start_ns;
        if (duration_sec > 0 && (uint64_t)(elapsed_ns / 1000000000LL) >= duration_sec) {
            std::ofstream ofs2("statistical_result/access.csv");
            dump_access_distribution_csv(ofs2);
            close(fan_fd);
            std::cout << "[CoreEngine] statistic: duration reached, results saved. Now calculating optimized parameters...\n";
            compute_max_file_size_95(g_stats.access, g_stats.sizes);
            return;
        }

        struct pollfd pfd { fan_fd, POLLIN, 0 };
        int pret = poll(&pfd, 1, 1000); // 1s to avoid busy loop
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
                const int64_t ts = now_ns_realtime();

                // resolve path; keep only under /home
                char fd_link[64];
                snprintf(fd_link, sizeof(fd_link), "/proc/self/fd/%d", metadata->fd);
                char path_buf[1024];
                ssize_t n = readlink(fd_link, path_buf, sizeof(path_buf) - 1);
                bool in_home = false;
                if (n >= 0) {
                    path_buf[n] = '\0';
                    std::string p = path_buf;
                    const std::string deleted_suffix = " (deleted)";
                    if (p.size() > deleted_suffix.size() &&
                        p.compare(p.size() - deleted_suffix.size(), deleted_suffix.size(), deleted_suffix) == 0) {
                        p.erase(p.size() - deleted_suffix.size());
                    }
                    if (p == "/home" || p.rfind("/home/", 0) == 0) {
                        in_home = true;
                    }
                }
                if (!in_home) {
                    if (metadata->fd >= 0) close(metadata->fd);
                    metadata = FAN_EVENT_NEXT(metadata, len);
                    continue;
                }

                // stat to get (dev, ino, size)
                struct stat st{};
                if (fstat(metadata->fd, &st) == 0) {
                    FileKey key{ (uint64_t)st.st_dev, (uint64_t)st.st_ino };
                    uint64_t fsize = (uint64_t)st.st_size;

                    // update access distribution
                    g_stats.access.open_hits[key] += 1;

                    // refresh size distribution (optional)
                    g_stats.sizes.sizes[key] = fsize;

                    // append to trace
                    g_stats.trace.events.push_back(TraceEvent{ ts, key, fsize, OpType::Open });

                    // restored DEBUG log
                    #ifdef DEBUG
                    std::cout << "[stat] OPEN dev=" << st.st_dev
                              << " ino=" << st.st_ino
                              << " size=" << st.st_size
                              << " path=" << path_buf
                              << " hits=" << g_stats.access.open_hits[key]
                              << std::endl;
                    #endif
                } else {
                    std::cout << "[stat] OPEN (fstat failed)\n";
                }

                // always close supplied FD
                close(metadata->fd);
            } else {
                if (metadata->fd >= 0) close(metadata->fd);
            }

            metadata = FAN_EVENT_NEXT(metadata, len);
        }
    }
}


