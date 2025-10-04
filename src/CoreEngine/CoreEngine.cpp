// === src/CoreEngine/CoreEngine.cpp ===
#include "CoreEngine.hpp"
#include "Logger.hpp"
#include "ConfigManager.hpp" 
#include "RuleEvaluator.hpp"
#include "CacheManager.hpp"
#include "StatisticStore.hpp"
#include "AsyncScanQueue.hpp"

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
#include <filesystem>
#include <math.h>


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





static void async_worker_loop(int log_write_fd) {
    for (;;) {
        AsyncScanTask t;
        // blocking: فقط این ترد می‌خوابه تا کار برسد یا shutdown شود
        if (!wait_dequeue_async_scan(t)) {
            // queue shut down and empty -> exit thread
            break;
        }
        std::cout << "test" << std::endl;
        ::close(t.fd);
    }    
            
}


// Desc: periodically print metrics every n decisions
// In: uint64_t n (report interval)
// Out: void
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


// Desc: run blocking fanotify loop with logging, cache, and rule evaluation
// In: const ConfigManager& config, sqlite3* cache_db
// Out: void
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

    const unsigned hw = std::thread::hardware_concurrency();
    const size_t NUM_WORKERS = hw ? std::max(1u, hw/2) : 2u;
    std::vector<std::thread> workers;
    workers.reserve(NUM_WORKERS);
    for (size_t i = 0; i < NUM_WORKERS; ++i) {
        workers.emplace_back(async_worker_loop, log_pipe[1]);
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




/*
##################################################################
Statistacl mode -----------> Finding optimized configurable option
##################################################################
*/

namespace fs = std::filesystem;

static StatisticStore g_stats;

// Desc: get current wall-clock time in nanoseconds
// In: (none)
// Out: int64_t (ns since Unix epoch)
static inline int64_t now_ns_realtime() {
    struct timespec ts{};
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
}

// Desc: get monotonic clock time in nanoseconds
// In: (none)
// Out: int64_t (ns, not affected by clock changes)
static inline int64_t now_ns_monotonic() {
    struct timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
}


// Desc: write CSV of file sizes per (dev, ino)
// In: std::ostream& os
// Out: void
#ifdef DEBUG
static void dump_size_distribution_csv(std::ostream& os) {
    os << "dev,ino,size_bytes\n";
    for (const auto& [key, sz] : g_stats.sizes.sizes) {
        os << key.dev << ',' << key.ino << ',' << sz << '\n';
    }
}
#endif

// Desc: write CSV of open-hit counts per (dev, ino)
// In: std::ostream& os
// Out: void
#ifdef DEBUG
static void dump_access_distribution_csv(std::ostream& os) {
    os << "dev,ino,open_hits\n";
    for (const auto& [key, hits] : g_stats.access.open_hits) {
        os << key.dev << ',' << key.ino << ',' << hits << '\n';
    }
}
#endif


// Desc: recursively scan root and record file sizes into g_stats
// In: const std::string& root_path
// Out: void
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


// Desc: compute 95th-percentile size by file count
// In: const SizeDistribution& sz
// Out: uint64_t (size threshold in bytes)
static uint64_t compute_max_file_size_by_count_95(const SizeDistribution& sz)
{
    if (sz.sizes.empty()) return 0;

    std::vector<uint64_t> sizes;
    sizes.reserve(sz.sizes.size());
    for (const auto& [key, size] : sz.sizes) {
        sizes.push_back(size);
    }

    std::sort(sizes.begin(), sizes.end());

    size_t total_files = sizes.size();
    size_t idx95 = (total_files * 95 + 99) / 100; // ceil(0.95 * total_files)

    if (idx95 == 0) idx95 = 1; 
    if (idx95 > total_files) idx95 = total_files;

    uint64_t threshold_size = sizes[idx95 - 1]; 

    double coverage = (double)idx95 / (double)total_files * 100.0;

    std::cout << COLOR_GREEN
              << "[stat] max_file_size_by_count_95 = " << threshold_size
              << " bytes"
              << COLOR_RESET << "  "
              << COLOR_CYAN << "(covers ~"
              << std::fixed << std::setprecision(2)
              << coverage << "% of files by count)"
              << COLOR_RESET << std::endl;

    return threshold_size;
}


// Desc: compute 95th-percentile size by file count
// In: const SizeDistribution& sz
// Out: uint64_t (size threshold in bytes)
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

static std::vector<K95WindowResult>

// Desc: compute sliding-window k95 metrics over trace events
// In: const TraceLog& trace, size_t window_hits, size_t hop_hits, double coverage
// Out: std::vector<K95WindowResult>
compute_k95_over_event_windows(const TraceLog& trace,
                               size_t window_hits = 1000,
                               size_t hop_hits    = 500,
                               double coverage    = 0.95)
{
    std::vector<K95WindowResult> out;
    const auto& evs = trace.events;
    const size_t N = evs.size();
    if (N == 0 || window_hits == 0) return out;
    auto pack_key = [](const FileKey& k)->uint64_t {
        return (uint64_t(k.dev) << 32) ^ uint64_t(k.ino);
    };

    size_t start = 0;
    while (start < N) {
        size_t end = start + window_hits - 1;
        if (end >= N) {
            if ((N - start) < hop_hits) break;
            end = N - 1;
        }
        std::unordered_map<uint64_t, std::pair<uint64_t,uint64_t>> per_file;
        per_file.reserve((end - start + 1) / 4 + 8);

        for (size_t i = start; i <= end; ++i) {
            const auto& e = evs[i];
            if (e.op != OpType::Open) continue;
            uint64_t k = pack_key(e.key);
            auto& ref = per_file[k];
            ref.first  += 1;      
            ref.second  = e.size;  
        }

        // contribution = size * hits_in_window
        std::vector<unsigned __int128> contribs;
        contribs.reserve(per_file.size());
        unsigned __int128 total_bytes_128 = 0;

        for (const auto& kv : per_file) {
            const uint64_t hits = kv.second.first;
            const uint64_t sz   = kv.second.second;
            unsigned __int128 c = (unsigned __int128)sz * (unsigned __int128)hits;
            contribs.push_back(c);
            total_bytes_128 += c;
        }

        uint64_t k95 = 0;
        double achieved = 0.0;

        if (!contribs.empty() && total_bytes_128 > 0) {
            std::sort(contribs.begin(), contribs.end(),
                      [](auto a, auto b){ return a > b; });

            const unsigned __int128 target =
                (unsigned __int128)std::ceil((long double)total_bytes_128 * coverage);

            unsigned __int128 cum = 0;
            size_t k = 0;
            for (auto c : contribs) {
                ++k;
                cum += c;
                if (cum >= target) {
                    k95 = (uint64_t)k;
                    achieved = (double)(unsigned long long)cum /
                               (double)(unsigned long long)total_bytes_128;
                    break;
                }
            }
            if (k95 == 0) { k95 = (uint64_t)contribs.size(); achieved = 1.0; }
        } else {
            k95 = 0;
            achieved = 0.0;
        }

        out.push_back(K95WindowResult{
            start,
            end,
            (uint64_t)(unsigned long long)total_bytes_128,
            k95,
            achieved
        });

        start += hop_hits;
    }

    return out;
}

static K95EmaSummary
// Desc: smooth k95 results using exponential moving average (EMA)
// In: const std::vector<K95WindowResult>& results, double alpha, double safety_factor
// Out: K95EmaSummary (EMA values and final target)
summarize_k95_with_ema(const std::vector<K95WindowResult>& results,
                       double alpha,
                       double safety_factor)
{
    K95EmaSummary out;
    out.ema_values.reserve(results.size());
    out.target_entries.reserve(results.size());

    if (results.empty()) {
        std::cout << "[k95][ema] no windows to summarize\n";
        return out;
    }

    // EMA initialization with first k95
    double ema = static_cast<double>(results.front().k95);

    for (size_t i = 0; i < results.size(); ++i) {
        const auto& r = results[i];

        if (i == 0) {
            // already initialized
        } else {
            ema = alpha * static_cast<double>(r.k95) + (1.0 - alpha) * ema;
        }

        uint64_t target = static_cast<uint64_t>(std::ceil(safety_factor * ema));

        out.ema_values.push_back(ema);
        out.target_entries.push_back(target);

        #ifdef DEBUG
        std::cout << "[k95][ema] win[" << r.start_idx << ".." << r.end_idx << "]"
                  << "  k95=" << r.k95
                  << "  achieved=" << std::fixed << std::setprecision(3) << r.achieved
                  << "  EMA=" << std::setprecision(2) << ema
                  << "  target≈" << target
                  << "  (safety=" << std::setprecision(2) << safety_factor << ")\n";
        #endif
    }

    out.final_ema = ema;
    out.final_target = out.target_entries.empty() ? 0 : out.target_entries.back();
    return out;
}

// Desc: run timed fanotify-based stats collection on /home
// In: const ConfigManager& config
// Out: void
void start_core_engine_statistic(const ConfigManager& config) {
    // read test duration (seconds) from config
    const uint64_t duration_sec = config.getStatisticDurationSeconds(); // must exist in ConfigManager
    const int64_t  t_start_ns   = now_ns_monotonic();
    // 1) pre-scan sizes and write sizes.csv once
    pre_scan_home_sizes("/home");
    #ifdef DEBUG
    std::ofstream ofs1("statistical_result/sizes.csv");
    dump_size_distribution_csv(ofs1);
    ofs1.close();
    #endif 

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
            #ifdef DEBUG
            std::ofstream ofs2("statistical_result/access.csv");
            dump_access_distribution_csv(ofs2);
            ofs2.close();
            #endif
            close(fan_fd);
            std::cout << "[CoreEngine] statistic: duration reached, results saved. Now calculating optimized parameters...\n";
            compute_max_file_size_95(g_stats.access, g_stats.sizes);
            compute_max_file_size_by_count_95(g_stats.sizes);
            auto wins = compute_k95_over_event_windows(g_stats.trace, /*window_hits=*/500, /*hop_hits=*/250, /*coverage=*/0.95);
            double alpha = 0.30;
            double safety = 1.20;

            auto summary = summarize_k95_with_ema(wins, alpha, safety);
            std::cout << COLOR_GREEN << "[k95][ema] final_EMA=" << std::fixed << std::setprecision(2) 
                    << summary.final_ema
                    << COLOR_RESET 
                    << COLOR_CYAN
                    << "  final_target≈" << summary.final_target
                    << " (entries)\n" << COLOR_RESET;
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


