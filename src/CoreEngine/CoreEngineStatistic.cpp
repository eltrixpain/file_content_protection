// === src/CoreEngine/CoreEngineStatistic.cpp ===
#include "CoreEngine.hpp"
#include "Logger.hpp"
#include "ConfigManager.hpp"
#include "StatisticStore.hpp"
#include "ContentParser.hpp"

#include <iostream>
#include <fstream>
#include <thread>
#include <vector>
#include <sys/fanotify.h> 
#include <fcntl.h>  
#include <unordered_map>
#include <algorithm>
#include <filesystem>
#include <poll.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cmath>
#include <cstring>

#define COLOR_GREEN "\033[1;32m"
#define COLOR_CYAN  "\033[1;36m"
#define COLOR_RESET "\033[0m"

namespace fs = std::filesystem;



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

    std::cout << COLOR_GREEN
              << "[stat] max_file_size based on static analysis = " << threshold_size
              << " bytes"
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
            std::cout << COLOR_GREEN
                      << "[stat] max_file_size based on dynamic analysis = " << size
                      << " bytes"
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

static K95OnlineEvalSummary test_k95_ema_online(const TraceLog& trace,
                         size_t window_hits,
                         size_t hop_hits,
                         double coverage,
                         double alpha,
                         double safety_factor)
{
    K95OnlineEvalSummary out;        // summary to return
    size_t step_count = 0;           // how many windows printed
    size_t pass_count = 0;           // how many windows passed
    const auto& evs = trace.events;
    const size_t N = evs.size();
    if (N == 0) return out;

    auto pack_key = [](const FileKey& k)->uint64_t {
        return (uint64_t(k.dev) << 32) ^ uint64_t(k.ino);
    };

    auto build_contribs = [&](size_t start, size_t end, std::vector<unsigned __int128>& contribs, unsigned __int128& total) {
        std::unordered_map<uint64_t, std::pair<uint64_t,uint64_t>> per_file;
        for (size_t i = start; i <= end && i < N; ++i) {
            const auto& e = evs[i];
            if (e.op != OpType::Open) continue;
            auto& ref = per_file[pack_key(e.key)];
            ref.first += 1;
            ref.second = e.size;
        }
        contribs.clear();
        total = 0;
        for (auto& kv : per_file) {
            unsigned __int128 c = (unsigned __int128)kv.second.first * kv.second.second;
            contribs.push_back(c);
            total += c;
        }
        std::sort(contribs.begin(), contribs.end(), [](auto a, auto b){ return a > b; });
    };

    auto compute_k95 = [&](const std::vector<unsigned __int128>& contribs, unsigned __int128 total){
        if (contribs.empty() || total == 0) return (uint64_t)0;
        unsigned __int128 target = (unsigned __int128)std::ceil((long double)total * coverage);
        unsigned __int128 cum = 0;
        uint64_t k = 0;
        for (auto c : contribs) {
            cum += c;
            ++k;
            if (cum >= target) return k;
        }
        return (uint64_t)contribs.size();
    };

    auto coverage_with_topk = [&](const std::vector<unsigned __int128>& contribs, unsigned __int128 total, uint64_t k){
        if (k == 0 || contribs.empty() || total == 0) return 0.0;
        if (k > contribs.size()) k = contribs.size();
        unsigned __int128 cum = 0;
        for (size_t i = 0; i < k; ++i) cum += contribs[i];
        return (double)cum / (double)total;
    };

    double ema = 0.0;
    bool initialized = false;
    size_t start = 0;
    std::vector<unsigned __int128> contribs;
    unsigned __int128 total = 0;

    while (start < N) {
        size_t end = std::min(start + window_hits, N) - 1;
        build_contribs(start, end, contribs, total);
        uint64_t k95 = compute_k95(contribs, total);

        if (!initialized) {
            ema = k95;
            initialized = true;
            std::cout << COLOR_CYAN << "[STEP " << step_count++ << "] INIT window[" << start << ".." << end << "]  k95=" << k95
                      << "  EMA=" << ema << COLOR_RESET << std::endl;
        } else {
            uint64_t target = (uint64_t)std::ceil(safety_factor * ema);
            double achieved = coverage_with_topk(contribs, total, target);
            bool pass = achieved >= coverage;

            std::cout << COLOR_CYAN << "[STEP " << step_count++ << "] window[" << start << ".." << end << "]  "
                       << "prevEMA=" << std::fixed << std::setprecision(2) << ema
                       << "  target=" << target
                       << "  achieved=" << std::setprecision(3) << achieved * 100 << "%  "
                       << (pass ? "PASS" : "FAIL")
                       <<  COLOR_RESET << std::endl;
            if (pass) ++pass_count;

            ema = alpha * k95 + (1.0 - alpha) * ema;
        }
        start += hop_hits;
    }

     out.final_ema = ema;
     out.pass_count = pass_count;
     out.steps.resize(step_count);
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
    // 1) launch pre-scan in background (runs concurrently with tracing)
     std::thread pre_scan_thr([]{
         pre_scan_home_sizes("/home"); 
     });

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
            if (pre_scan_thr.joinable()) pre_scan_thr.join();
            #ifdef DEBUG
            std::ofstream ofs2("statistical_result/access.csv");
            dump_access_distribution_csv(ofs2);
            ofs2.close();

            std::ofstream ofs1("statistical_result/sizes.csv");
            dump_size_distribution_csv(ofs1);
            ofs1.close();
            #endif 

            close(fan_fd);
            std::cout << "[CoreEngine] statistic: duration reached, results saved. Now calculating optimized parameters...\n";
            compute_max_file_size_95(g_stats.access, g_stats.sizes);
            compute_max_file_size_by_count_95(g_stats.sizes);
            double alpha = 0.10;
            double safety = 1.20;
            // === 3) Online EMA evaluation phase ===
            auto eval = test_k95_ema_online(
                g_stats.trace,
                /*window_hits=*/500,
                /*hop_hits=*/250,
                /*coverage=*/0.95,
                /*alpha=*/alpha,
                /*safety_factor=*/safety
            );

            std::cout << COLOR_GREEN
                    << "[k95][online] evaluated " << eval.steps.size() << " windows, "
                    << eval.pass_count << " passed (≥95% coverage)"
                    << "final_ema=" << std::fixed << std::setprecision(2) << eval.final_ema
                    << COLOR_RESET << std::endl;

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

