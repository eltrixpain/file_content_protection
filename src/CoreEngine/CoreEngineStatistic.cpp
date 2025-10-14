// === src/CoreEngine/CoreEngineStatistic.cpp ===
#include "CoreEngine.hpp"
#include "Logger.hpp"
#include "ConfigManager.hpp"
#include "StatisticStore.hpp"
#include "ContentParser.hpp"
#include "StatisticStoreIO.hpp"

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
#define COLOR_RED   "\033[1;31m"
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
            // SAVE only — no computation here
            std::filesystem::create_directories("statistical_result");
            if (save_statistic_store(g_stats, "statistical_result/trace_data.bin")) {
                std::cout << "[CoreEngine] statistic: trace saved to statistical_result/trace_data.bin\n";
            } else {
                std::cerr << "[CoreEngine] statistic: failed to save trace data\n";
            }
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

