#include "Warmup.hpp"
#include "AsyncScanQueue.hpp"
#include "ConfigManager.hpp"

#include <unordered_set>
#include <unordered_map>
#include <string>
#include <vector>
#include <mutex>
#include <filesystem>
#include <sqlite3.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <thread>
#include <unistd.h>
#include <iostream>
#include <cstring>


struct DevIno { long long dev, ino; };
static inline bool operator==(const DevIno& a, const DevIno& b) {
    return a.dev == b.dev && a.ino == b.ino;
}
struct DevInoHash {
    std::size_t operator()(const DevIno& k) const noexcept {
        return std::hash<long long>()((k.dev << 1) ^ (k.ino << 17) ^ (k.dev >> 7));
    }
};

static std::vector<DevIno>
select_top_scored_from_l1(sqlite3* db, std::size_t limit) {
    std::vector<DevIno> out;
    if (!db || limit == 0) return out;

    const char* sql =
        "SELECT dev, ino "
        "FROM cache_entries "
        "ORDER BY (CAST(hit_count AS REAL) * CAST(size AS REAL)) DESC, "
        "         last_access_ts DESC "
        "LIMIT ?;";

    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &st, nullptr) != SQLITE_OK) return out;
    sqlite3_bind_int(st, 1, (int)limit);

    while (sqlite3_step(st) == SQLITE_ROW) {
        out.push_back(DevIno{
            sqlite3_column_int64(st, 0),
            sqlite3_column_int64(st, 1)
        });
    }
    sqlite3_finalize(st);
    return out;
}

static std::unordered_map<DevIno, std::string, DevInoHash>
map_devino_to_paths(const std::string& root,
                    const std::unordered_set<DevIno, DevInoHash>& wanted) {
    namespace fs = std::filesystem;
    std::unordered_map<DevIno, std::string, DevInoHash> res;
    std::error_code ec;

    for (fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) { ec.clear(); continue; }

        const fs::directory_entry& de = *it;
        if (!de.is_regular_file(ec) || ec) { if (ec) ec.clear(); continue; }

        struct stat st{};
        if (::stat(de.path().c_str(), &st) != 0) continue;

        DevIno di{ (long long)st.st_dev, (long long)st.st_ino };
        if (wanted.find(di) != wanted.end()) {
            res.emplace(di, de.path().string());
            if (res.size() == wanted.size()) break;
        }
    }
    return res;
}


static const size_t kMaxDistinctDirs   = 256;   
static const size_t kMaxFilesTotal     = 10000; 
static const size_t kMaxFilesPerDir    = 10;   

static std::mutex g_mu;
static std::unordered_set<std::string> g_dirs_seen;
static size_t g_files_enqueued = 0;



namespace Warmup {

void scope_warmup_on_access(const std::string& path) {
    if (path.empty()) return;
    auto pos = path.rfind('/');
    if (pos == std::string::npos) return;
    std::string dir = (pos == 0) ? "/" : path.substr(0, pos);

    {
        std::lock_guard<std::mutex> lk(g_mu);
        if (g_dirs_seen.size() >= kMaxDistinctDirs) return;
        if (!g_dirs_seen.insert(dir).second) return;
        if (g_files_enqueued >= kMaxFilesTotal) return;
    }

    std::thread([dir]() {
        DIR* d = opendir(dir.c_str());
        if (!d) return;

        std::size_t files_in_dir = 0;
        struct dirent* ent;
        #ifdef DEBUG
        std::size_t debug_prints = 0;
        #endif
        while ((ent = readdir(d)) != nullptr) {
            if (::strcmp(ent->d_name, ".") == 0 || ::strcmp(ent->d_name, "..") == 0) continue;

            {
                std::lock_guard<std::mutex> lk(g_mu);
                if (g_files_enqueued >= kMaxFilesTotal) break;
                if (files_in_dir >= kMaxFilesPerDir) break;
            }

            std::string fpath = dir + "/" + ent->d_name;

            int fd = ::open(fpath.c_str(), O_RDONLY | O_CLOEXEC);
            if (fd < 0) {
                #ifdef DEBUG
                if (debug_prints < 10) { std::perror(("open fail: " + fpath).c_str()); ++debug_prints; }
                #endif
                continue;
            }

            struct stat st{};
            if (fstat(fd, &st) != 0) {
                #ifdef DEBUG
                if (debug_prints < 10) { std::perror(("fstat fail: " + fpath).c_str()); ++debug_prints; }
                #endif
                ::close(fd);
                continue;
            }
            if (!S_ISREG(st.st_mode)) { ::close(fd); continue; }
            if (st.st_size <= 0)     { ::close(fd); continue; }

            enqueue_async_scan(fd, 0, (std::size_t)st.st_size);

            {
                std::lock_guard<std::mutex> lk(g_mu);
                ++g_files_enqueued;
                ++files_in_dir;
            }
        }
        closedir(d);
        #ifdef DEBUG
        {
            std::lock_guard<std::mutex> lk(g_mu);
            std::cerr << "[warmup-scope] total_dirs=" << g_dirs_seen.size()
                      << " total_files=" << g_files_enqueued
                      << " (dir: " << dir << ")\n";
        }
        #endif
    }).detach();
}

void pattern_warmup(sqlite3* db, const ConfigManager& cfg,
                    std::size_t max_hit_candidates,
                    double l2_fill_ratio) {
    const std::string root = cfg.getWatchTarget();
    const std::uint64_t cap_bytes = cfg.max_cache_bytes();
    const std::uint64_t target_bytes =
        (cap_bytes > 0 && l2_fill_ratio > 0.0) ? (std::uint64_t)(cap_bytes * l2_fill_ratio) : 0;

    std::cout << "[warmup-pattern] starting\n";

    auto top = select_top_scored_from_l1(db, max_hit_candidates);
    if (top.empty()) {
        std::cout << "[warmup-pattern] no candidates; done\n";
        return;
    }

    std::unordered_set<DevIno, DevInoHash> wanted(top.begin(), top.end());
    auto mapping = map_devino_to_paths(root, wanted);
    if (mapping.empty()) {
        std::cout << "[warmup-pattern] no paths resolved; done\n";
        return;
    }

    std::uint64_t enq_bytes = 0;
    std::size_t enq_files = 0;

    for (const auto& kv : mapping) {
        const std::string& path = kv.second;

        int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            #ifdef DEBUG
            std::perror(("open fail: " + path).c_str());
            #endif
            continue;
        }

        struct stat st{};
        if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0) {
            #ifdef DEBUG
            std::perror(("fstat fail or not regular: " + path).c_str());
            #endif
            ::close(fd);
            continue;
        }

        if (target_bytes > 0 && (enq_bytes + (std::uint64_t)st.st_size) > target_bytes) {
            ::close(fd);
            break;
        }

        enqueue_async_scan(fd, /*pid*/0, (std::size_t)st.st_size);
        enq_bytes += (std::uint64_t)st.st_size;
        enq_files += 1;
    }

    std::cout << "[warmup-pattern] enqueued=" << enq_files
              << " bytes=" << enq_bytes << "\n";
    std::cout << "[warmup-pattern] done\n";
}

} // namespace Warmup