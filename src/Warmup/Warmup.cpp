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
}