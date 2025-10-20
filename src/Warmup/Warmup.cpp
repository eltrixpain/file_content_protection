#include "Warmup.hpp"
#include <unordered_set>
#include <string>
#include <mutex>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include "AsyncScanQueue.hpp"

static const size_t kMaxDistinctDirs   = 256;   
static const size_t kMaxFilesTotal     = 10000; 
static const size_t kMaxFilesPerDir    = 1000;   

static std::mutex g_mu;
static std::unordered_set<std::string> g_dirs_seen;
static size_t g_files_enqueued = 0;

namespace Warmup {

void pattern_warmup(sqlite3* /*db*/, const ConfigManager& /*cfg*/) {}

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
    std::cout << "asdlfnas" << std::endl;

    DIR* d = opendir(dir.c_str());
    if (!d) return;

    size_t files_in_dir = 0;
    struct dirent* ent;
    while ((ent = readdir(d)) != nullptr) {
        if (ent->d_name[0] == '.') continue;
        std::string fpath = dir + "/" + ent->d_name;

        {
            std::lock_guard<std::mutex> lk(g_mu);
            if (g_files_enqueued >= kMaxFilesTotal) break;
            if (files_in_dir >= kMaxFilesPerDir) break;
        }

        int fd = ::open(fpath.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;

        struct stat st{};
        if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0) {
            ::close(fd);
            continue;
        }

        enqueue_async_scan(fd, 0, (size_t)st.st_size);
        {
            std::lock_guard<std::mutex> lk(g_mu);
            ++g_files_enqueued;
            ++files_in_dir;
        }
    }
    closedir(d);
}

} // namespace Warmup
