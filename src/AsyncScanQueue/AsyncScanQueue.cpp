#include "AsyncScanQueue.hpp"
#include <mutex>
#include <condition_variable>
#include <deque>
#include <utility>
#include "ConfigManager.hpp"
#include "CacheManager.hpp"
#include "ContentParser.hpp"
#include <thread>
#include <vector>
#include <atomic>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
#include <cstring>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sched.h>


#ifndef IOPRIO_CLASS_SHIFT
#define IOPRIO_CLASS_SHIFT 13
#define IOPRIO_CLASS_NONE  0
#define IOPRIO_CLASS_RT    1
#define IOPRIO_CLASS_BE    2
#define IOPRIO_CLASS_IDLE  3
#define IOPRIO_PRIO_VALUE(class_, data_) (((class_) << IOPRIO_CLASS_SHIFT) | (data_))
#define IOPRIO_WHO_PROCESS 1
#endif

namespace {
    std::mutex                g_mtx;
    std::condition_variable   g_cv;
    std::deque<AsyncScanTask> g_q;
    bool                      g_shutdown = false;
    std::vector<std::thread>  g_workers;
    std::atomic<bool>         g_started{false};
}


// Desc: enqueue a scan task into the async queue
// In: int dup_fd, pid_t pid, size_t size
// Out: void
void enqueue_async_scan(int dup_fd, pid_t pid, size_t size) {
    AsyncScanTask t{dup_fd, pid, size};
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_q.emplace_back(std::move(t));
    }
    g_cv.notify_one();
}


// Desc: wait for and pop one scan task from queue
// In: AsyncScanTask& out
// Out: bool (false if shutdown and empty)
bool wait_dequeue_async_scan(AsyncScanTask& out) {
    std::unique_lock<std::mutex> lk(g_mtx);
    g_cv.wait(lk, []{ return g_shutdown || !g_q.empty(); });
    if (g_shutdown && g_q.empty()) return false;
    out = std::move(g_q.front());
    g_q.pop_front();
    return true;
}


// Desc: signal shutdown to all worker threads
// In: (none)
// Out: void
void shutdown_async_scan_queue() {
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_shutdown = true;
    }
    g_cv.notify_all();
}


// Desc: get current thread id (TID)
// In: (none)
// Out: pid_t
static inline pid_t gettid_wrap() {
    return static_cast<pid_t>(syscall(SYS_gettid));
}

// Desc: set I/O priority for a process/thread
// In: int which, int who, int ioprio
// Out: int (syscall result)
static inline int ioprio_set_wrap(int which, int who, int ioprio) {
    return syscall(SYS_ioprio_set, which, who, ioprio);
}

// Desc: lower thread CPU/I/O priority to background
// In: (none)
// Out: void    
static void set_thread_background_mode() {
    // I/O priority = IDLE 
    pid_t tid = gettid_wrap();
    const int io_idle = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0);
    if (ioprio_set_wrap(IOPRIO_WHO_PROCESS, tid, io_idle) != 0) {
        fprintf(stderr, "ioprio_set(IDLE) failed: %s\n", strerror(errno));
    }

    // Try CPU policy = SCHED_IDLE  
    struct sched_param sp; memset(&sp, 0, sizeof(sp));
    if (sched_setscheduler(0, SCHED_IDLE, &sp) != 0) {
        // fall back to nice = +19
        if (setpriority(PRIO_PROCESS, tid, 19) != 0) {
            fprintf(stderr, "setpriority(+19) failed: %s\n", strerror(errno));
        }
    }
}


// Desc: worker loop to read file, extract text, match rules, cache decision
// In: int log_write_fd, const ConfigManager* config, CacheManager* cache
// Out: void
static void async_worker_loop(int log_write_fd,
                              const ConfigManager* config,
                              CacheManager* cache)
{
    set_thread_background_mode();
    for (;;) {
        AsyncScanTask t;
        if (!wait_dequeue_async_scan(t)) break;

        int decision = 0; // 0 = ALLOW
        struct stat st{};
        if (fstat(t.fd, &st) == 0 && st.st_size > 0) {
            size_t fsz = static_cast<size_t>(st.st_size);
            std::vector<char> buffer(fsz);
            ssize_t done = 0;
            while (static_cast<size_t>(done) < fsz) {
                ssize_t r = pread(t.fd, buffer.data() + done, fsz - done, done);
                if (r <= 0) break;
                done += r;
            }
            if (static_cast<size_t>(done) == fsz) {
                std::string header(buffer.data(), std::min<size_t>(5, buffer.size()));
                std::string type = ContentParser::detect_type(header);
                std::string extracted = ContentParser::extract_text(
                    type, std::string(buffer.data(), buffer.size()), log_write_fd
                );
                if (config->matches(extracted)) {
                    decision = 1; // BLOCK
                }
            }
        }
        cache->put(st, config->getRulesetVersion(), decision, config->max_cache_bytes());
        if (t.fd >= 0) ::close(t.fd);
    }
}

// Desc: start N background async scan workers (idempotent)
// In: int log_write_fd, const ConfigManager& config, CacheManager& cache, size_t num_workers
// Out: void
void start_async_workers(int log_write_fd,
                         const ConfigManager& config,
                         CacheManager& cache,
                         size_t num_workers)
{
    if (g_started.exchange(true)) return; // already started
    if (num_workers == 0) num_workers = 1;
    g_workers.reserve(num_workers);
    for (size_t i = 0; i < num_workers; ++i) {
        g_workers.emplace_back(async_worker_loop, log_write_fd, &config, &cache);
    }
}


// Desc: stop workers, join threads, and reset state
// In: (none)
// Out: void
void stop_async_workers_and_join() {
    shutdown_async_scan_queue();
    for (auto& th : g_workers) {
        if (th.joinable()) th.join();
    }
    g_workers.clear();
    g_started = false;
}