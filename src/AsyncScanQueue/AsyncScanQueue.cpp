#include "AsyncScanQueue.hpp"
#include <mutex>
#include <condition_variable>
#include <deque>
#include <utility>

namespace {
    std::mutex                g_mtx;
    std::condition_variable   g_cv;
    std::deque<AsyncScanTask> g_q;
    bool                      g_shutdown = false;
}

void enqueue_async_scan(int dup_fd, pid_t pid, size_t size) {
    AsyncScanTask t{dup_fd, pid, size};
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_q.emplace_back(std::move(t));
    }
    g_cv.notify_one();
}

bool wait_dequeue_async_scan(AsyncScanTask& out) {
    std::unique_lock<std::mutex> lk(g_mtx);
    g_cv.wait(lk, []{ return g_shutdown || !g_q.empty(); });
    if (g_shutdown && g_q.empty()) return false;
    out = std::move(g_q.front());
    g_q.pop_front();
    return true;
}

void shutdown_async_scan_queue() {
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_shutdown = true;
    }
    g_cv.notify_all();
}
