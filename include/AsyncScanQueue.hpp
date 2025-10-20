#pragma once
#include <cstddef>
#include <sys/types.h> // pid_t

struct AsyncScanTask {
    int   fd;
    pid_t pid;
    size_t size;
};
struct ConfigManager;
class CacheL1;
class PatternMatcherHS;

void enqueue_async_scan(int dup_fd, pid_t pid, size_t size);
bool wait_dequeue_async_scan(AsyncScanTask& out);
void shutdown_async_scan_queue();
void start_async_workers(int log_write_fd,
                         const class ConfigManager& config,
                         const class PatternMatcherHS* matcher,
                         class CacheL2& l2,
                         size_t num_workers);
void stop_async_workers_and_join();
