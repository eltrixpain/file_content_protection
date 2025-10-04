#pragma once
#include <cstddef>
#include <sys/types.h> // pid_t

struct AsyncScanTask {
    int   fd;
    pid_t pid;
    size_t size;
};

void enqueue_async_scan(int dup_fd, pid_t pid, size_t size);
bool try_dequeue_async_scan(AsyncScanTask& out);
bool wait_dequeue_async_scan(AsyncScanTask& out);
void shutdown_async_scan_queue();
