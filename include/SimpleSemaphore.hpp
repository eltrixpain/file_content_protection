#pragma once
#include <mutex>
#include <condition_variable>

class SimpleSemaphore {
public:
    explicit SimpleSemaphore(int count) : count_(count) {}
    void acquire() {
        std::unique_lock<std::mutex> lk(m_);
        cv_.wait(lk, [&]{ return count_ > 0; });
        --count_;
    }
    void release() {
        std::lock_guard<std::mutex> lk(m_);
        ++count_;
        cv_.notify_one();
    }
private:
    std::mutex m_;
    std::condition_variable cv_;
    int count_;
};
