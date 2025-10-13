#pragma once
#include <cstdint>
#include <unordered_map>
#include <shared_mutex>
#include <sys/stat.h>

class CacheL1;

class CacheL2 {
public:
    struct Key {
        int64_t dev{0}, ino{0};
        bool operator==(const Key& o) const noexcept { return dev==o.dev && ino==o.ino; }
    };
    struct KeyHash {
        size_t operator()(const Key& k) const noexcept {
            uint64_t x = static_cast<uint64_t>(k.dev);
            uint64_t y = static_cast<uint64_t>(k.ino);
            x ^= y + 0x9e3779b97f4a7c15ULL + (x<<6) + (x>>2);
            return static_cast<size_t>(x);
        }
    };
    struct Entry {
        int64_t mtime_ns{0};
        int64_t ctime_ns{0};
        int64_t size{0};
        int     decision{0};
        int64_t last_access_ts{0};
        uint64_t hit_count{0};
    };

public:
    explicit CacheL2(CacheL1& l1_ref) : l1_(&l1_ref) {}

    int get(const struct stat& st, uint64_t ruleset_version, int& decision,uint64_t max_bytes);
    void put(const struct stat& st, uint64_t ruleset_version, int decision, uint64_t max_bytes);
    #ifdef LFU_SIZE
    // Evict up to max_rows_to_evict entries using size-aware LFU (age-decayed)
    void evict_lfu_size(int max_rows_to_evict, int candidate_limit = 256);
    #endif

    #ifdef LRU
        void evict_lru(int max_rows_to_evict);
    #endif

    #ifdef LFU
        void evict_lfu(int max_rows_to_evict, double tau_seconds = 3600.0);
    #endif

private:
    static inline int64_t to_ns(time_t s, long ns) {
        return static_cast<int64_t>(s) * 1000000000LL + static_cast<int64_t>(ns);
    }
    uint64_t sum_cached_file_sizes() const;
    bool check_capacity(uint64_t max_bytes)const;

private:
    mutable std::shared_mutex mu_;
    std::unordered_map<Key, Entry, KeyHash> map_;
    CacheL1* l1_{nullptr};
};
