#include "CacheL2.hpp"
#include "CacheL1.hpp"
#include <ctime>
#include <mutex>
#include <iostream>
#include <vector>
#include <algorithm>
#include <cmath>


#ifdef LFU_SIZE
void CacheL2::evict_lfu_size(int max_rows_to_evict, int candidate_limit) {
    if (max_rows_to_evict <= 0) return;
    if (candidate_limit <= 0) candidate_limit = 256;

    const double tau_seconds = 3600.0;
    const long long now_sec = static_cast<long long>(std::time(nullptr));

    struct Row {
        Key key;
        long long hits;
        long long sz;
        long long last_ts;
        double score;
    };

    // 1) snapshot candidates ordered by (hit_count ASC, last_access_ts ASC), limited
    std::vector<Row> rows;
    {
        std::shared_lock rlk(mu_);
        rows.reserve(std::min<size_t>(candidate_limit, map_.size()));

        // Collect all, then partial-sort by (hits, last_ts), then truncate
        for (const auto& kv : map_) {
            const Key& k = kv.first;
            const Entry& e = kv.second;
            rows.push_back(Row{ k, static_cast<long long>(e.hit_count),
                                static_cast<long long>(e.size),
                                static_cast<long long>(e.last_access_ts),
                                0.0 });
        }
    }

    if (rows.empty()) return;

    // Order by hit_count ASC, last_access_ts ASC
    std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b){
        if (a.hits != b.hits) return a.hits < b.hits;
        return a.last_ts < b.last_ts;
    });
    if (static_cast<int>(rows.size()) > candidate_limit)
        rows.resize(static_cast<size_t>(candidate_limit));

    // 2) compute LFU size-aware age-decayed score
    for (auto& r : rows) {
        const double sbytes = static_cast<double>(r.sz);
        const double h = static_cast<double>(r.hits);
        const double age = (now_sec > r.last_ts) ? double(now_sec - r.last_ts) : 0.0;
        const double eff_hits = h / (1.0 + age / tau_seconds);
        r.score = eff_hits * sbytes; // score = effective_hits * size
    }

    // 3) sort by score ASC (evict lowest score first), tie-breaker: older first
    std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b){
        if (a.score != b.score) return a.score < b.score;
        return a.last_ts < b.last_ts;
    });

    if (static_cast<size_t>(max_rows_to_evict) < rows.size())
        rows.resize(static_cast<size_t>(max_rows_to_evict));

    // 4) erase selected keys
    {
        std::unique_lock wlk(mu_);
        for (const auto& r : rows) {
            map_.erase(r.key);
        }
    }
}
#endif
// ---------------------------
// LRU (oldest by last_access)
// ---------------------------
#ifdef LRU
void CacheL2::evict_lru(int max_rows_to_evict) {
    if (max_rows_to_evict <= 0) return;
    struct Row { Key key; long long last_ts; };
    std::vector<Row> rows;
    {
        std::shared_lock rlk(mu_);
        rows.reserve(map_.size());
        for (const auto& kv : map_) {
            rows.push_back(Row{ kv.first, static_cast<long long>(kv.second.last_access_ts) });
        }
    }
    if (rows.empty()) return;
    std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b){
        return a.last_ts < b.last_ts;
    });
    if (static_cast<int>(rows.size()) > max_rows_to_evict)
        rows.resize(static_cast<size_t>(max_rows_to_evict));
    {
        std::unique_lock wlk(mu_);
        for (const auto& r : rows) {
            map_.erase(r.key);
        }
    }
}
#endif

// ----------------------------------------------------
// LFU with age-decay: score = hits / (1 + age / tau)
// tie-breaker: older first (last_ts ASC)
// ----------------------------------------------------
#ifdef LFU
void CacheL2::evict_lfu(int max_rows_to_evict, double tau_seconds) {
    if (max_rows_to_evict <= 0) return;
    const long long now_sec = static_cast<long long>(std::time(nullptr));
    struct Row { Key key; long long hits; long long last_ts; double score; };
    std::vector<Row> rows;
    {
        std::shared_lock rlk(mu_);
        rows.reserve(map_.size());
        for (const auto& kv : map_) {
            const Entry& e = kv.second;
            rows.push_back(Row{
                kv.first,
                static_cast<long long>(e.hit_count),
                static_cast<long long>(e.last_access_ts),
                0.0
            });
        }
    }
    if (rows.empty()) return;
    for (auto& r : rows) {
        const double h = static_cast<double>(r.hits);
        const double age = (now_sec > r.last_ts) ? double(now_sec - r.last_ts) : 0.0;
        r.score = h / (1.0 + age / tau_seconds);
    }
    std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b){
        if (a.score != b.score) return a.score < b.score;
        return a.last_ts < b.last_ts;
    });
    if (static_cast<int>(rows.size()) > max_rows_to_evict)
        rows.resize(static_cast<size_t>(max_rows_to_evict));
    {
        std::unique_lock wlk(mu_);
        for (const auto& r : rows) {
            map_.erase(r.key);
        }
    }
}
#endif

uint64_t CacheL2::sum_cached_file_sizes() const {
    std::shared_lock rlk(mu_);
    const uint64_t bucket_bytes =
        static_cast<uint64_t>(map_.bucket_count()) * sizeof(void*);
    const uint64_t node_bytes =
        static_cast<uint64_t>(map_.size()) * (sizeof(Key) + sizeof(Entry) + sizeof(void*));
    return bucket_bytes + node_bytes;
}


bool CacheL2::check_capacity(uint64_t max_bytes) const {
    const uint64_t live_bytes = sum_cached_file_sizes();
    std::cout << live_bytes << std::endl;
// #ifdef DEBUG
    std::cout << live_bytes << std::endl;
    if (live_bytes >= max_bytes) {
        std::cerr << "[L2] file-bytes quota exceeded: "
                  << live_bytes << " >= " << max_bytes << " bytes\n";
    }
// #endif
    return live_bytes < max_bytes;
}


bool CacheL2::get(const struct stat& st, uint64_t ruleset_version, int& decision,uint64_t max_bytes) {
    (void)ruleset_version; // used only if we consult L1
    const Key k{ static_cast<int64_t>(st.st_dev), static_cast<int64_t>(st.st_ino) };
    const int64_t cur_mtime_ns = to_ns(st.st_mtim.tv_sec, st.st_mtim.tv_nsec);
    const int64_t cur_ctime_ns = to_ns(st.st_ctim.tv_sec, st.st_ctim.tv_nsec);
    const int64_t cur_size     = static_cast<int64_t>(st.st_size);

    {
        std::shared_lock rlk(mu_);
        auto it = map_.find(k);
        if (it != map_.end()) {
            const Entry& e = it->second;
            if (e.mtime_ns == cur_mtime_ns &&
                e.ctime_ns == cur_ctime_ns &&
                e.size     == cur_size) {
                decision = e.decision;
                const_cast<Entry&>(e).hit_count++;
                const_cast<Entry&>(e).last_access_ts = static_cast<int64_t>(std::time(nullptr));
                #ifdef DEBUG
                std::cout << "[L2] Cache hit — served from Level 2" << std::endl;
                #endif
                return true;;
            }
        }
    }

    if (l1_) {
        int d = 0;
        if (l1_->get(st, ruleset_version, d)) {
            if (!check_capacity(max_bytes)) {
                #ifdef LFU_SIZE
                std::cout << "\033[31m"
                        << "[cache][evict] Cache full. Removing based on f(hit_count , size) item"
                        << "\033[0m" << std::endl;
                evict_lfu_size(20,1000);
                #endif

                #ifdef LRU
                std::cout << "\033[31m"
                        << "[cache][evict] Cache full. Removing least recently used item"
                        << "\033[0m" << std::endl;
                evict_lru(20);
                #endif

                #ifdef LFU
                std::cout << "\033[31m"
                        << "[cache][evict] Cache full. Removing least frequently used item"
                        << "\033[0m" << std::endl;
                evict_lfu(20);
                #endif
            }
            #ifdef DEBUG
            std::cout << "[L1] Cache hit — served from Level 1" << std::endl;
            #endif
            Entry ent{};
            ent.mtime_ns = cur_mtime_ns;
            ent.ctime_ns = cur_ctime_ns;
            ent.size = cur_size;
            ent.decision = d;
            ent.last_access_ts = static_cast<int64_t>(std::time(nullptr));
            ent.hit_count = 0;

            std::unique_lock wlk(mu_);
            map_[k] = ent;

            decision = d;
            
            return true;
        }
    }
    #ifdef DEBUG
    std::cout << "[MISS] Not found in any cache — reading from source" << std::endl;
    #endif

    return false;
}

void CacheL2::put(const struct stat& st, uint64_t ruleset_version, int decision, uint64_t max_bytes) {
    if (l1_) {
        l1_->put(st, ruleset_version, decision, max_bytes);
    }

    if (!check_capacity(max_bytes)) {
        #ifdef LFU_SIZE
        std::cout << "\033[31m"
                << "[cache][evict] Cache full. Removing based on f(hit_count , size) item"
                << "\033[0m" << std::endl;
        evict_lfu_size(20,1000);
        #endif

        #ifdef LRU
        std::cout << "\033[31m"
                << "[cache][evict] Cache full. Removing least recently used item"
                << "\033[0m" << std::endl;
        evict_lru(20);
        #endif

        #ifdef LFU
        std::cout << "\033[31m"
                << "[cache][evict] Cache full. Removing least frequently used item"
                << "\033[0m" << std::endl;
        evict_lfu(20);
        #endif
    }

    const Key k{ static_cast<int64_t>(st.st_dev), static_cast<int64_t>(st.st_ino) };
    Entry ent{};
    ent.mtime_ns = to_ns(st.st_mtim.tv_sec, st.st_mtim.tv_nsec);
    ent.ctime_ns = to_ns(st.st_ctim.tv_sec, st.st_ctim.tv_nsec);
    ent.size = static_cast<int64_t>(st.st_size);
    ent.decision = decision;
    ent.last_access_ts = static_cast<int64_t>(std::time(nullptr));
    ent.hit_count = 0;

    {
        std::unique_lock wlk(mu_);
        map_[k] = ent;
    }
}
