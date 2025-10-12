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
                evict_lfu_size(10,  100);
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
        evict_lfu_size( 10,  100);
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
