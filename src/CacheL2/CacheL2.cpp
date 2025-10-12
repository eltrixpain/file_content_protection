#include "CacheL2.hpp"
#include "CacheL1.hpp"
#include <ctime>
#include <mutex>
#include <iostream>

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
        return;
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
