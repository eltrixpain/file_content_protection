#include "CacheL2.hpp"
#include "CacheL1.hpp"
#include <ctime>
#include <mutex>

bool CacheL2::get(const struct stat& st, uint64_t ruleset_version, int& decision) {
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
                return true;;
            }
        }
    }

    if (l1_) {
        int d = 0;
        if (l1_->get(st, ruleset_version, d)) {
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

    return false;
}

void CacheL2::put(const struct stat& st, uint64_t ruleset_version, int decision, uint64_t max_bytes) {
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

    if (l1_) {
        l1_->put(st, ruleset_version, decision, max_bytes);
    }
}
