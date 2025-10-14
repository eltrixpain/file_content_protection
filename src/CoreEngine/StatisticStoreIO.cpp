// === src/CoreEngine/StatisticStoreIO.cpp ===
#include "StatisticStoreIO.hpp"
#include <fstream>
#include <cstddef>  

bool save_statistic_store(const StatisticStore& store, const std::string& path) {
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) return false;

    // Save AccessDistribution
    uint64_t hit_count = store.access.open_hits.size();
    ofs.write(reinterpret_cast<const char*>(&hit_count), sizeof(hit_count));
    for (const auto& [key, hits] : store.access.open_hits) {
        ofs.write(reinterpret_cast<const char*>(&key), sizeof(key));
        ofs.write(reinterpret_cast<const char*>(&hits), sizeof(hits));
    }

    // Save SizeDistribution
    uint64_t size_count = store.sizes.sizes.size();
    ofs.write(reinterpret_cast<const char*>(&size_count), sizeof(size_count));
    for (const auto& [key, sz] : store.sizes.sizes) {
        ofs.write(reinterpret_cast<const char*>(&key), sizeof(key));
        ofs.write(reinterpret_cast<const char*>(&sz), sizeof(sz));
    }

    // Save Trace
    uint64_t event_count = store.trace.events.size();
    ofs.write(reinterpret_cast<const char*>(&event_count), sizeof(event_count));
    for (const auto& ev : store.trace.events) {
        ofs.write(reinterpret_cast<const char*>(&ev), sizeof(ev));
    }

    return ofs.good();
}

bool load_statistic_store(StatisticStore& store, const std::string& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return false;

    store.access.open_hits.clear();
    store.sizes.sizes.clear();
    store.trace.events.clear();

    // AccessDistribution
    uint64_t hit_count = 0;
    ifs.read(reinterpret_cast<char*>(&hit_count), sizeof(hit_count));
    for (uint64_t i = 0; i < hit_count; ++i) {
        FileKey key;
        uint64_t hits;
        ifs.read(reinterpret_cast<char*>(&key), sizeof(key));
        ifs.read(reinterpret_cast<char*>(&hits), sizeof(hits));
        store.access.open_hits[key] = hits;
    }

    // SizeDistribution
    uint64_t size_count = 0;
    ifs.read(reinterpret_cast<char*>(&size_count), sizeof(size_count));
    for (uint64_t i = 0; i < size_count; ++i) {
        FileKey key;
        uint64_t sz;
        ifs.read(reinterpret_cast<char*>(&key), sizeof(key));
        ifs.read(reinterpret_cast<char*>(&sz), sizeof(sz));
        store.sizes.sizes[key] = sz;
    }

    // Trace
    uint64_t event_count = 0;
    ifs.read(reinterpret_cast<char*>(&event_count), sizeof(event_count));
    store.trace.events.resize(event_count);
    for (uint64_t i = 0; i < event_count; ++i) {
        ifs.read(reinterpret_cast<char*>(&store.trace.events[i]), sizeof(TraceEvent));
    }

    return ifs.good();
}
