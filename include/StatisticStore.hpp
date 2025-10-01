#pragma once
#include <cstdint>
#include <map>
#include <vector>

struct FileKey {
    uint64_t dev;
    uint64_t ino;
    bool operator<(const FileKey& o) const noexcept {
        return (dev < o.dev) || (dev == o.dev && ino < o.ino);
    }
};

enum class OpType : uint8_t { Open = 0 };

struct TraceEvent {
    int64_t ts_ns;   // timestamp
    FileKey key;     // (dev, ino)
    uint64_t size;   // file size in bytes
    OpType op;       // operation type
};

struct AccessDistribution {
    std::map<FileKey, uint64_t> open_hits; // per-file open count
};

struct SizeDistribution {
    std::map<FileKey, uint64_t> sizes; // per-file size
};

struct TraceLog {
    std::vector<TraceEvent> events; // ordered access trace
};

struct StatisticStore {
    AccessDistribution access;
    SizeDistribution sizes;
    TraceLog trace;
};


struct K95WindowResult {
    size_t   start_idx;
    size_t   end_idx;
    uint64_t total_bytes;
    uint64_t k95;
    double   achieved;
};

struct K95EmaSummary {
    std::vector<double>   ema_values;
    std::vector<uint64_t> target_entries;
    double   final_ema {0.0};
    uint64_t final_target {0};
};