#pragma once
#include <cstdint>
#include <map>
#include <vector>
#include <cstddef>

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


struct Size95OnlineEvalSummary {
    double   final_ema = 0.0;
    size_t   pass_count = 0;
    std::vector<int> steps; // reserved only, same style as K95OnlineEvalSummary
};

struct K95OnlineEvalStep {
    size_t   start_idx;
    size_t   end_idx;
    uint64_t total_bytes;         // sum(size*hits) in this test window
    double   prev_ema;            // EMA before evaluating this window
    uint64_t prev_target_entries; // ceil(safety_factor * prev_ema)
    double   achieved_with_prev;  // coverage achieved using prev_target_entries (0..1)
    bool     pass;                // achieved_with_prev >= coverage
    uint64_t k95_this_window;     // k95 computed *for this window*
    double   ema_after;           // EMA after incorporating k95_this_window
};

struct K95OnlineEvalSummary {
    std::vector<K95OnlineEvalStep> steps;
    double   final_ema = 0.0;
    size_t   pass_count = 0;
};
