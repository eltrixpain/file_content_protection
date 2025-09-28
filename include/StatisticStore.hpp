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
