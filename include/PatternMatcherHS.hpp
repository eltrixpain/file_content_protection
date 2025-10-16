#pragma once
#include <string>
#include <vector>
#include <hs/hs.h>

class ConfigManager;

// High-performance multi-regex matcher built on Hyperscan.
class PatternMatcherHS {
public:
    PatternMatcherHS();
    ~PatternMatcherHS();

    // Build (or rebuild) from ConfigManager's pattern strings.
    // Returns false if compilation fails.
    bool buildFromConfig(const ConfigManager& cfg);

    // Fast boolean check: does any pattern match 'text'?
    bool matches(const std::string& text) const;

    // Optional helpers
    size_t patternCount() const { return count_; }
    bool   isReady()      const { return ready_; }

private:
    // HS state
    hs_database_t* db_{nullptr};
    hs_scratch_t*  base_scratch_{nullptr};
    bool           ready_{false};
    size_t         count_{0};

    // For safe per-thread scanning we clone scratch lazily.
    static thread_local hs_scratch_t* tls_scratch_;

    // Internal helpers
    void freeAll_() noexcept;
};
