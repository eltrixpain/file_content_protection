#include "PatternMatcherHS.hpp"
#include "ConfigManager.hpp"
#include <iostream>

thread_local hs_scratch_t* PatternMatcherHS::tls_scratch_ = nullptr;

PatternMatcherHS::PatternMatcherHS() = default;

PatternMatcherHS::~PatternMatcherHS() {
    freeAll_();
}

void PatternMatcherHS::freeAll_() noexcept {
    if (base_scratch_) { hs_free_scratch(base_scratch_); base_scratch_ = nullptr; }
    if (db_)           { hs_free_database(db_);           db_           = nullptr; }
    ready_ = false;
    count_ = 0;
}

bool PatternMatcherHS::buildFromConfig(const ConfigManager& cfg) {
    freeAll_();

    const auto& pats = cfg.getPatternStrings();
    count_ = pats.size();
    if (pats.empty()) {
        // No patterns: treat as ready but trivially false on matches()
        ready_ = true;
        return true;
    }

    std::vector<const char*> cpat;
    cpat.reserve(pats.size());
    for (auto& s : pats) cpat.push_back(s.c_str());

    std::vector<unsigned> flags;
    flags.reserve(pats.size());
    for (size_t i = 0; i < pats.size(); ++i) flags.push_back(HS_FLAG_CASELESS); // mirror icase

    std::vector<unsigned> ids;
    ids.reserve(pats.size());
    for (size_t i = 0; i < pats.size(); ++i) ids.push_back(static_cast<unsigned>(i));

    hs_compile_error_t* ce = nullptr;
    hs_error_t rc = hs_compile_multi(
        cpat.data(),
        flags.data(),
        ids.data(),
        static_cast<unsigned>(cpat.size()),
        HS_MODE_BLOCK,
        nullptr,
        &db_,
        &ce
    );

    if (rc != HS_SUCCESS) {
        if (ce) {
            std::cerr << "[PatternMatcherHS] compile failed: " << ce->message << "\n";
            hs_free_compile_error(ce);
        } else {
            std::cerr << "[PatternMatcherHS] compile failed (unknown)\n";
        }
        freeAll_();
        return false;
    }
    if (ce) hs_free_compile_error(ce);

    rc = hs_alloc_scratch(db_, &base_scratch_);
    if (rc != HS_SUCCESS) {
        std::cerr << "[PatternMatcherHS] hs_alloc_scratch failed: " << rc << "\n";
        freeAll_();
        return false;
    }

    ready_ = true;
    return true;
}

bool PatternMatcherHS::matches(const std::string& text) const {
    if (!ready_) return false;
    if (count_ == 0) return false;

    // Clone per-thread scratch lazily and reuse.
    if (!tls_scratch_) {
        if (base_scratch_) {
            if (hs_clone_scratch(base_scratch_, &tls_scratch_) != HS_SUCCESS) {
                std::cerr << "[PatternMatcherHS] hs_clone_scratch failed\n";
                return false;
            }
        } else {
            std::cerr << "[PatternMatcherHS] base scratch is null\n";
            return false;
        }
    }

    bool matched = false;
    auto on_match = [](unsigned int, unsigned long long, unsigned long long, unsigned int, void* ctx) -> int {
        *static_cast<bool*>(ctx) = true;
        return HS_SCAN_TERMINATED;
    };

    hs_error_t rc = hs_scan(
        db_,
        text.data(),
        static_cast<unsigned int>(text.size()),
        0,
        tls_scratch_,
        on_match,
        &matched
    );

    if (rc != HS_SUCCESS && rc != HS_SCAN_TERMINATED) {
        std::cerr << "[PatternMatcherHS] hs_scan error: " << rc << "\n";
        return false;
    }
    return matched;
}
