#include "CoreEngine.hpp"
#include "StatisticStoreIO.hpp"
#include "StatisticStore.hpp"
#include <iostream>
#include <iomanip>
#include <filesystem>
#include <algorithm>
#include <unordered_map>
#include <cmath>

#define COLOR_GREEN "\033[1;32m"
#define COLOR_CYAN  "\033[1;36m"
#define COLOR_RED   "\033[1;31m"
#define COLOR_RESET "\033[0m"



// Desc: compute 95th-percentile size by file count
// In: const SizeDistribution& sz
// Out: uint64_t (size threshold in bytes)
static uint64_t compute_max_file_size_by_count_95(const SizeDistribution& sz)
{
    if (sz.sizes.empty()) return 0;

    std::vector<uint64_t> sizes;
    sizes.reserve(sz.sizes.size());
    for (const auto& [key, size] : sz.sizes) {
        sizes.push_back(size);
    }

    std::sort(sizes.begin(), sizes.end());

    size_t total_files = sizes.size();
    size_t idx95 = (total_files * 95 + 99) / 100; // ceil(0.95 * total_files)

    if (idx95 == 0) idx95 = 1; 
    if (idx95 > total_files) idx95 = total_files;

    uint64_t threshold_size = sizes[idx95 - 1]; 

    std::cout << COLOR_GREEN
              << "[stat] max_file_size based on static analysis = " << threshold_size
              << " bytes"
              << COLOR_RESET << std::endl;

    return threshold_size;
}


// Desc: Online EMA evaluation for "size95 by access count" over sliding windows.
// Each Open event is counted separately (duplicates included).
// In:  trace: event log (uses TraceEvent{..., size, op})
//      window_hits: number of events per window (like test_k95_ema_online)
//      hop_hits: sliding hop between windows
//      coverage: target fraction (e.g., 0.95)
//      alpha: EMA smoothing factor (0..1)
//      safety_factor: multiplicative safety margin applied to EMA for testing
// Out: summary with final_ema, pass_count, steps count (mirrors the other online eval)

static Size95OnlineEvalSummary test_size95_ema_online(const TraceLog& trace,
                                                      size_t window_hits,
                                                      size_t hop_hits,
                                                      double coverage,
                                                      double alpha,
                                                      double safety_factor)
{
    Size95OnlineEvalSummary out;
    size_t step_count = 0;
    size_t pass_count = 0;

    const auto& evs = trace.events;
    const size_t N = evs.size();
    if (N == 0 || window_hits == 0) return out;

    auto build_histogram = [&](size_t start, size_t end,
                               std::vector<std::pair<uint64_t,uint64_t>>& size_hits,
                               uint64_t& total_hits)
    {
        // Aggregate by exact file size; each Open event contributes +1 to its size bin.
        // Duplicates (same file opened multiple times) are counted multiple times as desired.
        std::unordered_map<uint64_t, uint64_t> by_size;
        total_hits = 0;

        for (size_t i = start; i <= end && i < N; ++i) {
            const auto& e = evs[i];
            if (e.op != OpType::Open) continue;
            by_size[e.size] += 1;
            total_hits += 1;
        }

        size_hits.clear();
        size_hits.reserve(by_size.size());
        for (auto& kv : by_size) size_hits.emplace_back(kv.first, kv.second);

        // Sort ascending by size so cumulative hits from smallest sizes upward
        // determine the "size95" threshold.
        std::sort(size_hits.begin(), size_hits.end(),
                  [](const auto& a, const auto& b){ return a.first < b.first; });
    };

    auto compute_size95 = [&](const std::vector<std::pair<uint64_t,uint64_t>>& size_hits,
                              uint64_t total_hits)->uint64_t
    {
        if (size_hits.empty() || total_hits == 0) return 0ULL;
        // ceil(coverage * total_hits) without floating rounding issues
        const uint64_t target = static_cast<uint64_t>(
            (static_cast<unsigned __int128>(total_hits) * static_cast<unsigned __int128>(std::llround(coverage*100))) + 99
        ) / 100;

        uint64_t cum = 0;
        for (const auto& [sz, hits] : size_hits) {
            cum += hits;
            if (cum >= target) return sz; // first size that achieves required coverage
        }
        return size_hits.back().first;
    };

    auto achieved_with_threshold = [&](const std::vector<std::pair<uint64_t,uint64_t>>& size_hits,
                                       uint64_t total_hits,
                                       uint64_t threshold)->double
    {
        if (total_hits == 0) return 0.0;
        uint64_t covered = 0;
        // size_hits is sorted ascending. Count all hits with size <= threshold.
        for (const auto& [sz, hits] : size_hits) {
            if (sz > threshold) break;
            covered += hits;
        }
        return static_cast<double>(covered) / static_cast<double>(total_hits);
    };

    double ema = 0.0;
    bool initialized = false;
    size_t start = 0;

    std::vector<std::pair<uint64_t,uint64_t>> size_hits; // (size, hits)
    uint64_t total_hits = 0;

    while (start < N) {
        const size_t end = std::min(start + window_hits, N) - 1;

        build_histogram(start, end, size_hits, total_hits);
        const uint64_t size95 = compute_size95(size_hits, total_hits);

        if (!initialized) {
            ema = static_cast<double>(size95);
            initialized = true;
            std::cout << COLOR_CYAN
                      << "[STEP " << step_count++ << "] INIT window[" << start << ".." << end << "]  "
                      << "size95=" << size95
                      << "  EMA=" << std::fixed << std::setprecision(2) << ema
                      << COLOR_RESET << std::endl;
        } else {
            // Use EMA (previous) × safety as the testing threshold
            const uint64_t target_bytes = static_cast<uint64_t>(std::ceil(safety_factor * ema));
            const double achieved = achieved_with_threshold(size_hits, total_hits, target_bytes);
            const bool pass = (achieved >= coverage);

            std::cout << COLOR_CYAN
                      << "[STEP " << step_count++ << "] window[" << start << ".." << end << "]  "
                      << "prevEMA=" << std::fixed << std::setprecision(2) << ema
                      << "  target_bytes=" << target_bytes
                      << "  achieved=" << std::setprecision(3) << (achieved * 100.0) << "%  "
                      << (pass ? "PASS" : "FAIL")
                      << COLOR_RESET << std::endl;
            if (pass) ++pass_count;

            // Update EMA with current window's size95
            ema = alpha * static_cast<double>(size95) + (1.0 - alpha) * ema;
        }

        start += hop_hits;
        if (hop_hits == 0) break; // safety guard
    }

    out.final_ema = ema;
    out.pass_count = pass_count;
    out.steps.resize(step_count);
    return out;
}


static K95OnlineEvalSummary test_k95_ema_online(const TraceLog& trace,
                         size_t window_hits,
                         size_t hop_hits,
                         double coverage,
                         double alpha,
                         double safety_factor)
{
    K95OnlineEvalSummary out;        // summary to return
    size_t step_count = 0;           // how many windows printed
    size_t pass_count = 0;           // how many windows passed
    const auto& evs = trace.events;
    const size_t N = evs.size();
    if (N == 0) return out;

    auto pack_key = [](const FileKey& k)->uint64_t {
        return (uint64_t(k.dev) << 32) ^ uint64_t(k.ino);
    };

    auto build_contribs = [&](size_t start, size_t end, std::vector<unsigned __int128>& contribs, unsigned __int128& total) {
        std::unordered_map<uint64_t, std::pair<uint64_t,uint64_t>> per_file;
        for (size_t i = start; i <= end && i < N; ++i) {
            const auto& e = evs[i];
            if (e.op != OpType::Open) continue;
            auto& ref = per_file[pack_key(e.key)];
            ref.first += 1;
            ref.second = e.size;
        }
        contribs.clear();
        total = 0;
        for (auto& kv : per_file) {
            unsigned __int128 c = (unsigned __int128)kv.second.first * kv.second.second;
            contribs.push_back(c);
            total += c;
        }
        std::sort(contribs.begin(), contribs.end(), [](auto a, auto b){ return a > b; });
    };

    auto compute_k95 = [&](const std::vector<unsigned __int128>& contribs, unsigned __int128 total){
        if (contribs.empty() || total == 0) return (uint64_t)0;
        unsigned __int128 target = (unsigned __int128)std::ceil((long double)total * coverage);
        unsigned __int128 cum = 0;
        uint64_t k = 0;
        for (auto c : contribs) {
            cum += c;
            ++k;
            if (cum >= target) return k;
        }
        return (uint64_t)contribs.size();
    };

    auto coverage_with_topk = [&](const std::vector<unsigned __int128>& contribs, unsigned __int128 total, uint64_t k){
        if (k == 0 || contribs.empty() || total == 0) return 0.0;
        if (k > contribs.size()) k = contribs.size();
        unsigned __int128 cum = 0;
        for (size_t i = 0; i < k; ++i) cum += contribs[i];
        return (double)cum / (double)total;
    };

    double ema = 0.0;
    bool initialized = false;
    size_t start = 0;
    std::vector<unsigned __int128> contribs;
    unsigned __int128 total = 0;

    while (start < N) {
        size_t end = std::min(start + window_hits, N) - 1;
        build_contribs(start, end, contribs, total);
        uint64_t k95 = compute_k95(contribs, total);

        if (!initialized) {
            ema = k95;
            initialized = true;
            std::cout << COLOR_CYAN << "[STEP " << step_count++ << "] INIT window[" << start << ".." << end << "]  k95=" << k95
                      << "  EMA=" << ema << COLOR_RESET << std::endl;
        } else {
            uint64_t target = (uint64_t)std::ceil(safety_factor * ema);
            double achieved = coverage_with_topk(contribs, total, target);
            bool pass = achieved >= coverage;

            std::cout << COLOR_CYAN << "[STEP " << step_count++ << "] window[" << start << ".." << end << "]  "
                       << "prevEMA=" << std::fixed << std::setprecision(2) << ema
                       << "  target=" << target
                       << "  achieved=" << std::setprecision(3) << achieved * 100 << "%  "
                       << (pass ? "PASS" : "FAIL")
                       <<  COLOR_RESET << std::endl;
            if (pass) ++pass_count;

            ema = alpha * k95 + (1.0 - alpha) * ema;
        }
        start += hop_hits;
    }

     out.final_ema = ema;
     out.pass_count = pass_count;
     out.steps.resize(step_count);
     return out;
}



void start_core_engine_simulation(const ConfigManager& config, const std::string& filename) {
    if (filename.empty()) {
        std::cerr << "[Simulation] Error: No filename provided.\n";
        std::cerr << "Usage: ./filegaurde simulation <trace_file.bin>\n";
        return;
    }

    std::string filepath = "statistical_result/" + filename;

    if (!std::filesystem::exists(filepath)) {
        std::cerr << "[Simulation] File not found: " << filepath << "\n";
        return;
    }

    StatisticStore loaded;
    if (!load_statistic_store(loaded, filepath)) {
        std::cerr << "[Simulation] Failed to load trace data from " << filepath << "\n";
        return;
    }

    std::cout << "[Simulation] Loaded trace: " << filepath << "\n";
    std::cout << "[Simulation] Events: " << loaded.trace.events.size()
              << " Sizes: " << loaded.sizes.sizes.size()
              << " Access: " << loaded.access.open_hits.size()
              << "\n";

    // === Run analysis ===
    compute_max_file_size_by_count_95(loaded.sizes);

    double safety = 1.20;
    size_t window_hits = 2000;
    size_t hop_hits = 1000;

    for (int i = 1; i < 10; i++) {
        double alpha = 0.1 * i;
        auto sz_eval = test_size95_ema_online(loaded.trace, window_hits, hop_hits, 0.95, alpha, safety);
        auto k_eval  = test_k95_ema_online(loaded.trace, window_hits, hop_hits, 0.95, alpha, safety);

        std::cout << COLOR_GREEN
                  << "[α=" << alpha << "] size95_ema=" << sz_eval.final_ema
                  << " | k95_ema=" << k_eval.final_ema
                  << COLOR_RESET << "\n";
    }
}