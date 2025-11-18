#pragma once
#include <atomic>
#include <thread>
#include <vector>
#include <mutex>
#include <chrono>

class MemoryMonitor {
private:
    std::atomic<bool> running_;
    std::thread monitor_thread_;
    std::atomic<double> peak_memory_gb_;
    std::vector<double> samples_gb_;
    mutable std::mutex samples_mutex_;
    int sample_interval_ms_;

    void monitorLoop();
    static double getCurrentMemoryGB();

public:
    // Start monitoring on construction
    explicit MemoryMonitor(int sample_interval_ms = 500);

    // Stop monitoring on destruction (RAII)
    ~MemoryMonitor();

    // Get peak memory observed
    double getPeakMemoryGB() const;

    // Get average memory during monitoring period
    double getAverageMemoryGB() const;

    // Static helper for one-time snapshot (for setup memory)
    static double getMemoryUsageGB();

    // Delete copy/move to prevent issues
    MemoryMonitor(const MemoryMonitor&) = delete;
    MemoryMonitor& operator=(const MemoryMonitor&) = delete;
    MemoryMonitor(MemoryMonitor&&) = delete;
    MemoryMonitor& operator=(MemoryMonitor&&) = delete;
};
