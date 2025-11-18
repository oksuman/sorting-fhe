#include "memory_tracker.h"
#include <fstream>
#include <sstream>
#include <numeric>
#include <iostream>

#ifdef __linux__
double MemoryMonitor::getCurrentMemoryGB() {
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.substr(0, 6) == "VmRSS:") {
            std::istringstream iss(line);
            std::string label;
            long kb;
            iss >> label >> kb;
            return kb / (1024.0 * 1024.0); // KB -> GB
        }
    }
    return 0.0;
}
#elif __APPLE__
#include <mach/mach.h>
double MemoryMonitor::getCurrentMemoryGB() {
    struct task_basic_info info;
    mach_msg_type_number_t size = TASK_BASIC_INFO_COUNT;
    kern_return_t kr = task_info(mach_task_self(), TASK_BASIC_INFO,
                                  (task_info_t)&info, &size);
    if (kr == KERN_SUCCESS) {
        return info.resident_size / (1024.0 * 1024.0 * 1024.0); // bytes -> GB
    }
    return 0.0;
}
#else
double MemoryMonitor::getCurrentMemoryGB() {
    return 0.0; // Unsupported platform
}
#endif

double MemoryMonitor::getMemoryUsageGB() {
    return getCurrentMemoryGB();
}

MemoryMonitor::MemoryMonitor(int sample_interval_ms)
    : running_(true),
      peak_memory_gb_(0.0),
      sample_interval_ms_(sample_interval_ms) {

    // Start the monitoring thread
    monitor_thread_ = std::thread(&MemoryMonitor::monitorLoop, this);
}

MemoryMonitor::~MemoryMonitor() {
    // Signal thread to stop
    running_ = false;

    // Wait for thread to finish
    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }
}

void MemoryMonitor::monitorLoop() {
    while (running_) {
        double current_memory = getCurrentMemoryGB();

        // Update peak memory (atomic)
        double current_peak = peak_memory_gb_.load();
        while (current_memory > current_peak &&
               !peak_memory_gb_.compare_exchange_weak(current_peak, current_memory)) {
            // Retry if another thread updated peak
        }

        // Store sample for average calculation
        {
            std::lock_guard<std::mutex> lock(samples_mutex_);
            samples_gb_.push_back(current_memory);
        }

        // Sleep for the sample interval
        std::this_thread::sleep_for(std::chrono::milliseconds(sample_interval_ms_));
    }
}

double MemoryMonitor::getPeakMemoryGB() const {
    return peak_memory_gb_.load();
}

double MemoryMonitor::getAverageMemoryGB() const {
    std::lock_guard<std::mutex> lock(samples_mutex_);

    if (samples_gb_.empty()) {
        return 0.0;
    }

    double sum = std::accumulate(samples_gb_.begin(), samples_gb_.end(), 0.0);
    return sum / samples_gb_.size();
}
