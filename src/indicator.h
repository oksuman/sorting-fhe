/*
 * Indicator Functions for Rank-based Sorting
 *
 * This file provides various indicator function implementations for
 * encrypted rank-based sorting algorithms.
 *
 * Indicator functions output ~1 when input is near 0, and ~0 otherwise.
 */
#pragma once

#include "encryption.h"
#include "openfhe.h"
#include <cmath>
#include <iostream>
#include <memory>
#include <string>

using namespace lbcrypto;

// Indicator function types
enum class IndicatorFunc {
    Ind0Naive,    // Direct Chebyshev approximation of indicator at 0
    Gaussian,     // e^{-kx^2} approximation
    CKK20,        // Comparison-based (CKK20 method)
    LLNK22,       // Comparison-based (LLNK22 minimax method)
    Sinc,         // Sinc function approximation: sin(pi*N*x)/(pi*N*x)
};

// Configuration for comparison-based indicators (CKK20, LLNK22)
struct CompIndicatorConfig {
    int dg;       // Number of g compositions
    int df;       // Number of f compositions
    int n_poly;   // Polynomial degree parameter (for CKK20: n in f_n, g_n)

    CompIndicatorConfig(int dg = 0, int df = 0, int n_poly = 3)
        : dg(dg), df(df), n_poly(n_poly) {}
};

// Main indicator configuration
struct IndicatorConfig {
    int N;                      // Array size (determines epsilon = 1/(2N))
    double epsilon;             // Indicator width (auto-computed from N if N > 0)
    int degree;                 // Polynomial degree (for Chebyshev methods)
    CompIndicatorConfig comp;   // Config for comparison-based methods
    int multDepth;              // Total multiplicative depth available

    IndicatorConfig()
        : N(0), epsilon(0.5), degree(100), comp(), multDepth(100) {}

    IndicatorConfig(int N, int degree = 0, CompIndicatorConfig comp = {},
                    int multDepth = 100)
        : N(N), epsilon(1.0 / (2.0 * N)), degree(degree), comp(comp),
          multDepth(multDepth) {}

    // Get epsilon based on N
    double getEpsilon() const {
        return (N > 0) ? (1.0 / (2.0 * N)) : epsilon;
    }
};

// Result structure for indicator evaluation (for benchmarking)
struct IndicatorResult {
    int degree;           // Polynomial degree used
    int depthConsumed;    // Multiplicative depth consumed
    std::string settings; // Settings description (for table)
};

// Helper functions for parameter computation

// Compute k for Gaussian e^{-kx^2} such that at ±epsilon, value <= 2^{-alpha}
inline double computeGaussianK(double epsilon, int alpha = 10) {
    // e^{-k*epsilon^2} <= 2^{-alpha}
    // -k*epsilon^2 <= -alpha*ln(2)
    // k >= alpha*ln(2)/epsilon^2
    return alpha * std::log(2.0) / (epsilon * epsilon);
}

// Get recommended (dg, df) for CKK20 method based on array size N
// Following MEHP24: dg = (log2(N)+1)/2, df = 2, n_poly = 3 (degree 7)
inline CompIndicatorConfig getCKK20Config(int N) {
    int dg = (static_cast<int>(std::log2(N)) + 1) / 2;
    int df = 2;
    int n_poly = 3;  // f and g are degree 2n+1 = 7 polynomials
    return CompIndicatorConfig(dg, df, n_poly);
}

// Print indicator settings for table
inline std::string getIndicatorSettings(IndicatorFunc func, const IndicatorConfig& cfg) {
    std::ostringstream oss;
    switch (func) {
    case IndicatorFunc::Ind0Naive:
        oss << "d=" << cfg.degree;
        break;
    case IndicatorFunc::Gaussian: {
        double k = computeGaussianK(cfg.getEpsilon());
        oss << "k=" << static_cast<int>(k) << ", d=" << cfg.degree;
        break;
    }
    case IndicatorFunc::CKK20:
        oss << "dg=" << cfg.comp.dg << ", df=" << cfg.comp.df;
        break;
    case IndicatorFunc::LLNK22:
        oss << "d=" << cfg.degree;  // Will be filled from precomputed coeffs
        break;
    case IndicatorFunc::Sinc:
        oss << "d=" << cfg.degree;
        break;
    }
    return oss.str();
}

// Function name for display
inline std::string getIndicatorName(IndicatorFunc func) {
    switch (func) {
    case IndicatorFunc::Ind0Naive:
        return "Ind0 (Naive Chebyshev)";
    case IndicatorFunc::Gaussian:
        return "Gaussian e^{-kx^2}";
    case IndicatorFunc::CKK20:
        return "Comp-based (CKK20)";
    case IndicatorFunc::LLNK22:
        return "Comp-based (LLNK22)";
    case IndicatorFunc::Sinc:
        return "Sinc";
    }
    return "Unknown";
}

// Plaintext evaluation of indicator functions (for error measurement)

// Ind0: 1 if |x| < epsilon, 0 otherwise
inline double evalInd0(double x, double epsilon) {
    return (std::abs(x) < epsilon) ? 1.0 : 0.0;
}

// Gaussian: e^{-kx^2}
inline double evalGaussian(double x, double k) {
    return std::exp(-k * x * x);
}

// CKK20 indicator: (1 - sign(x - epsilon)) * sign(x + epsilon) / 2
// Outputs 1 when -epsilon < x < epsilon
inline double evalCKK20Indicator(double x, double epsilon) {
    auto sign_func = [](double v) -> double {
        if (v > 0) return 1.0;
        if (v < 0) return -1.0;
        return 0.0;
    };
    double s1 = sign_func(x + epsilon);  // 1 if x > -epsilon
    double s2 = sign_func(x - epsilon);  // 1 if x > epsilon
    // (1 + s1) / 2 = 1 if x > -epsilon, 0 otherwise
    // (1 - s2) / 2 = 1 if x < epsilon, 0 otherwise
    return ((1.0 + s1) / 2.0) * ((1.0 - s2) / 2.0);
}

// Forward declarations for ciphertext operations
// (implementations in indicator.cpp)

Ciphertext<DCRTPoly> indicatorInd0Naive(const Ciphertext<DCRTPoly>& c,
                                         const CryptoContext<DCRTPoly>& cc,
                                         const IndicatorConfig& cfg);

Ciphertext<DCRTPoly> indicatorGaussian(const Ciphertext<DCRTPoly>& c,
                                        const CryptoContext<DCRTPoly>& cc,
                                        const IndicatorConfig& cfg);

Ciphertext<DCRTPoly> indicatorCKK20(const Ciphertext<DCRTPoly>& c,
                                     const CryptoContext<DCRTPoly>& cc,
                                     const IndicatorConfig& cfg);

Ciphertext<DCRTPoly> indicatorLLNK22(const Ciphertext<DCRTPoly>& c,
                                      const CryptoContext<DCRTPoly>& cc,
                                      const IndicatorConfig& cfg);

Ciphertext<DCRTPoly> indicatorSinc(const Ciphertext<DCRTPoly>& c,
                                    const CryptoContext<DCRTPoly>& cc,
                                    const IndicatorConfig& cfg);

// Main dispatcher
Ciphertext<DCRTPoly> indicator(const Ciphertext<DCRTPoly>& c,
                                const CryptoContext<DCRTPoly>& cc,
                                IndicatorFunc func,
                                const IndicatorConfig& cfg);

// Get depth consumed by indicator evaluation
int getIndicatorDepth(IndicatorFunc func, const IndicatorConfig& cfg);

