/*
 * Indicator-based Sorting Comparison Test
 *
 * Compares sorting performance with different indicator functions:
 * - Sinc: sin(pi*N*x) / (pi*N*x)
 * - Gaussian: e^{-kx^2}
 * - CKK20: Comparison-based (sign composition)
 *
 * For each indicator and array size, runs trials and measures:
 * - Average runtime
 * - Average precision (log2 of max error)
 * - Depth verification (final level == expected multDepth)
 */

#include <algorithm>
#include <chrono>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <random>
#include <vector>

#include "comparison.h"
#include "encryption.h"
#include "openfhe.h"
#include "sign.h"
#include "sort_algo.h"
#include "utils.h"

using namespace lbcrypto;

// ============================================================================
// Configuration Flags 
// ============================================================================

// Set to true for fast correctness check (N=4~32, small ring dimension)
// Set to false for full benchmark
// constexpr bool FAST_CHECK_MODE = true;
constexpr bool FAST_CHECK_MODE = false;

constexpr int NUM_TRIALS = 10;

// ============================================================================
// Depth Parameters per Indicator Type
// ============================================================================

// Sinc depth parameters 
struct SincDepthParams {
    static constexpr int depth_4 = 24;
    static constexpr int depth_8 = 25;
    static constexpr int depth_16 = 25;
    static constexpr int depth_32 = 29;
    static constexpr int depth_64 = 30;
    static constexpr int depth_128 = 31;
    static constexpr int depth_256 = 35;
    static constexpr int depth_512 = 36;
    static constexpr int depth_1024 = 40;

    template<size_t N>
    static constexpr int getDepth() {
        if constexpr (N == 4) return depth_4;
        else if constexpr (N == 8) return depth_8;
        else if constexpr (N == 16) return depth_16;
        else if constexpr (N == 32) return depth_32;
        else if constexpr (N == 64) return depth_64;
        else if constexpr (N == 128) return depth_128;
        else if constexpr (N == 256) return depth_256;
        else if constexpr (N == 512) return depth_512;
        else if constexpr (N == 1024) return depth_1024;
        else return 40;
    }
};

// Gaussian depth parameters 
struct GaussianDepthParams {
    static constexpr int depth_4 = 26;
    static constexpr int depth_8 = 27;
    static constexpr int depth_16 = 28;
    static constexpr int depth_32 = 32;
    static constexpr int depth_64 = 33;
    static constexpr int depth_128 = 34;
    static constexpr int depth_256 = 38;
    static constexpr int depth_512 = 39;
    static constexpr int depth_1024 = 43;

    template<size_t N>
    static constexpr int getDepth() {
        if constexpr (N == 4) return depth_4;
        else if constexpr (N == 8) return depth_8;
        else if constexpr (N == 16) return depth_16;
        else if constexpr (N == 32) return depth_32;
        else if constexpr (N == 64) return depth_64;
        else if constexpr (N == 128) return depth_128;
        else if constexpr (N == 256) return depth_256;
        else if constexpr (N == 512) return depth_512;
        else if constexpr (N == 1024) return depth_1024;
        else return 40;
    }
};

// CKK20 depth parameters
struct CKK20DepthParams {
    static constexpr int depth_4 = 31;
    static constexpr int depth_8 = 35;
    static constexpr int depth_16 = 35;
    static constexpr int depth_32 = 42;
    static constexpr int depth_64 = 42;
    static constexpr int depth_128 = 46;
    static constexpr int depth_256 = 49;
    static constexpr int depth_512 = 53;
    static constexpr int depth_1024 = 56;

    template<size_t N>
    static constexpr int getDepth() {
        if constexpr (N == 4) return depth_4;
        else if constexpr (N == 8) return depth_8;
        else if constexpr (N == 16) return depth_16;
        else if constexpr (N == 32) return depth_32;
        else if constexpr (N == 64) return depth_64;
        else if constexpr (N == 128) return depth_128;
        else if constexpr (N == 256) return depth_256;
        else if constexpr (N == 512) return depth_512;
        else if constexpr (N == 1024) return depth_1024;
        else return 56;
    }
};

// LLKN22 Depth-optimized depth parameters
struct LLKN22DepthParams {
    static constexpr int depth_4 = 28;    
    static constexpr int depth_8 = 32;    
    static constexpr int depth_16 = 32;   
    static constexpr int depth_32 = 37;   
    static constexpr int depth_64 = 39;   
    static constexpr int depth_128 = 40;  
    static constexpr int depth_256 = 45;  
    static constexpr int depth_512 = 45;  
    static constexpr int depth_1024 = 49; 

    template<size_t N>
    static constexpr int getDepth() {
        if constexpr (N == 4) return depth_4;
        else if constexpr (N == 8) return depth_8;
        else if constexpr (N == 16) return depth_16;
        else if constexpr (N == 32) return depth_32;
        else if constexpr (N == 64) return depth_64;
        else if constexpr (N == 128) return depth_128;
        else if constexpr (N == 256) return depth_256;
        else if constexpr (N == 512) return depth_512;
        else if constexpr (N == 1024) return depth_1024;
        else return 49;
    }
};

// LLKN22 Mult-optimized depth parameters
struct LLKN22MultParams {
    static constexpr int depth_4 = 29;    
    static constexpr int depth_8 = 35;    
    static constexpr int depth_16 = 35;   
    static constexpr int depth_32 = 39;   
    static constexpr int depth_64 = 39;   
    static constexpr int depth_128 = 41;  
    static constexpr int depth_256 = 47;  
    static constexpr int depth_512 = 47;  
    static constexpr int depth_1024 = 51; 

    template<size_t N>
    static constexpr int getDepth() {
        if constexpr (N == 4) return depth_4;
        else if constexpr (N == 8) return depth_8;
        else if constexpr (N == 16) return depth_16;
        else if constexpr (N == 32) return depth_32;
        else if constexpr (N == 64) return depth_64;
        else if constexpr (N == 128) return depth_128;
        else if constexpr (N == 256) return depth_256;
        else if constexpr (N == 512) return depth_512;
        else if constexpr (N == 1024) return depth_1024;
        else return 51;
    }
};

// ============================================================================
// Result Structures
// ============================================================================

struct TrialResult {
    double runtime_ms;
    double max_error;
    double log2_error;
    int final_level;
    int expected_depth;
    bool depth_optimal;
};

struct AggregateResult {
    std::string indicator_name;
    int array_size;
    double avg_runtime_ms;
    double std_runtime_ms;
    double avg_log2_error;
    double std_log2_error;
    int num_trials;
    int expected_depth;
    bool all_depth_optimal;
};

std::string indicatorToString(HybridIndicator ind) {
    switch (ind) {
    case HybridIndicator::Sinc:
        return "Sinc";
    case HybridIndicator::Gaussian:
        return "Gaussian";
    case HybridIndicator::CKK20:
        return "CKK20";
    case HybridIndicator::LLKN22Depth:
        return "LLKN22-D";
    case HybridIndicator::LLKN22Mult:
        return "LLKN22-M";
    default:
        return "Unknown";
    }
}

// ============================================================================
// Tester Class (per indicator type)
// ============================================================================

template <size_t N, HybridIndicator IndicatorType>
class IndicatorSortTester {
private:
    CryptoContext<DCRTPoly> m_cc;
    PublicKey<DCRTPoly> m_publicKey;
    PrivateKey<DCRTPoly> m_privateKey;
    std::shared_ptr<DebugEncryption> m_enc;
    std::vector<int> m_rotations;
    int m_multDepth;
    int m_scaleMod;

    static constexpr int getMultDepth() {
        if constexpr (IndicatorType == HybridIndicator::CKK20) {
            return CKK20DepthParams::getDepth<N>();
        } else if constexpr (IndicatorType == HybridIndicator::Gaussian) {
            return GaussianDepthParams::getDepth<N>();
        } else if constexpr (IndicatorType == HybridIndicator::LLKN22Depth) {
            return LLKN22DepthParams::getDepth<N>();
        } else if constexpr (IndicatorType == HybridIndicator::LLKN22Mult) {
            return LLKN22MultParams::getDepth<N>();
        } else {
            return SincDepthParams::getDepth<N>();
        }
    }

    void setupRotations() {
        switch (N) {
        case 4:
            m_rotations = {1, 2, 3, 4, 6, 8};
            break;
        case 8:
            m_rotations = {1, 2, 4, 6, 7, 8, 14, 16, 28, 32};
            break;
        case 16:
            m_rotations = {1, 2, 3, 4, 8, 12, 15, 16, 30, 32, 60, 64, 120, 128};
            break;
        case 32:
            m_rotations = {1,  2,  3,  4,  8,   12,  16,  20,  24,  28,
                           31, 32, 62, 64, 124, 128, 248, 256, 496, 512};
            break;
        case 64:
            m_rotations = {1,   2,   3,   4,    6,    7,    8,   16,  24,
                           32,  40,  48,  56,   63,   64,   126, 128, 252,
                           256, 504, 512, 1008, 1024, 2016, 2048};
            break;
        case 128:
            m_rotations = {1,   2,    3,    4,    5,    6,    7,    8,    16,
                           24,  32,   40,   48,   56,   64,   72,   80,   88,
                           96,  104,  112,  120,  127,  128,  254,  256,  508,
                           512, 1016, 1024, 2032, 2048, 4064, 4096, 8128, 8192};
            break;
        case 256:
            m_rotations = {1,    2,    3,     4,     5,     6,    7,    8,
                           9,    10,   11,    12,    13,    14,   15,   16,
                           32,   48,   64,    80,    96,    112,  128,  144,
                           160,  176,  192,   208,   224,   240,  255,  256,
                           510,  512,  1020,  1024,  2040,  2048, 4080, 4096,
                           8160, 8192, 16320, 16384, 32640, 32768};
            break;
        case 512:
            m_rotations = {-255, -1,   1,    2,     3,     4,     5,    6,
                           7,    8,    9,    10,    11,    12,    13,   14,
                           15,   16,   32,   48,    64,    80,    96,   112,
                           128,  144,  160,  176,   192,   208,   224,  240,
                           255,  256,  272,  288,   304,   320,   336,  352,
                           368,  384,  400,  416,   432,   448,   464,  480,
                           496,  510,  512,  1020,  1024,  2040,  2048, 4080,
                           4096, 8160, 8192, 16320, 16384, 32640, 32768};
            break;
        case 1024:
            m_rotations = {
                -510, -255, -2,   -1,   1,    2,     3,     4,     5,    6,
                7,    8,    9,    10,   11,   12,    13,    14,    15,   16,
                17,   28,   18,   20,   21,   22,    23,    24,    25,   26,
                27,   29,   30,   31,   32,   64,    96,    128,   160,  192,
                224,  255,  256,  288,  320,  352,   384,   416,   448,  480,
                510,  512,  544,  576,  608,  640,   672,   704,   736,  768,
                800,  832,  864,  896,  928,  960,   992,   1020,  1024, 2040,
                2048, 4080, 4096, 8160, 8192, 16320, 16384, 32640, 32768};
            break;
        default:
            throw std::runtime_error("Unsupported array size");
        }
    }

    void setupParameters() {
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetBatchSize(N);

        m_multDepth = getMultDepth();
        m_scaleMod = 40;
        setupRotations();

        if constexpr (FAST_CHECK_MODE) {
            parameters.SetSecurityLevel(HEStd_NotSet);
            parameters.SetRingDim(1 << 11);
        } else {
            parameters.SetSecurityLevel(HEStd_128_classic);
            parameters.SetRingDim(1 << 17);
        }
        parameters.SetScalingModSize(m_scaleMod);
        parameters.SetMultiplicativeDepth(m_multDepth);

        m_cc = GenCryptoContext(parameters);
        m_cc->Enable(PKE);
        m_cc->Enable(KEYSWITCH);
        m_cc->Enable(LEVELEDSHE);
        m_cc->Enable(ADVANCEDSHE);

        auto keyPair = m_cc->KeyGen();
        m_publicKey = keyPair.publicKey;
        m_privateKey = keyPair.secretKey;

        m_cc->EvalRotateKeyGen(m_privateKey, m_rotations);
        m_cc->EvalMultKeyGen(m_privateKey);

        m_enc = std::make_shared<DebugEncryption>(m_cc, keyPair);
    }

public:
    IndicatorSortTester() {
        setupParameters();
    }

    ~IndicatorSortTester() {
        m_cc->ClearEvalMultKeys();
        m_cc->ClearEvalAutomorphismKeys();
        lbcrypto::CryptoContextFactory<lbcrypto::DCRTPoly>::ReleaseAllContexts();
    }

    int getExpectedDepth() const { return m_multDepth; }

    TrialResult runTrial(const std::vector<double>& inputArray) {
        TrialResult result;
        result.expected_depth = m_multDepth;

        auto ctxt = m_enc->encryptInput(inputArray);

        auto directSort = std::make_unique<DirectSort<N>>(
            m_cc, m_publicKey, m_rotations, m_enc);

        SignConfig Cfg;
        if (N <= 16)
            Cfg = SignConfig(CompositeSignConfig(3, 2, 2));
        else if (N <= 128)
            Cfg = SignConfig(CompositeSignConfig(3, 3, 2));
        else if (N <= 512)
            Cfg = SignConfig(CompositeSignConfig(3, 4, 2));
        else
            Cfg = SignConfig(CompositeSignConfig(3, 5, 2));

        auto start = std::chrono::high_resolution_clock::now();

        Ciphertext<DCRTPoly> ctxt_out = directSort->sort_with_indicator(
            ctxt, SignFunc::CompositeSign, Cfg, IndicatorType, m_privateKey);

        auto end = std::chrono::high_resolution_clock::now();
        result.runtime_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        result.final_level = ctxt_out->GetLevel();

        // Depth verification: final_level should equal multDepth (all levels consumed)
        result.depth_optimal = (result.final_level == m_multDepth);

        // Decrypt and compute error
        Plaintext pt;
        m_cc->Decrypt(m_privateKey, ctxt_out, &pt);
        pt->SetLength(N);
        std::vector<double> output = pt->GetRealPackedValue();

        auto expected = inputArray;
        std::sort(expected.begin(), expected.end());

        // Compute L_inf error (max absolute error)
        result.max_error = 0.0;
        for (size_t i = 0; i < N; ++i) {
            double error = std::abs(output[i] - expected[i]);
            result.max_error = std::max(result.max_error, error);
        }
        result.log2_error = std::log2(result.max_error);  // log2(L_inf)

        return result;
    }

    AggregateResult runTrials(int numTrials) {
        AggregateResult agg;
        agg.indicator_name = indicatorToString(IndicatorType);
        agg.array_size = N;
        agg.num_trials = numTrials;
        agg.expected_depth = m_multDepth;
        agg.all_depth_optimal = true;

        std::vector<double> runtimes;
        std::vector<double> log2_errors;

        for (int t = 0; t < numTrials; ++t) {
            std::vector<double> inputArray = getVectorWithMinDiff(N, 0, 1, 1.0 / N);

            std::cout << "  Trial " << (t + 1) << "/" << numTrials << "..." << std::flush;
            auto result = runTrial(inputArray);

            std::cout << " runtime=" << result.runtime_ms << "ms"
                      << ", log2_err=" << std::fixed << std::setprecision(2) << result.log2_error
                      << ", final_level=" << result.final_level
                      << "/" << result.expected_depth;

            if (!result.depth_optimal) {
                std::cout << " [DEPTH NOT OPTIMAL]";
                agg.all_depth_optimal = false;
            }
            std::cout << std::endl;

            runtimes.push_back(result.runtime_ms);
            log2_errors.push_back(result.log2_error);
        }

        auto computeStats = [](const std::vector<double>& v) {
            double sum = 0, sq_sum = 0;
            for (double x : v) {
                sum += x;
                sq_sum += x * x;
            }
            double mean = sum / v.size();
            double variance = sq_sum / v.size() - mean * mean;
            double std = variance > 0 ? std::sqrt(variance) : 0;
            return std::make_pair(mean, std);
        };

        auto [avg_rt, std_rt] = computeStats(runtimes);
        auto [avg_err, std_err] = computeStats(log2_errors);  // avg of log2(L_inf) per trial

        agg.avg_runtime_ms = avg_rt;
        agg.std_runtime_ms = std_rt;
        agg.avg_log2_error = avg_err;   // E[log2(L_inf)]
        agg.std_log2_error = std_err;

        return agg;
    }
};

// ============================================================================
// Result Printing
// ============================================================================

void printResultsTable(const std::vector<AggregateResult>& results) {
    std::cout << "\n";
    std::cout << std::string(115, '=') << "\n";
    std::cout << "SORTING COMPARISON RESULTS";
    if constexpr (FAST_CHECK_MODE) {
        std::cout << " [FAST CHECK MODE - RingDim=2^11]";
    }
    std::cout << "\n";
    std::cout << std::string(115, '=') << "\n";
    std::cout << std::left << std::setw(12) << "Indicator"
              << std::right << std::setw(8) << "N"
              << std::setw(15) << "Avg Time(ms)"
              << std::setw(15) << "Std Time(ms)"
              << std::setw(15) << "Avg log2 Err"
              << std::setw(15) << "Std log2 Err"
              << std::setw(10) << "Depth"
              << std::setw(12) << "Optimal?"
              << std::setw(10) << "Trials"
              << "\n";
    std::cout << std::string(115, '-') << "\n";

    for (const auto& r : results) {
        std::cout << std::left << std::setw(12) << r.indicator_name
                  << std::right << std::setw(8) << r.array_size
                  << std::fixed << std::setprecision(1)
                  << std::setw(15) << r.avg_runtime_ms
                  << std::setw(15) << r.std_runtime_ms
                  << std::setprecision(2)
                  << std::setw(15) << r.avg_log2_error
                  << std::setw(15) << r.std_log2_error
                  << std::setw(10) << r.expected_depth
                  << std::setw(12) << (r.all_depth_optimal ? "YES" : "NO")
                  << std::setw(10) << r.num_trials
                  << "\n";
    }
    std::cout << std::string(115, '=') << "\n";
    std::cout << "Note: Error = E[log2(L_inf)], where L_inf is max absolute error per trial\n";
}

// ============================================================================
// Test Runner Functions
// ============================================================================

template <size_t N, HybridIndicator Indicator>
void runSingleTest(std::vector<AggregateResult>& allResults) {
    std::cout << "\n  [" << indicatorToString(Indicator) << ", N=" << N << "]\n";
    IndicatorSortTester<N, Indicator> tester;
    auto result = tester.runTrials(NUM_TRIALS);
    allResults.push_back(result);
}

template <size_t N>
void runTestsForSize(std::vector<AggregateResult>& allResults) {
    std::cout << "\n========================================\n";
    std::cout << "Testing N = " << N << "\n";
    std::cout << "========================================\n";

    // runSingleTest<N, HybridIndicator::Sinc>(allResults);
    // runSingleTest<N, HybridIndicator::Gaussian>(allResults);
    // runSingleTest<N, HybridIndicator::CKK20>(allResults);
    runSingleTest<N, HybridIndicator::LLKN22Depth>(allResults);
    runSingleTest<N, HybridIndicator::LLKN22Mult>(allResults);
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    std::cout << "Indicator-based Sorting Comparison Test\n";
    std::cout << "Number of trials per configuration: " << NUM_TRIALS << "\n";
    if constexpr (FAST_CHECK_MODE) {
        std::cout << "*** FAST CHECK MODE ENABLED ***\n";
        std::cout << "  - Testing N = 4, 8, 16, 32 only\n";
        std::cout << "  - RingDim = 2^11 (reduced security for speed)\n";
    }

    std::vector<AggregateResult> allResults;

    if constexpr (FAST_CHECK_MODE) {
        // Fast check: N = 4 ~ 32 only
        runTestsForSize<4>(allResults);
        runTestsForSize<8>(allResults);
        runTestsForSize<16>(allResults);
        runTestsForSize<32>(allResults);
    } else {
        // Full benchmark
        runTestsForSize<4>(allResults);
        runTestsForSize<8>(allResults);
        runTestsForSize<16>(allResults);
        runTestsForSize<32>(allResults);
        runTestsForSize<64>(allResults);
        runTestsForSize<128>(allResults);
        runTestsForSize<256>(allResults);
        runTestsForSize<512>(allResults);
        runTestsForSize<1024>(allResults);
    }

    printResultsTable(allResults);

    // Summary of depth verification
    std::cout << "\nDepth Verification Summary:\n";
    bool all_optimal = true;
    for (const auto& r : allResults) {
        if (!r.all_depth_optimal) {
            std::cout << "  WARNING: " << r.indicator_name << " N=" << r.array_size
                      << " - depth not optimal (expected " << r.expected_depth << ")\n";
            all_optimal = false;
        }
    }
    if (all_optimal) {
        std::cout << "  All configurations have optimal depth settings.\n";
    }

    return 0;
}
