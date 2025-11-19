#include <algorithm>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <iomanip>
#include <random>
#include <vector>

#include "comparison.h"
#include "encryption.h"
#include "memory_tracker.h"
#include "openfhe.h"
#include "sign.h"
#include "sort_algo.h"
#include "utils.h"

using namespace lbcrypto;
namespace fs = std::filesystem;

template <size_t N> class HybridSortTest : public ::testing::Test {
  protected:
    void SetupParameters() {
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetBatchSize(N);

        // Set up rotation keys based on array size
        switch (N) {
        case 4:
            m_multDepth = 24;
            m_scaleMod = 40;
            rotations = {1, 2, 3, 4, 6, 8};
            break;
        case 8:
            m_multDepth = 25;
            m_scaleMod = 40;
            rotations = {1, 2, 4, 6, 7, 8, 14, 16, 28, 32};
            break;
        case 16:
            m_multDepth = 25;
            m_scaleMod = 40;
            rotations = {1, 2, 3, 4, 8, 12, 15, 16, 30, 32, 60, 64, 120, 128};
            break;
        case 32:
            m_multDepth = 29;
            m_scaleMod = 40;
            rotations = {1,  2,  3,  4,  8,   12,  16,  20,  24,  28,
                         31, 32, 62, 64, 124, 128, 248, 256, 496, 512};
            break;
        case 64:
            m_multDepth = 30;
            m_scaleMod = 40;
            rotations = {1,   2,   3,   4,    6,    7,    8,   16,  24,
                         32,  40,  48,  56,   63,   64,   126, 128, 252,
                         256, 504, 512, 1008, 1024, 2016, 2048};
            break;
        case 128:
            m_multDepth = 31;
            m_scaleMod = 40;
            rotations = {1,   2,    3,    4,    5,    6,    7,    8,    16,
                         24,  32,   40,   48,   56,   64,   72,   80,   88,
                         96,  104,  112,  120,  127,  128,  254,  256,  508,
                         512, 1016, 1024, 2032, 2048, 4064, 4096, 8128, 8192};
            break;
        case 256:
            m_multDepth = 44;
            m_scaleMod = 40;
            rotations = {1,    2,    3,     4,     5,     6,    7,    8,
                         9,    10,   11,    12,    13,    14,   15,   16,
                         32,   48,   64,    80,    96,    112,  128,  144,
                         160,  176,  192,   208,   224,   240,  255,  256,
                         510,  512,  1020,  1024,  2040,  2048, 4080, 4096,
                         8160, 8192, 16320, 16384, 32640, 32768};
            break;
        case 512:
            m_multDepth = 47;
            m_scaleMod = 40;
            rotations = {-255, -1,   1,    2,     3,     4,     5,    6,
                         7,    8,    9,    10,    11,    12,    13,   14,
                         15,   16,   32,   48,    64,    80,    96,   112,
                         128,  144,  160,  176,   192,   208,   224,  240,
                         255,  256,  272,  288,   304,   320,   336,  352,
                         368,  384,  400,  416,   432,   448,   464,  480,
                         496,  510,  512,  1020,  1024,  2040,  2048, 4080,
                         4096, 8160, 8192, 16320, 16384, 32640, 32768};
            break;
        case 1024:
            m_multDepth = 50;
            m_scaleMod = 40;
            rotations = {
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

        parameters.SetSecurityLevel(HEStd_128_classic);
        parameters.SetRingDim(1 << 17); // 2^17
        parameters.SetScalingModSize(m_scaleMod);
        parameters.SetMultiplicativeDepth(m_multDepth);

        m_cc = GenCryptoContext(parameters);
        m_cc->Enable(PKE);
        m_cc->Enable(KEYSWITCH);
        m_cc->Enable(LEVELEDSHE);
        m_cc->Enable(ADVANCEDSHE);
    }

    void SetUp() override {
        SetupParameters();

        auto keyPair = m_cc->KeyGen();
        m_publicKey = keyPair.publicKey;
        m_privateKey = keyPair.secretKey;

        m_cc->EvalRotateKeyGen(m_privateKey, rotations);
        m_cc->EvalMultKeyGen(m_privateKey);

        m_enc = std::make_shared<DebugEncryption>(m_cc, keyPair);
    }

    std::vector<int> rotations;
    CryptoContext<DCRTPoly> m_cc;
    PublicKey<DCRTPoly> m_publicKey;
    PrivateKey<DCRTPoly> m_privateKey;
    std::shared_ptr<DebugEncryption> m_enc;
    int m_multDepth;
    int m_scaleMod;
};

template <typename T>
class HybridSortTestFixture : public HybridSortTest<T::value> {};

TYPED_TEST_SUITE_P(HybridSortTestFixture);

TYPED_TEST_P(HybridSortTestFixture, SortHybridTest) {
    constexpr size_t N = TypeParam::value;

    double idleMemoryGB = MemoryMonitor::getMemoryUsageGB();

    std::vector<double> inputArray =
        getVectorWithMinDiff(N, 0, 1, 1 / (double)N);

    std::cout << "Input array size: " << N << std::endl;
    std::cout << "Using Ring Dimension: " << this->m_cc->GetRingDimension()
              << std::endl;
    std::cout << "Multiplicative depth: " << this->m_multDepth << std::endl;
    std::cout << "Scaling Mod: " << this->m_scaleMod << std::endl;

    auto ctxt = this->m_enc->encryptInput(inputArray);

    auto directSort = std::make_unique<DirectSort<N>>(
        this->m_cc, this->m_publicKey, this->rotations, this->m_enc);

    SignConfig Cfg;
    if (N <= 16)
        Cfg = SignConfig(CompositeSignConfig(3, 2, 2));
    else if (N <= 128)
        Cfg = SignConfig(CompositeSignConfig(3, 3, 2));
    else if (N <= 512)
        Cfg = SignConfig(CompositeSignConfig(3, 4, 2));
    else
        Cfg = SignConfig(CompositeSignConfig(3, 5, 2));
    std::cout << "Sign Configuration: CompositeSign(" << Cfg.compos.n << ", "
              << Cfg.compos.dg << ", " << Cfg.compos.df << ")" << std::endl;

    double setupMemoryGB = MemoryMonitor::getMemoryUsageGB();
    MemoryMonitor memMonitor(500);

    // Start timing
    auto start = std::chrono::high_resolution_clock::now();

    // Perform the hybrid sort
    Ciphertext<DCRTPoly> ctxt_out = directSort->sort_hybrid(
        ctxt, SignFunc::CompositeSign, Cfg, this->m_privateKey);

    // End timing
    auto end = std::chrono::high_resolution_clock::now();
    auto duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    EXPECT_EQ(ctxt_out->GetLevel(), this->m_multDepth)
        << "Use the level returned by the result for best performance";

    Plaintext result;
    this->m_cc->Decrypt(this->m_privateKey, ctxt_out, &result);
    result->SetLength(N);
    std::vector<double> output_array = result->GetRealPackedValue();

    auto expected = inputArray;
    std::sort(expected.begin(), expected.end());

    // Calculate errors
    double maxError = 0.0;
    double totalError = 0.0;
    int largeErrorCount = 0;

    for (size_t i = 0; i < N; ++i) {
        double error = std::abs(output_array[i] - expected[i]);
        maxError = std::max(maxError, error);
        totalError += error;
        if (error >= 0.01) {
            largeErrorCount++;
        }
    }

    double avgError = totalError / output_array.size();

    double peakMemoryGB = memMonitor.getPeakMemoryGB();
    double avgMemoryGB = memMonitor.getAverageMemoryGB();
    double cryptoOverheadGB = setupMemoryGB - idleMemoryGB;
    double sortingOverheadGB = peakMemoryGB - setupMemoryGB;

    std::cout << "\nPerformance Analysis:" << std::endl;
    std::cout << "Execution time: " << duration.count() << " ms" << std::endl;
    std::cout << "\nMemory Analysis:" << std::endl;
    std::cout << "Idle Memory (GB): " << idleMemoryGB << std::endl;
    std::cout << "Setup Memory (GB): " << setupMemoryGB << std::endl;
    std::cout << "Peak Memory (GB): " << peakMemoryGB << std::endl;
    std::cout << "Average Memory (GB): " << avgMemoryGB << std::endl;
    std::cout << "Crypto Overhead (GB): " << cryptoOverheadGB << std::endl;
    std::cout << "Sorting Overhead (GB): " << sortingOverheadGB << std::endl;
    std::cout << "\nError Analysis:" << std::endl;
    std::cout << "Maximum error: " << maxError
              << " (log2: " << std::log2(maxError) << ")" << std::endl;
    std::cout << "Average error: " << avgError
              << " (log2: " << std::log2(avgError) << ")" << std::endl;
    std::cout << "Number of errors larger than 0.01: " << largeErrorCount
              << std::endl;

    ASSERT_LT(maxError, 0.01);
}

REGISTER_TYPED_TEST_SUITE_P(HybridSortTestFixture, SortHybridTest);

using TestSizes = ::testing::Types<
    std::integral_constant<size_t, 4>, std::integral_constant<size_t, 8>,
    std::integral_constant<size_t, 16>, std::integral_constant<size_t, 32>,
    std::integral_constant<size_t, 64>, std::integral_constant<size_t, 128>,
    std::integral_constant<size_t, 256>, std::integral_constant<size_t, 512>,
    std::integral_constant<size_t, 1024>>;

INSTANTIATE_TYPED_TEST_SUITE_P(HybridSort, HybridSortTestFixture, TestSizes);