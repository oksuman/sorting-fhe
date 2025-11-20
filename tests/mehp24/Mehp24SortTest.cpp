#include <algorithm>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <iomanip>
#include <random>
#include <vector>

#include "../src/mehp24/mehp24_sort.h"
#include "../src/mehp24/mehp24_utils.h"
#include "../utils.h"
#include "../memory_tracker.h"
#include "comparison.h"
#include "encryption.h"
#include "openfhe.h"

using namespace lbcrypto;
using namespace std::chrono;
namespace fs = std::filesystem;

template <int N> class MEHPSortTest : public ::testing::Test {
  protected:
    void SetUp() override {
        CCParams<CryptoContextCKKSRNS> parameters;

        parameters.SetSecurityLevel(HEStd_128_classic);
        auto logRingDim = 17;
        parameters.SetRingDim(1 << logRingDim);
        auto batchSize = std::min(N * N, (1 << logRingDim) / 2);
        parameters.SetBatchSize(batchSize);

        switch (N) {
        case 4:
            m_multDepth = 31;
            break;
        case 8:
            m_multDepth = 35;
            break;
        case 16:
            m_multDepth = 35;
            break;
        case 32:
            m_multDepth = 42;
            break;
        case 64:
            m_multDepth = 42;
            break;
        case 128:
            m_multDepth = 46;
            break;
        case 256:
            m_multDepth = 49;
            break;
        case 512:
            m_multDepth = 57;
            break;
        case 1024:
            m_multDepth = 60;
            break;
        case 2048:
            m_multDepth = 64;
            break;
        default:
            break;
        }
        m_scaleMod = 40;
        parameters.SetMultiplicativeDepth(m_multDepth);
        parameters.SetScalingModSize(m_scaleMod);

        m_cc = GenCryptoContext(parameters);
        m_cc->Enable(PKE);
        m_cc->Enable(KEYSWITCH);
        m_cc->Enable(LEVELEDSHE);
        m_cc->Enable(ADVANCEDSHE);

        auto keyPair = m_cc->KeyGen();
        m_publicKey = keyPair.publicKey;
        m_privateKey = keyPair.secretKey;

        m_cc->EvalMultKeyGen(m_privateKey);
        rotations = mehp24::utils::getRotationIndices(N);
        m_cc->EvalRotateKeyGen(m_privateKey, rotations);
        m_cc->EvalMultKeyGen(m_privateKey);
        m_enc = std::make_shared<DebugEncryption>(m_cc, keyPair);
        comp = std::make_unique<Comparison>(m_enc);
    }

    std::vector<int> rotations;
    CryptoContext<DCRTPoly> m_cc;
    PublicKey<DCRTPoly> m_publicKey;
    PrivateKey<DCRTPoly> m_privateKey;
    std::shared_ptr<DebugEncryption> m_enc;
    std::unique_ptr<Comparison> comp;
    int m_multDepth;
    int m_scaleMod;
};

template <typename T>
class MEHPSortTestFixture : public MEHPSortTest<T::value> {};

TYPED_TEST_SUITE_P(MEHPSortTestFixture);

TYPED_TEST_P(MEHPSortTestFixture, SortFGTest) {
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

    SignConfig Cfg;
    if (N <= 16)
        Cfg = SignConfig(CompositeSignConfig(3, 2, 2));
    else if (N <= 128)
        Cfg = SignConfig(CompositeSignConfig(3, 3, 2));
    else if (N <= 512)
        Cfg = SignConfig(CompositeSignConfig(3, 4, 2));
    else
        Cfg = SignConfig(CompositeSignConfig(3, 5, 2));

    uint32_t dg_i = (log2(N) + 1) / 2; // N = vectorLength
    uint32_t df_i = 2;

    std::cout << "Sign Configuration: CompositeSign(" << Cfg.compos.n << ", "
              << Cfg.compos.dg << ", " << Cfg.compos.df << ")" << std::endl;
    std::cout << ", dg_i=" << dg_i << ", df_i=" << df_i << std::endl;

    double setupMemoryGB = MemoryMonitor::getMemoryUsageGB();
    MemoryMonitor memMonitor(500);

    Ciphertext<DCRTPoly> ctxt_out;
    auto start = high_resolution_clock::now();
    if (N <= 256)
        ctxt_out = mehp24::sortFG(ctxt, N, SignFunc::CompositeSign, Cfg,
                                  this->comp, dg_i, df_i, this->m_cc);
    else {
        const size_t subLength = 256;
        ctxt_out = mehp24::sortLargeArrayFG(ctxt, N, subLength,
                                            SignFunc::CompositeSign, Cfg,
                                            this->comp, dg_i, df_i, this->m_cc);
    }

    auto end = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(end - start).count();

    Plaintext result;
    this->m_cc->Decrypt(this->m_privateKey, ctxt_out, &result);
    std::vector<double> outputArray = result->GetRealPackedValue();

    std::vector<double> expectedArray = inputArray;
    std::sort(expectedArray.begin(), expectedArray.end());

    // Calculate errors
    double maxError = 0.0;
    double totalError = 0.0;
    int largeErrorCount = 0;

    for (size_t i = 0; i < N; ++i) {
        double error = std::abs(outputArray[i] - expectedArray[i]);
        maxError = std::max(maxError, error);
        totalError += error;
        if (error >= 0.01) {
            largeErrorCount++;
        }
    }

    double avgError = totalError / N;

    double peakMemoryGB = memMonitor.getPeakMemoryGB();
    double avgMemoryGB = memMonitor.getAverageMemoryGB();
    double cryptoOverheadGB = setupMemoryGB - idleMemoryGB;
    double sortingOverheadGB = peakMemoryGB - setupMemoryGB;

    std::cout << "\nPerformance Analysis:" << std::endl;
    std::cout << "Execution time: " << duration << " ms" << std::endl;
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
    std::cout << "Result Level: " << ctxt_out->GetLevel() << std::endl;

    ASSERT_LT(maxError, 0.01);

    this->m_cc->ClearEvalMultKeys();
    this->m_cc->ClearEvalAutomorphismKeys();
    lbcrypto::CryptoContextFactory<lbcrypto::DCRTPoly>::ReleaseAllContexts();
}

REGISTER_TYPED_TEST_SUITE_P(MEHPSortTestFixture, SortFGTest);

using TestSizes = ::testing::Types<
    std::integral_constant<size_t, 4>, std::integral_constant<size_t, 8>,
    std::integral_constant<size_t, 16>, std::integral_constant<size_t, 32>,
    std::integral_constant<size_t, 64>, std::integral_constant<size_t, 128>,
    std::integral_constant<size_t, 256>, std::integral_constant<size_t, 512>,
    std::integral_constant<size_t, 1024>>;

INSTANTIATE_TYPED_TEST_SUITE_P(MEHPSort, MEHPSortTestFixture, TestSizes);