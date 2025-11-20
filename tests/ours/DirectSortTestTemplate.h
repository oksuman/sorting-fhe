#pragma once

#include <algorithm>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <iomanip>
#include <random>
#include <vector>

#include "../utils.h"
#include "../memory_tracker.h"
#include "openfhe.h"
#include "comparison.h"
#include "encryption.h"
#include "sign.h"
#include "sort_algo.h"

using namespace lbcrypto;
namespace fs = std::filesystem;

template <size_t N>
class DirectSortTest : public ::testing::Test {
protected:
    void SetUp() override {
        CCParams<CryptoContextCKKSRNS> parameters;
        DirectSort<N>::getSizeParameters(parameters, rotations);

        parameters.SetSecurityLevel(HEStd_128_classic);

        auto logRingDim = 17;
        parameters.SetRingDim(1 << logRingDim);

        m_cc = GenCryptoContext(parameters);
        m_cc->Enable(PKE);
        m_cc->Enable(KEYSWITCH);
        m_cc->Enable(LEVELEDSHE);
        m_cc->Enable(ADVANCEDSHE);

        auto keyPair = m_cc->KeyGen();
        m_publicKey = keyPair.publicKey;
        m_privateKey = keyPair.secretKey;

        m_cc->EvalRotateKeyGen(m_privateKey, rotations);
        m_cc->EvalMultKeyGen(m_privateKey);

        m_enc = std::make_shared<DebugEncryption>(m_cc, keyPair);

        m_multDepth = parameters.GetMultiplicativeDepth();
        m_scaleMod = parameters.GetScalingModSize();
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
class DirectSortTestFixture : public DirectSortTest<T::value> {};

TYPED_TEST_SUITE_P(DirectSortTestFixture);

TYPED_TEST_P(DirectSortTestFixture, SortTest) {
    constexpr size_t N = TypeParam::value;

    double idleMemoryGB = MemoryMonitor::getMemoryUsageGB();

    std::vector<double> inputArray =
        getVectorWithMinDiff(N, 0, 1, 1 / (double)N);

    std::cout << "Input array size: " << N << std::endl;
    std::cout << "Using Ring Dimension: "
              << this->m_cc->GetRingDimension() << std::endl;
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

    std::cout << "Sign Configuration: CompositeSign("
              << Cfg.compos.n << ", "
              << Cfg.compos.dg << ", "
              << Cfg.compos.df << ")" << std::endl;

    double setupMemoryGB = MemoryMonitor::getMemoryUsageGB();
    MemoryMonitor memMonitor(500);

    auto start = std::chrono::high_resolution_clock::now();
    Ciphertext<DCRTPoly> ctxt_out =
        directSort->sort(ctxt, SignFunc::CompositeSign, Cfg);
    auto end = std::chrono::high_resolution_clock::now();

    auto duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    EXPECT_EQ(ctxt_out->GetLevel(), this->m_multDepth)
        << "Use the level returned by the result for best performance";

    Plaintext result;
    this->m_cc->Decrypt(this->m_privateKey, ctxt_out, &result);
    std::vector<double> output_array = result->GetRealPackedValue();

    std::cout << "input:" << std::endl;
    std::cout << inputArray << std::endl;
    std::cout << "output:" << std::endl;
    std::cout << output_array << std::endl;

    auto expected = inputArray;
    std::sort(expected.begin(), expected.end());

    double maxError = 0.0;
    double totalError = 0.0;
    int largeErrorCount = 0;

    for (size_t i = 0; i < output_array.size(); ++i) {
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
    std::cout << "Number of errors larger than 0.01: "
              << largeErrorCount << std::endl;

    ASSERT_LT(maxError, 0.01);
}

REGISTER_TYPED_TEST_SUITE_P(DirectSortTestFixture, SortTest);
