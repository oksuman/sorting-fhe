#include <cmath>
#include <vector>
#include <iostream>
#include <iomanip>
#include <chrono>

#include "ciphertext-fwd.h"
#include "lattice/hal/lat-backend.h"
#include "openfhe.h"

#include "generated_doubled_sinc_coeffs.h"
#include "comparison.h"   // for Sinc
#include "encryption.h"   // for DebugEncryption

using namespace lbcrypto;

double evalChebyshev(const std::vector<double>& coeffs, double x) {
    const size_t d = coeffs.size();
    if (d == 0) return 0.0;
    if (d == 1) {
        // only T0 term: p(x) = c0/2
        return 0.5 * coeffs[0];
    }

    double T0 = 1.0;  // T0(x)
    double T1 = x;    // T1(x)

    // constant term has 1/2 factor: c0/2
    double result = 0.5 * coeffs[0] + coeffs[1] * T1;

    for (size_t k = 2; k < d; ++k) {
        double Tk = 2.0 * x * T1 - T0;
        result += coeffs[k] * Tk;
        T0 = T1;
        T1 = Tk;
    }

    return result;
}


template <int N>
void runPlainExperiment(size_t samples) {
    const auto& coeffs = selectDoubledSincCoefficients<N>();

    std::cout << "\n=== Plaintext approximation: N = " << N
              << " | degree = " << coeffs.size() - 1 << " ===\n";

    double Linf = 0.0;
    double L2acc = 0.0;

    const double a = -1.0;
    const double b = 1.0;
    const double dx = (b - a) / (samples - 1);

    for (size_t i = 0; i < samples; ++i) {
        double x = a + dx * i;

        double f = Sinc<2 * N>::doubled_sinc(x);
        double p = evalChebyshev(coeffs, x);

        double e = std::abs(f - p);
        Linf = std::max(Linf, e);
        L2acc += e * e;
    }

    double L2 = std::sqrt(L2acc * dx);

    std::cout << std::scientific << std::setprecision(6);
    std::cout << "L_inf (plain) = " << Linf << "\n";
    std::cout << "L2    (plain) = " << L2   << "\n";

    // log2 errors
    double log2_Linf = std::log2(Linf);
    double log2_L2   = std::log2(L2);

    std::cout << "log2(L_inf)   = " << log2_Linf << "\n";
    std::cout << "log2(L2)      = " << log2_L2   << "\n";

}

struct CKKSContext {
    CryptoContext<DCRTPoly> cc;
    PublicKey<DCRTPoly> pk;
    PrivateKey<DCRTPoly> sk;
    std::shared_ptr<DebugEncryption> enc;
};

CKKSContext setupCKKS() {
    CKKSContext ctx;

    int multDepth = 15;
    CCParams<CryptoContextCKKSRNS> params;
    params.SetSecurityLevel(HEStd_NotSet);
    params.SetRingDim(1 << 17);
    params.SetMultiplicativeDepth(multDepth);

    ctx.cc = GenCryptoContext(params);
    ctx.cc->Enable(PKE);
    ctx.cc->Enable(KEYSWITCH);
    ctx.cc->Enable(LEVELEDSHE);
    ctx.cc->Enable(ADVANCEDSHE);

    auto keyPair = ctx.cc->KeyGen();
    ctx.pk = keyPair.publicKey;
    ctx.sk = keyPair.secretKey;

    ctx.cc->EvalMultKeyGen(ctx.sk);
    ctx.enc = std::make_shared<DebugEncryption>(ctx.cc, keyPair);

    return ctx;
}

template <int N>
void runEncryptedExperiment(const CKKSContext& ctx) {
    const auto& coeffs = selectDoubledSincCoefficients<N>();

    const size_t ringDim = ctx.cc->GetRingDimension();
    const size_t slots   = ringDim / 2;

    std::cout << "\n=== Encrypted approximation: N = " << N
              << " | degree = " << coeffs.size() - 1
              << " | slots = " << slots
              << " ===\n";

    std::vector<double> x(slots);
    const double a = -1.0;
    const double b = 1.0;
    const double dx = (b - a) / (slots - 1);

    for (size_t i = 0; i < slots; ++i) {
        x[i] = a + dx * i;
    }

    auto ctxt = ctx.enc->encryptInput(x);

    auto start = std::chrono::high_resolution_clock::now();
    auto chebCtxt = ctx.cc->EvalChebyshevSeriesPS(ctxt, coeffs, -1.0, 1.0);
    auto end   = std::chrono::high_resolution_clock::now();
    auto duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    Plaintext pt;
    ctx.cc->Decrypt(ctx.sk, chebCtxt, &pt);
    std::vector<double> y = pt->GetRealPackedValue();

    double Linf = 0.0;
    double L2acc = 0.0;

    for (size_t i = 0; i < slots; ++i) {
        double f = Sinc<2 * N>::doubled_sinc(x[i]);
        double e = std::abs(y[i] - f);
        Linf = std::max(Linf, e);
        L2acc += e * e;
    }

    double L2 = std::sqrt(L2acc * dx);

    std::cout << std::scientific << std::setprecision(6);
    std::cout << "Time (encrypted Chebyshev) = " << duration.count() << " ms\n";
    std::cout << "L_inf (enc) = " << Linf << "\n";
    std::cout << "L2    (enc) = " << L2   << "\n";

    double log2_Linf = std::log2(Linf);
    double log2_L2   = std::log2(L2);

    std::cout << "log2(L_inf)   = " << log2_Linf << "\n";
    std::cout << "log2(L2)      = " << log2_L2   << "\n";

}

int main() {
    const size_t S_plain = 1 << 20;  // samples for plaintext grid

    std::cout << "=== Polynomial degree summary ===\n";
    std::cout << "N = 4    degree = " << selectDoubledSincCoefficients<4>().size()    - 1 << "\n";
    std::cout << "N = 8    degree = " << selectDoubledSincCoefficients<8>().size()    - 1 << "\n";
    std::cout << "N = 16   degree = " << selectDoubledSincCoefficients<16>().size()   - 1 << "\n";
    std::cout << "N = 32   degree = " << selectDoubledSincCoefficients<32>().size()   - 1 << "\n";
    std::cout << "N = 64   degree = " << selectDoubledSincCoefficients<64>().size()   - 1 << "\n";
    std::cout << "N = 128  degree = " << selectDoubledSincCoefficients<128>().size()  - 1 << "\n";
    std::cout << "N = 256  degree = " << selectDoubledSincCoefficients<256>().size()  - 1 << "\n";
    std::cout << "N = 512  degree = " << selectDoubledSincCoefficients<512>().size()  - 1 << "\n";
    std::cout << "N = 1024 degree = " << selectDoubledSincCoefficients<1024>().size() - 1 << "\n";
    std::cout << "=================================\n";

    std::cout << "\n===== Plaintext experiments =====\n";
    runPlainExperiment<4>(S_plain);
    runPlainExperiment<8>(S_plain);
    runPlainExperiment<16>(S_plain);
    runPlainExperiment<32>(S_plain);
    runPlainExperiment<64>(S_plain);
    runPlainExperiment<128>(S_plain);
    runPlainExperiment<256>(S_plain);
    runPlainExperiment<512>(S_plain);
    runPlainExperiment<1024>(S_plain);

    std::cout << "\n===== Encrypted experiments =====\n";
    CKKSContext ctx = setupCKKS();
    runEncryptedExperiment<4>(ctx);
    runEncryptedExperiment<8>(ctx);
    runEncryptedExperiment<16>(ctx);
    runEncryptedExperiment<32>(ctx);
    runEncryptedExperiment<64>(ctx);
    runEncryptedExperiment<128>(ctx);
    runEncryptedExperiment<256>(ctx);
    runEncryptedExperiment<512>(ctx);
    runEncryptedExperiment<1024>(ctx);

    return 0;
}
