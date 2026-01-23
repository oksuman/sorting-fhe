/*
 * Indicator Function Comparison Test
 *
 * This test evaluates and compares various indicator functions for
 * rank-based FHE sorting. It measures:
 * - Polynomial degree (Settings)
 * - Multiplicative depth consumed
 * - Approximation error (L_inf norm in log2 scale)
 *
 * Error is measured by:
 * 1. Encrypting sample points
 * 2. Running indicator function on ciphertext
 * 3. Decrypting result
 * 4. Comparing with ideal indicator function
 *
 * Candidates:
 * 1. Ind0 (naive Chebyshev approximation)
 * 2. Gaussian e^{-kx^2}
 * 3. Comparison-based (CKK20)
 * 4. Comparison-based (LLNK22) [requires precomputed coefficients]
 * 5. Sinc: sin(pi*N*x) / (pi*N*x)
 */

#include <cmath>
#include <iomanip>
#include <iostream>
#include <vector>
#include <chrono>
#include <fstream>
#include <sstream>
#include <stdexcept>

#include "openfhe.h"
#include "comparison.h"
#include "encryption.h"
#include "mehp24/mehp24_utils.h"

// Include generated coefficients if available
#if __has_include("generated_sinc_coeffs.h")
#include "generated_sinc_coeffs.h"
#define HAS_SINC_COEFFS 1
#else
#define HAS_SINC_COEFFS 0
#endif

#if __has_include("generated_indicator_coeffs.h")
#include "generated_indicator_coeffs.h"
#define HAS_INDICATOR_COEFFS 1
#else
#define HAS_INDICATOR_COEFFS 0
#endif

using namespace lbcrypto;

// ============================================================================
// LLKN22 Precomputed Coefficients Loader
// ============================================================================
struct CompositeChebyPoly {
    std::vector<int> degrees;
    std::vector<std::vector<double>> coeffs;
};

CompositeChebyPoly LoadCompositeChebyPoly(const std::string& filepath) {
    CompositeChebyPoly poly;
    std::ifstream file(filepath);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open coefficient file: " + filepath);
    }

    std::string line;
    int currentPoly = -1;

    while (std::getline(file, line)) {
        // Skip empty lines
        if (line.empty()) continue;

        // Parse degrees line: "# degrees: 5,5,5"
        if (line.find("# degrees:") != std::string::npos) {
            size_t pos = line.find(':');
            std::string degStr = line.substr(pos + 1);
            std::istringstream iss(degStr);
            std::string token;
            while (std::getline(iss, token, ',')) {
                poly.degrees.push_back(std::stoi(token));
            }
            poly.coeffs.resize(poly.degrees.size());
            continue;
        }

        // Skip other comments
        if (line[0] == '#') continue;

        // Parse polynomial section: "[p0]", "[p1]", etc.
        if (line[0] == '[' && line[1] == 'p') {
            currentPoly = std::stoi(line.substr(2, line.find(']') - 2));
            continue;
        }

        // Parse degree line: "degree=5"
        if (line.find("degree=") != std::string::npos) {
            continue;  // Already have degrees from header
        }

        // Parse coefficient line: "0\t1.23456..."
        if (currentPoly >= 0 && std::isdigit(line[0])) {
            size_t tabPos = line.find('\t');
            if (tabPos != std::string::npos) {
                double coeff = std::stod(line.substr(tabPos + 1));
                poly.coeffs[currentPoly].push_back(coeff);
            }
        }
    }

    return poly;
}

// Check if file is readable
static inline bool FileReadable(const std::string& path) {
    std::ifstream in(path);
    return in.good();
}

// Get coefficient file path for LLKN22
// Tries multiple paths to handle different working directories
std::string getLLKN22CoeffPath(int N, const std::string& kind) {
    std::ostringstream oss;
    oss << "n" << N << "-" << kind << ".txt";
    std::string filename = oss.str();

    // Try various paths
    std::vector<std::string> paths = {
        "LLKN22-precomputed-coeffs/" + filename,
        "../LLKN22-precomputed-coeffs/" + filename,
        "../../tests/indicators/LLKN22-precomputed-coeffs/" + filename,
        "../../../tests/indicators/LLKN22-precomputed-coeffs/" + filename,
    };

    for (const auto& path : paths) {
        if (FileReadable(path)) {
            return path;
        }
    }

    // Return default path (will fail with error message)
    return paths[0];
}

// ============================================================================
// CKKS Context Setup
// ============================================================================
struct CKKSContext {
    CryptoContext<DCRTPoly> cc;
    PublicKey<DCRTPoly> pk;
    PrivateKey<DCRTPoly> sk;
    std::shared_ptr<DebugEncryption> enc;
    size_t slots;
};

CKKSContext setupCKKS(int multDepth = 20) {
    CKKSContext ctx;

    CCParams<CryptoContextCKKSRNS> params;
    params.SetSecurityLevel(HEStd_NotSet);
    params.SetRingDim(1 << 11);
    params.SetScalingModSize(50);
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

    ctx.slots = ctx.cc->GetRingDimension() / 2;

    return ctx;
}

// ============================================================================
// Target Functions (Ground Truth)
// ============================================================================

// Ideal indicator: 1 if |x| < epsilon, 0 otherwise
double targetIndicator(double x, double epsilon) {
    return (std::abs(x) < epsilon) ? 1.0 : 0.0;
}

// Gaussian: e^{-kx^2}
double targetGaussian(double x, double k) {
    return std::exp(-k * x * x);
}

// Sinc function: sin(pi*N*x) / (pi*N*x)
template<int N>
double targetSinc(double x) {
    return Sinc<2 * N>::scaled_sinc(x);
}

// ============================================================================
// Result Structure
// ============================================================================
struct IndicatorResult {
    double L_inf;
    double log2_L_inf;
    int degree;
    int depthConsumed;
    std::string settings;
    double timeMs;
};

// ============================================================================
// Compute k for Gaussian such that e^{-k*epsilon^2} = 2^{-alpha}
// ============================================================================
double computeGaussianK(double epsilon, int alpha = 10) {
    return alpha * std::log(2.0) / (epsilon * epsilon);
}

// ============================================================================
// CKK20 Config (following MEHP24)
// ============================================================================
struct CKK20Config {
    int n;   // polynomial degree parameter (degree = 2n+1)
    int dg;  // number of g compositions
    int df;  // number of f compositions
};

CKK20Config getCKK20Config(int N) {
    CKK20Config cfg;
    cfg.n = 3;  // degree 7 polynomials
    cfg.dg = (static_cast<int>(std::log2(N)) + 1) / 2;
    cfg.df = 2;
    return cfg;
}

// ============================================================================
// LLKN22 Sign Function with Precomputed Coefficients
// Evaluates sign(x) using composite Chebyshev polynomials
// ============================================================================
Ciphertext<DCRTPoly> EvalSignPrecomp(
    const CryptoContext<DCRTPoly>& cc,
    ConstCiphertext<DCRTPoly> x,
    const CompositeChebyPoly& poly) {

    Ciphertext<DCRTPoly> y = x->Clone();

    // Apply each polynomial in sequence (composition)
    for (const auto& coeffs : poly.coeffs) {
        y = cc->EvalChebyshevSeries(y, coeffs, -1.0, 1.0);
    }

    return y;
}

// LLKN22 Indicator function: 1 if |x| < epsilon, 0 otherwise
// Uses sign(x + epsilon) * (1 - sign(x - epsilon))
// This is similar to CKK20's indicatorAdv but with precomputed polynomials
//
// NOTE: LLKN22 sign function outputs in [-1, 1], but CKK20's signAdv outputs
// in [0, 1]. We transform: sign_{[0,1]} = (sign_{[-1,1]} + 1) / 2
Ciphertext<DCRTPoly> indicatorAdvPrecomp(
    const CryptoContext<DCRTPoly>& cc,
    const Ciphertext<DCRTPoly>& c,
    double b,  // scaling factor (N for our use case)
    const CompositeChebyPoly& poly) {

    // Scale input to [-1, 1] range: tmp = c / b
    auto tmp = cc->EvalMult(c, 1.0 / b);
    cc->ModReduceInPlace(tmp);

    // c1 = tmp + epsilon = tmp + 0.5/b (since epsilon = 1/(2N) = 0.5/N)
    auto c1 = cc->EvalAdd(tmp, 0.5 / b);

    // c2 = tmp - epsilon = tmp - 0.5/b
    auto c2 = cc->EvalSub(tmp, 0.5 / b);

    // Apply sign function to both (outputs in [-1, 1])
    c1 = EvalSignPrecomp(cc, c1, poly);
    c2 = EvalSignPrecomp(cc, c2, poly);

    // Transform from [-1, 1] to [0, 1]: s' = (s + 1) / 2
    c1 = cc->EvalAdd(c1, 1.0);
    c1 = cc->EvalMult(c1, 0.5);
    cc->ModReduceInPlace(c1);

    c2 = cc->EvalAdd(c2, 1.0);
    c2 = cc->EvalMult(c2, 0.5);
    cc->ModReduceInPlace(c2);

    // indicator = sign_{[0,1]}(x+eps) * (1 - sign_{[0,1]}(x-eps))
    auto oneMinusC2 = cc->EvalSub(1.0, c2);
    auto result = cc->EvalMult(c1, oneMinusC2);
    cc->ModReduceInPlace(result);

    return result;
}

// ============================================================================
// 1. Ind0 (Naive Chebyshev Approximation)
// Naive Chebyshev doesn't converge well for discontinuous functions
// ============================================================================

// ============================================================================
// 2. Gaussian e^{-kx^2}
// Target: e^{-kx^2} (smooth approximation of indicator)
// Approximation: Chebyshev approximation of Gaussian
// Uses pre-generated coefficients from generated_indicator_coeffs.h
// ============================================================================
#if HAS_INDICATOR_COEFFS
template<int N>
IndicatorResult testGaussian(const CKKSContext& ctx) {
    IndicatorResult result;
    constexpr double epsilon = 1.0 / (2.0 * N);
    const double k = computeGaussianK(epsilon, 10);
    const auto& coeffs = selectGaussianCoefficients<N>();

    // Generate sample points
    std::vector<double> x(ctx.slots);
    const double a = -1.0, b = 1.0;
    const double dx = (b - a) / (ctx.slots - 1);
    for (size_t i = 0; i < ctx.slots; ++i) {
        x[i] = a + dx * i;
    }

    // Encrypt
    auto ctxt = ctx.enc->encryptInput(x);
    int levelBefore = ctxt->GetLevel();

    // Compute Gaussian using pre-generated Chebyshev coefficients
    auto start = std::chrono::high_resolution_clock::now();
    auto resultCtxt = ctx.cc->EvalChebyshevSeriesPS(ctxt, coeffs, -1.0, 1.0);
    auto end = std::chrono::high_resolution_clock::now();

    int levelAfter = resultCtxt->GetLevel();

    // Decrypt
    Plaintext pt;
    ctx.cc->Decrypt(ctx.sk, resultCtxt, &pt);
    std::vector<double> p = pt->GetRealPackedValue();

    // Compute error against Gaussian function
    result.L_inf = 0.0;
    for (size_t i = 0; i < ctx.slots; ++i) {
        double target = targetGaussian(x[i], k);
        double err = std::abs(p[i] - target);
        result.L_inf = std::max(result.L_inf, err);
    }

    result.log2_L_inf = std::log2(result.L_inf);
    result.degree = static_cast<int>(coeffs.size()) - 1;
    result.depthConsumed = levelAfter - levelBefore;
    result.timeMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    std::ostringstream oss;
    oss << "k=" << static_cast<int>(k) << ", d=" << result.degree;
    result.settings = oss.str();

    return result;
}
#endif

// ============================================================================
// 3. CKK20 (Comparison-based)
// Target: f(x) = 1 if |x| < epsilon, 0 otherwise
// Approximation: sign(x+epsilon) * (1 - sign(x-epsilon)) using composed polys
//
// NOTE: To match sorting workflow, we encrypt N*x directly instead of doing
// EvalMult(ctxt, N). In sorting, the input to indicatorAdv is from
// EvalSub(plaintext, ciphertext), which is a fresh ciphertext.
// ============================================================================
IndicatorResult testCKK20(const CKKSContext& ctx, int N) {
    IndicatorResult result;
    double epsilon = 1.0 / (2.0 * N);
    auto cfg = getCKK20Config(N);

    // Generate sample points in [-1+eps, 1-eps] and pre-scale by N
    // Include x=0, x=±2*eps but exclude x=±1
    std::vector<double> x(ctx.slots);
    std::vector<double> scaled_x(ctx.slots);
    const double a = -1.0 + epsilon;
    const double b = 1.0 - epsilon;
    const double dx = (ctx.slots > 1) ? (b - a) / (ctx.slots - 1) : 0.0;
    for (size_t i = 0; i < ctx.slots; ++i) {
        x[i] = a + dx * static_cast<double>(i);
        scaled_x[i] = x[i] * N;
    }

    // Encrypt scaled values directly (no EvalMult, matching sorting workflow)
    auto ctxt = ctx.enc->encryptInput(scaled_x);
    int levelBefore = ctxt->GetLevel();

    auto start = std::chrono::high_resolution_clock::now();

    // Use indicatorAdv with b=N
    // indicator(x) = comp(x, -eps) * (1 - comp(x, eps))
    // where comp outputs 0 or 1
    auto resultCtxt = mehp24::utils::indicatorAdv(ctxt, static_cast<double>(N), cfg.dg, cfg.df);

    auto end = std::chrono::high_resolution_clock::now();

    int levelAfter = resultCtxt->GetLevel();

    // Decrypt
    Plaintext pt;
    ctx.cc->Decrypt(ctx.sk, resultCtxt, &pt);
    std::vector<double> p = pt->GetRealPackedValue();

    // Compute error against ideal indicator
    // Skip 0 < |x| < 2*eps, but include x=0 and x=±2*eps
    result.L_inf = 0.0;
    for (size_t i = 0; i < ctx.slots; ++i) {
        const double xi = x[i];
        if (xi != 0.0 && std::abs(xi) < 2.0 * epsilon) {
            continue;
        }
        double target = targetIndicator(xi, epsilon);
        double err = std::abs(p[i] - target);
        result.L_inf = std::max(result.L_inf, err);
    }

    result.log2_L_inf = std::log2(result.L_inf);
    result.degree = 0;  // Not a single polynomial

    // Note: indicatorAdv includes internal 1/N scaling (tmp = (1/b)*c),
    // whereas Sinc uses external scaling (EvalMult before Chebyshev).
    // Subtract 1 to compare core indicator depth fairly with Sinc.
    result.depthConsumed = (levelAfter - levelBefore) - 1;

    result.timeMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    std::ostringstream oss;
    oss << "n=" << cfg.n << ", dg=" << cfg.dg << ", df=" << cfg.df;
    result.settings = oss.str();

    return result;
}

// ============================================================================
// 5. Sinc: sin(pi*N*x) / (pi*N*x)
// Target: Sinc function
// Approximation: Chebyshev approximation of Sinc
// ============================================================================
#if HAS_SINC_COEFFS
template<int N>
IndicatorResult testSinc(const CKKSContext& ctx) {
    IndicatorResult result;
    const auto& coeffs = selectCoefficients<N>();

    // Generate sample points
    std::vector<double> x(ctx.slots);
    const double a = -1.0, b = 1.0;
    const double dx = (b - a) / (ctx.slots - 1);
    for (size_t i = 0; i < ctx.slots; ++i) {
        x[i] = a + dx * i;
    }

    // Encrypt
    auto ctxt = ctx.enc->encryptInput(x);
    int levelBefore = ctxt->GetLevel();

    // Compute Sinc using Chebyshev series
    auto start = std::chrono::high_resolution_clock::now();
    auto resultCtxt = ctx.cc->EvalChebyshevSeriesPS(ctxt, coeffs, -1.0, 1.0);
    auto end = std::chrono::high_resolution_clock::now();

    int levelAfter = resultCtxt->GetLevel();

    // Decrypt
    Plaintext pt;
    ctx.cc->Decrypt(ctx.sk, resultCtxt, &pt);
    std::vector<double> p = pt->GetRealPackedValue();

    // Compute error against Sinc function
    result.L_inf = 0.0;
    for (size_t i = 0; i < ctx.slots; ++i) {
        double target = targetSinc<N>(x[i]);
        double err = std::abs(p[i] - target);
        result.L_inf = std::max(result.L_inf, err);
    }

    result.log2_L_inf = std::log2(result.L_inf);
    result.degree = static_cast<int>(coeffs.size()) - 1;
    result.depthConsumed = levelAfter - levelBefore;
    result.timeMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    std::ostringstream oss;
    oss << "d=" << result.degree;
    result.settings = oss.str();

    return result;
}
#endif

// ============================================================================
// 4. LLKN22 (Comparison-based with precomputed coefficients)
// Target: f(x) = 1 if |x| < epsilon, 0 otherwise
// Uses precomputed composite Chebyshev polynomials for sign function
// Two variants: depth-optimized and multiplication-optimized
// ============================================================================
IndicatorResult testLLKN22(const CKKSContext& ctx, int N, const std::string& kind) {
    IndicatorResult result;
    double epsilon = 1.0 / (2.0 * N);

    // Load precomputed coefficients
    std::string filepath = getLLKN22CoeffPath(N, kind);
    CompositeChebyPoly poly;
    try {
        poly = LoadCompositeChebyPoly(filepath);
    } catch (const std::exception& e) {
        result.L_inf = -1;
        result.log2_L_inf = 0;
        result.degree = 0;
        result.depthConsumed = 0;
        result.settings = "FILE NOT FOUND";
        result.timeMs = 0;
        return result;
    }

    // Generate sample points in [-1+eps, 1-eps] and pre-scale by N
    // Include x=0, x=±2*eps but exclude x=±1
    std::vector<double> x(ctx.slots);
    std::vector<double> scaled_x(ctx.slots);
    const double a = -1.0 + epsilon;
    const double b = 1.0 - epsilon;
    const double dx = (ctx.slots > 1) ? (b - a) / (ctx.slots - 1) : 0.0;
    for (size_t i = 0; i < ctx.slots; ++i) {
        x[i] = a + dx * static_cast<double>(i);
        scaled_x[i] = x[i] * N;
    }

    // Encrypt scaled values directly
    auto ctxt = ctx.enc->encryptInput(scaled_x);
    int levelBefore = ctxt->GetLevel();

    auto start = std::chrono::high_resolution_clock::now();

    // Use indicatorAdvPrecomp with b=N
    // indicator(x) = comp(x, -eps) * (1 - comp(x, eps))
    // where comp outputs 0 or 1
    auto resultCtxt = indicatorAdvPrecomp(ctx.cc, ctxt, static_cast<double>(N), poly);

    auto end = std::chrono::high_resolution_clock::now();

    int levelAfter = resultCtxt->GetLevel();

    // Decrypt
    Plaintext pt;
    ctx.cc->Decrypt(ctx.sk, resultCtxt, &pt);
    std::vector<double> p = pt->GetRealPackedValue();

    // Compute error against ideal indicator
    // Skip 0 < |x| < 2*eps, but include x=0 and x=±2*eps
    result.L_inf = 0.0;
    for (size_t i = 0; i < ctx.slots; ++i) {
        const double xi = x[i];
        if (xi != 0.0 && std::abs(xi) < 2.0 * epsilon) {
            continue;
        }
        double target = targetIndicator(xi, epsilon);
        double err = std::abs(p[i] - target);
        result.L_inf = std::max(result.L_inf, err);
    }

    result.log2_L_inf = std::log2(result.L_inf);
    result.degree = 0;  // Not meaningful for composite polynomials

    // Note: indicatorAdvPrecomp includes internal 1/N scaling,
    // same as CKK20. Subtract 1 for fair comparison with Sinc.
    result.depthConsumed = (levelAfter - levelBefore) - 1;

    result.timeMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    // Build settings string: "deg:7,13" format
    std::ostringstream oss;
    oss << "deg:";
    for (size_t i = 0; i < poly.degrees.size(); ++i) {
        if (i > 0) oss << ",";
        oss << poly.degrees[i];
    }
    result.settings = oss.str();

    return result;
}

// ============================================================================
// Print Functions
// ============================================================================
void printTableRow(const std::string& func, int N, const std::string& settings,
                   int depth, double log2Error, double timeMs = 0) {
    std::cout << std::left << std::setw(30) << func
              << std::right << std::setw(6) << N
              << std::setw(25) << settings
              << std::setw(8) << depth
              << std::fixed << std::setprecision(2)
              << std::setw(12) << log2Error
              << std::setw(10) << timeMs << " ms"
              << std::endl;
}

void printTableHeader() {
    std::cout << std::string(100, '=') << std::endl;
    std::cout << std::left << std::setw(30) << "Function"
              << std::right << std::setw(6) << "N"
              << std::setw(25) << "Settings"
              << std::setw(8) << "Depth"
              << std::setw(12) << "Error(log2)"
              << std::setw(10) << "Time"
              << std::endl;
    std::cout << std::string(100, '-') << std::endl;
}

// ============================================================================
// Main Test
// ============================================================================
int main() {
    const std::vector<int> sizes = {4, 8, 16, 32, 64, 128, 256, 512, 1024};

    std::cout << "\n";
    std::cout << "================================================================\n";
    std::cout << "  Indicator Function Comparison for Rank-based Sorting\n";
    std::cout << "================================================================\n";

    // Setup CKKS context
    std::cout << "Setting up CKKS context...\n";
    CKKSContext ctx = setupCKKS(40);
    std::cout << "Slots: " << ctx.slots << "\n\n";

    printTableHeader();

    // -------------------------------------------------------------------------
    // 1. Ind0 (Naive Chebyshev Approximation)
    // -------------------------------------------------------------------------
// #if HAS_INDICATOR_COEFFS
//     std::cout << "\n--- Ind0 (Naive Chebyshev) ---\n";
//     std::cout << "Target: f(x) = 1 if |x| < 1/(2N), 0 otherwise\n\n";
//     {
//         auto r = testInd0<4>(ctx);
//         printTableRow("Ind0 (Naive)", 4, r.settings, r.depthConsumed, r.log2_L_inf, r.timeMs);
//     }
//     {
//         auto r = testInd0<8>(ctx);
//         printTableRow("Ind0 (Naive)", 8, r.settings, r.depthConsumed, r.log2_L_inf, r.timeMs);
//     }
//     {
//         auto r = testInd0<16>(ctx);
//         printTableRow("Ind0 (Naive)", 16, r.settings, r.depthConsumed, r.log2_L_inf, r.timeMs);
//     }
//     {
//         auto r = testInd0<32>(ctx);
//         printTableRow("Ind0 (Naive)", 32, r.settings, r.depthConsumed, r.log2_L_inf, r.timeMs);
//     }
//     {
//         auto r = testInd0<64>(ctx);
//         printTableRow("Ind0 (Naive)", 64, r.settings, r.depthConsumed, r.log2_L_inf, r.timeMs);
//     }
//     {
//         auto r = testInd0<128>(ctx);
//         printTableRow("Ind0 (Naive)", 128, r.settings, r.depthConsumed, r.log2_L_inf, r.timeMs);
//     }
//     {
//         auto r = testInd0<256>(ctx);
//         printTableRow("Ind0 (Naive)", 256, r.settings, r.depthConsumed, r.log2_L_inf, r.timeMs);
//     }
//     {
//         auto r = testInd0<512>(ctx);
//         printTableRow("Ind0 (Naive)", 512, r.settings, r.depthConsumed, r.log2_L_inf, r.timeMs);
//     }
//     {
//         auto r = testInd0<1024>(ctx);
//         printTableRow("Ind0 (Naive)", 1024, r.settings, r.depthConsumed, r.log2_L_inf, r.timeMs);
//     }
// #else
//     std::cout << "\n--- Ind0 (Naive Chebyshev) ---\n";
//     std::cout << "  [Coefficients not generated - build with generate_coeffs_target]\n";
// #endif

    // -------------------------------------------------------------------------
    // 2. Gaussian e^{-kx^2}
    // -------------------------------------------------------------------------
#if HAS_INDICATOR_COEFFS
    std::cout << "\n--- Gaussian e^{-kx^2} ---\n";
    std::cout << "Target: f(x) = e^{-kx^2}, k chosen so f(epsilon) ~ 2^{-10}\n\n";
    {
        auto r = testGaussian<4>(ctx);
        printTableRow("Gaussian", 4, r.settings, r.depthConsumed, r.log2_L_inf, r.timeMs);
    }
    {
        auto r = testGaussian<8>(ctx);
        printTableRow("Gaussian", 8, r.settings, r.depthConsumed, r.log2_L_inf, r.timeMs);
    }
    {
        auto r = testGaussian<16>(ctx);
        printTableRow("Gaussian", 16, r.settings, r.depthConsumed, r.log2_L_inf, r.timeMs);
    }
    {
        auto r = testGaussian<32>(ctx);
        printTableRow("Gaussian", 32, r.settings, r.depthConsumed, r.log2_L_inf, r.timeMs);
    }
    {
        auto r = testGaussian<64>(ctx);
        printTableRow("Gaussian", 64, r.settings, r.depthConsumed, r.log2_L_inf, r.timeMs);
    }
    {
        auto r = testGaussian<128>(ctx);
        printTableRow("Gaussian", 128, r.settings, r.depthConsumed, r.log2_L_inf, r.timeMs);
    }
    {
        auto r = testGaussian<256>(ctx);
        printTableRow("Gaussian", 256, r.settings, r.depthConsumed, r.log2_L_inf, r.timeMs);
    }
    {
        auto r = testGaussian<512>(ctx);
        printTableRow("Gaussian", 512, r.settings, r.depthConsumed, r.log2_L_inf, r.timeMs);
    }
    {
        auto r = testGaussian<1024>(ctx);
        printTableRow("Gaussian", 1024, r.settings, r.depthConsumed, r.log2_L_inf, r.timeMs);
    }
#else
    std::cout << "\n--- Gaussian e^{-kx^2} ---\n";
    std::cout << "  [Coefficients not generated - build with generate_coeffs_target]\n";
#endif

//     // -------------------------------------------------------------------------
//     // 3. CKK20 (Comparison-based)
//     // -------------------------------------------------------------------------
    std::cout << "\n--- CKK20 (Comparison-based) ---\n";
    std::cout << "Target: f(x) = 1 if |x| < 1/(2N), 0 otherwise\n";
    std::cout << "Approx: comp(x,-eps) * (1 - comp(x,eps))\n\n";
    for (int N : sizes) {
        auto result = testCKK20(ctx, N);
        printTableRow("CKK20", N, result.settings,
                      result.depthConsumed, result.log2_L_inf, result.timeMs);
    }

    // -------------------------------------------------------------------------
    // 4. LLKN22 (Comparison-based, precomputed) - Depth Optimized
    // -------------------------------------------------------------------------
    std::cout << "\n--- LLKN22 (Depth-optimized) ---\n";
    std::cout << "Target: f(x) = 1 if |x| < 1/(2N), 0 otherwise\n";
    std::cout << "Approx: comp(x,-eps) * (1 - comp(x,eps)) with composite polys\n\n";
    for (int N : sizes) {
        auto result = testLLKN22(ctx, N, "depth");
        if (result.L_inf >= 0) {
            printTableRow("LLKN22-Depth", N, result.settings,
                          result.depthConsumed, result.log2_L_inf, result.timeMs);
        } else {
            std::cout << "  [N=" << N << "] Coefficients not found\n";
        }
    }

    // -------------------------------------------------------------------------
    // 4b. LLKN22 (Comparison-based, precomputed) - Mult Optimized
    // -------------------------------------------------------------------------
    std::cout << "\n--- LLKN22 (Mult-optimized) ---\n";
    std::cout << "Target: f(x) = 1 if |x| < 1/(2N), 0 otherwise\n";

    std::cout << "Approx: comp(x,-eps) * (1 - comp(x,eps)) with composite polys\n\n";
    for (int N : sizes) {
        auto result = testLLKN22(ctx, N, "mult");
        if (result.L_inf >= 0) {
            printTableRow("LLKN22-Mult", N, result.settings,
                          result.depthConsumed, result.log2_L_inf, result.timeMs);
        } else {
            std::cout << "  [N=" << N << "] Coefficients not found\n";
        }
    }

    // -------------------------------------------------------------------------
    // 5. Sinc
    // -------------------------------------------------------------------------
#if HAS_SINC_COEFFS
    std::cout << "\n--- Sinc ---\n";
    std::cout << "Target: f(x) = sin(pi*N*x) / (pi*N*x)\n\n";
    {
        auto r = testSinc<4>(ctx);
        printTableRow("Sinc", 4, r.settings, r.depthConsumed, r.log2_L_inf, r.timeMs);
    }
    {
        auto r = testSinc<8>(ctx);
        printTableRow("Sinc", 8, r.settings, r.depthConsumed, r.log2_L_inf, r.timeMs);
    }
    {
        auto r = testSinc<16>(ctx);
        printTableRow("Sinc", 16, r.settings, r.depthConsumed, r.log2_L_inf, r.timeMs);
    }
    {
        auto r = testSinc<32>(ctx);
        printTableRow("Sinc", 32, r.settings, r.depthConsumed, r.log2_L_inf, r.timeMs);
    }
    {
        auto r = testSinc<64>(ctx);
        printTableRow("Sinc", 64, r.settings, r.depthConsumed, r.log2_L_inf, r.timeMs);
    }
    {
        auto r = testSinc<128>(ctx);
        printTableRow("Sinc", 128, r.settings, r.depthConsumed, r.log2_L_inf, r.timeMs);
    }
    {
        auto r = testSinc<256>(ctx);
        printTableRow("Sinc", 256, r.settings, r.depthConsumed, r.log2_L_inf, r.timeMs);
    }
    {
        auto r = testSinc<512>(ctx);
        printTableRow("Sinc", 512, r.settings, r.depthConsumed, r.log2_L_inf, r.timeMs);
    }
    {
        auto r = testSinc<1024>(ctx);
        printTableRow("Sinc", 1024, r.settings, r.depthConsumed, r.log2_L_inf, r.timeMs);
    }
#else
    std::cout << "\n--- Sinc ---\n";
    std::cout << "  [Coefficients not generated - build with generate_coeffs_target]\n";
#endif

    std::cout << "\n" << std::string(100, '=') << std::endl;
    std::cout << "Notes:\n";
    std::cout << "  - Error = ||p - f||_inf where p is decrypted result\n";
    std::cout << "  - Depth is measured as (level_before - level_after)\n";
    std::cout << "  - epsilon = 1/(2N) for indicator functions\n";
    std::cout << std::string(100, '=') << std::endl;

    return 0;
}
