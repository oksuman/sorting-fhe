/*
 * LLKN22 Utilities for Precomputed Chebyshev Polynomials
 *
 * Implements sign function and indicator using composite Chebyshev polynomials
 * with precomputed coefficients (LLKN22 method).
 *
 * Reference: Lee, Lee, Kim, No (LLKN22)
 */
#pragma once

#include "openfhe.h"
#include "generated_llkn22_coeffs.h"
#include <string>
#include <vector>

using namespace lbcrypto;

namespace llkn22 {

// ============================================================================
// Evaluate Sign Function with Precomputed Coefficients
// Evaluates sign(x) using composite Chebyshev polynomials
// Output range: [-1, 1]
// ============================================================================
inline Ciphertext<DCRTPoly> EvalSign(
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

// ============================================================================
// LLKN22 Indicator Function
// Output: 1 if |x| < epsilon, 0 otherwise
//
// Uses: comp(x, -eps) * (1 - comp(x, eps))
// where comp(x, a) = 1 if x > a, 0 otherwise
//
// Since sign outputs in [-1, 1], we transform to [0, 1]:
//   comp = (sign + 1) / 2
// ============================================================================
inline Ciphertext<DCRTPoly> indicatorAdv(
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
    c1 = EvalSign(cc, c1, poly);
    c2 = EvalSign(cc, c2, poly);

    // Transform from [-1, 1] to [0, 1]: comp = (sign + 1) / 2
    c1 = cc->EvalAdd(c1, 1.0);
    c1 = cc->EvalMult(c1, 0.5);
    cc->ModReduceInPlace(c1);

    c2 = cc->EvalAdd(c2, 1.0);
    c2 = cc->EvalMult(c2, 0.5);
    cc->ModReduceInPlace(c2);

    // indicator = comp(x,-eps) * (1 - comp(x,eps))
    auto oneMinusC2 = cc->EvalSub(1.0, c2);
    auto result = cc->EvalMult(c1, oneMinusC2);
    cc->ModReduceInPlace(result);

    return result;
}

// Templated version for compile-time N selection (Depth-optimized)
template<int N>
inline Ciphertext<DCRTPoly> indicatorAdvDepth(
    const CryptoContext<DCRTPoly>& cc,
    const Ciphertext<DCRTPoly>& c) {
    auto poly = getDepthPoly<N>();
    return indicatorAdv(cc, c, static_cast<double>(N), poly);
}

// Templated version for compile-time N selection (Mult-optimized)
template<int N>
inline Ciphertext<DCRTPoly> indicatorAdvMult(
    const CryptoContext<DCRTPoly>& cc,
    const Ciphertext<DCRTPoly>& c) {
    auto poly = getMultPoly<N>();
    return indicatorAdv(cc, c, static_cast<double>(N), poly);
}

} // namespace llkn22
