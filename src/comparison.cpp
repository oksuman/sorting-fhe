#include "comparison.h"
#include "sign.h"

Ciphertext<DCRTPoly> Comparison::compare(const CryptoContext<DCRTPoly> &cc,
                                         const Ciphertext<DCRTPoly> &a,
                                         const Ciphertext<DCRTPoly> &b,
                                         SignFunc SignFunc, SignConfig &Cfg) {

    // (sgn(a-b) + 1)/2
    // Returns 1 if a > b
    //         0 if a < b
    // Step 1: Subtraction
    auto diff = cc->EvalSub(a, b);

    // Step 2: Sign function
    auto signValue = sign(diff, cc, SignFunc, Cfg);

    // Step 3: Compute comparison result
    auto comp = cc->EvalMult(cc->EvalAdd(signValue, 1), 0.5);

    return comp;
}

Ciphertext<DCRTPoly> Comparison::indicator(const CryptoContext<DCRTPoly> &cc,
                                           const Ciphertext<DCRTPoly> &x,
                                           const double c, SignFunc SignFunc,
                                           SignConfig &Cfg) {

    auto diff1 = cc->EvalAdd(x, c);
    auto diff2 = cc->EvalSub(x, c);

    auto sign1 = sign(diff1, cc, SignFunc, Cfg);
    auto sign2 = sign(diff2, cc, SignFunc, Cfg);

    auto comp1 = cc->EvalMult(cc->EvalAdd(sign1, 1.0), 0.5);
    auto comp2 = cc->EvalMult(cc->EvalAdd(sign2, 1.0), 0.5);

    auto result = cc->EvalMultAndRelinearize(comp1, cc->EvalSub(1.0, comp2));
    return result;
}
