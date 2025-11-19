#include "EvalUtils.h"
#include "lattice/hal/lat-backend.h"
#include "scheme/ckksrns/ckksrns-fhe.h"
#include "sign.h"

namespace kwaySort {

// Used for binary decomposition in rotation composition
std::vector<int> binary(int n) {
    std::vector<int> bin_vec;
    while (n > 0) {
        bin_vec.push_back(n % 2);
        n /= 2;
    }
    return bin_vec;
}

void EvalUtils::multByInt(Ciphertext<DCRTPoly> &ctxt, long coeff,
                          Ciphertext<DCRTPoly> &ctxt_out) {
    Ciphertext<DCRTPoly> ctxt_origin;
    if (coeff < 0) {
        coeff *= -1;
        ctxt_out = m_cc->EvalNegate(ctxt);
        ctxt_origin = ctxt_out;
    } else {
        ctxt_out = ctxt;
        ctxt_origin = ctxt;
    }

    std::vector<bool> bin;
    while (coeff > 0) {
        bin.push_back(coeff % 2);
        coeff /= 2;
    }

    // Binary multiplication implementation
    for (int i = bin.size() - 1; i > 0; i--) {
        ctxt_out = m_cc->EvalAdd(ctxt_out, ctxt_out);
        if (bin[i - 1]) {
            ctxt_out = m_cc->EvalAdd(ctxt_out, ctxt_origin);
        }
    }
}

void EvalUtils::multAndKillImage(Ciphertext<DCRTPoly> &ctxt1,
                                 Ciphertext<DCRTPoly> &ctxt2,
                                 Ciphertext<DCRTPoly> &ctxt_out) {
    // Imaginary part is not used in OpenFHE
    ctxt_out = m_cc->EvalMult(ctxt1, ctxt2);
}

void EvalUtils::squareAndKillImage(Ciphertext<DCRTPoly> &ctxt1,
                                   Ciphertext<DCRTPoly> &ctxt_out) {
    ctxt_out = m_cc->EvalSquare(ctxt1);
}

void EvalUtils::checkLevelAndBoot(Ciphertext<DCRTPoly> &ctxt, int level,
                                  int multDepth, bool verbose) {
    auto currentLevel = ctxt->GetLevel();

    // Bootstrap if level is too high
    // Required level is added by 1 since it is not possible to bootstrap when
    // ctxt level = depth
    if (static_cast<int>(multDepth - currentLevel) < level + 1) {
        if (verbose) {
            std::cout << "Starting bootstrap at level " << currentLevel
                      << " (MultDepth : " << multDepth
                      << ", Required level: " << level << ")" << std::endl;
            debugWithSk(ctxt, 5, "before boot");
        }

        // Perform bootstrapping
        // std::cout << "Bootstrapping required" << std::endl;
        // std::cout << "Level befor bootstrapping: " << ctxt->GetLevel()
        //           << std::endl;
        ctxt = m_cc->EvalBootstrap(ctxt);
        // std::cout << "Level after bootstrapping: " << ctxt->GetLevel()
        //           << std::endl;

        if (verbose) {
            std::cout << "Finished bootstrapping at level " << ctxt->GetLevel()
                      << std::endl;
            debugWithSk(ctxt, 5, "after boot");
        }
    }
}

void EvalUtils::checkLevelAndBoot2(Ciphertext<DCRTPoly> &ctxt,
                                   Ciphertext<DCRTPoly> &ctxt2, long level,
                                   long multDepth, bool verbose) {
    // Check the levels and bootstrap if needed
    checkLevelAndBoot(ctxt, level, multDepth, verbose);
    checkLevelAndBoot(ctxt2, level, multDepth, verbose);
}

void EvalUtils::flipCtxt(Ciphertext<DCRTPoly> &ctxt) {
    m_cc->EvalNegateInPlace(ctxt);
    m_cc->EvalAddInPlace(ctxt, 1.0);
}

void EvalUtils::flipCtxt(Ciphertext<DCRTPoly> &ctxt, Plaintext &mask) {
    m_cc->EvalNegateInPlace(ctxt);
    m_cc->EvalAddInPlace(ctxt, mask);
}

void EvalUtils::leftRotate(Ciphertext<DCRTPoly> &ctxt, long r,
                           Ciphertext<DCRTPoly> &ctxt_out) {
    if (r == 0) {
        ctxt_out = ctxt;
        return;
    }

    std::vector<int> r_bin = binary(r);
    long power_of_two = 1;

    ctxt_out = ctxt;
    for (size_t i = 0; i < r_bin.size(); i++) {
        long rot = r_bin[i] * power_of_two;
        if (rot > 0) {
            // std::cout << "Left Rotate: \n";
            // std::cout << rot << "\n";
            ctxt_out = m_cc->EvalRotate(ctxt_out, rot);
        }
        power_of_two *= 2;
    }
}

void EvalUtils::rightRotate(Ciphertext<DCRTPoly> &ctxt, long r,
                            Ciphertext<DCRTPoly> &ctxt_out) {
    if (r == 0) {
        ctxt_out = ctxt;
        return;
    }

    std::vector<int> r_bin = binary(r);
    long power_of_two = 1;

    ctxt_out = ctxt;
    for (size_t i = 0; i < r_bin.size(); i++) {
        long rot = r_bin[i] * power_of_two;
        if (rot > 0) {
            ctxt_out =
                m_cc->EvalRotate(ctxt_out, -rot); // Negative for right rotation
        }
        power_of_two *= 2;
    }
}

void EvalUtils::debugWithSk(Ciphertext<DCRTPoly> &ctxt, long length,
                            const std::string &str) {
    if (!str.empty()) {
        std::cout << "check " + str << std::endl;
    }

    Plaintext decrypted;
    m_cc->Decrypt(m_privateKey, ctxt, &decrypted);
    std::vector<double> result = decrypted->GetRealPackedValue();

    // Print first 20 values
    for (int i = 0; i < std::min(20L, length); i++) {
        std::cout << "(" << i << ", " << result[i] << "), ";
    }

    // Print last 20 values
    for (size_t i = std::max(static_cast<size_t>(0), result.size() - 20);
         i < result.size(); i++) {
        std::cout << "(" << i << ", " << result[i] << "), ";
    }

    // Find max value
    double max_val = 0;
    size_t index = 0;
    for (size_t i = 0; i < result.size(); i++) {
        if (std::abs(result[i]) > max_val) {
            max_val = std::abs(result[i]);
            index = i;
        }
    }
    std::cout << str << " max val = " << index << ", " << max_val << std::endl;
}

} // namespace kwaySort
