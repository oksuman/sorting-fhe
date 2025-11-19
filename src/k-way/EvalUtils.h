#ifndef EVALUTILS_H_
#define EVALUTILS_H_

#include "ciphertext-fwd.h"
#include "encryption.h"
#include "openfhe.h"
#include "sign.h"
#include <memory>
#include <string>
#include <vector>

using namespace lbcrypto;

namespace kwaySort {

std::vector<int> binary(int n);

class EvalUtils {
  public:
    EvalUtils() = default;
    EvalUtils(CryptoContext<DCRTPoly> cc) : m_cc(cc) {}
    EvalUtils(CryptoContext<DCRTPoly> cc, std::shared_ptr<Encryption> enc,
              const PublicKey<DCRTPoly> &publicKey,
              const PrivateKey<DCRTPoly> &privateKey)
        : m_cc(cc), m_publicKey(publicKey), m_privateKey(privateKey),
          m_enc(enc) {}

    // Continuously adds cipher to reach the target multiplication
    void multByInt(Ciphertext<DCRTPoly> &ctxt, long coeff,
                   Ciphertext<DCRTPoly> &ctxt_out);

    // Wrappers which do not have effect on imaginary since OpenFHE has no
    // support for it
    void multAndKillImage(Ciphertext<DCRTPoly> &ctxt1,
                          Ciphertext<DCRTPoly> &ctxt2,
                          Ciphertext<DCRTPoly> &ctxt_out);

    void squareAndKillImage(Ciphertext<DCRTPoly> &ctxt1,
                            Ciphertext<DCRTPoly> &ctxt_out);

    // Level management and bootstrapping
    void checkLevelAndBoot(Ciphertext<DCRTPoly> &ctxt, int level, int multDepth,
                           bool verbose = true);

    void checkLevelAndBoot2(Ciphertext<DCRTPoly> &ctxt,
                            Ciphertext<DCRTPoly> &ctxt2, long depth,
                            long po2bit, bool verbose = true);

    // Wrappers for ciphertext negation and masking
    void flipCtxt(Ciphertext<DCRTPoly> &ctxt);
    void flipCtxt(Ciphertext<DCRTPoly> &ctxt, Plaintext &mask);

    // General odd polynomial evaluation for degree 7 or 9
    void evalPoly(Ciphertext<DCRTPoly> &ctxt, const std::vector<long> &coeff,
                  long logDivByPo2, Ciphertext<DCRTPoly> &ctxt_out);

    // f and g function for iterative sign approximation
    void evalF(Ciphertext<DCRTPoly> &ctxt, Ciphertext<DCRTPoly> &ctxt_out);

    void evalG(Ciphertext<DCRTPoly> &ctxt, Ciphertext<DCRTPoly> &ctxt_out);

    void approxComp(Ciphertext<DCRTPoly> &a, Ciphertext<DCRTPoly> &b,
                    int multDepth, long d_f, long d_g);

    void approxComp2(Ciphertext<DCRTPoly> &a, Ciphertext<DCRTPoly> &b,
                     Ciphertext<DCRTPoly> &c, Ciphertext<DCRTPoly> &d,
                     int multDepth, long d_f, long d_g);

    void leftRotate(Ciphertext<DCRTPoly> &ctxt, long r,
                    Ciphertext<DCRTPoly> &ctxt_out);

    void rightRotate(Ciphertext<DCRTPoly> &ctxt, long r,
                     Ciphertext<DCRTPoly> &ctxt_out);

    // Debug utilities
    void debugWithSk(Ciphertext<DCRTPoly> &ctxt, long length,
                     const std::string &str);

    // Setters for keys if needed after construction
    void setPrivateKey(const PrivateKey<DCRTPoly> &privateKey) {
        m_privateKey = privateKey;
    }

    void setPublicKey(const PublicKey<DCRTPoly> &publicKey) {
        m_publicKey = publicKey;
    }

  protected:
    CryptoContext<DCRTPoly> m_cc;
    PublicKey<DCRTPoly> m_publicKey;
    PrivateKey<DCRTPoly> m_privateKey;
    std::shared_ptr<Encryption> m_enc;
};
} // namespace kwaySort

#endif
