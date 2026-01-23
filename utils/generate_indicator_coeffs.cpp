#include "math/chebyshev.h"
#include "openfhe.h"
#include <cmath>
#include <fstream>
#include <iostream>
#include <vector>

constexpr double COEFFICIENT_THRESHOLD = 1e-7;
constexpr double GAUSSIAN_COEFFICIENT_THRESHOLD = 1e-8;  // Higher threshold for Gaussian
constexpr int maxPolyDegree = 53011;

// Compute k for Gaussian such that e^{-k*epsilon^2} = 2^{-alpha}
double computeGaussianK(double epsilon, int alpha = 10) {
    return alpha * std::log(2.0) / (epsilon * epsilon);
}

// ============================================================================
// Ind0: f(x) = 1 if |x| < epsilon, 0 otherwise
// epsilon = 1/(2N)
// ============================================================================
template <int N> std::vector<double> generateInd0Coefficients() {
    constexpr double epsilon = 1.0 / (2.0 * N);

    auto coeffs = lbcrypto::EvalChebyshevCoefficients(
        [](double x) -> double {
            return (std::abs(x) < epsilon) ? 1.0 : 0.0;
        },
        -1.0, 1.0, maxPolyDegree);

    // Filter small coefficients and trim
    while (!coeffs.empty() && std::abs(coeffs.back()) < COEFFICIENT_THRESHOLD) {
        coeffs.pop_back();
    }

    return coeffs;
}

// ============================================================================
// Gaussian: f(x) = e^{-kx^2}
// k chosen so that f(epsilon) ~ 2^{-10}
// ============================================================================
template <int N> std::vector<double> generateGaussianCoefficients() {
    constexpr double epsilon = 1.0 / (2.0 * N);
    const double k = computeGaussianK(epsilon, 10);

    auto coeffs = lbcrypto::EvalChebyshevCoefficients(
        [k](double x) -> double {
            return std::exp(-k * x * x);
        },
        -1.0, 1.0, maxPolyDegree);

    // Gaussian is even function, so odd coefficients should be ~0
    // Filter them out
    for (size_t i = 1; i < coeffs.size(); i += 2) {
        coeffs[i] = 0.0;
    }

    // Trim trailing small coefficients (using higher threshold for Gaussian)
    while (!coeffs.empty() && std::abs(coeffs.back()) < GAUSSIAN_COEFFICIENT_THRESHOLD) {
        coeffs.pop_back();
    }

    return coeffs;
}

// ============================================================================
// Output helpers
// ============================================================================
void writeCoefficients(std::ofstream &outFile, const std::string& name,
                       int N, const std::vector<double>& coeffs) {
    outFile << "// N=" << N << ", degree=" << (coeffs.size() - 1) << "\n";
    outFile << "const std::vector<double> " << name << "_" << N << " = {\n";
    for (size_t j = 0; j < coeffs.size(); ++j) {
        outFile << "    " << std::scientific << coeffs[j];
        if (j < coeffs.size() - 1)
            outFile << ",";
        outFile << "\n";
    }
    outFile << "};\n\n";
}

template <int N>
void generateInd0(std::ofstream &outFile) {
    std::cout << "Generating Ind0 coefficients for N=" << N << "..." << std::flush;
    auto coeffs = generateInd0Coefficients<N>();
    std::cout << " degree=" << (coeffs.size() - 1) << std::endl;
    writeCoefficients(outFile, "ind0Coeffs", N, coeffs);
}

template <int N>
void generateGaussian(std::ofstream &outFile) {
    std::cout << "Generating Gaussian coefficients for N=" << N << "..." << std::flush;
    auto coeffs = generateGaussianCoefficients<N>();
    std::cout << " degree=" << (coeffs.size() - 1) << std::endl;
    writeCoefficients(outFile, "gaussianCoeffs", N, coeffs);
}

void generateInd0Selector(std::ofstream &outFile) {
    outFile << "template<int N>\n";
    outFile << "const std::vector<double>& selectInd0Coefficients() {\n";
    outFile << "    if constexpr (N == 4) {\n";
    outFile << "        return ind0Coeffs_4;\n";

    auto print_size = [&outFile](int size) {
        outFile << "    } else if constexpr (N == " << size << ") {\n";
        outFile << "        return ind0Coeffs_" << size << ";\n";
    };

    print_size(8);
    print_size(16);
    print_size(32);
    print_size(64);
    print_size(128);
    print_size(256);
    print_size(512);
    print_size(1024);

    outFile << "    } else {\n";
    outFile << "        static_assert(N >= 4 && N <= 1024, \"Unsupported N for Ind0\");\n";
    outFile << "        return ind0Coeffs_4;\n";
    outFile << "    }\n";
    outFile << "}\n\n";
}

void generateGaussianSelector(std::ofstream &outFile) {
    outFile << "template<int N>\n";
    outFile << "const std::vector<double>& selectGaussianCoefficients() {\n";
    outFile << "    if constexpr (N == 4) {\n";
    outFile << "        return gaussianCoeffs_4;\n";

    auto print_size = [&outFile](int size) {
        outFile << "    } else if constexpr (N == " << size << ") {\n";
        outFile << "        return gaussianCoeffs_" << size << ";\n";
    };

    print_size(8);
    print_size(16);
    print_size(32);
    print_size(64);
    print_size(128);
    print_size(256);
    print_size(512);
    print_size(1024);

    outFile << "    } else {\n";
    outFile << "        static_assert(N >= 4 && N <= 1024, \"Unsupported N for Gaussian\");\n";
    outFile << "        return gaussianCoeffs_4;\n";
    outFile << "    }\n";
    outFile << "}\n";
}

int main() {
    std::ofstream outFile("generated_indicator_coeffs.h");
    outFile << "// Auto-generated Chebyshev coefficients for indicator functions\n";
    outFile << "// Gaussian: f(x) = e^{-kx^2}, k = 10*ln(2)/epsilon^2\n";
    outFile << "#pragma once\n";
    outFile << "#include <vector>\n\n";

    // Generate Ind0 coefficients
    // outFile << "// ============================================================================\n";
    // outFile << "// Ind0 Coefficients\n";
    // outFile << "// ============================================================================\n\n";
    // generateInd0<4>(outFile);
    // generateInd0<8>(outFile);
    // generateInd0<16>(outFile);
    // generateInd0<32>(outFile);
    // generateInd0<64>(outFile);
    // generateInd0<128>(outFile);
    // generateInd0<256>(outFile);
    // generateInd0<512>(outFile);
    // generateInd0<1024>(outFile);

    // Generate Gaussian coefficients
    outFile << "// ============================================================================\n";
    outFile << "// Gaussian Coefficients\n";
    outFile << "// ============================================================================\n\n";
    generateGaussian<4>(outFile);
    generateGaussian<8>(outFile);
    generateGaussian<16>(outFile);
    generateGaussian<32>(outFile);
    generateGaussian<64>(outFile);
    generateGaussian<128>(outFile);
    generateGaussian<256>(outFile);
    generateGaussian<512>(outFile);
    generateGaussian<1024>(outFile);

    // Generate selector functions
    outFile << "// ============================================================================\n";
    outFile << "// Selector Functions\n";
    outFile << "// ============================================================================\n\n";
    // Ind0 removed - naive Chebyshev doesn't converge well for discontinuous functions
    // generateInd0Selector(outFile);
    generateGaussianSelector(outFile);

    outFile.close();
    std::cout << "Generated generated_indicator_coeffs.h" << std::endl;
    return 0;
}
