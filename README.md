# sorting-fhe

Blind sorting using the CKKS scheme.

## Overview

This project implements sorting algorithms for real numbers encrypted under the CKKS homomorphic encryption scheme using the OpenFHE library. The core implementation is based on the following paper:

> [Optimized Rank Sort for Encrypted Real Numbers](https://eprint.iacr.org/2025/1170.pdf)

In addition, the repository includes implementations sorting methods from:

- **k-way sorting**  
  [HKC+21] S. Hong, S. Kim, J. Choi, Y. Lee, and J. H. Cheon, *Efficient Sorting of Homomorphic Encrypted Data With $k$-Way Sorting Network*, IEEE Transactions on Information Forensics and Security, vol. 16, pp. 4389–4404, 2021.

- **MEHP24**  
  [MEHP24] F. Mazzone, M. H. Everts, F. Hahn, and A. Peter, *Efficient Ranking, Order Statistics, and Sorting under CKKS*, to appear in USENIX Security 2025.  
  This implementation is based on their OpenFHE-based implementation: [https://github.com/FedericoMazzone/openfhe-statistics](https://github.com/FedericoMazzone/openfhe-statistics)

## Requirements

- C++ (g++ ≥ 9.4.0)
- CMake ≥ 3.5
- Git
- OpenFHE library
- OpenMP

On Ubuntu most of the required packages can be installed with:
```bash
sudo apt update && sudo apt install -y clang libomp-dev cmake git build-essential
```

### Installing OpenFHE

To install the OpenFHE library, refer to:

- Source code: [https://github.com/openfheorg/openfhe-development](https://github.com/openfheorg/openfhe-development)  
- Documentation: [https://openfhe-development.readthedocs.io](https://openfhe-development.readthedocs.io)

> 📦 This project includes Google Benchmark and GoogleTest as submodules.

## Installation

```bash
git clone --recursive https://github.com/oksuman/sorting-fhe.git
cd sorting-fhe
mkdir build && cd build
cmake -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_C_COMPILER=clang ..
make -j
```

## Running Tests

After building:

```bash
./DirectSortTest              # Run a unit test
```

## Benchmarking & Experiments

To run experimental comparisons among sorting algorithms:

```bash
cd comparison
bash run_experiments.sh
```

This script evaluates performance using internally generated arrays of distinct real numbers with uniform gaps.

## Project Structure

```
sorting-fhe/
├── src/                   # Sorting algorithm implementations (rank sort, k-way, MEHP24)
├── tests/                 # Unit tests for all methods
├── benchmarks/            # Performance benchmarks
├── comparison/            # Scripts and result logs for comparative experiments
├── utils/                 # Helper code (e.g., Chebyshev coefficients)
├── scripts/               # Python scripts for sorting visualization
├── third_party/           # Google Benchmark and GoogleTest
```

## License

This project is licensed under the [MIT License](./LICENSE).

## References

- [HKC+21] S. Hong, S. Kim, J. Choi, Y. Lee, and J. H. Cheon, *Efficient Sorting of Homomorphic Encrypted Data With $k$-Way Sorting Network*, IEEE Trans. Inf. Forensics Secur., vol. 16, pp. 4389–4404, 2021.

- [MEHP24] F. Mazzone, M. H. Everts, F. Hahn, and A. Peter, *Efficient Ranking, Order Statistics, and Sorting under CKKS*, To appear in USENIX Security 2025.
