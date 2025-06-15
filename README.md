# PIR-FHE
This repository implements Private Information Retrieval (PIR) protocols using Fully Homomorphic Encryption (FHE), evaluating different approaches for efficiency and scalability in encrypted database queries.

- **Four PIR-FHE implementations**:
  - Basic vectorial (position-wise multiplication) - Vectorial1.cpp
  - Optimized SIMD vectorial (parallel processing) - VectorialOptimizada.cpp
  - Matrix-based 2D approach - Matricial.cpp
  - Lagrange interpolation for continuous data (CKKS scheme) - Lagrange.cpp

### Prerequisites
- OpenFHE (v1.0+) [installation guide](https://www.openfhe.org/)
- CMake (v3.20+)
- C++17 compatible compiler
- 
### Instructions
To compile follow the instructions of https://www.openfhe.org/ , and change the name of the program you want to run to main.cpp
