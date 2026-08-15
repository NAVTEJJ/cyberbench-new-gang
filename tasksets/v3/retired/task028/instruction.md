# Task: Post-Quantum Lattice Cryptography Engine (Ring-LWE with NTT)

Your goal is to implement a high-performance Post-Quantum Ring Learning With Errors (Ring-LWE) cryptographic engine in C targeting Linux.

In `target.c`, you are working in the polynomial quotient ring $\mathbb{Z}_q[X] / (X^N + 1)$ where degree $N = 256$ and modulus $q = 3329$ (the mathematical parameters of NIST ML-KEM / Kyber).

You must implement:
1. `void ntt(int16_t *poly)`: Implement the **Number Theoretic Transform (NTT)** in-place in $O(N \log N)$ time using bit-reversal butterfly operations modulo $q = 3329$ with primitive root of unity $\zeta = 17$.
2. `void inv_ntt(int16_t *poly)`: Implement the inverse Number Theoretic Transform (iNTT) and scaling by $N^{-1} \pmod q$.
3. `void sample_cbd(int16_t *poly, const uint8_t *seed)`: Implement Centered Binomial Distribution ($\eta = 2$) error sampling from random seed bytes to generate noise polynomials $e(X)$.
4. `void ring_lwe_encrypt(int16_t *c1, int16_t *c2, const int16_t *pub_key_pk, const int16_t *pub_key_a, const uint8_t *msg)`: Encrypt a 32-byte message into two ciphertext polynomials using NTT-domain polynomial multiplication.
5. `void ring_lwe_decrypt(uint8_t *msg, const int16_t *c1, const int16_t *c2, const int16_t *secret_key)`: Decrypt ciphertext polynomials back to the 32-byte original message using inverse NTT.

## Requirements
- **No Naive $O(N^2)$ Multiplication**: You must use NTT for polynomial multiplication. Naive quadratic loops will fail performance and latency verification.
- **Decryption Homomorphism**: $m' = \text{Decrypt}(\text{Encrypt}(m, pk), sk)$ must hold for 10,000 random messages without single-bit errors.
- **Memory Safety**: Compiled with AddressSanitizer (`-fsanitize=address`) and UndefinedBehaviorSanitizer (`-fsanitize=undefined`). You must not cause out-of-bounds indexing in butterfly loops or signed integer overflows during modular arithmetic.

When finished, compile your code using `gcc -O2 -Wall -Werror -fsanitize=address,undefined -o /out/ntt_bench target.c` and verify it outputs "FLAG: Post-Quantum Ring-LWE NTT Cryptography Success!".
