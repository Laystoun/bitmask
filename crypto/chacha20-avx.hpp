#ifndef CHACHA_20
#define CHACHA_20

#include <cstdint>
#include <array>
#include <immintrin.h>

class ChaCha20AVX {
private:
    __m256i consts_avx2[4];
    __m256i nonce_avx2[3];
    __m256i key_avx2[8];

public:
    std::array<uint32_t, 16> state;

    void init(uint8_t key[32], uint8_t nonce[12]);
    
    __m256i rot32l(__m256i x, int n);
    uint32_t load32le(uint8_t *key);
    void quarter_round_avx2(__m256i& a, __m256i& b, __m256i& c, __m256i& d);
    void quarter_core_avx2(uint32_t* output);
    void crypto(uint8_t* input, int len);
};

#endif