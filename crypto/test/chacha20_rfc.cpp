#include <iostream>
#include <immintrin.h>

#include "../chacha20.h"
#include "chacha20_rfc.h"

bool ChaCha20RFC::quarter_round_vector() {
    ChaCha20 chacha20;

    __m256i a = _mm256_set1_epi32(0x11111111);
    __m256i b = _mm256_set1_epi32(0x01020304);
    __m256i c = _mm256_set1_epi32(0x9b8d6f43);
    __m256i d = _mm256_set1_epi32(0x01234567);

    chacha20.quarter_round_avx2(a, b, c, d);

    const uint32_t expected_a = 0xea2a92f4;
    const uint32_t expected_b = 0xcb1cf8ce;
    const uint32_t expected_c = 0x4581472e;
    const uint32_t expected_d = 0x5881c4bb;

    auto all_lanes_equal = [](__m256i reg, uint32_t expected) -> bool {
        uint32_t lanes[8];
        _mm256_storeu_si256((__m256i*)lanes, reg);
        for (int i = 0; i < 8; i++) {
            if (lanes[i] != expected) {
                std::cout << "  lane " << i << " mismatch: got 0x" << std::hex << lanes[i]
                          << " expected 0x" << expected << std::dec << "\n";
                return false;
            } else {
                std::cout << lanes[i] << " == " << expected << " True" << "\n";
            }
        }
        return true;
    };

    bool ok = true;
    ok &= all_lanes_equal(a, expected_a);
    ok &= all_lanes_equal(b, expected_b);
    ok &= all_lanes_equal(c, expected_c);
    ok &= all_lanes_equal(d, expected_d);

    return ok;
}

void ChaCha20RFC::run() {
    bool quarter_round_vec = quarter_round_vector();

    if (quarter_round_vec)
    {
        std::cout << "Quarter Round: Valid" << "\n"; 
    } else {
        std::cout << "Quarter Round: Not valid" << "\n";
    }
}