/*  Copyright (c) 2020-2026 Bitmask developers
 *  Distributed under the GNU General Public License v2.0,
 *  see the accompanying file COPYING or
 *  https://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 */

// Basic Implementation: https://datatracker.ietf.org/doc/html/rfc7539
// ChaCha20 designed by D. Bernstein 

#include "chacha20-avx.hpp"
#include <immintrin.h>

void ChaCha20AVX::init(uint8_t key[32], uint8_t nonce[12]) {
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    for (int i = 0; i < 8; i++)
        state[i + 4] = load32le(&key[i * 4]);

    state[12] = 1;

    for (int i = 0; i < 3; i++)
        state[i + 13] = load32le(&nonce[i * 4]);

    for (int i = 0; i < 4; i++) consts_avx2[i] = _mm256_set1_epi32(state[i]);
    for (int i = 0; i < 8; i++) key_avx2[i]    = _mm256_set1_epi32(state[i + 4]);
    for (int i = 0; i < 3; i++) nonce_avx2[i]  = _mm256_set1_epi32(state[i + 13]);
}

uint32_t ChaCha20AVX::load32le(uint8_t* key) {
    return (
        key[0]       |
        key[1] << 8  |
        key[2] << 16 |
        key[3] << 24
    );
}

__m256i ChaCha20AVX::rot32l(__m256i x, int n) {
    return _mm256_or_si256(
        _mm256_slli_epi32(x, n),
        _mm256_srli_epi32(x, 32 - n)
    );
}

void ChaCha20AVX::quarter_round_avx2(__m256i& a, __m256i& b, __m256i& c, __m256i& d) {
    a = _mm256_add_epi32(a, b); d = _mm256_xor_si256(d, a); d = rot32l(d, 16);
    c = _mm256_add_epi32(c, d); b = _mm256_xor_si256(b, c); b = rot32l(b, 12);
    a = _mm256_add_epi32(a, b); d = _mm256_xor_si256(d, a); d = rot32l(d, 8);
    c = _mm256_add_epi32(c, d); b = _mm256_xor_si256(b, c); b = rot32l(b, 7);
}

void ChaCha20AVX::quarter_core_avx2(uint32_t* keyStream) {
    __m256i s0 = consts_avx2[0];
    __m256i s1 = consts_avx2[1];
    __m256i s2 = consts_avx2[2];
    __m256i s3 = consts_avx2[3];

    __m256i s4  = key_avx2[0];
    __m256i s5  = key_avx2[1];
    __m256i s6  = key_avx2[2];
    __m256i s7  = key_avx2[3];
    __m256i s8  = key_avx2[4];
    __m256i s9  = key_avx2[5];
    __m256i s10 = key_avx2[6];
    __m256i s11 = key_avx2[7];

    __m256i s12 = _mm256_setr_epi32(
        state[12] + 0, state[12] + 1, state[12] + 2, state[12] + 3,
        state[12] + 4, state[12] + 5, state[12] + 6, state[12] + 7
    );

    __m256i s13 = nonce_avx2[0];
    __m256i s14 = nonce_avx2[1];
    __m256i s15 = nonce_avx2[2];

    __m256i orig0 = s0, orig1 = s1, orig2 = s2, orig3 = s3;
    __m256i orig4 = s4, orig5 = s5, orig6 = s6, orig7 = s7;
    __m256i orig8 = s8, orig9 = s9, orig10 = s10, orig11 = s11;
    __m256i orig12 = s12, orig13 = s13, orig14 = s14, orig15 = s15;

    for (size_t r = 0; r < 10; r++)
    {
        /* LINEAR */
        quarter_round_avx2(s0, s4, s8,  s12);
        quarter_round_avx2(s1, s5, s9,  s13);
        quarter_round_avx2(s2, s6, s10, s14);
        quarter_round_avx2(s3, s7, s11, s15);

        /* DIAGONAL */
        quarter_round_avx2(s0, s5, s10, s15);
        quarter_round_avx2(s1, s6, s11, s12);
        quarter_round_avx2(s2, s7, s8,  s13);
        quarter_round_avx2(s3, s4, s9,  s14);
    }

    s0  = _mm256_add_epi32(s0, orig0  ); s1  = _mm256_add_epi32(s1, orig1  );
    s2  = _mm256_add_epi32(s2, orig2  ); s3  = _mm256_add_epi32(s3, orig3  );
    s4  = _mm256_add_epi32(s4, orig4  ); s5  = _mm256_add_epi32(s5, orig5  );
    s6  = _mm256_add_epi32(s6, orig6  ); s7  = _mm256_add_epi32(s7, orig7  );
    s8  = _mm256_add_epi32(s8, orig8  ); s9  = _mm256_add_epi32(s9, orig9  );
    s10 = _mm256_add_epi32(s10, orig10); s11 = _mm256_add_epi32(s11, orig11);
    s12 = _mm256_add_epi32(s12, orig12); s13 = _mm256_add_epi32(s13, orig13);
    s14 = _mm256_add_epi32(s14, orig14); s15 = _mm256_add_epi32(s15, orig15);

    state[12] += 8;

    auto transpose4x8 = [](__m256i& a, __m256i& b, __m256i& c, __m256i& d) {
        __m256i t0 = _mm256_unpacklo_epi32(a, b);
        __m256i t1 = _mm256_unpackhi_epi32(a, b);
        __m256i t2 = _mm256_unpacklo_epi32(c, d);
        __m256i t3 = _mm256_unpackhi_epi32(c, d);

        __m256i u0 = _mm256_unpacklo_epi64(t0, t2);
        __m256i u1 = _mm256_unpackhi_epi64(t0, t2);
        __m256i u2 = _mm256_unpacklo_epi64(t1, t3);
        __m256i u3 = _mm256_unpackhi_epi64(t1, t3);

        a = _mm256_permute2x128_si256(u0, u1, 0x20);
        b = _mm256_permute2x128_si256(u2, u3, 0x20);
        c = _mm256_permute2x128_si256(u0, u1, 0x31);
        d = _mm256_permute2x128_si256(u2, u3, 0x31);
    };

    transpose4x8(s0, s1, s2, s3    );
    transpose4x8(s4, s5, s6, s7    );
    transpose4x8(s8, s9, s10, s11  );
    transpose4x8(s12, s13, s14, s15);
    
    auto store_pair = [&](uint32_t* dst_block_lo, uint32_t* dst_block_hi,
                           __m256i a, __m256i b, __m256i c, __m256i d) {
        _mm_storeu_si128((__m128i*)(dst_block_lo + 0 ),  _mm256_castsi256_si128(a));
        _mm_storeu_si128((__m128i*)(dst_block_lo + 4 ),  _mm256_castsi256_si128(b));
        _mm_storeu_si128((__m128i*)(dst_block_lo + 8 ),  _mm256_castsi256_si128(c));
        _mm_storeu_si128((__m128i*)(dst_block_lo + 12),  _mm256_castsi256_si128(d));

        _mm_storeu_si128((__m128i*)(dst_block_hi + 0 ),  _mm256_extracti128_si256(a, 1));
        _mm_storeu_si128((__m128i*)(dst_block_hi + 4 ),  _mm256_extracti128_si256(b, 1));
        _mm_storeu_si128((__m128i*)(dst_block_hi + 8 ),  _mm256_extracti128_si256(c, 1));
        _mm_storeu_si128((__m128i*)(dst_block_hi + 12),  _mm256_extracti128_si256(d, 1));
    };

    store_pair(&keyStream[0*16],  &keyStream[1*16],  s0, s4, s8,  s12);
    store_pair(&keyStream[2*16],  &keyStream[3*16],  s1, s5, s9,  s13);
    store_pair(&keyStream[4*16],  &keyStream[5*16],  s2, s6, s10, s14);
    store_pair(&keyStream[6*16],  &keyStream[7*16],  s3, s7, s11, s15);
}

void ChaCha20AVX::crypto(uint8_t* input, int len) {
    uint32_t keyStream[128];

    int i = 0;
    for (; i + 512 <= len; i += 512) {
        quarter_core_avx2(keyStream);

        for (int x = 0; x < 16; x++) {
            __m256i key_load = _mm256_loadu_si256((__m256i*)&keyStream[x * 8]);
            __m256i data =     _mm256_loadu_si256((__m256i*)&input[i + x * 32]);
            __m256i res =      _mm256_xor_si256(key_load, data);
            _mm256_storeu_si256((__m256i*)&input[i + x * 32], res);
        }
    }

    if (i < len) {
        quarter_core_avx2(keyStream);
        uint8_t* key_b = reinterpret_cast<uint8_t*>(keyStream);
        for (int j = 0; i + j < len; j++) {
            input[i + j] ^= key_b[j];
        }
    }
}