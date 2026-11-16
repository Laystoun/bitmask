#pragma once

#include "chacha20-avx.hpp"
#include "chacha20.hpp"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <vector>

/* https://www.rfc-editor.org/info/rfc8439/ */

struct chacha20Vectors
{
    ChaCha20 cipher;

    // =====================================
    // 1. QUARTER ROUND TEST
    // RFC 8439, Section 2.1.1
    // =====================================

    bool quarterRoundTest()
    {
        std::uint32_t a = 0x11111111;
        std::uint32_t b = 0x01020304;
        std::uint32_t c = 0x9b8d6f43;
        std::uint32_t d = 0x01234567;

        cipher.quarter_round(a, b, c, d);

        return
            a == 0xea2a92f4 &&
            b == 0xcb1cf8ce &&
            c == 0x4581472e &&
            d == 0x5881c4bb;
    }


    // =====================================
    // 2. BLOCK FUNCTION TEST
    // RFC 8439, Section 2.3.2
    // =====================================

    bool blockFunctionTest()
    {
        std::uint8_t key[32] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        };

        std::uint8_t nonce[12] = {
            0x00, 0x00, 0x00, 0x09,
            0x00, 0x00, 0x00, 0x4a,
            0x00, 0x00, 0x00, 0x00
        };

        std::uint32_t state[16]{};
        std::uint32_t orig_state[16]{};

        std::uint8_t output[64]{};

        // Ожидаемый результат из RFC 8439
        const std::uint8_t expected[64] = {
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
            0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
            0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03,
            0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
            0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09,
            0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
            0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
            0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e
        };

        INIT_CHACHA_STATE(state, key, nonce, 1);
        BLOCKFUNC(output, state, orig_state);

        return std::memcmp(output, expected, 64) == 0;
    }


    // =====================================
    // 3. ENCRYPTION + DECRYPTION TEST
    // RFC 8439, Section 2.4.2
    // =====================================

    bool cipherTest()
    {
        std::uint8_t key[32] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        };

        std::uint8_t nonce[12] = {
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x4a,
            0x00, 0x00, 0x00, 0x00
        };

        const char plaintext[] =
            "Ladies and Gentlemen of the class of '99: "
            "If I could offer you only one tip for the future, "
            "sunscreen would be it.";

        constexpr std::size_t message_size = sizeof(plaintext) - 1;

        const std::uint8_t expected[114] = {
            0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80,
            0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
            0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2,
            0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
            0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab,
            0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
            0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
            0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
            0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61,
            0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
            0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06,
            0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
            0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6,
            0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
            0x87, 0x4d
        };

        std::uint8_t encrypted[message_size]{};
        std::uint8_t decrypted[message_size]{};

        cipher.encrypt(
            key,
            nonce,
            1,
            reinterpret_cast<const std::uint8_t*>(plaintext),
            message_size,
            encrypted
        );

        if (std::memcmp(encrypted, expected, message_size) != 0) {
            return false;
        }

        cipher.decrypt(
            key,
            nonce,
            1,
            encrypted,
            message_size,
            decrypted
        );

        return std::memcmp(decrypted, plaintext, message_size) == 0;
    }
};

struct chacha20AvxVectors
{
    ChaCha20AVX cipher;
    ChaCha20    base;

    // =====================================
    // 1. QUARTER ROUND TEST (AVX2)
    // RFC 8439, Section 2.1.1
    // =====================================

    bool quarterRoundAvx2Test()
    {
        __m256i a = _mm256_set1_epi32(0x11111111);
        __m256i b = _mm256_set1_epi32(0x01020304);
        __m256i c = _mm256_set1_epi32(0x9b8d6f43);
        __m256i d = _mm256_set1_epi32(0x01234567);

        cipher.quarter_round_avx2(a, b, c, d);

        alignas(32) std::uint32_t ra[8], rb[8], rc[8], rd[8];
        _mm256_store_si256(reinterpret_cast<__m256i*>(ra), a);
        _mm256_store_si256(reinterpret_cast<__m256i*>(rb), b);
        _mm256_store_si256(reinterpret_cast<__m256i*>(rc), c);
        _mm256_store_si256(reinterpret_cast<__m256i*>(rd), d);

        for (int i = 0; i < 8; ++i) {
            if (ra[i] != 0xea2a92f4 || rb[i] != 0xcb1cf8ce ||
                rc[i] != 0x4581472e || rd[i] != 0x5881c4bb)
                return false;
        }
        return true;
    }


    // =====================================
    // 2. BLOCK FUNCTION TEST
    // RFC 8439, Section 2.3.2
    // =====================================

    bool blockFunctionTest()
    {
        std::uint8_t key[32] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        };

        std::uint8_t nonce[12] = {
            0x00, 0x00, 0x00, 0x09,
            0x00, 0x00, 0x00, 0x4a,
            0x00, 0x00, 0x00, 0x00
        };

        const std::uint8_t expected[64] = {
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
            0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
            0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03,
            0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
            0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09,
            0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
            0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
            0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e
        };

        std::uint8_t output[64]{};

        cipher.init(key, nonce);
        cipher.crypto(output, 64);

        return std::memcmp(output, expected, 64) == 0;
    }


    // =====================================
    // 3. ENCRYPTION + DECRYPTION TEST
    // RFC 8439, Section 2.4.2
    // =====================================

    bool cipherTest()
    {
        std::uint8_t key[32] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        };

        std::uint8_t nonce[12] = {
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x4a,
            0x00, 0x00, 0x00, 0x00
        };

        const char plaintext[] =
            "Ladies and Gentlemen of the class of '99: "
            "If I could offer you only one tip for the future, "
            "sunscreen would be it.";

        constexpr std::size_t message_size = sizeof(plaintext) - 1;

        const std::uint8_t expected[] = {
            0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80,
            0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
            0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2,
            0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
            0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab,
            0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
            0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
            0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
            0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61,
            0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
            0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06,
            0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
            0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6,
            0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
            0x87, 0x4d
        };
        static_assert(sizeof(expected) == message_size, "vector size mismatch");

        std::uint8_t buf[message_size];
        std::memcpy(buf, plaintext, message_size);

        cipher.init(key, nonce);
        cipher.crypto(buf, static_cast<int>(message_size));

        if (std::memcmp(buf, expected, message_size) != 0)
            return false;


        cipher.init(key, nonce);
        cipher.crypto(buf, static_cast<int>(message_size));

        return std::memcmp(buf, plaintext, message_size) == 0;
    }

    bool crossCheckTest()
    {
        std::uint8_t key[32], nonce[12];
        for (int i = 0; i < 32; ++i) key[i] = std::uint8_t(i * 7 + 3);
        for (int i = 0; i < 12; ++i) nonce[i] = std::uint8_t(i * 11 + 5);

        const std::size_t lengths[] = {1, 63, 64, 65, 511, 512, 513, 1024, 1100};

        for (std::size_t len : lengths) {
            std::vector<std::uint8_t> in(len), ref(len), out(len);
            for (std::size_t i = 0; i < len; ++i) in[i] = std::uint8_t(i * 31 + 1);

            base.encrypt(key, nonce, 1, in.data(), len, ref.data());

            cipher.init(key, nonce);
            out = in;
            cipher.crypto(out.data(), static_cast<int>(len));

            if (out != ref) return false;
        }
        return true;
    }
};

void runChaCha20Tests()
{
    chacha20Vectors base;
    chacha20AvxVectors avx;

    std::ofstream log("chacha20-rfc.test", std::ios::app);

    auto report = [&](const char* name, bool ok, int& n) {
        std::printf("Log %d.. %s: %s\n", n, name, ok ? "PASS" : "FAIL");
        if (log)
            log << "Log " << n << ".. " << name << ": " << (ok ? "PASS" : "FAIL") << '\n';
        ++n;
    };

    std::printf("====== CHACHA20 - BASE =======\n");
    if (log) log << "====== CHACHA20 - BASE =======\n";
    int n = 1;
    report("quarter round", base.quarterRoundTest(), n);
    report("block function", base.blockFunctionTest(), n);
    report("cipher enc/dec", base.cipherTest(), n);

    std::printf("\n====== CHACHA20 - AVX2 ========\n");
    if (log) log << "\n====== CHACHA20 - AVX2 ========\n";
    n = 1;
    
    report("quarter round", avx.quarterRoundAvx2Test(), n);
    report("block function", avx.blockFunctionTest(), n);
    report("cipher enc/dec", avx.cipherTest(), n);
    report("cross-check vs scalar", avx.crossCheckTest(), n);

    std::printf("\n");
    if (log) log << "\n";
}