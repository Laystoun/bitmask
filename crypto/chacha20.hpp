#pragma once

#include <cstdint>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>

#define ROTL32(x, n) ( \
    ((x) << (n)) | \
    ((x) >> (32 - (n))) \
)

#define QUARTER_ROUND(a, b, c, d) do { \
    (a) += (b); (d) ^= (a); (d) = ROTL32((d), 16); \
    (c) += (d); (b) ^= (c); (b) = ROTL32((b), 12); \
    (a) += (b); (d) ^= (a); (d) = ROTL32((d), 8);  \
    (c) += (d); (b) ^= (c); (b) = ROTL32((b), 7);  \
} while (0)

#define INIT_CHACHA_CONSTANTS(state) do { \
    (state)[0] = UINT32_C(0x61707865); \
    (state)[1] = UINT32_C(0x3320646e); \
    (state)[2] = UINT32_C(0x79622d32); \
    (state)[3] = UINT32_C(0x6b206574); \
} while(0)

#define LOAD32_LE(key) ( \
    ((std::uint32_t)(key)[0])       | \
    ((std::uint32_t)(key)[1] << 8)  | \
    ((std::uint32_t)(key)[2] << 16) | \
    ((std::uint32_t)(key)[3] << 24)   \
)

#define INIT_CHACHA_STATE(s, k, n, c) do { \
    INIT_CHACHA_CONSTANTS(s); \
    for (std::size_t i = 0; i < 8; i++) { \
        (s)[4 + i] = LOAD32_LE((k) + i * 4); \
    } \
    (s)[12] = c; \
    for (std::size_t i = 0; i < 3; i++) { \
        (s)[13 + i] = LOAD32_LE((n) + i * 4); \
    } \
} while(0)

#define DIAGONAL_ROUND(state) do { \
    QUARTER_ROUND((state)[0], (state)[5], (state)[10], (state)[15]); \
    QUARTER_ROUND((state)[1], (state)[6], (state)[11], (state)[12]); \
    QUARTER_ROUND((state)[2], (state)[7], (state)[8], (state)[13]);  \
    QUARTER_ROUND((state)[3], (state)[4], (state)[9], (state)[14]);  \
} while (0)

#define COLUMN_ROUND(state) do { \
    QUARTER_ROUND((state)[0], (state)[4], (state)[8],  (state)[12]);  \
    QUARTER_ROUND((state)[1], (state)[5], (state)[9],  (state)[13]);  \
    QUARTER_ROUND((state)[2], (state)[6], (state)[10], (state)[14]);  \
    QUARTER_ROUND((state)[3], (state)[7], (state)[11], (state)[15]);  \
} while(0)

#define STORE32_LE(out, w) do { \
    (out)[0] = (std::uint8_t)(w);          \
    (out)[1] = (std::uint8_t)((w) >> 8);   \
    (out)[2] = (std::uint8_t)((w) >> 16);  \
    (out)[3] = (std::uint8_t)((w) >> 24);  \
} while (0)

#define BLOCKFUNC(out, state, orig_state) do { \
    for(std::size_t i = 0; i < (4*4); i++) { \
        (orig_state)[i] = (state)[i]; \
    } \
    for (std::size_t i = 0; i < 10; i++) { \
        COLUMN_ROUND(state);   \
        DIAGONAL_ROUND(state); \
    } \
    for (std::size_t i = 0; i < (4*4); i++) { \
        (state)[i] += (orig_state)[i]; \
    } \
    for (std::size_t i = 0; i < 16; i++) { \
        STORE32_LE((out) + i * 4, state[i]); \
    } \
} while(0)

#define CHACHA20_ENCRYPT(key, nonce, counter, input, size, output) \
    CHACHA20_XOR(key, nonce, counter, input, size, output)

#define CHACHA20_DECRYPT(key, nonce, counter, input, size, output) \
    CHACHA20_XOR(key, nonce, counter, input, size, output)

#define CHACHA20_XOR(key, nonce, counter, input, size, output) do { \
    std::uint32_t _state[16]; \
    std::uint32_t _orig_state[16]; \
    std::uint32_t _counter = (counter); \
    std::uint8_t _keystream[64]; \
    std::size_t _offset = 0; \
    \
    while (_offset < (size)) { \
        INIT_CHACHA_STATE(_state, key, nonce, _counter); \
        BLOCKFUNC(_keystream, _state, _orig_state); \
        \
        std::size_t _remaining = (size) - _offset; \
        std::size_t _block_size = (_remaining < 64) ? _remaining : 64; \
        \
        for (std::size_t i = 0; i < _block_size; i++) { \
            (output)[_offset + i] = (input)[_offset + i] ^ _keystream[i]; \
        } \
        \
        _offset += _block_size; \
        \
        if (_offset < (size)) { \
            if (_counter == UINT32_MAX) { \
                throw std::overflow_error("ChaCha20 counter exhausted"); \
            } \
            _counter++; \
        } \
    } \
} while (0)

struct ChaCha20
{
public:
    void quarter_round(
        std::uint32_t& a,
        std::uint32_t& b,
        std::uint32_t& c,
        std::uint32_t& d
    ) const {
        QUARTER_ROUND(a, b, c, d);
    }

    void encrypt(
        const std::uint8_t* key,
        const std::uint8_t* nonce,
        std::uint32_t counter,
        const std::uint8_t* input,
        std::size_t size,
        std::uint8_t* output
    ) const {
        transform(key, nonce, counter, input, size, output);
    }

    void decrypt(
        const std::uint8_t* key,
        const std::uint8_t* nonce,
        std::uint32_t counter,
        const std::uint8_t* input,
        std::size_t size,
        std::uint8_t* output
    ) const {
        transform(key, nonce, counter, input, size, output);
    }

private:
    void transform(
        const std::uint8_t* key,
        const std::uint8_t* nonce,
        std::uint32_t counter,
        const std::uint8_t* input,
        std::size_t size,
        std::uint8_t* output
    ) const {

        if (key == nullptr || nonce == nullptr) {
            throw std::invalid_argument("Key or nonce is null");
        }

        if (size != 0 && (input == nullptr || output == nullptr)) {
            throw std::invalid_argument("Input or output is null");
        }

        const std::uint64_t blocks =
            size / 64 + (size % 64 != 0 ? 1 : 0);

        // How many blocks are still available from the current counter
        const std::uint64_t available_blocks =
            static_cast<std::uint64_t>(
                std::numeric_limits<std::uint32_t>::max()
            ) - counter + 1ULL;

        // Checking for overflow before processing begins
        if (blocks > available_blocks) {
            throw std::length_error("ChaCha20 counter exhausted");
        }

        CHACHA20_XOR(key, nonce, counter, input, size, output);
    }
};
