/*  Copyright (c) 2020-2026 Bitmask developers
 *  Distributed under the GNU General Public License v2.0,
 *  see the accompanying file COPYING or
 *  https://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 */



/* 
 * The BigNum struct enable operations to be performed on large numbers
 * Can be used for algorithms such as:
 * RSA-2048:3072:4096:..., ECDSA, ECDH
 */

#pragma once

#include <sodium.h>
#include <cstddef>
#include <cstdint>
#include <vector>
#include <utility>

#ifdef _WIN32
    #include <windows.h>
#endif

struct BigNum {
    std::vector<uint32_t> limbs;

    BigNum() = default;

    BigNum(const std::vector<uint32_t>& v) : limbs(v)
    {

    }

    ~BigNum()
    {

    }

    BigNum operator+(const BigNum& other) const;
    BigNum operator-(const BigNum& other) const;
    BigNum operator*(const BigNum& other) const;
    BigNum operator/(const BigNum& other) const;
    BigNum operator%(const BigNum& other) const;

    bool operator>=(const BigNum& other) const;
    bool operator==(const BigNum& other) const;

    BigNum get_prime_number(size_t bit_size);
    std::vector<BigNum> get_prime_numbers(size_t bit_size);
    static std::vector<BigNum> get_prime_numbers(size_t bit_size, size_t count);
    std::pair<BigNum, BigNum> divmod(const BigNum& other) const;

    BigNum shiftLeft1() const;
    BigNum shiftRight1() const;
    int getBit(size_t bitIndex) const;
    void trim();

    static BigNum generate_random(size_t bit_size)
    {
        size_t limbs_count = (bit_size + 31) / 32;
        std::vector<uint32_t> v(limbs_count, 0);

        randombytes_buf(v.data(), v.size() * sizeof(uint32_t));

        size_t extra_bits = limbs_count * 32 - bit_size;
        if (extra_bits > 0)
            v.back() &= (0xFFFFFFFFu >> extra_bits);

        size_t top_bit_in_limb = (bit_size - 1) % 32;
        v.back() |= (1u << top_bit_in_limb);

        if (top_bit_in_limb > 0) {
            v.back() |= (1u << (top_bit_in_limb - 1));
        } else if (v.size() > 1) {
            v[v.size() - 2] |= 0x80000000u;
        }

        v[0] |= 1u;

        return BigNum(v);
    }
};