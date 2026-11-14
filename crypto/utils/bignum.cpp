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

#include <algorithm>
#include <iostream>
#include <utility>
#include <iomanip>

#include "bitmath.h"
#include "bignum.h"

using namespace std;

BigNum BigNum::operator+(const BigNum& other) const
{
    std::vector<uint32_t> result;
    size_t n = (std::max)(limbs.size(), other.limbs.size());
    result.reserve(n + 1);
    uint64_t crr = 0;
    uint64_t sum = 0;

    for(int j = 0; j < n; j++) {
        uint64_t a = (j < limbs.size()) ? limbs[j] : 0;
        uint64_t b = (j < other.limbs.size()) ? other.limbs[j] : 0;

        uint64_t sum = a + b + crr;
        result.push_back((uint32_t)sum);

        crr = sum >> 32;
    }

    if (crr) {
        result.push_back((uint32_t)crr);
    }

    return BigNum(result);
}

BigNum BigNum::operator-(const BigNum& other) const
{
    if (!(*this >= other)) throw std::runtime_error("(*this >= other) == 0; Error in the BigNum module");
    
    std::vector<uint32_t> result;
    int64_t borrow = 0;

    for (size_t j = 0; j < this->limbs.size(); j++)
    {
        int64_t a = (int64_t)this->limbs[j];
        int64_t b = (j < other.limbs.size()) ? other.limbs[j] : 0;
        int64_t diff = a - b - borrow;

        if (diff < 0) {
            diff += (int64_t)1 << 32;
            borrow = 1;
        }
        else {
            borrow = 0;
        }

        result.push_back((uint32_t)diff);
    }

    BigNum r_obj = BigNum(result); r_obj.trim();
    return r_obj;
}

BigNum BigNum::operator*(const BigNum& other) const {
    std::vector<uint32_t> result(limbs.size() + other.limbs.size(), 0);

    for (size_t i = 0; i < limbs.size(); i++) {
        uint64_t carry = 0;
        for (size_t j = 0; j < other.limbs.size(); j++) {
            uint64_t cur = (uint64_t)limbs[i] * other.limbs[j]
                         + result[i + j]
                         + carry;

            result[i + j] = (uint32_t)cur;
            carry = cur >> 32;
        }
        size_t k = i + other.limbs.size();
        while (carry) {
            uint64_t cur = (uint64_t)result[k] + carry;
            result[k] = (uint32_t)cur;
            carry = cur >> 32;
            k++;
        }
    }
    
    BigNum r_obj = BigNum(result);
    r_obj.trim();
    return r_obj;
}

bool BigNum::operator>=(const BigNum& other) const
{
    if(this->limbs.size() == other.limbs.size())
    {
        for(int i = this->limbs.size() - 1; i >= 0; i--)
        {
            if (this->limbs[i] == other.limbs[i]) continue;
            if (this->limbs[i] >  other.limbs[i]) return true;
            if (this->limbs[i] <  other.limbs[i]) return false;
        }

        return true;
    }

    return this->limbs.size() >= other.limbs.size();
}

std::pair<BigNum, BigNum> BigNum::divmod(const BigNum& other) const
{
    std::vector<uint32_t> _zero{0};
    std::vector<uint32_t> _one{1};
    BigNum zero(_zero);
    BigNum one(_one);

    if (other == zero)
        throw std::runtime_error("BigNum::divmod: division by zero");

    BigNum remainder(_zero);
    BigNum quotient(_zero);

    size_t total_bits = limbs.size() * 32;

    for (size_t i = total_bits; i-- > 0; )
    {
        remainder = remainder.shiftLeft1();
        quotient  = quotient.shiftLeft1();

        if (this->getBit(i))
            remainder = remainder + one;

        if (remainder >= other)
        {
            remainder = remainder - other;
            quotient  = quotient + one;
        }
    }

    remainder.trim();
    quotient.trim();

    return { quotient, remainder };
}

BigNum BigNum::operator/(const BigNum& other) const
{
    return this->divmod(other).first;
}

BigNum BigNum::operator%(const BigNum& other) const
{
    return this->divmod(other).second;
}

std::ostream& operator<<(std::ostream& os, const BigNum& obj) {
    const std::ios_base::fmtflags saved_flags = os.flags();
    const char saved_fill = os.fill();

    if (obj.limbs.empty()) {
        os << '0';
    } else {
        os << std::hex;
        bool first = true;
        for (auto it = obj.limbs.rbegin(); it != obj.limbs.rend(); ++it) {
            if (first) {
                os << *it;
                first = false;
            } else {
                os << std::setw(8) << std::setfill('0') << *it;
            }
        }
    }

    os.flags(saved_flags);
    os.fill(saved_fill);
    return os;
}

BigNum BigNum::shiftLeft1() const {
    std::vector<uint32_t> result(limbs.size());
    uint32_t carry = 0;
    for (size_t i = 0; i < limbs.size(); i++) {
        uint32_t newCarry = limbs[i] >> 31;
        result[i] = (limbs[i] << 1) | carry;
        carry = newCarry;
    }
    if (carry)
        result.push_back(carry);
    return BigNum(result);
}

BigNum BigNum::shiftRight1() const {
    std::vector<uint32_t> result(limbs.size());
    uint32_t carry = 0;
    for (int i = limbs.size() - 1; i >= 0; i--) {
        uint32_t newCarry = limbs[i] & 1;
        result[i] = (limbs[i] >> 1) | (carry << 31);
        carry = newCarry;
    }
    BigNum r = BigNum(result);
    r.trim();
    return r;
}

int BigNum::getBit(size_t bitIndex) const {
    size_t limbIndex = bitIndex / 32;
    size_t bitInLimb = bitIndex % 32;
    if (limbIndex >= limbs.size())
        return 0;
    return (limbs[limbIndex] >> bitInLimb) & 1;
}

bool BigNum::operator==(const BigNum& other) const
{
    if (this->limbs.size() != other.limbs.size()) return false;

    for(int i = 0; i < this->limbs.size(); i++)
    {
        if (this->limbs[i] != other.limbs[i]) return false;
    }

    return true;
}

static uint32_t mod_small(const BigNum& x, uint32_t p) {
    uint64_t r = 0;
    for (size_t i = x.limbs.size(); i-- > 0; ) {
        r = ((r << 32) | x.limbs[i]) % p;
    }
    return (uint32_t)r;
}

static bool passes_small_primes(const BigNum& x) {
    static const uint32_t small_primes[] = {3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47};
    for (uint32_t p : small_primes) {
        if (mod_small(x, p) == 0) return false;
    }
    return true;
}

BigNum BigNum::get_prime_number(size_t bit_size)
{
    BigNum candidate = BigNum::generate_random(bit_size);
    BitMath b_math;

    while (true) {
        if (passes_small_primes(candidate) && b_math.is_probably_prime(candidate, 8))
            break;
        candidate = BigNum::generate_random(bit_size);
    }

    return candidate;
}

vector<BigNum> BigNum::get_prime_numbers(size_t bit_size)
{
    BigNum n1 = get_prime_number(bit_size);
    BigNum n2;

    do {
        n2 = get_prime_number(bit_size);
    } while (n1 == n2);

    return {n1, n2};
}

vector<BigNum> BigNum::get_prime_numbers(size_t bit_size, size_t count)
{
    vector<uint32_t> gen { 0 };
    BigNum gen_x (gen);

    vector<BigNum> res;
    res.reserve(count);

    for (size_t i = 0; i < count; i++)
    {
        BigNum candidate;
        do {
            candidate = gen_x.get_prime_number(bit_size);
        } while (std::find(res.begin(), res.end(), candidate) != res.end());

        res.push_back(candidate);
    }

    return res;
}

void BigNum::trim() {
    while(this->limbs.size() > 1 && this->limbs.back() == 0) { this->limbs.pop_back(); }
}
