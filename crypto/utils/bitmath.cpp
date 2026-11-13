/*  Copyright (c) 2020-2026 Bitmask developers
 *  Distributed under the GNU General Public License v2.0,
 *  see the accompanying file COPYING or
 *  https://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 */


/*
 *  BitMath Enables mathematical operations
 *  to be performed on the BigNum structure
 */

#include "bitmath.h"
#include <iostream>

using namespace std;

BigNum pow_mod(const BigNum& base_in, const BigNum& exp, const BigNum& mod)
{
    vector<uint32_t> r { 1 };
    BigNum result(r);
    BigNum base = base_in % mod;

    unsigned long long total_bits = exp.limbs.size() * 32;

    for (unsigned long long i = 0; i < total_bits; i++)
    {
        if (exp.getBit(i) == 1)
            result = (result * base) % mod;
        base = (base * base) % mod;
    }

    return result;
}

bool BitMath::miller_rabin_round(BigNum& n, BigNum& a)
{
    vector<uint32_t> _one { 1 };
    BigNum one( _one );

    BigNum n_minus_1 = n - one;
    BigNum d = n_minus_1;

    int r = 0;

    while (d.getBit(0) == 0)
    {
        d = d.shiftRight1();
        r++;       
    }

    BigNum x_round = pow_mod(a, d, n);

    if (x_round == one || x_round == n_minus_1) return true;

    for (int i = 0; i < r - 1; i++)
    {
        x_round = (x_round * x_round) % n;
        if (x_round == n_minus_1) return true;
    }

    return false;
}

bool BitMath::is_probably_prime(BigNum& n, int rounds)
{
    vector<uint32_t> _one{1};
    BigNum one(_one);

    vector<uint32_t> _two{2};
    BigNum two(_two);

    vector<uint32_t> _three{3};
    BigNum three(_three);

    if (n == one)         return false;
    if (n == two)         return true;
    if (n.getBit(0) == 0) return false;

    BigNum range = n - three;
    size_t bit_len = n.limbs.size() * 32;

    for (int i = 0; i < rounds; i++)
    {
        BigNum a = BigNum::generate_random(bit_len) % range + two;

        if (!miller_rabin_round(n, a)) return false;
    }

    return true;
}

BigNum BitMath::mod_inverse(const BigNum& a, const BigNum& m)
{
    std::vector<uint32_t> one_v  { 1 };
    std::vector<uint32_t> zero_v { 0 };
    BigNum one(one_v);
    BigNum zero(zero_v);

    BigNum old_r = a % m;
    BigNum r = m;
    BigNum old_s = one;
    BigNum s = zero;

    while (!(r == zero))
    {
        BigNum q   = old_r / r;
        BigNum rem = old_r % r;

        old_r = r;
        r = rem;

        BigNum qs = (q * s) % m;
        BigNum new_s = (old_s >= qs) ? (old_s - qs) : (old_s + m) - qs;

        old_s = s;
        s = new_s;
    }

    if (!(old_r == one))
        throw std::runtime_error("mod_inverse: gcd != 1, inverse doesn't exist");

    return old_s % m;
}