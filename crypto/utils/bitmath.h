/*  Copyright (c) 2020-2026 Bitmask developers
 *  Distributed under the GNU General Public License v2.0,
 *  see the accompanying file COPYING or
 *  https://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 */

#pragma once

#include <concepts>

#include "bignum.h"

struct BitMath
{
    BigNum pow_mod(const BigNum& base, const BigNum& exp,const BigNum& mod);
    BigNum mod_inverse(const BigNum& a, const BigNum& b);
    bool is_probably_prime(BigNum& n, int rounds);
    bool miller_rabin_round(BigNum& n, BigNum& a);
};