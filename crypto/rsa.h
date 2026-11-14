#pragma once

#include <utility>
#include <cstddef>
#include <vector>
#include <cmath>
#include <map>
#include <stdexcept>
#include <iostream>

#include "bignum.h"

struct RSA_Pair
{
    BigNum priv_key;
    BigNum  pub_key;
    BigNum exponent;

    RSA_Pair() = default;

    RSA_Pair(BigNum priv, BigNum pub, BigNum ex)
        : priv_key(priv), pub_key(pub), exponent(ex)
    {

    }
};

struct RSA_Base
{
    size_t bit_size;
    RSA_Pair keys;

    RSA_Base(size_t bit_size = 3072)
    {
        this->bit_size=bit_size;
        this->keys=this->init();
    }

    RSA_Pair init();

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& msg,
                                 const std::vector<uint8_t>& label = {});
                                 
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ct,
                                 const std::vector<uint8_t>& label = {});
};