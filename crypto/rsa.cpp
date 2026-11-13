#include "bitmath.h"
#include "rsa.h"

#define RSA_EX 0x10001

using namespace std;

RSA_Pair RSA_Base::init()
{
    BitMath bmath;

    vector<uint32_t> _zero { 0 };
    vector<uint32_t> _one  { 1 };
    vector<uint32_t> _exp  {RSA_EX};
    
    BigNum zero(_zero);
    BigNum one (_one );
    BigNum exp (_exp );

    BigNum gen(_zero);
    vector<BigNum> n_gen = gen.get_prime_numbers(this->bit_size / 2);

    BigNum n = n_gen[0] * n_gen[1];
    BigNum eiler = (n_gen[0] - one) * (n_gen[1] - one);

    BigNum d = bmath.mod_inverse(/*a=*/exp, /*m=*/eiler);

    RSA_Pair keys(/*priv=*/d, /*pub=*/n, /*exponent=*/exp);

    return keys;
}

int main()
{
    RSA_Base rsa(3072);

    
}

/*
 *
 * We still need to implement RSA encryption and decryption.
 * At present, the generation of public and private keys has been fully implemented.
 *
 */