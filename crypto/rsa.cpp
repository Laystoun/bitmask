#include "bitmath.h"
#include "rsa.h"

#define RSA_EX 0x10001

using namespace std;

#include <chrono>

RSA_Pair RSA_Base::init()
{
    using clock = std::chrono::steady_clock;
    auto ms = [](clock::time_point a, clock::time_point b) {
        return std::chrono::duration_cast<std::chrono::milliseconds>(b - a).count();
    };

    BitMath bmath;
    vector<uint32_t> _zero{0}, _one{1}, _exp{RSA_EX};
    BigNum zero(_zero), one(_one), e(_exp);

    BigNum gen(_zero);
    BigNum n, eiler, d;

    for (;;) {
        auto t0 = clock::now();
        vector<BigNum> p = gen.get_prime_numbers(bit_size / 2);
        auto t1 = clock::now();
        std::cerr << "primes: " << ms(t0, t1) << " ms\n";

        n     = p[0] * p[1];
        eiler = (p[0] - one) * (p[1] - one);

        auto t2 = clock::now();
        try {
            d = bmath.mod_inverse(e, eiler);
            auto t3 = clock::now();
            std::cerr << "mod_inverse: " << ms(t2, t3) << " ms\n";
            break;
        } catch (const std::runtime_error&) {
            std::cerr << "mod_inverse failed, retry\n";
        }
    }

    return RSA_Pair(d, n, e);
}

BigNum rsa_encrypt(const BigNum& m, const BigNum& e, const BigNum& n)
{
    BitMath bm;
    return bm.pow_mod(m, e, n);
}

BigNum rsa_decrypt(const BigNum& c, const BigNum& d, const BigNum& n)
{
    BitMath bm;
    return bm.pow_mod(c, d, n);
}

int main()
{
    RSA_Base rsa {4096};

    
    std::cout << "private key: " << rsa.keys.priv_key << "\n\n";
    std::cout << "public key: " << rsa.keys.pub_key << "\n";
    
}