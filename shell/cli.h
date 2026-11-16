#include "crypto/kyznechik.h"
#include "crypto/utils/crypto_io.h"
#include "crypto/utils/key_utils.h"
#include "crypto/chacha20.hpp"
#include "crypto/chacha20-avx.hpp"

#include "shell.h"

#include <iostream>
#include <variant>

void crypto_cli(CryptoEntry& crypto_entry) {
    switch(crypto_entry.crypto_values.algorithm) {
        case CryptoAlgorithms::CHACHA20:
            crypto_entry.crypto_values.cipher.emplace<ChaCha20>();
            break;
        case CryptoAlgorithms::KYZ_CBC:
        case CryptoAlgorithms::KYZ_ECB:
            crypto_entry.crypto_values.cipher.emplace<Kyznechik>();
            break;

        default:
            break;
    }

    if (crypto_entry.crypto_flags.is_encrypt) {
        encrypt_something(crypto_entry);
    }
    if (crypto_entry.crypto_flags.is_decrypt) { 
        decrypt_something(crypto_entry);
    }
}

void network_cli(NetworkEntry& network_entry) {
    /*
    if (network_entry.network_protocol == NetworkProtocolListen::DNS)
    {
        NetworkCore core(network_entry);
    }
    */
}