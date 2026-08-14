#include "../crypto/kyznechik.h"
#include "../network/core.h"
#include "../crypto/utils/crypto_io.h"
#include "../crypto/utils/key_utils.h"
#include "shell.h"

void crypto_cli(CryptoEntry& crypto_entry) {
    Kyznechik kyz;
    encrypt_something(kyz, crypto_entry);
}

void network_cli(NetworkEntry& network_entry) {
    if (network_entry.network_protocol == NetworkProtocolListen::DNS)
    {
        NetworkCore core(network_entry);
    }
}