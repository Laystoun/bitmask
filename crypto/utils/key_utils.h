#ifndef KEY_UTILS_H
#define KEY_UTILS_H

#include <array>
#include <cstdint>

#include "sodium.h"

class Kyznechik;

struct SecureKey {
    uint8_t mac_key[32];

    ~SecureKey() {
        sodium_memzero(mac_key, 32);
    }
};

void print_rounded_keys(Kyznechik& kyz);
void key_finger_print(std::array<std::array<uint8_t, 16ULL>, 10ULL>& ROUND_KEY);
void derive_file_keys(const std::string& password, int iters,
                       uint8_t out_salt[16], Kyznechik& kyz, SecureKey& keys,
                       const uint8_t* in_salt = nullptr);
void derive_keys(const uint8_t master_secret[32], Kyznechik& kyz, SecureKey& out);
std::string ask_password();

#endif