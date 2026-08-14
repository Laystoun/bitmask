/*  Copyright (c) 2020-2026 Bitmask developers
 *  Distributed under the GNU General Public License v2.0,
 *  see the accompanying file COPYING or
 *  https://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 */

//  Essential utilities for working with keys

#ifndef KEY_UTILS_H
#define KEY_UTILS_H

#include <array>
#include <cstdint>
#include "../../shell/shell.h"
#include "../kyznechik.h"

#include "sodium.h"

class Kyznechik;

struct SecureKey {
    uint8_t mac_key[32];

    ~SecureKey() {
        sodium_memzero(mac_key, 32);
    }
};

void kyz_fingerprint(Kyznechik& kyz);
void key_finger_print(std::array<std::array<uint8_t, 16ULL>, 10ULL>& ROUND_KEY);
void derive_file_keys(const std::string& password, int iters,
                       uint8_t out_salt[16], Kyznechik& kyz, SecureKey& keys,
                       const uint8_t* in_salt = nullptr);

void derive_multifile_keys(const uint8_t master_session_secret[32], 
                           uint8_t out_salt[16], Kyznechik& kyz, SecureKey& keys,
                           const uint8_t* in_salt);

void fill_session_key(
    CryptoEntry& crypto_entry,
    std::string& password,
    std::array<uint8_t, 32>& master_session_secret
);
void derive_keys(const uint8_t master_secret[32], Kyznechik& kyz, SecureKey& out);
std::string ask_password_hidden(const string& prompt = "Password: ");

#endif