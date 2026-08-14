#include <iostream>
#include <iomanip>

#include "key_utils.h"
#include "../SHA256.h"
#include "sodium.h"

using namespace std;

void derive_keys(const uint8_t master_secret[32], Kyznechik& kyz, SecureKey& out) {
    crypto_kdf_derive_from_key(kyz.master_key, 32, 1, "KEYGEN-X", master_secret);
    crypto_kdf_derive_from_key(out.mac_key, sizeof(out.mac_key), 2, "KEYGEN-X", master_secret);
}

void print_rounded_keys(Kyznechik& kyz) {
        wcout << "MASTER KEY: ";
        for (int m_key = 0; m_key < 32; m_key++) {
        wcout << hex << setw(2) << setfill(L'0') << static_cast<int>(kyz.master_key[m_key]);
        }
        wcout << endl << endl;
    
        wcout << "Rounded keys: \n" << endl;

        for (int i = 0; i < 10; i++)
        {
            wcout << i << ": ";
            for (int j = 0; j < 16; j++)
            {
            wcout << hex << setw(2) << setfill(L'0') << static_cast<int>(kyz.ROUND_KEYS[i][j]);
            }
            wcout << endl;
        }
        wcout << endl;
}

void key_finger_print(std::array<std::array<uint8_t, 16ULL>, 10ULL>& ROUND_KEY) {
    SHA256 sha;
    const wchar_t* SHADE[] = {
        L" ",        // 0x00–0x1F
        L"░",        // 0x20–0x5F
        L"▒",        // 0x60–0x9F
        L"▓",        // 0xA0–0xDF
        L"█"         // 0xE0–0xFF
    };
    
    const size_t ROUND_KEY_SIZE = 160;
    
    uint8_t key_linear[ROUND_KEY_SIZE];
    for (int r_key = 0; r_key < 10; r_key++) {
        for (int key_v = 0; key_v < 16; key_v++) {
            key_linear[r_key * 16 + key_v] = ROUND_KEY[r_key][key_v];       
        }
    }
    
    sha.update(key_linear, 160);

    array<uint8_t, 32> key_hash = sha.digest();
    array<uint8_t, 96 + 32> expand_fingerprint;

    for (int f_hash = 0; f_hash < 32; f_hash++) {
        expand_fingerprint[f_hash] = key_hash[f_hash];
    }

    for (int ex = 1; ex < 4; ex++) {
        int rotr = (key_hash[ex] >> 4) & 0x0F;
        uint8_t rotl_res = (uint8_t)((key_hash[ex] & 0x0F) ^ rotr);

        sha.update(&rotl_res, 1);

        array<uint8_t, 32> bit_hash = sha.digest();

        for (int dec = 0; dec < 32; dec++)
            expand_fingerprint[32 * ex + dec] = bit_hash[dec];
    }

    wcout << "KEY FINGERPRINT (SHA-256):" << endl << endl;
    for(int key_c = 0; key_c < 128; key_c++) {
        uint8_t hex_v = expand_fingerprint[key_c];
        if (hex_v >= 0x00 && hex_v <= 0x1F) wcout << SHADE[0];
        if (hex_v <= 0x5F && hex_v >= 0x20) wcout << SHADE[1];
        if (hex_v >= 0x60 && hex_v <= 0x9F) wcout << SHADE[2];
        if (hex_v <= 0xDF && hex_v >= 0xA0) wcout << SHADE[3];
        if (hex_v >= 0xE0 && hex_v <= 0xFF) wcout << SHADE[4];

        if ((key_c + 1) % 16 == 0) std::wcout << std::endl;
    }
    std::wcout << std::endl;
}

string ask_password() {
    cout << "Password: ";
    string password;
    getline(cin, password);

    return password;
}

void derive_file_keys(const std::string& password, int iters,
                       uint8_t out_salt[16], Kyznechik& kyz, SecureKey& keys,
                       const uint8_t* in_salt) {
    std::array<uint8_t, 32> this_hash = {0};
    std::string salted_password = password;

    if (in_salt == nullptr) {
        randombytes_buf(out_salt, 16);
    } else {
        std::memcpy(out_salt, in_salt, 16);
    }
    salted_password.reserve(password.size() + 16);
    for (int i = 0; i < 16; i++) salted_password += out_salt[i];

    SHA256 sha;
    for (int i = 0; i < iters; i++) {
        if (i == 0) sha.update(salted_password);
        else sha.update(SHA256::toString(this_hash));
        this_hash = sha.digest();
    }

    derive_keys(this_hash.data(), kyz, keys);
    sodium_memzero(this_hash.data(), this_hash.size());
    sodium_memzero(&salted_password[0], salted_password.size());

    kyz.init();
}