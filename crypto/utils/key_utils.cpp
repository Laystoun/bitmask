/*  Copyright (c) 2020-2026 Bitmask developers
 *  Distributed under the GNU General Public License v2.0,
 *  see the accompanying file COPYING or
 *  https://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 */

#include <iostream>
#include <iomanip>

#ifdef _WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif


#include "key_utils.h"
#include "../SHA256.h"
#include "sodium.h"

using namespace std;

void derive_keys(const uint8_t master_secret[32], Kyznechik& kyz, SecureKey& out) {
    crypto_kdf_derive_from_key(kyz.master_key, 32, 1, "KEYGEN-X", master_secret);
    crypto_kdf_derive_from_key(out.mac_key, sizeof(out.mac_key), 2, "KEYGEN-X", master_secret);
}

void kyz_fingerprint(Kyznechik& kyz) {
        cout << "\n\n" << "MASTER KEY (SHA256): ";
        for (int m_key = 0; m_key < 32; m_key++) {
            cout << hex << uppercase << setw(2)
                 << setfill('0')
                 << static_cast<int>(kyz.master_key[m_key]) << " ";
        }
        cout << dec;
        cout << endl << endl;
    
        cout << "ROUND KEY FINGERPRINT (SHA256): \n" << endl;

        key_finger_print(kyz.ROUND_KEYS);
}

void key_finger_print(std::array<std::array<uint8_t, 16ULL>, 10ULL>& ROUND_KEY) {
    SHA256 sha;

    const size_t ROUND_KEY_SIZE = 160;
    uint8_t key_linear[ROUND_KEY_SIZE];
    for (int r_key = 0; r_key < 10; r_key++) {
        for (int key_v = 0; key_v < 16; key_v++) {
            key_linear[r_key * 16 + key_v] = ROUND_KEY[r_key][key_v];
        }
    }

    sha.update(key_linear, ROUND_KEY_SIZE);
    std::array<uint8_t, 32> key_hash = sha.digest();

    const int FIELD_W = 17;
    const int FIELD_H = 9;
    const char* SYMBOLS = " .o+=*BOX@%&#/^SE";
    const int MAX_SYMBOL_IDX = 15;

    int field[FIELD_H][FIELD_W] = {0};

    int x = FIELD_W / 2;
    int y = FIELD_H / 2;
    int start_x = x, start_y = y;

    for (int byte_i = 0; byte_i < (int)key_hash.size(); byte_i++) {
        uint8_t byte = key_hash[byte_i];
        for (int shift = 0; shift < 4; shift++) {
            int move = byte & 0x03;
            byte >>= 2;
            x += (move & 0x01) ? 1 : -1;
            y += (move & 0x02) ? 1 : -1;

            if (x < 0) x = 0;
            if (x >= FIELD_W) x = FIELD_W - 1;
            if (y < 0) y = 0;
            if (y >= FIELD_H) y = FIELD_H - 1;

            if (field[y][x] < MAX_SYMBOL_IDX) {
                field[y][x]++;
            }
        }
    }

    field[start_y][start_x] = 16;
    field[y][x] = 17;

    cout << "+---[SHA256]-----+" << endl;
    for (int row = 0; row < FIELD_H; row++) {
        cout << "|";
        for (int col = 0; col < FIELD_W; col++) {
            int idx = field[row][col];
            cout << SYMBOLS[idx];
        }
        cout << "|" << endl;
    }
    cout << "+-----------------+" << endl;
}

string ask_password_hidden(const string& prompt) {
    cout << prompt;
    cout.flush();

    string password;

#ifdef _WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & ~ENABLE_ECHO_INPUT);

    getline(cin, password);

    SetConsoleMode(hStdin, mode);
#else
    termios oldt;
    tcgetattr(STDIN_FILENO, &oldt);
    termios newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    getline(cin, password);

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif

    cout << "\n";

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

void derive_multifile_keys(const uint8_t master_session_secret[32], 
                           uint8_t out_salt[16], Kyznechik& kyz, SecureKey& keys,
                           const uint8_t* in_salt) {
    if (in_salt == nullptr) {
        randombytes_buf(out_salt, 16);
    } else {
        std::memcpy(out_salt, in_salt, 16);
    }

    uint32_t subkey_id = 0;
    std::memcpy(&subkey_id, out_salt, 4);

    uint8_t file_secret[32];
    crypto_kdf_derive_from_key(file_secret, 32, subkey_id, "FILE_KEY", master_session_secret);

    derive_keys(file_secret, kyz, keys); 

    sodium_memzero(file_secret, 32);

    kyz.expand_keys();
}

void fill_session_key(
    CryptoEntry& crypto_entry,
    std::string& password,
    std::array<uint8_t, 32>& master_session_secret
) {
    std::string salted_password = password; 
    SHA256 sha;
    for (int i = 0; i < crypto_entry.crypto_values.kdf_iterations; i++) {
        if (i == 0) sha.update(salted_password);
        else sha.update(SHA256::toString(master_session_secret));
        master_session_secret = sha.digest();
    }
    sodium_memzero(&salted_password[0], salted_password.size());
}