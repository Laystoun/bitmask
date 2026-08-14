#include <string>
#include <cassert>
#include <vector>
#include <fstream>
#include <sodium.h>

#include "../kyznechik.h"
#include "../pkcs.h"
#include "../../shell/shell.h"
#include "../../shell/log/logs.h"
#include "key_utils.h"

#ifndef CRYPTO_IO_H
#define CRYPTO_IO_H

#define CURRENT_FORMAT_VERSION 1

using namespace std;

#pragma pack(push, 1)
struct EncryptFileHeader {
    char magic[8] = { 'K', 'E', 'Y', 'G', 'E', 'N', '-', 'X' };
    uint8_t version = CURRENT_FORMAT_VERSION;
    uint8_t algorithm_mode;
    uint8_t salt[16];
    uint8_t iv[16];
    uint32_t kdf_iterations;
};
#pragma pack(pop)

struct CryptoActions {
public:
    void encrypt_file(Kyznechik& kyz,
                        CryptoEntry& crypto_entry,
                        CryptoBenchmark& benchmark,
                        SecureKey& keys, const uint8_t salt[16]) {
        std::filesystem::path in_path(crypto_entry.crypto_values.in);
                    
        bool has_out = !crypto_entry.crypto_values.out.empty();
        std::filesystem::path final_path = has_out
            ? std::filesystem::path(crypto_entry.crypto_values.out)
            : in_path;
                    
        std::filesystem::path work_path = final_path;
        work_path += ".tmp";

        ifstream in(in_path, ios::binary);
        assert(in && "'in' file not found.");
                    
        ofstream out(work_path, ios::binary | ios::trunc);
        assert(out && "'out' file open error.");
                    
        EncryptFileHeader header;
        header.algorithm_mode = static_cast<std::uint8_t>(crypto_entry.crypto_values.algorithm);
        header.kdf_iterations = crypto_entry.crypto_values.kdf_iterations;
        std::memcpy(header.salt, salt, sizeof(header.salt));
                    
        switch (crypto_entry.crypto_values.algorithm) {
            case CryptoAlgorithms::KYZ_CBC: {
                kyz.cbc_generate_iv();
                memcpy(header.iv, kyz.cbc_prev_block, sizeof(header.iv));
                break;
            }
            default:
                break;
        }
    
        out.write(reinterpret_cast<char*>(&header), sizeof(header));
    
        crypto_auth_hmacsha256_state mac_state;
        crypto_auth_hmacsha256_init(&mac_state, keys.mac_key, crypto_auth_hmacsha256_KEYBYTES);
        crypto_auth_hmacsha256_update(&mac_state, reinterpret_cast<std::uint8_t*>(&header), sizeof(header));
    
        const bool verbose = crypto_entry.crypto_flags.verbose;
        const bool use_avx2 = !crypto_entry.crypto_flags.no_simd;

        vector<std::uint8_t> buffer(256 * 1024 * 1024);
    
        while (in.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || in.gcount() > 0) {
            size_t read_bytes = in.gcount();
        
            if (in.eof()) {
                buffer.resize(read_bytes);
                pkcspad(buffer);
                read_bytes = buffer.size();
            }
        
            benchmark.start_crypt_region();
        
            switch (crypto_entry.crypto_values.algorithm) {
                case CryptoAlgorithms::KYZ_ECB: {
                    if (use_avx2) {
                        #pragma omp parallel for
                        for (size_t i = 0; i < read_bytes; i += 128) {
                            kyz.encrypt_block_x8_avx2(buffer.data() + i);
                        }
                    } else {
                        #pragma omp parallel for
                        for (size_t i = 0; i < read_bytes; i += 128) {
                            kyz.encrypt_block_x8_base(buffer.data() + i);
                        }
                    }
                    break;
                }
                case CryptoAlgorithms::KYZ_CBC: {
                    for (size_t i = 0; i < read_bytes; i += 16) {
                        kyz.cbc_encrypt_block(buffer.data() + i);
                    }
                    break;
                }
            }
        
            benchmark.end_crypt_region(read_bytes);
        
            out.write(reinterpret_cast<char*>(buffer.data()), read_bytes);
            crypto_auth_hmacsha256_update(&mac_state, buffer.data(), read_bytes);
        }
    
        unsigned char mac_tag[crypto_auth_hmacsha256_BYTES];
        crypto_auth_hmacsha256_final(&mac_state, mac_tag);
        out.write(reinterpret_cast<char*>(mac_tag), sizeof(mac_tag));
    
        in.close();
        out.close();
    
        std::error_code ec;
        if (!has_out) {
            std::filesystem::remove(in_path, ec);
            assert(!ec && "failed to remove source file");
        }
        std::filesystem::rename(work_path, final_path, ec);
        assert(!ec && "failed to finalize output file");
    }
};

inline void encrypt_something(Kyznechik& kyz, CryptoEntry& crypto_entry) {
    // Header the encrypt file:
    // [
    //     magic-bytes (8 bytes) & version (1 byte) & algorithm-mode (1 byte) &
    //     salt (16 bytes) & kdf-iterations (4 bytes) & iv (16 bytes)
    // ]
    // at the end file: MAC-TAG (32 byte)

    std::string password = ask_password();
    CryptoActions crypto_action;

    if (filesystem::is_directory(crypto_entry.crypto_values.in)) {
        CryptoBenchmark benchmark;

        for (auto& entry : filesystem::recursive_directory_iterator(crypto_entry.crypto_values.in)) {
            if (!entry.is_regular_file()) continue;

            CryptoEntry file_entry = crypto_entry;
            file_entry.crypto_values.in = entry.path().string();
            file_entry.crypto_values.out.clear(); // without --out flag

            SecureKey keys;
            uint8_t salt[16];

            derive_file_keys(password, file_entry.crypto_values.kdf_iterations, salt, kyz, keys);

            crypto_action.encrypt_file(kyz, file_entry, benchmark, keys, salt);
        }

        if (crypto_entry.crypto_flags.verbose) {
            benchmark.print_session_report();
        }
    } else {
        SecureKey keys;
        uint8_t salt[16];

        derive_file_keys(password, crypto_entry.crypto_values.kdf_iterations, salt, kyz, keys);

        CryptoBenchmark benchmark;
        crypto_action.encrypt_file(kyz, crypto_entry, benchmark, keys, salt);

        if (crypto_entry.crypto_flags.verbose) {
            benchmark.print_session_report();
        }
    }

    sodium_memzero(&password[0], password.size());
    password.clear();
}

#endif