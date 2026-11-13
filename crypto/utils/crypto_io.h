/*  Copyright (c) 2020-2026 Bitmask developers
 *  Distributed under the GNU General Public License v2.0,
 *  see the accompanying file COPYING or
 *  https://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 *  
 *  
 *  Interaction with the encryption module
 */

#include <string>
#include <cassert>
#include <vector>
#include <fstream>
#include <sodium.h>
#include <functional>

#include "../kyznechik.h"
#include "../pkcs.h"
#include "../../shell/shell.h"
#include "../../shell/log/logs.h"
#include "key_utils.h"
#include "ux_render.h"

#ifndef CRYPTO_IO_H
#define CRYPTO_IO_H

#define CURRENT_FORMAT_VERSION 1

using namespace std;

#pragma pack(push, 1)
struct EncryptFileHeader {
    char magic[7] = { 'B', 'I', 'T', 'M', 'A', 'S', 'K' };
    uint8_t version = CURRENT_FORMAT_VERSION;
    uint8_t algorithm_mode;
    uint8_t salt[16];
    uint8_t iv[16];
    uint32_t kdf_iterations;
};
#pragma pack(pop)

struct CryptoActions {
public:
    using ProgressDisplay = std::function<void(unsigned long long processed_bytes)>;

    void encrypt_file(Kyznechik& kyz,
                      CryptoEntry& crypto_entry,
                      CryptoBenchmark& benchmark,
                      SecureKey& keys, const uint8_t salt[16],
                      ProgressDisplay on_progress = nullptr) {

        std::filesystem::path in_path(crypto_entry.crypto_values.in);
                    
        bool has_out = !crypto_entry.crypto_values.out.empty();
        std::filesystem::path final_path = has_out
            ? std::filesystem::path(crypto_entry.crypto_values.out)
            : in_path;
                    
        std::filesystem::path work_path = final_path;
        work_path += ".tmp";
        try {
            ifstream in(in_path, ios::binary);
            if (!in) throw std::runtime_error("'in' file not found.");
                        
            ofstream out(work_path, ios::binary | ios::trunc);
            if (!out) throw std::runtime_error("'out' file create error.");
                        
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
    
            vector<std::uint8_t> buffer(128 * 1024 * 1024);
    
            unsigned long long file_size = 0;
            unsigned long long processed_bytes = 0;
    
            if (crypto_entry.crypto_flags.verbose) {
                file_size = filesystem::file_size(in_path);
            }
    
            while (in.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || in.gcount() > 0) {
                size_t read_bytes = in.gcount();
    
                if (in.eof()) {
                    buffer.resize(read_bytes);
                    pkcspad(buffer);
                    read_bytes = buffer.size();
                }
    
                if (crypto_entry.crypto_flags.verbose) benchmark.start_crypt_region();
    
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
    
                if (crypto_entry.crypto_flags.verbose) benchmark.end_crypt_region(read_bytes);
    
                out.write(reinterpret_cast<char*>(buffer.data()), read_bytes);
                crypto_auth_hmacsha256_update(&mac_state, buffer.data(), read_bytes);
    
                processed_bytes += read_bytes;
                if (on_progress) {
                    on_progress(processed_bytes);
                }
            }
    
            uint8_t tag[32];
            crypto_auth_hmacsha256_final(&mac_state, tag);
            out.write(reinterpret_cast<char*>(tag), sizeof(tag));
    
            out.close();
            in.close();
    
            if (!has_out) {
                error_code pem_ec;
                filesystem::permissions(in_path,
                    filesystem::perms::owner_write,
                    filesystem::perm_options::add,
                    pem_ec
                );

                error_code ec;
                filesystem::remove(in_path, ec); 
                filesystem::rename(work_path, in_path, ec); 
            } else {
                std::error_code ec;
                filesystem::rename(work_path, final_path, ec);
            }
        } catch(...) {
            error_code ec;
            filesystem::remove(work_path, ec);
            throw;
        }
    }

    void decrypt_file(Kyznechik& kyz,
                       CryptoEntry& crypto_entry,
                       CryptoBenchmark& benchmark,
                       SecureKey& keys,
                       ProgressDisplay on_progress = nullptr) {

        std::filesystem::path in_path(crypto_entry.crypto_values.in);

        bool has_out = !crypto_entry.crypto_values.out.empty();
        std::filesystem::path final_path = has_out
            ? std::filesystem::path(crypto_entry.crypto_values.out)
            : in_path;

        std::filesystem::path work_path = final_path;
        work_path += ".tmp";

        unsigned long long total_file_size = std::filesystem::file_size(in_path);
        if (total_file_size < sizeof(EncryptFileHeader) + 32) throw std::runtime_error("file too small / corrupted.");

        unsigned long long ciphertext_size = total_file_size - sizeof(EncryptFileHeader) - 32;

        EncryptFileHeader header;
        {
            ifstream header_in(in_path, ios::binary);
            if (!header_in) throw std::runtime_error("'header_in' file not found.");
            header_in.read(reinterpret_cast<char*>(&header), sizeof(header));
            header_in.close();
        }

        uint8_t salt[16];
        std::memcpy(salt, header.salt, sizeof(salt));

        switch (static_cast<CryptoAlgorithms>(header.algorithm_mode)) {
            case CryptoAlgorithms::KYZ_CBC: {
                std::memcpy(kyz.cbc_prev_block, header.iv, sizeof(header.iv));
                break;
            }
            default:
                break;
        }
        // HMAC part
        uint8_t stored_tag[32];
        {
            ifstream tag_in(in_path, ios::binary);
            tag_in.seekg(static_cast<std::streamoff>(sizeof(header) + ciphertext_size));
            tag_in.read(reinterpret_cast<char*>(stored_tag), sizeof(stored_tag));
        }

        {
            crypto_auth_hmacsha256_state mac_state;
            crypto_auth_hmacsha256_init(&mac_state, keys.mac_key, crypto_auth_hmacsha256_KEYBYTES);
            crypto_auth_hmacsha256_update(&mac_state, reinterpret_cast<std::uint8_t*>(&header), sizeof(header));

            ifstream verify_in(in_path, ios::binary);
            verify_in.seekg(sizeof(header));

            vector<std::uint8_t> vbuf(128 * 1024 * 1024);
            unsigned long long remaining = ciphertext_size;

            while (remaining > 0) {
                size_t chunk = static_cast<size_t>(std::min<unsigned long long>(vbuf.size(), remaining));
                verify_in.read(reinterpret_cast<char*>(vbuf.data()), chunk);
                crypto_auth_hmacsha256_update(&mac_state, vbuf.data(), chunk);
                remaining -= chunk;
            }

            uint8_t computed_tag[32];
            crypto_auth_hmacsha256_final(&mac_state, computed_tag);

            if (sodium_memcmp(computed_tag, stored_tag, 32) != 0) {
                throw std::runtime_error("MAC verification failed: wrong password/key or corrupted file.");
                
            }
        }

        // decrypt part
        ifstream in(in_path, ios::binary);
        in.seekg(sizeof(header));
        try {
            ofstream out(work_path, ios::binary | ios::trunc);
            if (!out) throw std::runtime_error("'out' file open error.");
    
            const bool verbose = crypto_entry.crypto_flags.verbose;
            const bool use_avx2 = !crypto_entry.crypto_flags.no_simd;
    
            vector<std::uint8_t> buffer(256 * 1024 * 1024);
            unsigned long long remaining = ciphertext_size;
            unsigned long long processed_bytes = 0;
    
            while (remaining > 0) {
                size_t read_bytes = static_cast<size_t>(std::min<unsigned long long>(buffer.size(), remaining));
                in.read(reinterpret_cast<char*>(buffer.data()), read_bytes);
    
                if (verbose) benchmark.start_crypt_region();
    
                switch (static_cast<CryptoAlgorithms>(header.algorithm_mode)) {
                    case CryptoAlgorithms::KYZ_ECB: {
                        if (use_avx2) {
                            #pragma omp parallel for
                            for (size_t i = 0; i < read_bytes; i += 128) {
                                kyz.decrypt_block_x8_avx2(buffer.data() + i);
                            }
                        } else {
                            #pragma omp parallel for
                            for (size_t i = 0; i < read_bytes; i += 128) {
                                kyz.decrypt_block_x8_base(buffer.data() + i);
                            }
                        }
                        break;
                    }
                    case CryptoAlgorithms::KYZ_CBC: {
                        for (size_t i = 0; i < read_bytes; i += 16) {
                            kyz.cbc_decrypt_block(buffer.data() + i);
                        }
                        break;
                    }
                }
    
                if (verbose) benchmark.end_crypt_region(read_bytes);
    
                remaining -= read_bytes;
    
                if (remaining == 0) {
                    buffer.resize(read_bytes);
                    pkcsunpad(buffer);
                    read_bytes = buffer.size();
                }
    
                out.write(reinterpret_cast<char*>(buffer.data()), read_bytes);
    
                processed_bytes += read_bytes;
                if (on_progress) {
                    on_progress(processed_bytes);
                }
            }
    
            out.close();
            in.close();
    
            if (!has_out) {
                error_code pem_ec;
                filesystem::permissions(in_path,
                    filesystem::perms::owner_write,
                    filesystem::perm_options::add,
                    pem_ec
                );

                std::error_code ec;
                filesystem::remove(in_path, ec);
                if (ec) cout << "remove error: " << ec.message();
                filesystem::rename(work_path, in_path, ec);
                if (ec) cout << "rename error: " << ec.message();
            } else {
                std::error_code ec;
                filesystem::rename(work_path, final_path, ec);
                if (ec) cout << "rename error: " << ec.message();
            }
        } catch (...) {
            error_code ec;
            filesystem::remove(work_path, ec);
            throw;
        }
    }
};

inline void encrypt_something(Kyznechik& kyz, CryptoEntry& crypto_entry) {
    /*   Header the encrypt file:
     *   [
     *       magic-bytes (8 bytes) & version (1 byte) & algorithm-mode (1 byte) &
     *       salt (16 bytes) & kdf-iterations (4 bytes) & iv (16 bytes)
     *   ]
     *   at the end file: MAC-TAG (32 byte)
     */

    string password = ask_password_hidden();

    CryptoActions crypto_action;
    ProgressDisplay progress("Encrypt");

    if (filesystem::is_directory(crypto_entry.crypto_values.in)) {
        CryptoBenchmark benchmark;
        vector<pair<string, string>> skipped;

        array<uint8_t, 32> master_session_secret; 
        fill_session_key(crypto_entry, password, master_session_secret);
        for (int i = 0; i < 32; i++) {
            kyz.master_key[i] = master_session_secret[i];
        }
        kyz.init();

        std::vector<std::filesystem::path> files;
        unsigned long long total_bytes = 0;
        for (auto& entry : filesystem::recursive_directory_iterator(crypto_entry.crypto_values.in)) {
            if (!entry.is_regular_file()) continue;
            files.push_back(entry.path());
            total_bytes += filesystem::file_size(entry.path());
        }

        unsigned long long processed_before_this_file = 0;

        for (auto& path : files) {
            CryptoEntry file_entry = crypto_entry;
            file_entry.crypto_values.in = path.string();
            file_entry.crypto_values.out.clear(); // without --out flag

            unsigned long long file_size = filesystem::file_size(path);

            SecureKey keys;
            uint8_t salt[16];

            derive_multifile_keys(master_session_secret.data(), salt, kyz, keys, nullptr);

            try {
                crypto_action.encrypt_file(
                    kyz, file_entry, benchmark, keys, salt,
                    [&](unsigned long long processed) {
                        unsigned long long overall = processed_before_this_file + processed;
                        int percent = total_bytes > 0
                            ? static_cast<int>(overall * 100 / total_bytes)
                            : 100;
                        progress.set_progress(percent);
                    }
                );
            } catch(std::exception& ex) {
                skipped.push_back(make_pair(path.string(), ex.what()));
                continue;
            }

            processed_before_this_file += file_size;

            if (crypto_entry.crypto_flags.verbose) {
                progress.set_file(path.string());
            }
        }

        progress.finish();
        cout << "\n";
        if (crypto_entry.crypto_flags.verbose) {
            benchmark.print_session_report();
        }

        if(skipped.size() >= 1) {
            cout << "Skipped: \n\n";
            for(int i = 0; i < skipped.size(); i++) {
                cout << skipped[i].first << ": " << skipped[i].second << "\n";
            }
        }
    } else {
        SecureKey keys;
        uint8_t salt[16];

        derive_file_keys(password, crypto_entry.crypto_values.kdf_iterations, salt, kyz, keys);

        CryptoBenchmark benchmark;
        unsigned long long file_size = filesystem::file_size(crypto_entry.crypto_values.in);

        crypto_action.encrypt_file(
            kyz, crypto_entry, benchmark, keys, salt,
            [&](unsigned long long processed) {
                int percent = file_size > 0
                    ? static_cast<int>(processed * 100 / file_size)
                    : 100;
                progress.set_progress(percent);
            }
        );

        if (crypto_entry.crypto_flags.verbose) {
            cout << "\n";
            benchmark.print_session_report();
        }
        cout << "\n";
    }

    sodium_memzero(&password[0], password.size());
    password.clear();
}

inline void decrypt_something(Kyznechik& kyz, CryptoEntry& crypto_entry) {
    string password = ask_password_hidden();

    CryptoActions crypto_action;
    ProgressDisplay progress("Decrypt");

    if (filesystem::is_directory(crypto_entry.crypto_values.in)) {
        CryptoBenchmark benchmark;
        vector<pair<string, string>> skipped;

        std::array<uint8_t, 32> master_session_secret;
        fill_session_key(crypto_entry, password, master_session_secret);
        for(int i = 0; i < 32; i++) {
            kyz.master_key[i] = master_session_secret[i];
        }
        kyz.init();

        std::vector<std::filesystem::path> files;
        unsigned long long total_bytes = 0;
        for (auto& entry : filesystem::recursive_directory_iterator(crypto_entry.crypto_values.in)) {
            if (!entry.is_regular_file()) continue;
            files.push_back(entry.path());
            total_bytes += filesystem::file_size(entry.path());
        }

        unsigned long long processed_before_this_file = 0;

        for (auto& path : files) {
            CryptoEntry file_entry = crypto_entry;
            file_entry.crypto_values.in = path.string();
            file_entry.crypto_values.out.clear();

            unsigned long long file_size = filesystem::file_size(path);

            EncryptFileHeader header;
            {
                ifstream header_in(path, ios::binary);
                header_in.read(reinterpret_cast<char*>(&header), sizeof(header));
                header_in.close();
            }

            SecureKey keys;
            uint8_t scratch_salt[16];
            derive_multifile_keys(master_session_secret.data(), scratch_salt, kyz, /*mac_key=*/keys, header.salt);

            try {
                crypto_action.decrypt_file(
                    kyz, file_entry, benchmark, keys,
                    [&](unsigned long long processed) {
                        unsigned long long overall = processed_before_this_file + processed;
                        int percent = total_bytes > 0
                            ? static_cast<int>(overall * 100 / total_bytes)
                            : 100;
                        progress.set_progress(percent);
                    }
                );
            } catch(std::exception& ex) {
                skipped.push_back(make_pair(path.string(), ex.what()));
                continue;
            }

            processed_before_this_file += file_size;

            if (crypto_entry.crypto_flags.verbose) {
                progress.set_file(path.string());
            }
        }

        progress.finish();
        cout << "\n";
        if (crypto_entry.crypto_flags.verbose) {
            cout << "\n";
            benchmark.print_session_report();
        }

        if(skipped.size() >= 1) {
            cout << "Skipped: \n\n";
            for(int i = 0; i < skipped.size(); i++) {
                cout << skipped[i].first << ": " << skipped[i].second << "\n";
            }
        }
    } else {
        EncryptFileHeader header;
        {
            ifstream header_in(crypto_entry.crypto_values.in, ios::binary);
            if (!header_in) throw std::runtime_error("'in' file not found");
            header_in.read(reinterpret_cast<char*>(&header), sizeof(header));
        }

        SecureKey keys;
        uint8_t scratch_salt[16];
        derive_file_keys(password, header.kdf_iterations, scratch_salt, kyz, /*mac_key=*/keys, header.salt);

        CryptoBenchmark benchmark;
        unsigned long long file_size = filesystem::file_size(crypto_entry.crypto_values.in);

        crypto_action.decrypt_file(
            kyz, crypto_entry, benchmark, keys,
            [&](unsigned long long processed) {
                int percent = file_size > 0
                    ? static_cast<int>(processed * 100 / file_size)
                    : 100;
                progress.set_progress(percent);
            }
        );

        if (crypto_entry.crypto_flags.verbose) {
            benchmark.print_session_report();
        }
        cout << "\n";
    }

    sodium_memzero(&password[0], password.size());
    password.clear();
}

#endif