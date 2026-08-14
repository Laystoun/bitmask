#ifndef SHELL_H
#define SHELL_H

#include <string>
#include <vector>

#include "../Include/CLI11.hpp"

using std::string, std::vector, std::pair;

enum CryptoAlgorithms {
    KYZ_ECB,
    KYZ_CBC
};

struct CryptoFlags {
    bool verbose;
    bool pbdkf2;
    bool emergency; // then
    bool is_encrypt = false;
    bool is_decrypt = false;
    bool no_simd = false;
};

struct CryptoValues {
    CryptoAlgorithms algorithm;
    string in;
    string out;
    uint32_t kdf_iterations = 500000;
};


enum NetworkProtocolListen {
    ARP,
    DNS,
    ALL_ON
};

enum NetworkStartType {
    EMERGENCY,
    STANDARD
};

struct NetworkFlags {
    bool verbose;
    NetworkProtocolListen type;
    NetworkStartType launch_type;
};

// Base data pull

struct CryptoEntry {
    CryptoValues crypto_values {};
    CryptoFlags crypto_flags {};
};

struct NetworkEntry {
    NetworkProtocolListen network_protocol {};
    NetworkStartType network_start_type {};
    NetworkFlags network_flags {};
};

// Registered flags and values

void register_entries(
    CLI::App& app,
    CryptoEntry& crypto_entry,
    NetworkEntry& network_entry
);

void register_crypto_sub(CLI::App& app, CryptoEntry& entry);
void register_network_sub(CLI::App& app, NetworkEntry& entry);

#endif