#pragma once

#include <string>
#include <cstdint>
#include <variant>

#include "crypto/kyznechik.h"
#include "crypto/chacha20.hpp"
#include "crypto/chacha20-avx.hpp"

using std::string;

enum CryptoAlgorithms {
    KYZ_ECB,
    KYZ_CBC,
    CHACHA20
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
    std::variant<std::monostate, Kyznechik, ChaCha20, ChaCha20AVX> cipher;
    string in;
    string out;
    uint32_t kdf_iterations = 500000;
};

struct CryptoEntry {
    CryptoValues crypto_values {};
    CryptoFlags crypto_flags {};
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

struct NetworkEntry {
    NetworkProtocolListen network_protocol {};
    NetworkStartType network_start_type {};
    NetworkFlags network_flags {};
};