#include "shell.h"

using std::map;

void register_entries(CLI::App& app,CryptoEntry& crypto_entry, NetworkEntry& network_entry) {
    register_crypto_sub(app, crypto_entry);
    register_network_sub(app, network_entry);
}

void register_crypto_sub(CLI::App& app, CryptoEntry& entry) {
    app.add_flag("--verbose, -v", entry.crypto_flags.verbose, "details and benchbark");
    app.add_flag("--emergency", entry.crypto_flags.emergency, "emergency shutdown (later)");
    app.add_flag("--no-simd, --ns", entry.crypto_flags.no_simd, "disable simd-avx2 instruction");
    
    auto* mode = app.add_option_group("Crypto module mode");
    
    mode->add_flag("-e, --enc, --encrypt", entry.crypto_flags.is_encrypt, "is encrypt mode");
    mode->add_flag("-d, --dec, --decrypt", entry.crypto_flags.is_decrypt, "is decrypt mode");

    mode->require_option(1);


    app.add_option("--input, --in", entry.crypto_values.in, "file to encrypt")
        ->required()
        ->check(CLI::ExistingPath);

    app.add_option("--output, --out", entry.crypto_values.out, "output file");
    
    app.add_option("--iterations, --iter, --it", entry.crypto_values.kdf_iterations, "iterations cout for pbkdf2 default: 500.000");
    
    app.add_option("--mode", entry.crypto_values.algorithm, "cipher mode: kyz-cbc, kyz-ecb, aes256-gcm.")
        ->required()
        ->transform(CLI::CheckedTransformer(
            map<string, CryptoAlgorithms>{
                { "kyz-cbc", CryptoAlgorithms::KYZ_CBC },
                { "kyz-ecb", CryptoAlgorithms::KYZ_ECB }
            }
        ));
}

void register_network_sub(CLI::App& app, NetworkEntry& entry) {
    app.add_flag("--verbose, -v", entry.network_flags.verbose, "detail information");
    
    CLI::Option_group* group_protocol = app.add_option_group("protocol", "choise protocol for listen");
    group_protocol->require_option(1);

    static const vector<pair<string, NetworkProtocolListen>> protocols = {
        {"--dns", NetworkProtocolListen::DNS },
        {"--arp", NetworkProtocolListen::ARP },
        {"--all", NetworkProtocolListen::ALL_ON }
    };

    static const vector<pair<string, NetworkStartType>> run_types = {
        {"emergency", NetworkStartType::EMERGENCY },
        {"standart", NetworkStartType::STANDARD },
        {"standard", NetworkStartType::STANDARD }
    };

    entry.network_start_type = NetworkStartType::STANDARD;
    
    for (const auto& [flag, prot] : protocols) {
        group_protocol->add_flag_function(
            flag,
            [&entry, prot](int64_t){ entry.network_protocol = prot; },
            "protocol: " + prot
        );
    }

    app.add_option("mode", entry.network_start_type, "Launch mode (emergency, standard)")
        ->transform(CLI::CheckedTransformer(run_types));
}