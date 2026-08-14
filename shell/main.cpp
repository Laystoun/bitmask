#include <iostream>

#include "shell.h"
#include "cli.h"

#ifdef _WIN32
int wmain(int argc, wchar_t *argv[])
#else
int main(int argc, char *argv[])
#endif
{
    CLI::App app {"bitmask free software"};

    app.allow_windows_style_options();

    NetworkEntry network_entry;
    CryptoEntry crypto_entry;

    CLI::App* crypto_sub = app.add_subcommand("crypto", "Crypto Module");
    CLI::App* network_sub = app.add_subcommand("network", "Network Module");

    register_network_sub(*network_sub, network_entry);
    register_crypto_sub(*crypto_sub, crypto_entry);

    CLI11_PARSE(app, argc, argv);

    if (*crypto_sub) {
        crypto_cli(crypto_entry);
    }
    else if (*network_sub) {
        network_cli(network_entry);
    }
    else {
        std::cout << "No subcommand provided. Use --help for usage.\n";
    }

    return 0;
}
