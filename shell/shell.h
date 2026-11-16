#pragma once

#include <string>
#include <vector>
#include <iostream>

#include "types.h"
#include "../Include/CLI11.hpp"

using std::string, std::vector, std::pair;

void register_entries(CLI::App& app, CryptoEntry& crypto_entry, NetworkEntry& network_entry);
void register_crypto_sub(CLI::App& app, CryptoEntry& entry);
void register_network_sub(CLI::App& app, NetworkEntry& entry);