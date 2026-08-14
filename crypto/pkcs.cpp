/*  Copyright (c) 2020-2026 Bitmask developers
 *  Distributed under the GNU General Public License v2.0,
 *  see the accompanying file COPYING or
 *  https://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 */

#include "pkcs.h"
#include <iostream>
#include <cassert>

void pkcspad(std::vector<uint8_t>& block) {
    uint8_t pad_len = 16 - (block.size() % 16);

    for (int i = 0; i < pad_len; i++) {
        block.push_back(pad_len);
    }
}

void pkcsunpad(std::vector<uint8_t>& block) {
    uint8_t pad_val = block.back();
    if (pad_val == 0 || pad_val > 16 || pad_val > block.size()) {
        return; 
    }
    block.resize(block.size() - pad_val);
}