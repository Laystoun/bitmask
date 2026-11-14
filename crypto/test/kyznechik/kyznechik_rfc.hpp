/*  Copyright (c) 2020-2026 Bitmask developers
 *  Distributed under the GNU General Public License v2.0,
 *  see the accompanying file COPYING or
 *  https://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 *  
 *  
 *  Interaction with the encryption module
 */

/*
 *   This file verifies the test vectors in accordance with the official documentation
 *   for theimplementation of the “Kyznechik” block cipher algorithm.
 *   The input and output data were taken from RFC 7801 (all references are listed below).
 *
 *   This test confirms that the algorithm implementation is correct by
 *   performing bit-by-bit comparisons of the results from the individual function modules.
 *
 *   RFC 7801: https://datatracker.ietf.org/doc/html/rfc7801
 */

#pragma once

#include "kyznechik.h"

#include <algorithm>
#include <vector>
#include <exception>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

struct kyznechikRFCVector {
    Kyznechik cipher;

    static std::vector<uint8_t> hex(const char* s) {
        std::vector<uint8_t> out;
        for (size_t i = 0; s[i] && s[i + 1]; i += 2) {
            out.push_back(static_cast<uint8_t>(std::stoul(std::string(s + i, 2), nullptr, 16)));
        }
        return out;
    }

    template <size_t N>
    static std::vector<uint8_t> to_vec(const std::array<uint8_t, N>& a) {
        return std::vector<uint8_t>(a.begin(), a.end());
    }

    void load_rfc_key() {
        auto key = hex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
        std::copy(key.begin(), key.end(), cipher.master_key);
        cipher.expand_keys();
    }

    bool vector_expected(const std::vector<uint8_t>& v, const std::vector<uint8_t>& expected) {
        if (v.size() != expected.size()) {
            return false;
        }
        for (size_t i = 0; i < v.size(); i++) {
            if (v[i] != expected[i]) {
                return false;
            }
        }
        return true;
    }

    /*
    * ================================
    * S BLOCK VECTOR TEST
    * RFC 7801. Section: 5.1
    * ================================ 
    */
    bool s_block_vector() {
        std::vector<uint8_t> input1 {
            0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00
        };

        std::vector<uint8_t> input2 {
            0xb6, 0x6c, 0xd8, 0x88, 0x7d, 0x38, 0xe8, 0xd7,
            0x77, 0x65, 0xae, 0xea, 0x0c, 0x9a, 0x7e, 0xfc
        };

        std::vector<uint8_t> input3 {
            0x55, 0x9d, 0x8d, 0xd7, 0xbd, 0x06, 0xcb, 0xfe,
            0x7e, 0x7b, 0x26, 0x25, 0x23, 0x28, 0x0d, 0x39
        };

        std::vector<uint8_t> input4 {
            0x0c, 0x33, 0x22, 0xfe, 0xd5, 0x31, 0xe4, 0x63,
            0x0d, 0x80, 0xef, 0x5c, 0x5a, 0x81, 0xc5, 0x0b
        };


        std::vector<uint8_t> expected1 {
            0xb6, 0x6c, 0xd8, 0x88, 0x7d, 0x38, 0xe8, 0xd7,
            0x77, 0x65, 0xae, 0xea, 0x0c, 0x9a, 0x7e, 0xfc
        };

        std::vector<uint8_t> expected2 {
            0x55, 0x9d, 0x8d, 0xd7, 0xbd, 0x06, 0xcb, 0xfe,
            0x7e, 0x7b, 0x26, 0x25, 0x23, 0x28, 0x0d, 0x39
        };

        std::vector<uint8_t> expected3 {
            0x0c, 0x33, 0x22, 0xfe, 0xd5, 0x31, 0xe4, 0x63,
            0x0d, 0x80, 0xef, 0x5c, 0x5a, 0x81, 0xc5, 0x0b
        };

        std::vector<uint8_t> expected4 {
            0x23, 0xae, 0x65, 0x63, 0x3f, 0x84, 0x2d, 0x29,
            0xc5, 0xdf, 0x52, 0x9c, 0x13, 0xf5, 0xac, 0xda
        };

        cipher.S_transformation(input1.data());
        cipher.S_transformation(input2.data());
        cipher.S_transformation(input3.data());
        cipher.S_transformation(input4.data());

        bool test1 = vector_expected(input1, expected1);
        bool test2 = vector_expected(input2, expected2);
        bool test3 = vector_expected(input3, expected3);
        bool test4 = vector_expected(input4, expected4);

        return test1 && test2 && test3 && test4;
    }

    /*
    * ================================
    * R BLOCK VECTOR TEST
    * RFC 7801. Section: 5.2
    * ================================
    */
    bool r_block_vector() {
        std::vector<uint8_t> input1 {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00
        };

        std::vector<uint8_t> input2 {
            0x94, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
        };

        std::vector<uint8_t> input3 {
            0xa5, 0x94, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        std::vector<uint8_t> input4 {
            0x64, 0xa5, 0x94, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        std::vector<uint8_t> expected1 {
            0x94, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
        };

        std::vector<uint8_t> expected2 {
            0xa5, 0x94, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        std::vector<uint8_t> expected3 {
            0x64, 0xa5, 0x94, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        std::vector<uint8_t> expected4 {
            0x0d, 0x64, 0xa5, 0x94, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        cipher.R_transformation(input1.data());
        cipher.R_transformation(input2.data());
        cipher.R_transformation(input3.data());
        cipher.R_transformation(input4.data());

        bool test1 = vector_expected(input1, expected1);
        bool test2 = vector_expected(input2, expected2);
        bool test3 = vector_expected(input3, expected3);
        bool test4 = vector_expected(input4, expected4);

        return test1 && test2 && test3 && test4;
    }

    /*
    * ================================
    * L BLOCK VECTOR TEST
    * RFC 7801. Section: 5.3
    * ================================
    */
    bool l_block_vector() {
        std::vector<uint8_t> input1 {
            0x64, 0xa5, 0x94, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        std::vector<uint8_t> input2 {
            0xd4, 0x56, 0x58, 0x4d, 0xd0, 0xe3, 0xe8, 0x4c,
            0xc3, 0x16, 0x6e, 0x4b, 0x7f, 0xa2, 0x89, 0x0d
        };

        std::vector<uint8_t> input3 {
            0x79, 0xd2, 0x62, 0x21, 0xb8, 0x7b, 0x58, 0x4c,
            0xd4, 0x2f, 0xbc, 0x4f, 0xfe, 0xa5, 0xde, 0x9a
        };

        std::vector<uint8_t> input4 {
            0x0e, 0x93, 0x69, 0x1a, 0x0c, 0xfc, 0x60, 0x40,
            0x8b, 0x7b, 0x68, 0xf6, 0x6b, 0x51, 0x3c, 0x13
        };

        std::vector<uint8_t> expected1 {
            0xd4, 0x56, 0x58, 0x4d, 0xd0, 0xe3, 0xe8, 0x4c,
            0xc3, 0x16, 0x6e, 0x4b, 0x7f, 0xa2, 0x89, 0x0d
        };

        std::vector<uint8_t> expected2 {
            0x79, 0xd2, 0x62, 0x21, 0xb8, 0x7b, 0x58, 0x4c,
            0xd4, 0x2f, 0xbc, 0x4f, 0xfe, 0xa5, 0xde, 0x9a
        };

        std::vector<uint8_t> expected3 {
            0x0e, 0x93, 0x69, 0x1a, 0x0c, 0xfc, 0x60, 0x40,
            0x8b, 0x7b, 0x68, 0xf6, 0x6b, 0x51, 0x3c, 0x13
        };

        std::vector<uint8_t> expected4 {
            0xe6, 0xa8, 0x09, 0x4f, 0xee, 0x0a, 0xa2, 0x04,
            0xfd, 0x97, 0xbc, 0xb0, 0xb4, 0x4b, 0x85, 0x80
        };

        cipher.L_transformation(input1.data());
        cipher.L_transformation(input2.data());
        cipher.L_transformation(input3.data());
        cipher.L_transformation(input4.data());

        bool test1 = vector_expected(input1, expected1);
        bool test2 = vector_expected(input2, expected2);
        bool test3 = vector_expected(input3, expected3);
        bool test4 = vector_expected(input4, expected4);

        return test1 && test2 && test3 && test4;
    }

    /*
    * ================================
    * ITERATION CONSTANTS TEST
    * RFC 7801. Section: 5.4 (C_1 .. C_8)
    * ================================
    */
    bool iter_constants_vector() {
        static const char* c_hex[8] = {
            "6ea276726c487ab85d27bd10dd849401",
            "dc87ece4d890f4b3ba4eb92079cbeb02",
            "b2259a96b4d88e0be7690430a44f7f03",
            "7bcd1b0b73e32ba5b79cb140f2551504",
            "156f6d791fab511deabb0c502fd18105",
            "a74af7efab73df160dd208608b9efe06",
            "c9e8819dc73ba5ae50f5b570561a6a07",
            "f6593616e6055689adfba18027aa2a08"
        };

        bool ok = true;
        for (size_t i = 0; i < 8; i++) {
            ok = vector_expected(to_vec(cipher.ITER_CONSTANTS[i]), hex(c_hex[i])) && ok;
        }
        return ok;
    }

    /*
    * ================================
    * KEY SCHEDULE VECTOR TEST
    * RFC 7801. Section: 5.4 (K_1 .. K_10)
    * ================================
    */
    bool key_schedule_vector() {
        load_rfc_key();

        static const char* k_hex[10] = {
            "8899aabbccddeeff0011223344556677",
            "fedcba98765432100123456789abcdef",
            "db31485315694343228d6aef8cc78c44",
            "3d4553d8e9cfec6815ebadc40a9ffd04",
            "57646468c44a5e28d3e59246f429f1ac",
            "bd079435165c6432b532e82834da581b",
            "51e640757e8745de705727265a0098b1",
            "5a7925017b9fdd3ed72a91a22286f984",
            "bb44e25378c73123a5f32f73cdb6e517",
            "72e9dd7416bcf45b755dbaa88e4a4043"
        };

        bool ok = true;
        for (size_t i = 0; i < 10; i++) {
            ok = vector_expected(to_vec(cipher.ROUND_KEYS[i]), hex(k_hex[i])) && ok;
        }
        return ok;
    }

    /*
    * ================================
    * ENCRYPTION VECTOR TEST
    * RFC 7801. Section: 5.5
    * ================================
    */
    bool encrypt_vector() {
        load_rfc_key();

        auto blk = hex("1122334455667700ffeeddccbbaa9988");
        cipher.encrypt_block_single(blk.data());

        return vector_expected(blk, hex("7f679d90bebc24305a468d42b9d4edcd"));
    }

    /*
    * ================================
    * DECRYPTION VECTOR TEST
    * RFC 7801. Section: 5.6
    * ================================
    */
    bool decrypt_vector() {
        load_rfc_key();

        auto blk = hex("7f679d90bebc24305a468d42b9d4edcd");
        cipher.decrypt_block_single(blk.data());

        return vector_expected(blk, hex("1122334455667700ffeeddccbbaa9988"));
    }

};

bool run_kyznechik_rfc_tests(const char* log_path = "kyznechik-rfc.test") {
    std::ofstream file(log_path);
    if (!file) {
        std::cerr << "cannot open " << log_path << " for writing\n";
        return false;
    }

    auto emit = [&](const std::string& line) {
        std::cout << line << '\n';
        file << line << '\n';
    };

    struct Case {
        const char* name;
        bool (kyznechikRFCVector::*fn)();
    };

    static const Case cases[] = {
        {"S transformation (5.1)",   &kyznechikRFCVector::s_block_vector},
        {"R transformation (5.2)",   &kyznechikRFCVector::r_block_vector},
        {"L transformation (5.3)",   &kyznechikRFCVector::l_block_vector},
        {"iteration constants (5.4)", &kyznechikRFCVector::iter_constants_vector},
        {"key schedule (5.4)",       &kyznechikRFCVector::key_schedule_vector},
        {"encryption (5.5)",         &kyznechikRFCVector::encrypt_vector},
        {"decryption (5.6)",         &kyznechikRFCVector::decrypt_vector},
    };
    const size_t total = sizeof(cases) / sizeof(cases[0]);

    emit("====== KUZNYECHIK - BASE =======");

    kyznechikRFCVector t;
    t.cipher.init();

    size_t passed = 0;
    for (size_t i = 0; i < total; ++i) {
        bool ok = false;
        std::string note;
        try {
            ok = (t.*cases[i].fn)();
        } catch (const std::exception& e) {
            note = std::string(" (exception: ") + e.what() + ")";
        }
        if (ok) ++passed;

        std::ostringstream line;
        line << "Log " << (i + 1) << ".. " << std::left << std::setw(28)
             << cases[i].name << ": " << (ok ? "PASS" : "FAIL") << note;
        emit(line.str());
    }

    emit("");
    std::ostringstream summary;
    summary << "Total: " << passed << "/" << total << " passed";
    emit(summary.str());

    file.flush();
    return passed == total;
}