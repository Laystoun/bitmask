/*  Copyright (c) 2020-2026 Bitmask developers
 *  Distributed under the GNU General Public License v2.0,
 *  see the accompanying file COPYING or
 *  https://www.gnu.org/licenses/old-licenses/gpl-2.0.html
 */

#ifndef CHACHA20_VECTOR_H
#define CHACHA20_VECTOR_H

/* 
 *  RFC Tests for the ChaCha20 algorithm
 *  https://datatracker.ietf.org/doc/html/rfc8439
 */


struct ChaCha20RFC
{
    bool is_avx2;

    ChaCha20RFC(bool is_avx2)
    {
        this->is_avx2 = is_avx2;
    }

    bool quarter_round_vector();

    void run();
};

void func()
{
    int* array = new int[3];

    
}

#endif