#ifndef AESNI_H
#define AESNI_H

#include <string.h>

#include "aes.h"

/**
 *  This code is very much a light refactoring of the C code that
 *  Intel provides in their AES whitepaper. In particular, key schedule
 *  derivation is not as straightforward as the instruction name suggests.
 */

/*
 * Precondition: p_key_sched should be initialized with KeyExpansion
 *               before using the cipher, since the key schedule is
 *               the same for every 128-bit block.
 */
__m128i AesCipher128(const __m128i input,
                     const key_schedule_t* const p_key_sched,
                     const __m128i counter)
{
    __m128i state = counter ^ p_key_sched->k[0].i;
    
    // The last round is a little different, so it is excluded
    state = _mm_aesenc_si128(state, p_key_sched->k[1].i);
    state = _mm_aesenc_si128(state, p_key_sched->k[2].i);
    state = _mm_aesenc_si128(state, p_key_sched->k[3].i);
    state = _mm_aesenc_si128(state, p_key_sched->k[4].i);
    state = _mm_aesenc_si128(state, p_key_sched->k[5].i);
    state = _mm_aesenc_si128(state, p_key_sched->k[6].i);
    state = _mm_aesenc_si128(state, p_key_sched->k[7].i);
    state = _mm_aesenc_si128(state, p_key_sched->k[8].i);
    state = _mm_aesenc_si128(state, p_key_sched->k[9].i);

    // Perform the last round
    state = _mm_aesenclast_si128(state, p_key_sched->k[NUM_ROUNDS].i);
    
    return state ^ input;
}

__m128i KeyExpansionAssist(__m128i tmp1, __m128i tmp2)
{
    // Intel provides this function
    
    tmp2 = _mm_shuffle_epi32(tmp2, 0xff);
    __m128i tmp3 = _mm_slli_si128(tmp1, 0x04);
    tmp1 = _mm_xor_si128(tmp1, tmp3);
    tmp3 = _mm_slli_si128(tmp3, 0x04);
    tmp1 = _mm_xor_si128(tmp1, tmp3);
    tmp3 = _mm_slli_si128(tmp3, 0x04);
    tmp1 = _mm_xor_si128(tmp1, tmp3);
    tmp1 = _mm_xor_si128(tmp1, tmp2);
    return tmp1;
}

void KeyExpansion(const aes_key_t* const p_key,
                  key_schedule_t* const p_key_sched)
{
    // Manipulate the key
    __m128i tmp1, tmp2;
    
    tmp1 = _mm_loadu_si128((__m128i*) &(p_key->i));
    p_key_sched->k[0].i = tmp1;
    
    tmp2 = _mm_aeskeygenassist_si128(tmp1, 0x01);
    tmp1 = KeyExpansionAssist(tmp1, tmp2);
    p_key_sched->k[1].i = tmp1;
    
    tmp2 = _mm_aeskeygenassist_si128(tmp1, 0x02);
    tmp1 = KeyExpansionAssist(tmp1, tmp2);
    p_key_sched->k[2].i = tmp1;
    
    tmp2 = _mm_aeskeygenassist_si128(tmp1, 0x04);
    tmp1 = KeyExpansionAssist(tmp1, tmp2);
    p_key_sched->k[3].i = tmp1;
    
    tmp2 = _mm_aeskeygenassist_si128(tmp1, 0x08);
    tmp1 = KeyExpansionAssist(tmp1, tmp2);
    p_key_sched->k[4].i = tmp1;
    
    tmp2 = _mm_aeskeygenassist_si128(tmp1, 0x10);
    tmp1 = KeyExpansionAssist(tmp1, tmp2);
    p_key_sched->k[5].i = tmp1;
    
    tmp2 = _mm_aeskeygenassist_si128(tmp1, 0x20);
    tmp1 = KeyExpansionAssist(tmp1, tmp2);
    p_key_sched->k[6].i = tmp1;
    
    tmp2 = _mm_aeskeygenassist_si128(tmp1, 0x40);
    tmp1 = KeyExpansionAssist(tmp1, tmp2);
    p_key_sched->k[7].i = tmp1;
    
    tmp2 = _mm_aeskeygenassist_si128(tmp1, 0x80);
    tmp1 = KeyExpansionAssist(tmp1, tmp2);
    p_key_sched->k[8].i = tmp1;
    
    tmp2 = _mm_aeskeygenassist_si128(tmp1, 0x1b);
    tmp1 = KeyExpansionAssist(tmp1, tmp2);
    p_key_sched->k[9].i = tmp1;
    
    tmp2 = _mm_aeskeygenassist_si128(tmp1, 0x36);
    tmp1 = KeyExpansionAssist(tmp1, tmp2);
    p_key_sched->k[10].i = tmp1;
}

#endif
