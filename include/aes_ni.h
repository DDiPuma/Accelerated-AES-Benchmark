#ifndef AESNI_H
#define AESNI_H

#include <string.h>

#include "aes.h"

/**
 *  This code is very much a light refactoring of the C code that
 *  Intel provides in their AES whitepaper. In particular, key schedule
 *  derivation is not as straightforward as the instruction name suggests.
 */

void KeyExpansion(const aes_key_t* const p_key,
                  key_schedule_t* const p_key_sched);

__m128i AesCipher128(__m128i input,
                     const key_schedule_t* const p_key_sched);

__m128i InvAesCipher128(__m128i input,
                        const key_schedule_t* const p_key_sched);

/*
 * Precondition: p_key_sched should be initialized with KeyExpansion
 *               before using the cipher, since the key schedule is
 *               the same for every 128-bit block.
 */
__m128i AesCipher128(const __m128i input,
                     const key_schedule_t* const p_key_sched)
{
    __m128i state = input ^ p_key_sched->i[0];

    // The last round is a little different, so it is excluded
    for (uint8_t round = 1; round < NUM_ROUNDS; ++round)
    {
        state = _mm_aesenc_si128(state, p_key_sched->i[round]);
    }

    // Perform the last round
    state = _mm_aesenclast_si128(state, p_key_sched->i[NUM_ROUNDS]);
    
    return state;
}

/*
 * Precondition: p_key_sched should be initialized with KeyExpansion
 *               before using the cipher, since the key schedule is
 *               the same for every 128-bit block.
 */
__m128i InvAesCipher128(const __m128i input,
                        const key_schedule_t* const p_key_sched)
{
    __m128i state = input ^ p_key_sched->i[NUM_ROUNDS];

    // The last round is a little different, so it is excluded
    for (uint8_t round = NUM_ROUNDS-1; round > 0; --round)
    {
        state = _mm_aesdec_si128(state, p_key_sched->i[round]);
    }

    // Perform the last round
    state = _mm_aesdeclast_si128(state, p_key_sched->i[0]);
    
    return state;
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
    
    tmp1 = _mm_loadu_si128((__m128i*) &(p_key->i[0]));
    p_key_sched->i[0] = tmp1;
    
    tmp2 = _mm_aeskeygenassist_si128(tmp1, 0x01);
    tmp1 = KeyExpansionAssist(tmp1, tmp2);
    p_key_sched->i[1] = tmp1;
    
    tmp2 = _mm_aeskeygenassist_si128(tmp1, 0x02);
    tmp1 = KeyExpansionAssist(tmp1, tmp2);
    p_key_sched->i[2] = tmp1;
    
    tmp2 = _mm_aeskeygenassist_si128(tmp1, 0x04);
    tmp1 = KeyExpansionAssist(tmp1, tmp2);
    p_key_sched->i[3] = tmp1;
    
    tmp2 = _mm_aeskeygenassist_si128(tmp1, 0x08);
    tmp1 = KeyExpansionAssist(tmp1, tmp2);
    p_key_sched->i[4] = tmp1;
    
    tmp2 = _mm_aeskeygenassist_si128(tmp1, 0x10);
    tmp1 = KeyExpansionAssist(tmp1, tmp2);
    p_key_sched->i[5] = tmp1;
    
    tmp2 = _mm_aeskeygenassist_si128(tmp1, 0x20);
    tmp1 = KeyExpansionAssist(tmp1, tmp2);
    p_key_sched->i[6] = tmp1;
    
    tmp2 = _mm_aeskeygenassist_si128(tmp1, 0x40);
    tmp1 = KeyExpansionAssist(tmp1, tmp2);
    p_key_sched->i[7] = tmp1;
    
    tmp2 = _mm_aeskeygenassist_si128(tmp1, 0x80);
    tmp1 = KeyExpansionAssist(tmp1, tmp2);
    p_key_sched->i[8] = tmp1;
    
    tmp2 = _mm_aeskeygenassist_si128(tmp1, 0x1b);
    tmp1 = KeyExpansionAssist(tmp1, tmp2);
    p_key_sched->i[9] = tmp1;
    
    tmp2 = _mm_aeskeygenassist_si128(tmp1, 0x36);
    tmp1 = KeyExpansionAssist(tmp1, tmp2);
    p_key_sched->i[10] = tmp1;
}

void InvKeyExpansion(const aes_key_t* const p_key,
                     key_schedule_t* const p_key_sched)
{
    KeyExpansion(p_key, p_key_sched);
    
    for (uint8_t round = 1; round < NUM_ROUNDS; ++round)
    {
        p_key_sched->i[round] = _mm_aesimc_si128(p_key_sched->i[round]);
    }
}

#endif
