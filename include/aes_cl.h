#ifndef AESCL_H
#define AESCL_H

#include <arpa/inet.h>

#include <stdbool.h>
#include <string.h>

#include "aes.h"

uint32_t SubWord(uint32_t in);
uint32_t RotWord(uint32_t in);
void KeyExpansion(const aes_key_t* const p_key,
                  key_schedule_t* const p_key_sched);

uint8_t GFMul(uint8_t a, uint8_t b);

void SubBytes(block_vector_t* const p_state);
void ShiftRows(block_vector_t* const p_state);
void MixColumns(block_vector_t* const p_state);
void AddRoundKey(block_vector_t* const p_state,
                 const key_schedule_t* const p_keys,
                 const uint8_t round);
void AesCipher128(const block_vector_t* const p_input,
                  block_vector_t* const p_output,
                  const key_schedule_t* const p_key_sched);

/*
 * Precondition: p_key_sched should be initialized with KeyExpansion
 *               before using the cipher, since the key schedule is
 *               the same for every 128-bit block.
 */
void AesCipher128(const block_vector_t* const p_input, 
                  block_vector_t* const p_output,
                  const key_schedule_t* const p_key_sched)
{
    block_vector_t state;
    
    memcpy(state.x, p_input->x, sizeof(state));
    
    AddRoundKey(&state, p_key_sched, 0);

    // The last round is a little different, so it is excluded
    for (uint8_t round = 1; round < NUM_ROUNDS; ++round)
    {
        SubBytes(&state);
        ShiftRows(&state);
        MixColumns(&state);
        AddRoundKey(&state, p_key_sched, round);
    }

    // Perform the last round
    SubBytes(&state);
    ShiftRows(&state);
    AddRoundKey(&state, p_key_sched, NUM_ROUNDS);

    memcpy(p_output->x, state.x, sizeof(state));
}

void SubBytes(block_vector_t* const p_state)
{
    // This is a simple lookup-table substitution
    // It's a Caesar cipher, where the symbols are every possible byte!
    
    for (uint8_t col = 0; col < BLOCK_SIZE; ++col)
    {
        for (uint8_t row = 0; row < WORD_SIZE; ++row)
        {
            p_state->x[col*WORD_SIZE+row] = sbox[p_state->x[col*WORD_SIZE+row]];
        }
    }
}

void ShiftRows(block_vector_t* const p_state)
{
    uint8_t tmp_byte1, tmp_byte2, tmp_byte3;

    // Do nothing to the first row

    // Shift the second row by 1
    tmp_byte1      = p_state->x[1];
    p_state->x[1]  = p_state->x[5];
    p_state->x[5]  = p_state->x[9];
    p_state->x[9]  = p_state->x[13];
    p_state->x[13] = tmp_byte1;

    // Shift the second row by 2
    tmp_byte1      = p_state->x[2];
    tmp_byte2      = p_state->x[6];
    p_state->x[2]  = p_state->x[10];
    p_state->x[6]  = p_state->x[14];
    p_state->x[10] = tmp_byte1;
    p_state->x[14] = tmp_byte2;

    // Shift the third row by 3
    tmp_byte1      = p_state->x[3];
    tmp_byte2      = p_state->x[7];
    tmp_byte3      = p_state->x[11];
    p_state->x[3]  = p_state->x[15];
    p_state->x[7]  = tmp_byte1;
    p_state->x[11] = tmp_byte2;
    p_state->x[15] = tmp_byte3;
}

void MixColumns(block_vector_t* const p_state)
{
    // This is the matrix-multiply step
    // Note that this is not a simple 8-bit integer multiply
    // The multiplication is done over Galois fields 

    for (uint8_t col = 0; col < WORD_SIZE; ++col)
    {
        // Store the previous column states
        const uint8_t b[BLOCK_SIZE] = {p_state->x[col*WORD_SIZE  ],
                                       p_state->x[col*WORD_SIZE+1],
                                       p_state->x[col*WORD_SIZE+2],
                                       p_state->x[col*WORD_SIZE+3]};
        
        // Perform matrix multiply
        p_state->x[col*WORD_SIZE  ] = GFMul(0x02, b[0]) ^ GFMul(0x03, b[1]) ^
                                      GFMul(0x01, b[2]) ^ GFMul(0x01, b[3]);
        p_state->x[col*WORD_SIZE+1] = GFMul(0x01, b[0]) ^ GFMul(0x02, b[1]) ^
                                      GFMul(0x03, b[2]) ^ GFMul(0x01, b[3]);
        p_state->x[col*WORD_SIZE+2] = GFMul(0x01, b[0]) ^ GFMul(0x01, b[1]) ^
                                      GFMul(0x02, b[2]) ^ GFMul(0x03, b[3]);
        p_state->x[col*WORD_SIZE+3] = GFMul(0x03, b[0]) ^ GFMul(0x01, b[1]) ^
                                      GFMul(0x01, b[2]) ^ GFMul(0x02, b[3]);
    }
}

void AddRoundKey(block_vector_t* const p_state,
                 const key_schedule_t* const p_key_sched,
                 const uint8_t round)
{
    for (uint8_t byte = 0; byte < BLOCK_SIZE*WORD_SIZE; ++byte)
    {
        p_state->x[byte] ^= p_key_sched->b[round][byte];
    }
}

void KeyExpansion(const aes_key_t* const p_key,
                  key_schedule_t* const p_key_sched)
{
    // This makes the key unique at each round of encryption
    
    uint8_t round = 0;
    
    // Start with the key itself
    for (uint8_t word = 0; word < KEY_LENGTH; ++word)
    {
        p_key_sched->w[word] = htonl(p_key->w[word]);
    }
    
    // Manipulate the key for future rounds
    for (uint8_t i = KEY_LENGTH; i < (NUM_ROUNDS+1)*BLOCK_SIZE; ++i)
    {
        uint32_t temp = p_key_sched->w[i-1];
        if (i % KEY_LENGTH == 0)
        {
            temp = SubWord(RotWord(temp)) ^ Rcon[i/KEY_LENGTH];
        }
        p_key_sched->w[i] = p_key_sched->w[i-KEY_LENGTH] ^ temp;
    }
    
    for (uint8_t i = 0; i < (NUM_ROUNDS+1)*BLOCK_SIZE; ++i)
    {
        p_key_sched->w[i] = ntohl(p_key_sched->w[i]);
    }
}

uint32_t SubWord(uint32_t in)
{
    // This is part of the key expansion process
    uint32_t out = in;
    
    // Treat the word as a group of bytes, and perform substitution
    uint8_t* p_bytes = (uint8_t*) &out;
    p_bytes[0] = sbox[p_bytes[0]];
    p_bytes[1] = sbox[p_bytes[1]];
    p_bytes[2] = sbox[p_bytes[2]];
    p_bytes[3] = sbox[p_bytes[3]];
    
    return out;
}

uint32_t RotWord(uint32_t in)
{
    // This is part of the key expansion process
    // Just rotate the lower 24 bits up, and the upper 8 bits down
    return (in << 8 | in >> 24);
    
}

uint8_t GFMul(uint8_t a, uint8_t b)
{    
    // This multiplies in the Galois field GF(2^8)
    // with modulo x^8 + x^4 + x^3 + x + 1 (i.e. 0x1b)
    // The spec makes this unclear, so I used this site as a reference:
    // http://www.cs.utsa.edu/~wagner/laws/FFM.html
    
    uint8_t result = 0;
    
    for (uint8_t bit = 0; bit < BITS_PER_BYTE; ++bit)
    {
        if ((b & 0x01) != 0)
        {
            result ^= a;
        }
        
        bool overflow = ((a & 0x80) != 0x00);
        a <<= 1;
        if (overflow)
        {
            a ^= 0x1b;
        }
        
        b >>= 1;
    }
    
    return result;
}

#endif
