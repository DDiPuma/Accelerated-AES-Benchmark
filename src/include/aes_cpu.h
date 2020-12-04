#ifndef AESCPU_H
#define AESCPU_H

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

    // Manually unrolled loop
    // Disassembled output did not suggest unrolling by compiler
    
    // Round 1
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, p_key_sched, 1);
    
    // Round 2
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, p_key_sched, 2);
    
    // Round 3
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, p_key_sched, 3);
    
    // Round 4
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, p_key_sched, 4);
    
    // Round 5
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, p_key_sched, 5);
    
    // Round 6
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, p_key_sched, 6);

    // Round 7
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, p_key_sched, 7);
    
    // Round 8
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, p_key_sched, 8);
    
    // Round 9
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, p_key_sched, 9);
    
    // Round 10 (no MixColumns for last round)
    SubBytes(&state);
    ShiftRows(&state);
    AddRoundKey(&state, p_key_sched, 10);

    memcpy(p_output->x, state.x, sizeof(state));
}

void SubBytes(block_vector_t* const p_state)
{
    // This is a simple lookup-table substitution
    // It's a Caesar cipher, where the symbols are every possible byte!
    
    p_state->x[0] = sbox[p_state->x[0]];
    p_state->x[1] = sbox[p_state->x[1]];
    p_state->x[2] = sbox[p_state->x[2]];
    p_state->x[3] = sbox[p_state->x[3]];
    
    p_state->x[WORD_SIZE  ] = sbox[p_state->x[WORD_SIZE  ]];
    p_state->x[WORD_SIZE+1] = sbox[p_state->x[WORD_SIZE+1]];
    p_state->x[WORD_SIZE+2] = sbox[p_state->x[WORD_SIZE+2]];
    p_state->x[WORD_SIZE+3] = sbox[p_state->x[WORD_SIZE+3]];
    
    p_state->x[2*WORD_SIZE  ] = sbox[p_state->x[2*WORD_SIZE  ]];
    p_state->x[2*WORD_SIZE+1] = sbox[p_state->x[2*WORD_SIZE+1]];
    p_state->x[2*WORD_SIZE+2] = sbox[p_state->x[2*WORD_SIZE+2]];
    p_state->x[2*WORD_SIZE+3] = sbox[p_state->x[2*WORD_SIZE+3]];
    
    p_state->x[3*WORD_SIZE  ] = sbox[p_state->x[3*WORD_SIZE  ]];
    p_state->x[3*WORD_SIZE+1] = sbox[p_state->x[3*WORD_SIZE+1]];
    p_state->x[3*WORD_SIZE+2] = sbox[p_state->x[3*WORD_SIZE+2]];
    p_state->x[3*WORD_SIZE+3] = sbox[p_state->x[3*WORD_SIZE+3]];
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

    // First column
    // Store the previous column states
    uint8_t b[BLOCK_SIZE];
    b[0] = p_state->x[0];
    b[1] = p_state->x[1];
    b[2] = p_state->x[2];
    b[3] = p_state->x[3];
    
    // Perform matrix multiply
    p_state->x[0] = GFMulBy2[b[0]] ^ GFMulBy3[b[1]] ^
                    b[2]           ^ b[3];
    p_state->x[1] = b[0]           ^ GFMulBy2[b[1]] ^
                    GFMulBy3[b[2]] ^ b[3];
    p_state->x[2] = b[0]           ^ b[1] ^
                    GFMulBy2[b[2]] ^ GFMulBy3[b[3]];
    p_state->x[3] = GFMulBy3[b[0]] ^ b[1] ^
                    b[2]           ^ GFMulBy2[b[3]];
                                  
    // Second column
    // Store the previous column states
    b[0] = p_state->x[WORD_SIZE  ];
    b[1] = p_state->x[WORD_SIZE+1];
    b[2] = p_state->x[WORD_SIZE+2];
    b[3] = p_state->x[WORD_SIZE+3];
    
    // Perform matrix multiply
    p_state->x[WORD_SIZE  ] = GFMulBy2[b[0]] ^ GFMulBy3[b[1]] ^
                              b[2]           ^ b[3];
    p_state->x[WORD_SIZE+1] = b[0]           ^ GFMulBy2[b[1]] ^
                              GFMulBy3[b[2]] ^ b[3];
    p_state->x[WORD_SIZE+2] = b[0]           ^ b[1] ^
                              GFMulBy2[b[2]] ^ GFMulBy3[b[3]];
    p_state->x[WORD_SIZE+3] = GFMulBy3[b[0]] ^ b[1] ^
                              b[2]           ^ GFMulBy2[b[3]];
                                  
    // Third column
    // Store the previous column states
    b[0] = p_state->x[2*WORD_SIZE  ];
    b[1] = p_state->x[2*WORD_SIZE+1];
    b[2] = p_state->x[2*WORD_SIZE+2];
    b[3] = p_state->x[2*WORD_SIZE+3];
    
    // Perform matrix multiply
    p_state->x[2*WORD_SIZE  ] = GFMulBy2[b[0]] ^ GFMulBy3[b[1]] ^
                                b[2]           ^ b[3];
    p_state->x[2*WORD_SIZE+1] = b[0]           ^ GFMulBy2[b[1]] ^
                                GFMulBy3[b[2]] ^ b[3];
    p_state->x[2*WORD_SIZE+2] = b[0]           ^ b[1] ^
                                GFMulBy2[b[2]] ^ GFMulBy3[b[3]];
    p_state->x[2*WORD_SIZE+3] = GFMulBy3[b[0]] ^ b[1] ^
                                b[2]           ^ GFMulBy2[b[3]];
                                  
    // Fourth column
    // Store the previous column states
    b[0] = p_state->x[3*WORD_SIZE  ];
    b[1] = p_state->x[3*WORD_SIZE+1];
    b[2] = p_state->x[3*WORD_SIZE+2];
    b[3] = p_state->x[3*WORD_SIZE+3];
    
    // Perform matrix multiply
    p_state->x[3*WORD_SIZE  ] = GFMulBy2[b[0]] ^ GFMulBy3[b[1]] ^
                                b[2]           ^ b[3];
    p_state->x[3*WORD_SIZE+1] = b[0]           ^ GFMulBy2[b[1]] ^
                                GFMulBy3[b[2]] ^ b[3];
    p_state->x[3*WORD_SIZE+2] = b[0]           ^ b[1] ^
                                GFMulBy2[b[2]] ^ GFMulBy3[b[3]];
    p_state->x[3*WORD_SIZE+3] = GFMulBy3[b[0]] ^ b[1] ^
                                b[2]           ^ GFMulBy2[b[3]];
}

void AddRoundKey(block_vector_t* const p_state,
                 const key_schedule_t* const p_key_sched,
                 const uint8_t round)
{
    p_state->x[0] ^= p_key_sched->b[round][0];
    p_state->x[1] ^= p_key_sched->b[round][1];
    p_state->x[2] ^= p_key_sched->b[round][2];
    p_state->x[3] ^= p_key_sched->b[round][3];
    p_state->x[4] ^= p_key_sched->b[round][4];
    p_state->x[5] ^= p_key_sched->b[round][5];
    p_state->x[6] ^= p_key_sched->b[round][6];
    p_state->x[7] ^= p_key_sched->b[round][7];
    p_state->x[8] ^= p_key_sched->b[round][8];
    p_state->x[9] ^= p_key_sched->b[round][9];
    p_state->x[10] ^= p_key_sched->b[round][10];
    p_state->x[11] ^= p_key_sched->b[round][11];
    p_state->x[12] ^= p_key_sched->b[round][12];
    p_state->x[13] ^= p_key_sched->b[round][13];
    p_state->x[14] ^= p_key_sched->b[round][14];
    p_state->x[15] ^= p_key_sched->b[round][15];
}

void KeyExpansion(const aes_key_t* const p_key,
                  key_schedule_t* const p_key_sched)
{
    // This makes the key unique at each round of encryption
    
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
    
    
    // Long story short, this is a carryless multiply modulo 0x1b
    
    uint8_t result = 0;
    
    while (a && b)
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
