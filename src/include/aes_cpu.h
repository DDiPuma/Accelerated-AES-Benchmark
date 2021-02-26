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
                 const aes_key_t* const p_key);
void AesCipher128(const block_vector_t* const p_input,
                  block_vector_t* const p_output,
                  const key_schedule_t* const p_key_sched,
                  const size_t counter);

const u8x16 shift_rows_mask = {0,  5,  10, 15,
                               4,  9,  14, 3,
                               8,  13, 2,  7,
                               12, 1,  6,  11};

/*
 * Precondition: p_key_sched should be initialized with KeyExpansion
 *               before using the cipher, since the key schedule is
 *               the same for every 128-bit block.
 */
void AesCipher128(const block_vector_t* const p_input, 
                  block_vector_t* const p_output,
                  const key_schedule_t* const p_key_sched,
                  const size_t counter)
{
    block_vector_t state;
    
    memcpy(state.x, p_input->x, sizeof(state));
    
    // Add in the counter
    state.i ^= counter; 
    
    AddRoundKey(&state, &(p_key_sched->k[0]));

    // Manually unrolled loop
    // Disassembled output did not suggest unrolling by compiler
    
    // Round 1
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, &(p_key_sched->k[1]));
    
    // Round 2
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, &(p_key_sched->k[2]));
    
    // Round 3
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, &(p_key_sched->k[3]));
    
    // Round 4
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, &(p_key_sched->k[4]));
    
    // Round 5
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, &(p_key_sched->k[5]));
    
    // Round 6
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, &(p_key_sched->k[6]));

    // Round 7
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, &(p_key_sched->k[7]));
    
    // Round 8
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, &(p_key_sched->k[8]));
    
    // Round 9
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, &(p_key_sched->k[9]));
    
    // Round 10 (no MixColumns for last round)
    SubBytes(&state);
    ShiftRows(&state);
    AddRoundKey(&state, &(p_key_sched->k[10]));

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
    p_state->vec = __builtin_shuffle(p_state->vec, shift_rows_mask);
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
                 const aes_key_t* const p_key)
{
    p_state->i ^= p_key->i;
}

void KeyExpansion(const aes_key_t* const p_key,
                  key_schedule_t* const p_key_sched)
{
    // This makes the key unique at each round of encryption
    
    // Start with the key itself
    // The operations from the spec work in big endian byte order
    for (uint8_t word = 0; word < KEY_LENGTH; ++word)
    {
        p_key_sched->k[0].w[word] = htonl(p_key->w[word]);
    }
    
    // Manipulate the key for future rounds
    uint32_t* const p_key_sched_words = (uint32_t* const) p_key_sched;
    for (uint8_t i = KEY_LENGTH; i < (NUM_ROUNDS+1)*BLOCK_SIZE; ++i)
    {
        // Take previous word
        uint32_t temp = p_key_sched_words[i-1];
        
        // First word of a new round gets transformed
        if (i % KEY_LENGTH == 0)
        {
            temp = SubWord(RotWord(temp)) ^ Rcon[i/KEY_LENGTH];
        }
        
        // XOR this round's i-th word with previous round's i-th word
        p_key_sched_words[i] = p_key_sched_words[i-KEY_LENGTH] ^ temp;
    }
    
    // Convert back to system byte order
    for (uint8_t i = 0; i < (NUM_ROUNDS+1)*BLOCK_SIZE; ++i)
    {
        p_key_sched_words[i] = ntohl(p_key_sched_words[i]);
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
    // Endianness makes this look backwards
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
