#define AES_CL

#include "aes.h"

void SubBytes(block_vector_t* const p_state);
void ShiftRows(block_vector_t* const p_state);
void MixColumns(block_vector_t* const p_state);
void AddRoundKey(block_vector_t* const p_state,
                 const aes_key_t* const p_key);

__constant uchar16 shift_rows_mask = {0,  5,  10, 15,
                                      4,  9,  14, 3,
                                      8,  13, 2,  7,
                                      12, 1,  6,  11};
/*
 * Precondition: p_key_sched should be initialized with KeyExpansion
 *               before using the cipher, since the key schedule is
 *               the same for every 128-bit block.
 */
__kernel void AesCipher128(__constant block_vector_t* p_inputs, 
                           __global block_vector_t* p_outputs,
                           __global const key_schedule_t* p_key_sched)
{
    int idx = get_global_id(0);
    
    // Copy data into GPU private address space
    block_vector_t state = p_inputs[idx];
    key_schedule_t key_sched = *p_key_sched;
    
    AddRoundKey(&state, &(key_sched.k[0]));

    // Round 1
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, &(key_sched.k[1]));
    
    // Round 2
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, &(key_sched.k[2]));
    
    // Round 3
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, &(key_sched.k[3]));
    
    // Round 4
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, &(key_sched.k[4]));
    
    // Round 5
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, &(key_sched.k[5]));
    
    // Round 6
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, &(key_sched.k[6]));
    
    // Round 7
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, &(key_sched.k[7]));
    
    // Round 8
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, &(key_sched.k[8]));
    
    // Round 9
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, &(key_sched.k[9]));

    // Round 10 (final round excludes MixColumns)
    SubBytes(&state);
    ShiftRows(&state);
    AddRoundKey(&state, &(key_sched.k[10]));

    // Save output
    p_outputs[idx] = state;
}

void SubBytes(block_vector_t* const p_state)
{
    // This is a simple lookup-table substitution
    // It's a Caesar cipher, where the symbols are every possible byte!
    
    p_state->s0 = sbox[p_state->s0];
    p_state->s1 = sbox[p_state->s1];
    p_state->s2 = sbox[p_state->s2];
    p_state->s3 = sbox[p_state->s3];
    
    p_state->s4 = sbox[p_state->s4];
    p_state->s5 = sbox[p_state->s5];
    p_state->s6 = sbox[p_state->s6];
    p_state->s7 = sbox[p_state->s7];
    
    p_state->s8 = sbox[p_state->s8];
    p_state->s9 = sbox[p_state->s9];
    p_state->sa = sbox[p_state->sa];
    p_state->sb = sbox[p_state->sb];
    
    p_state->sc = sbox[p_state->sc];
    p_state->sd = sbox[p_state->sd];
    p_state->se = sbox[p_state->se];
    p_state->sf = sbox[p_state->sf];
}

void ShiftRows(block_vector_t* const p_state)
{
    *p_state = shuffle(*p_state, shift_rows_mask);
}

void MixColumns(block_vector_t* const p_state)
{
    // This is the matrix-multiply step
    // Note that this is not a simple 8-bit integer multiply
    // The multiplication is done over Galois fields 

    // First column
    // Store the previous column states
    uchar4 b;
    b.s0 = p_state->s0;
    b.s1 = p_state->s1;
    b.s2 = p_state->s2;
    b.s3 = p_state->s3;
    
    // Perform matrix multiply
    p_state->s0 = GFMulBy2[b.s0] ^ GFMulBy3[b.s1] ^ b.s2           ^ b.s3;
    p_state->s1 = b.s0           ^ GFMulBy2[b.s1] ^ GFMulBy3[b.s2] ^ b.s3;
    p_state->s2 = b.s0           ^ b.s1           ^ GFMulBy2[b.s2] ^ GFMulBy3[b.s3];
    p_state->s3 = GFMulBy3[b.s0] ^ b.s1           ^ b.s2           ^ GFMulBy2[b.s3];
                                  
    // Second column
    // Store the previous column states
    b.s0 = p_state->s4;
    b.s1 = p_state->s5;
    b.s2 = p_state->s6;
    b.s3 = p_state->s7;
    
    // Perform matrix multiply
    p_state->s4 = GFMulBy2[b.s0] ^ GFMulBy3[b.s1] ^ b.s2           ^ b.s3;
    p_state->s5 = b.s0           ^ GFMulBy2[b.s1] ^ GFMulBy3[b.s2] ^ b.s3;
    p_state->s6 = b.s0           ^ b.s1           ^ GFMulBy2[b.s2] ^ GFMulBy3[b.s3];
    p_state->s7 = GFMulBy3[b.s0] ^ b.s1           ^ b.s2           ^ GFMulBy2[b.s3];
                                  
    // Third column
    // Store the previous column states
    b.s0 = p_state->s8;
    b.s1 = p_state->s9;
    b.s2 = p_state->sa;
    b.s3 = p_state->sb;
    
    // Perform matrix multiply
    p_state->s8 = GFMulBy2[b.s0] ^ GFMulBy3[b.s1] ^ b.s2           ^ b.s3;
    p_state->s9 = b.s0           ^ GFMulBy2[b.s1] ^ GFMulBy3[b.s2] ^ b.s3;
    p_state->sa = b.s0           ^ b.s1           ^ GFMulBy2[b.s2] ^ GFMulBy3[b.s3];
    p_state->sb = GFMulBy3[b.s0] ^ b.s1           ^ b.s2           ^ GFMulBy2[b.s3];
                                  
    // Fourth column
    // Store the previous column states
    b.s0 = p_state->sc;
    b.s1 = p_state->sd;
    b.s2 = p_state->se;
    b.s3 = p_state->sf;
    
    // Perform matrix multiply
    p_state->sc = GFMulBy2[b.s0] ^ GFMulBy3[b.s1] ^ b.s2           ^ b.s3;
    p_state->sd = b.s0           ^ GFMulBy2[b.s1] ^ GFMulBy3[b.s2] ^ b.s3;
    p_state->se = b.s0           ^ b.s1           ^ GFMulBy2[b.s2] ^ GFMulBy3[b.s3];
    p_state->sf = GFMulBy3[b.s0] ^ b.s1           ^ b.s2           ^ GFMulBy2[b.s3];
}

void AddRoundKey(block_vector_t* const p_state,
                 const aes_key_t* const p_key)
{
    *p_state ^= *p_key;
}
