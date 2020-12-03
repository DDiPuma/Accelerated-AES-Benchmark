#define AES_CL

#include "aes.h"

void SubBytes(block_vector_t* const p_state);
void ShiftRows(block_vector_t* const p_state);
void MixColumns(block_vector_t* const p_state);
void AddRoundKey(block_vector_t* const p_state,
                 const key_schedule_t* const p_keys,
                 const uint8_t round);

/*
 * Precondition: p_key_sched should be initialized with KeyExpansion
 *               before using the cipher, since the key schedule is
 *               the same for every 128-bit block.
 */
__kernel void AesCipher128(__global const block_vector_t* p_inputs, 
                           __global block_vector_t* p_outputs,
                           __global const key_schedule_t* p_key_sched)
{
    int idx = get_global_id(0);
    
    block_vector_t state;
    key_schedule_t key_sched = *p_key_sched;
    
    // Get input
    state.w[0] = p_inputs[idx].w[0];
    state.w[1] = p_inputs[idx].w[1];
    state.w[2] = p_inputs[idx].w[2];
    state.w[3] = p_inputs[idx].w[3];
        
    AddRoundKey(&state, &key_sched, 0);

    // Round 1
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, &key_sched, 1);
    
    // Round 2
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, &key_sched, 2);
    
    // Round 3
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, &key_sched, 3);
    
    // Round 4
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, &key_sched, 4);
    
    // Round 5
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, &key_sched, 5);
    
    // Round 6
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, &key_sched, 6);
    
    // Round 7
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, &key_sched, 7);
    
    // Round 8
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, &key_sched, 8);
    
    // Round 9
    SubBytes(&state);
    ShiftRows(&state);
    MixColumns(&state);
    AddRoundKey(&state, &key_sched, 9);

    // Round 10 (final round excludes MixColumns)
    SubBytes(&state);
    ShiftRows(&state);
    AddRoundKey(&state, &key_sched, NUM_ROUNDS);

    // Save output
    p_outputs[idx].w[0] = state.w[0];
    p_outputs[idx].w[1] = state.w[1];
    p_outputs[idx].w[2] = state.w[2];
    p_outputs[idx].w[3] = state.w[3];
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
