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
    for (uint8_t word = 0; word < BLOCK_SIZE; ++word)
    {
        state.w[word] = p_inputs[idx].w[word];
    }
        
    AddRoundKey(&state, &key_sched, 0);

    // The last round is a little different, so it is excluded
    for (uint8_t round = 1; round < NUM_ROUNDS; ++round)
    {
        SubBytes(&state);
        ShiftRows(&state);
        MixColumns(&state);
        AddRoundKey(&state, &key_sched, round);
    }

    // Perform the last round
    SubBytes(&state);
    ShiftRows(&state);
    AddRoundKey(&state, &key_sched, NUM_ROUNDS);

    // Save output
    for (uint8_t word = 0; word < BLOCK_SIZE; ++word)
    {
        p_outputs[idx].w[word] = state.w[word];
    }
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
        // Perform matrix multiply
        p_state->x[col*WORD_SIZE  ] = GFMulBy2[b[0]] ^ GFMulBy3[b[1]] ^
                                      b[2]           ^ b[3];
        p_state->x[col*WORD_SIZE+1] = b[0]           ^ GFMulBy2[b[1]] ^
                                      GFMulBy3[b[2]] ^ b[3];
        p_state->x[col*WORD_SIZE+2] = b[0]           ^ b[1] ^
                                      GFMulBy2[b[2]] ^ GFMulBy3[b[3]];
        p_state->x[col*WORD_SIZE+3] = GFMulBy3[b[0]] ^ b[1] ^
                                      b[2]           ^ GFMulBy2[b[3]];
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
