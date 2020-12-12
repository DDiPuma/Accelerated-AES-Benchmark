#include <stdio.h>
#include <stdlib.h>

#include "include/aes_cpu.h"

/*
 * This is Appendix B of the FIPS AES spec to ensure that this is correct.
 * Think of this as a "unit test suite".
 * 
 * This tests ECB mode, since that is what the FIPS spec covers.
 */

int main(int argc, char** argv)
{
    // Perform setup
    block_vector_t input = { .x = {0x32, 0x43, 0xf6, 0xa8,
                                   0x88, 0x5a, 0x30, 0x8d,
                                   0x31, 0x31, 0x98, 0xa2,
                                   0xe0, 0x37, 0x07, 0x34}};
    block_vector_t input_copy;
    memcpy(&input_copy, &input, sizeof(input));
    
    aes_key_t key = { .b = {0x2b, 0x7e, 0x15, 0x16,
                            0x28, 0xae, 0xd2, 0xa6,
                            0xab, 0xf7, 0x15, 0x88,
                            0x09, 0xcf, 0x4f, 0x3c}};
    key_schedule_t key_sched;
    KeyExpansion(&key, &key_sched);

    // First, do a few individual steps of the algorithm and check that each
    // sub-function works as expected
    
    // Step 1
    const block_vector_t valid_state1 =  { .x = {0x19, 0x3d, 0xe3, 0xbe,
                                                 0xa0, 0xf4, 0xe2, 0x2b,
                                                 0x9a, 0xc6, 0x8d, 0x2a,
                                                 0xe9, 0xf8, 0x48, 0x08}};
    AddRoundKey(&input, &(key_sched.k[0]));
    for (uint8_t byte = 0; byte < sizeof(input); ++byte)
    {
        if (input.x[byte] != valid_state1.x[byte])
        {
            printf("After initial AddRoundKey, expected byte %hhu to be 0x%hhx, but got 0x%hhx\n",
                   byte, valid_state1.x[byte], input.x[byte]);
            exit(-1);
        }
    }

    // Step 2
    const block_vector_t valid_state2 =  { .x = {0xd4, 0x27, 0x11, 0xae,
                                                 0xe0, 0xbf, 0x98, 0xf1,
                                                 0xb8, 0xb4, 0x5d, 0xe5,
                                                 0x1e, 0x41, 0x52, 0x30}};
    SubBytes(&input);
    for (uint8_t byte = 0; byte < sizeof(input); ++byte)
    {
        if (input.x[byte] != valid_state2.x[byte])
        {
            printf("After first SubBytes, expected byte %hhu to be 0x%hhx, but got 0x%hhx\n",
                   byte, valid_state2.x[byte], input.x[byte]);
            exit(-1);
        }
    }

    // Step 3
    const block_vector_t valid_state3 =  { .x = {0xd4, 0xbf, 0x5d, 0x30,
                                                 0xe0, 0xb4, 0x52, 0xae,
                                                 0xb8, 0x41, 0x11, 0xf1,
                                                 0x1e, 0x27, 0x98, 0xe5}};
    ShiftRows(&input);
    for (uint8_t byte = 0; byte < sizeof(input); ++byte)
    {
        if (input.x[byte] != valid_state3.x[byte])
        {
            printf("After first ShiftRows, expected byte %hhu to be 0x%hhx, but got 0x%hhx\n",
                   byte, valid_state3.x[byte], input.x[byte]);
            exit(-1);
        }
    }

    // Step 4
    const block_vector_t valid_state4 =  { .x = {0x04, 0x66, 0x81, 0xe5,
                                                 0xe0, 0xcb, 0x19, 0x9a,
                                                 0x48, 0xf8, 0xd3, 0x7a,
                                                 0x28, 0x06, 0x26, 0x4c}};
    MixColumns(&input);
    for (uint8_t byte = 0; byte < sizeof(input); ++byte)
    {
        if (input.x[byte] != valid_state4.x[byte])
        {
            printf("After first MixColumns, expected byte %hhu to be 0x%hhx, but got 0x%hhx\n",
                   byte, valid_state4.x[byte], input.x[byte]);
            exit(-1);
        }
    }
    
    // Step 5
    const block_vector_t valid_state5 =  { .x = {0xa4, 0x9c, 0x7f, 0xf2,
                                                 0x68, 0x9f, 0x35, 0x2b,
                                                 0x6b, 0x5b, 0xea, 0x43,
                                                 0x02, 0x6a, 0x50, 0x49}};
    AddRoundKey(&input, &(key_sched.k[1]));
    for (uint8_t byte = 0; byte < sizeof(input); ++byte)
    {
        if (input.x[byte] != valid_state5.x[byte])
        {
            printf("After first AddRoundKey, expected byte %hhu to be 0x%hhx, but got 0x%hhx\n",
                   byte, valid_state5.x[byte], input.x[byte]);
            printf("Round key was: 0x%hhx\n", key_sched.k[1].b[byte]);
            exit(-1);
        }
    }
    
    // At this point, everything has been tested at least once
    // Now do a full round of encryption
    const block_vector_t cipher_text = {.x = {0x39, 0x25, 0x84, 0x1d,
                                              0x02, 0xdc, 0x09, 0xfb,
                                              0xdc, 0x11, 0x85, 0x97,
                                              0x19, 0x6a, 0x0b, 0x32}};
    block_vector_t output;
    AesCipher128(&input_copy, &output, &key_sched);
    for (uint8_t byte = 0; byte < sizeof(input); ++byte)
    {
        if (output.x[byte] != cipher_text.x[byte])
        {
            printf("After AesCipher128, expected byte %hhu to be 0x%hhx, but got 0x%hhx\n",
                   byte, cipher_text.x[byte], output.x[byte]);
            exit(-1);
        }
    }
    
    
    printf("Success!\n");
    return 0;
}
