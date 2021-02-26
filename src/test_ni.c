#include <stdio.h>
#include <stdlib.h>

#include "include/aes_ni.h"

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
    
    aes_key_t key = { .b = {0x2b, 0x7e, 0x15, 0x16,
                            0x28, 0xae, 0xd2, 0xa6,
                            0xab, 0xf7, 0x15, 0x88,
                            0x09, 0xcf, 0x4f, 0x3c}};
    key_schedule_t key_sched;
    

    // Try encryption
    KeyExpansion(&key, &key_sched);
    const block_vector_t cipher_text = {.x = {0x39, 0x25, 0x84, 0x1d,
                                              0x02, 0xdc, 0x09, 0xfb,
                                              0xdc, 0x11, 0x85, 0x97,
                                              0x19, 0x6a, 0x0b, 0x32}};
    block_vector_t output;
    output.i = AesCipher128(input.i, &key_sched, 0);
    for (uint8_t byte = 0; byte < sizeof(input); ++byte)
    {
        if (output.x[byte] != cipher_text.x[byte])
        {
            printf("After AesCipher128, expected byte %hhu to be 0x%hhx, but got 0x%hhx\n",
                   byte, cipher_text.x[byte], output.x[byte]);
        }
    }
    
    
    // Try decryption
    
    InvKeyExpansion(&key, &key_sched);
    
    block_vector_t decrypted;
    decrypted.i = InvAesCipher128(cipher_text.i, &key_sched, 0);
    for (uint8_t byte = 0; byte < sizeof(cipher_text); ++byte)
    {
        if (decrypted.x[byte] != input.x[byte])
        {
            printf("After AesCipher128, expected byte %hhu to be 0x%hhx, but got 0x%hhx\n",
                   byte, input.x[byte], decrypted.x[byte]);
        }
    }
    
    printf("Success!\n");
    return 0;
}
