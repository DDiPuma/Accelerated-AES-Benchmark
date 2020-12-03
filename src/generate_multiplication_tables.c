#include <stdio.h>

#include "include/aes_cpu.h"

int main(int argc, char** argv)
{
    printf("Multiplication table by 2 in GF(2^8) with AES modulus\n");
    printf("{");
    for (size_t i = 0; i < 256; ++i)
    {
        printf("0x%02hhx", GFMul(i, 0x02));

        if (i == 255)
        {
            printf("};");
        }
        else
        {
            printf(", ");
        }

        if (i % 16 == 15)
        {
            printf("\n");
        }
    }

    printf("Multiplication table by 3 in GF(2^8) with AES modulus\n");
    printf("{");
    for (size_t i = 0; i < 256; ++i)
    {
        printf("0x%02hhx", GFMul(i, 0x03));

        if (i == 255)
        {
            printf("};");
        }
        else
        {
            printf(", ");
        }

        if (i % 16 == 15)
        {
            printf("\n");
        }
    }
    
    return 0;
}
