#include <stdio.h>
#include <stdlib.h>

#include "include/aes_ni.h"
#include "include/file_utils.h"

int main(int argc, char** argv)
{
    // Hardcoded key
    aes_key_t key = { .b = {0x2b, 0x7e, 0x15, 0x16,
                            0x28, 0xae, 0xd2, 0xa6,
                            0xab, 0xf7, 0x15, 0x88,
                            0x09, 0xcf, 0x4f, 0x3c}};
                            
    // Take input from files (provided at command line)
    aes_file_t input;
    aes_file_t output;
    memset(&input, 0, sizeof(input));
    memset(&output, 0, sizeof(output));
    if (argc < 3)
    {
        print_usage_and_cleanup(&input, &output);
    }
    open_files(argv[1], argv[2], &input, &output);
    
    // Expand keys
    key_schedule_t key_sched;
    KeyExpansion(&key, &key_sched);

    // TODO - make this a pthread; break the loop up into N pieces (per argc)
    
    // Perform encryption
    for (size_t block = 0; block < input.size_blocks; ++block)
    {
        output.p_data[block].i = AesCipher128(input.p_data[block].i,
                                              &key_sched);
    }
    
    close_files(&input, &output);
    return 0;
}
