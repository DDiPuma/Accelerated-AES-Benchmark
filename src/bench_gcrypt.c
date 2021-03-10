#include <stdio.h>
#include <stdlib.h>

#include <pthread.h>

#include <gcrypt.h>

#include "include/file_utils.h"

void* encrypt(void* pv_args)
{
    thread_args_t* p_args = (thread_args_t*) pv_args;
    
    aes_file_t* p_input = p_args->p_input;
    aes_file_t* p_output = p_args->p_output;
    key_schedule_t* p_key_sched = p_args->p_key_sched;
    
    gcry_cipher_hd_t cipher_handle;
    
    gcry_cipher_open(&cipher_handle,
                     GCRY_CIPHER_AES128,
                     GCRY_CIPHER_MODE_CTR,
                     0);
    
    gcry_cipher_setkey(cipher_handle,
                       p_key_sched,
                       sizeof(aes_key_t));

    __m128i init_ctr = _mm_set_epi64x(0, 
                                      p_args->nonce + p_args->offset);
    
    gcry_cipher_setctr(cipher_handle,
                       &init_ctr,
                       sizeof(block_vector_t));
        
    gcry_cipher_encrypt(cipher_handle,
                        p_output->p_data + p_args->offset,
                        p_args->count * sizeof(block_vector_t),
                        p_input->p_data + p_args->offset,
                        p_args->count * sizeof(block_vector_t));
    
    gcry_cipher_close(cipher_handle);
    
    return NULL;
}

int main(int argc, char** argv)
{
    // Hardcoded key
    aes_key_t key = { .b = {0x2b, 0x7e, 0x15, 0x16,
                            0x28, 0xae, 0xd2, 0xa6,
                            0xab, 0xf7, 0x15, 0x88,
                            0x09, 0xcf, 0x4f, 0x3c}};
    // Hardcoded nonce
    uint64_t nonce = 0;
                            
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
    
    long thread_count;
    if (argc > 3)
    {
        thread_count = strtol(argv[3], NULL, 10);
        if (thread_count < 0)
        {
            printf("Thread count is not a positive number\n");
            print_usage_and_cleanup(&input, &output);
        }
    }
    else
    {
        printf("Thread count not provided; defaulting to 1 thread.\n");
        thread_count = 1;
    }

    // libgcrypt performs key schedule derivation
    // We pass the key instead of a key schedule
    key_schedule_t key_sched;
    key_sched.k[0] = key;
    
    // Perform encryption    
    if (thread_count == 1)
    {
        // Just run in this thread
        thread_args_t thread_args;
        thread_args.p_input = &input;
        thread_args.p_output = &output;
        thread_args.p_key_sched = &key_sched;
        thread_args.offset = 0;
        thread_args.count = input.size_blocks;
        thread_args.nonce = nonce;
        encrypt((void*) &thread_args);
    }
    else
    {       
        // Taking a shortcut here
        // Arrays are not thread-safe in general
        // However, if I ensure that no cache line spans multiple threads,
        // I can assume that I am thread-safe.
        
        // Determine offsets and sizes
        if (input.size_blocks % thread_count != 0)
        {
            printf("Blocks cannot be evenly divided across thread count\n");
            print_usage_and_cleanup(&input, &output);
        }
        
        size_t thread_block_size = input.size_blocks / thread_count;
        
        if (thread_block_size % CACHE_LINE_SIZE_BLOCKS != 0)
        {
            printf("Block size per thread is not a multiple of cache line size\n");
            print_usage_and_cleanup(&input, &output);
        }
        
        // Most OSes should be cache line-aligning mmap()
        // Double check this assumption
        if ((size_t) input.p_data % CACHE_LINE_SIZE != 0 ||
            (size_t) output.p_data % CACHE_LINE_SIZE != 0)
        {
            printf("Working memory is not cache aligned\n");
            print_usage_and_cleanup(&input, &output);
        }
        
        pthread_t* p_threads = calloc(thread_count, sizeof(pthread_t));
        thread_args_t* p_thread_args = calloc(thread_count, sizeof(thread_args_t));
                
        // Spawn pthreads
        for (int i = 0; i < thread_count; ++i)
        {
            // Create arguments
            p_thread_args[i].p_input = &input;
            p_thread_args[i].p_output = &output;
            p_thread_args[i].p_key_sched = &key_sched;
            p_thread_args[i].offset = thread_block_size*i;
            p_thread_args[i].count = thread_block_size;
            p_thread_args[i].nonce = nonce;
            
            // Start thread
            int result = pthread_create(&(p_threads[i]),
                                        NULL,
                                        encrypt,
                                        (void*) &(p_thread_args[i]));
            
            if (result != 0)
            {
                printf("pthread_create failed\n");
                print_usage_and_cleanup(&input, &output);
            }
        }
        
        // Wait for threads to finish
        for (int i = 0; i < thread_count; ++i)
        {
            // Join thread
            int result = pthread_join(p_threads[i],
                                      NULL);
            
            if (result != 0)
            {
                printf("pthread_join failed\n");
                print_usage_and_cleanup(&input, &output);
            }
        }
        
        free(p_thread_args);
        free(p_threads);
    }

    close_files(&input, &output);
    return 0;
}
