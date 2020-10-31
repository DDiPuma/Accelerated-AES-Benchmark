#ifndef FILEUTILS_H
#define FILEUTILS_H

#include <errno.h>
#include <stdio.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "aes.h"

void close_files(aes_file_t* p_input, aes_file_t* p_output)
{
    if (p_input->p_data != NULL && p_input->p_data != MAP_FAILED)
    {
        munmap(p_input->p_data, p_input->size_blocks*BLOCK_SIZE*WORD_SIZE);
    }
    
    if (p_input->fd > 0)
    {
        close(p_input->fd);
    }
    
    if (p_output->p_data != NULL && p_output->p_data != MAP_FAILED)
    {
        munmap(p_output->p_data, p_output->size_blocks*BLOCK_SIZE*WORD_SIZE);
    }
    
    if (p_output->fd > 0)
    {
        close(p_output->fd);
    }
}

void print_usage_and_cleanup(aes_file_t* p_input, aes_file_t* p_output)
{
    printf("Usage:\n");
    printf("bench_<IMPLEMENTATION> <INPUT_FILENAME> <OUTPUT_FILENAME>\n");
    printf("Notes:\n");
    printf("You must have permissions to read <INPUT_FILENAME>\n");
    printf("<INPUT_FILENAME> must be an integer multiple of 16 bytes\n");
    printf("You must have permissions to write <OUTPUT_FILENAME>\n");
    printf("<OUTPUT_FILENAME> will be overwritten\n");

    close_files(p_input, p_output);
    exit(-1);
}

void open_files(char* in_filename, char* out_filename,
                aes_file_t* p_infile, aes_file_t* p_outfile)
{
    // Open the input file and memory map it
    // A lot of checks are made in this process
    int fd = open(in_filename, O_RDONLY);
    if (fd <= 0)
    {
        perror("Error in open() on input file");
        print_usage_and_cleanup(p_infile, p_outfile);
    }
    p_infile->fd = fd;
    
    struct stat file_stats;
    int success = fstat(fd, &file_stats);
    if (success != 0)
    {
        perror("Error in stat() on input file");
        print_usage_and_cleanup(p_infile, p_outfile);
    }
    else if (file_stats.st_size % BLOCK_SIZE*WORD_SIZE != 0 ||
             file_stats.st_size == 0)
    {
        printf("Input file size is not a multiple of 16 bytes\n");
        print_usage_and_cleanup(p_infile, p_outfile);
    }
    p_infile->size_blocks = file_stats.st_size / (WORD_SIZE*BLOCK_SIZE);
    
    void* p_data = mmap(NULL, file_stats.st_size, PROT_READ,
                        MAP_PRIVATE, fd, 0);
    if (p_data == NULL || p_data == MAP_FAILED)
    {
        perror("Error in mmap() on input file");
        print_usage_and_cleanup(p_infile, p_outfile);
    }
    p_infile->p_data = (block_vector_t*) p_data;
    
    // Open and memory map the output file
    fd = open(out_filename, O_CREAT | O_TRUNC | O_RDWR,
              S_IRUSR | S_IWUSR);
    if (fd <= 0)
    {
        perror("Error in open() on output file");
        print_usage_and_cleanup(p_infile, p_outfile);
    }
    p_outfile->fd = fd;
    
    // Set the filesize
    success = ftruncate(fd, file_stats.st_size);
    if (success != 0)
    {
        perror("Error in ftruncate() on output file");
        print_usage_and_cleanup(p_infile, p_outfile);
    }
    p_outfile->size_blocks = p_infile->size_blocks;
    
    p_data = mmap(NULL, file_stats.st_size, PROT_READ | PROT_WRITE,
                        MAP_SHARED, fd, 0);
    if (p_data == NULL || p_data == MAP_FAILED)
    {
        perror("Error in mmap() on output file");
        print_usage_and_cleanup(p_infile, p_outfile);
    }
    
    p_outfile->p_data = (block_vector_t*) p_data;
}


#endif
