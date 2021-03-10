#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define CL_TARGET_OPENCL_VERSION 220

#include <CL/cl.h>

#include "include/aes_cpu.h"   // For KeyExpansion
#include "include/file_utils.h"

// Arbitrary size
const size_t MAX_BIN_SIZE = 262144;

int main(int argc, char** argv)
{
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
    
    // Set up the OpenCL environment
    cl_int err;
    cl_platform_id platform;
    clGetPlatformIDs(1, &platform, NULL);
    cl_device_id device;
    clGetDeviceIDs(platform,
                   CL_DEVICE_TYPE_GPU,
                   1,
                   &device,
                   NULL);
    cl_context context;
    context = clCreateContext(NULL,
                              1,
                              &device,
                              NULL,
                              NULL,
                              NULL);
    cl_command_queue queue = clCreateCommandQueueWithProperties(context,
                                                                device,
                                                                0,
                                                                NULL);
    
    // Now we need to load the OpenCL binary
    char filename[] = "bin/aes_cl.bin";
    int fd = open(filename, O_RDONLY);
    if (!fd)
    {
        printf("Failed to open OpenCL binary.\n");
        exit(1);
    }
    unsigned char* binary = malloc(MAX_BIN_SIZE);
    ssize_t bin_size = read(fd, binary, MAX_BIN_SIZE);
    if (bin_size < 0)
    {
        printf("Error reading OpenCL binary\n");
        exit(1);
    }
    else if (bin_size == MAX_BIN_SIZE)
    {
        printf("OpenCL binary was maximum length\n");
        exit(1);
    }
    close(fd);
    
    // Build the binary into a kernel
    size_t bin_size_u = (size_t) bin_size;
    cl_int bin_status;
    cl_program program = clCreateProgramWithBinary(context,
                                                   1,
                                                   &device,
                                                   &bin_size_u,
                                                   (const unsigned char**) &binary,
                                                   &bin_status,
                                                   &err);
    clBuildProgram(program, 1, &device, "-Isrc/include", NULL, NULL);
    cl_kernel kernel = clCreateKernel(program, "AesCipher128", &err);
    free(binary);
    
    if (err)
    {
        printf("Error in clCreateKernel: %d\n", err);
    }
    
    // Hardcoded key
    aes_key_t key = { .b = {0x2b, 0x7e, 0x15, 0x16,
                            0x28, 0xae, 0xd2, 0xa6,
                            0xab, 0xf7, 0x15, 0x88,
                            0x09, 0xcf, 0x4f, 0x3c}};
    
    // Expand keys
    key_schedule_t key_sched;
    KeyExpansion(&key, &key_sched);
    
    // The maximum memory allocation provides an upper limit on the
    // amount of operations which can be done in a single batch
    cl_ulong max_alloc_bytes;
    clGetDeviceInfo(device,
                    CL_DEVICE_MAX_MEM_ALLOC_SIZE,
                    sizeof(max_alloc_bytes),
                    &max_alloc_bytes,
                    NULL);
    size_t max_alloc_blocks = max_alloc_bytes /
                              sizeof(block_vector_t);
    
    // Allocate only as much memory as we need or are allowed to
    size_t alloc_size_blocks = 
        input.size_blocks < max_alloc_blocks ?
        input.size_blocks :
        max_alloc_blocks;
    
    // Set up memory for OpenCL
    cl_mem d_input = clCreateBuffer(context,
                                    CL_MEM_READ_ONLY,
                                    alloc_size_blocks*sizeof(block_vector_t),
                                    NULL,
                                    NULL);
    cl_mem d_output = clCreateBuffer(context,
                                     CL_MEM_WRITE_ONLY,
                                     alloc_size_blocks*sizeof(block_vector_t),
                                     NULL,
                                     NULL);
    cl_mem d_key_schedule = clCreateBuffer(context,
                                           CL_MEM_READ_ONLY,
                                           sizeof(key_sched),
                                           NULL,
                                           NULL);

    // Only need to write the key schedule one time
    clEnqueueWriteBuffer(queue,
                         d_key_schedule,
                         CL_FALSE,
                         0,
                         sizeof(key_sched),
                         &key_sched,
                         0,
                         NULL,
                         NULL);
    
    uint64_t current_offset_blocks = 0;
    while (current_offset_blocks < input.size_blocks)
    {
        size_t operation_size =
            input.size_blocks - current_offset_blocks < max_alloc_blocks ?
            input.size_blocks - current_offset_blocks :
            max_alloc_blocks;
        
        // Copy batch-specific input to OpenCL
        clEnqueueWriteBuffer(queue,
                             d_input,
                             CL_FALSE,
                             0,
                             operation_size*sizeof(block_vector_t),
                             input.p_data + current_offset_blocks,
                             0,
                             NULL,
                             NULL);
        
        // Provide arguments to kernel
        clSetKernelArg(kernel, 0, sizeof(cl_mem), &d_input);
        clSetKernelArg(kernel, 1, sizeof(cl_mem), &d_output);
        clSetKernelArg(kernel, 2, sizeof(cl_mem), &d_key_schedule);
        clSetKernelArg(kernel, 3, sizeof(uint64_t), &current_offset_blocks);

        // Run the kernel
        clEnqueueNDRangeKernel(queue,
                               kernel,
                               1,
                               NULL,
                               &alloc_size_blocks,
                               NULL,
                               0,
                               NULL,
                               NULL);
        clFinish(queue);
        
        // Read outputs back to host
        clEnqueueReadBuffer(queue,
                            d_output,
                            CL_TRUE, // Block here to avoid collisions
                            0,
                            operation_size*sizeof(block_vector_t),
                            output.p_data + current_offset_blocks,
                            0,
                            NULL,
                            NULL);

        current_offset_blocks += alloc_size_blocks;
    }
    
    // Cleanup
    clReleaseMemObject(d_input);
    clReleaseMemObject(d_output);
    clReleaseMemObject(d_key_schedule);
    clReleaseProgram(program);
    clReleaseKernel(kernel);
    clReleaseCommandQueue(queue);
    clReleaseContext(context);

    close_files(&input, &output);
    
    return 0;
}
