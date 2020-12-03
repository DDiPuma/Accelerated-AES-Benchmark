#include <stdio.h>
#include <stdlib.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <CL/cl.h>

// Arbitrary size
const size_t MAX_CODE_SIZE = 65536;

int main(int argc, char** argv)
{
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
    
    // Now we need to load the OpenCL code
    char filename[] = "src/include/aes.cl";
    int fd = open(filename, O_RDONLY);
    if (!fd)
    {
        printf("Failed to open OpenCL source code.\n");
        exit(1);
    }
    char* code = malloc(MAX_CODE_SIZE);
    ssize_t code_size = read(fd, code, MAX_CODE_SIZE);
    if (code_size < 0)
    {
        printf("Error reading code\n");
        exit(-1);
    }
    else if (code_size == MAX_CODE_SIZE)
    {
        printf("Code was maximum length\n");
        exit(-1);
    }
    close(fd);
    
    // Build the OpenCL program
    cl_program program = clCreateProgramWithSource(context,
                                                   1,
                                                   (const char**) &code,
                                                   (const size_t*) &code_size,
                                                   NULL);
    clBuildProgram(program, 1, &device, "-Isrc/include", NULL, NULL);
    cl_kernel kernel = clCreateKernel(program, "AesCipher128", &err);
    free(code);
    
    if (err)
    {
        printf("Error in clCreateKernel: %d\n", err);
        
        char* errors = malloc(MAX_CODE_SIZE);
        size_t error_size;
        clGetProgramBuildInfo(program,
                              device,
                              CL_PROGRAM_BUILD_LOG,
                              MAX_CODE_SIZE,
                              errors,
                              &error_size);
        
        printf("%s", errors);
        
        if (error_size == MAX_CODE_SIZE)
        {
            printf("Failed to capture build log\n");
        }
        
        free(errors);
    }
    
    // Now capture the binary and save it to another file
    // There is 1 binary per device, and 1 device
    size_t binary_size;
    err = clGetProgramInfo(program,
                           CL_PROGRAM_BINARY_SIZES,
                           sizeof(size_t),
                           &binary_size,
                           NULL);
    if (err)
    {
        printf("Error reading CL_PROGRAM_BINARY_SIZES\n");
    }
    unsigned char* binary = malloc(binary_size);
    err = clGetProgramInfo(program,
                           CL_PROGRAM_BINARIES,
                           binary_size,
                           &binary,
                           NULL);
    
    // Dump the binary to a file
    char binary_filename[] = "bin/aes_cl.bin";
    int binary_fd = open(binary_filename,
                         O_RDWR | O_CREAT,
                         // Permissions 644
                         S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (!binary_fd)
    {
        printf("Error opening %s\n", binary_filename);
    }
    else
    {
        write(binary_fd, binary, binary_size);
    }

    // Cleanup
    close(binary_fd);
    free(binary);
    clReleaseKernel(kernel);
    clReleaseProgram(program);
    clReleaseContext(context);
    
    return 0;
}
