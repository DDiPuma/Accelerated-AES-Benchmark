# GPU and ISA-Accelerated Computing for the AES-128 Algorithm

This is a work in progress, but will implement the AES-128 algorithm in C on
the CPU, in OpenCL C on the GPU, and in C with inline assembly to target the
x86 AESNI instruction set extensions.  The goal is to demonstrate the
capabilities of GPU-accelerated computing and of function-specific hardware.

## Source Material
- FIPS AES Specification
- OpenCL
- Intel

## Limitations

- This code makes no attempts at security. At least one (and probably more)
  function provided here is vulnerable to side-channel attacks (e.g. cache
  timing). If you want to encrypt data, look elsewhere.
- Input files must be of length that is an integer multiple of 16 bytes.
- There are currently no decryption functions implemented.
