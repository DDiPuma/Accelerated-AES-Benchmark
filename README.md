# GPU and ISA-Accelerated Computing for the AES-128 Algorithm

This implements the AES-128 algorithm in C on the CPU, in OpenCL C on
the GPU, and in C with compiler intrinsics to target the x86 AESNI
instruction set extensions.  The goal is to demonstrate the capabilities
of GPU-accelerated computing and of function-specific hardware.

There are several scripts designed to make building and profiling
these implementations easier.

## Source Material
- FIPS AES Specification from NIST
- Intel's Whitepaper on the AES-NI Instruction Set

## Limitations

- This code makes no attempts at security. At least one (and probably more)
  function provided here is vulnerable to side-channel attacks (e.g. cache
  timing). If you want to encrypt data, look elsewhere.
- This code uses the ECB block mode, which reveals repetition in input data.
  Again, this is not secure.
- Input files must be of length that is an integer multiple of 16 bytes.
- Decryption is only implemented for test purposes and is not optimized.
- This is only tested on one machine on one OS, and may not work elsewhere
  without tweaking.
