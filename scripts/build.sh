#!/usr/bin/env bash

# This is a hacky "makefile"

# -O2 builds with safe optimizations on
# -march=native is required to enable AES instructions and allow vector optimizations

CC="gcc"
CFLAGS="-Wall -O2 -funroll-loops -march=native -lpthread -lOpenCL"

SRC_DIR="src"
INCLUDE_DIR="src/include"
BIN_DIR="bin"

mkdir -p $BIN_DIR

# Compile C programs
for cfile in ${SRC_DIR}/*.c; do
  ${CC} ${CFLAGS} -I${INCLUDE_DIR} ${cfile} -o $(pwd)/${BIN_DIR}/$(basename -s .c ${cfile})
done

# Compile OpenCL binary
./${BIN_DIR}/compile_cl
