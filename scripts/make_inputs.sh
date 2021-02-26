# Creates pseudorandom files of varying size

mkdir -p input
mkdir -p output

head -c 1KiB   /dev/urandom > input/1K.bin
head -c 2KiB   /dev/urandom > input/2K.bin
head -c 4KiB   /dev/urandom > input/4K.bin
head -c 8KiB   /dev/urandom > input/8K.bin
head -c 16KiB  /dev/urandom > input/16K.bin
head -c 32KiB  /dev/urandom > input/32K.bin
head -c 64KiB  /dev/urandom > input/64K.bin
head -c 128KiB /dev/urandom > input/128K.bin
head -c 256KiB /dev/urandom > input/256K.bin
head -c 512KiB /dev/urandom > input/512K.bin
head -c 1MiB   /dev/urandom > input/1M.bin
head -c 2MiB   /dev/urandom > input/2M.bin
head -c 4MiB   /dev/urandom > input/4M.bin
head -c 8MiB   /dev/urandom > input/8M.bin
head -c 16MiB  /dev/urandom > input/16M.bin
head -c 32MiB  /dev/urandom > input/32M.bin
head -c 64MiB  /dev/urandom > input/64M.bin
head -c 128MiB /dev/urandom > input/128M.bin
head -c 256MiB /dev/urandom > input/256M.bin
head -c 512MiB /dev/urandom > input/512M.bin
head -c 1GiB   /dev/urandom > input/1G.bin
head -c 2GiB   /dev/urandom > input/2G.bin
head -c 4GiB   /dev/urandom > input/4G.bin

