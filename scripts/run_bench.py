#!/usr/bin/env python3

from statistics import mean
from subprocess import run
from time import time_ns
from typing import Dict, List

ITERATIONS: int = 10

FILE_SIZES: Dict[str, int] = {
    "1K": 2**10,
    "2K": 2**11,
    "4K": 2**12,
    "8K": 2**13,
    "16K": 2**14,
    "32K": 2**15,
    "64K": 2**16,
    "128K": 2**17,
    "256K": 2**18,
    "512K": 2**19,
    "1M": 2**20,
    "2M": 2**21,
    "4M": 2**22,
    "8M": 2**23,
    "16M": 2**24,
    "32M": 2**25,
    "64M": 2**26,
    "128M": 2**27,
    "256M": 2**28,
    "512M": 2**29,
    "1G": 2**30,
    "2G": 2**31,
    }

PROGRAMS: List[str] = ["bench_cpu", "bench_cl", "bench_ni"]

def main() -> None:
    raw_timing_ns: Dict[str, Dict[int, List[int]]] = {}
    
    for iteration in range(ITERATIONS):
        for program in PROGRAMS:
            if not raw_timing_ns.get(program):
                raw_timing_ns[program] = {}
        
            for filename, size in FILE_SIZES.items():
                if not raw_timing_ns[program].get(size):
                    raw_timing_ns[program][size] = []

                start_time: int = time_ns()
                
                # Run program in 4 threads
                run([f"bin/{program}", f"input/{filename}.bin", "output/out.bin", "4"])
                
                run_time: int = time_ns() - start_time
                
                raw_timing_ns[program][size].append(run_time)
    
    timing_ms: Dict[str, Dict[str, float]] = {}
    
    for program in PROGRAMS:
        timing_ms[program] = {}
        
        for size in FILE_SIZES.values():
            timing_ms[program][size] = mean(raw_timing_ns[program][size])/10**6
    
    print(timing_ms)
                
                
if __name__ == "__main__":
    main()
