#!/usr/bin/env python3

# Raw data from run_bench.py output
# This is from old source code before unrolling loops
#data = {'bench_cpu': {1024: 211.14271680000002, 2048: 1.8387678, 4096: 1.7906572, 8192: 1.6976444, 16384: 1.9360978, 32768: 2.2490257999999996, 65536: 2.7482586, 131072: 3.755276, 262144: 5.858024, 524288: 10.166219, 1048576: 17.5088468, 2097152: 32.819779600000004, 4194304: 63.9061722, 8388608: 126.52097959999999, 16777216: 258.03844, 33554432: 499.25231160000004, 67108864: 1072.702212, 134217728: 2012.8192448, 268435456: 3996.3968164000003, 536870912: 8075.7701318, 1073741824: 16894.6200132}, 'bench_cl': {1024: 165.5889316, 2048: 7.151830599999999, 4096: 7.4023598, 8192: 7.4326734000000005, 16384: 7.2362642, 32768: 7.302358, 65536: 7.7220224, 131072: 8.5139886, 262144: 9.6080626, 524288: 12.188681, 1048576: 17.363747399999998, 2097152: 28.580204600000002, 4194304: 49.9116034, 8388608: 87.71845459999999, 16777216: 183.26037, 33554432: 373.9549998, 67108864: 656.0393424, 134217728: 1236.3460636, 268435456: 2403.8450978, 536870912: 4824.541558, 1073741824: 10038.878105}, 'bench_ni': {1024: 196.5916752, 2048: 2.4342628, 4096: 2.5390596000000003, 8192: 2.4315178, 16384: 2.41823, 32768: 2.426165, 65536: 2.6256172, 131072: 3.2736782, 262144: 3.5133364, 524288: 3.3814604, 1048576: 3.2736874, 2097152: 3.7455844, 4194304: 5.757012, 8388608: 9.578009400000001, 16777216: 16.629579800000002, 33554432: 31.6004702, 67108864: 60.697851799999995, 134217728: 119.5112744, 268435456: 240.1781244, 536870912: 467.935765, 1073741824: 1445.5781247999998}}

# With loop unrolling
data = {'bench_cpu': {1024: 437.4372792, 2048: 2.0400511, 4096: 2.1116555, 8192: 2.2540596, 16384: 2.3571044, 32768: 2.6759771, 65536: 3.2805184, 131072: 4.5800865, 262144: 7.12078, 524288: 10.9351062, 1048576: 17.693065899999997, 2097152: 30.2204482, 4194304: 56.839378100000005, 8388608: 112.75540240000001, 16777216: 220.4464381, 33554432: 444.6432373, 67108864: 874.1028499, 134217728: 1742.4346122, 268435456: 3493.5006043000003, 536870912: 7071.075645399999, 1073741824: 14403.0052729, 2147483648: 29644.362548099998}, 'bench_cl': {1024: 302.2994208, 2048: 16.7649193, 4096: 18.5769665, 8192: 18.1104684, 16384: 16.6792389, 32768: 18.168133100000002, 65536: 16.5995125, 131072: 16.6161679, 262144: 16.6223706, 524288: 16.6061524, 1048576: 16.6498063, 2097152: 33.3529918, 4194304: 39.999990200000006, 8388608: 73.5772642, 16777216: 134.4914075, 33554432: 243.1097456, 67108864: 432.9728414, 134217728: 799.287291, 268435456: 1557.0877288, 536870912: 3042.4508437, 1073741824: 6644.9643512, 2147483648: 3001.3503311}, 'bench_ni': {1024: 5.5450397, 2048: 4.0133928999999995, 4096: 4.2530446, 8192: 4.376025599999999, 16384: 3.8347335, 32768: 4.338583799999999, 65536: 4.9849739, 131072: 5.186368, 262144: 5.2877373, 524288: 7.6936785, 1048576: 10.452101599999999, 2097152: 14.0743814, 4194304: 23.3432651, 8388608: 20.268633899999998, 16777216: 21.930066800000002, 33554432: 41.7358811, 67108864: 72.77937390000001, 134217728: 142.95018140000002, 268435456: 280.995946, 536870912: 563.0427403, 1073741824: 1156.5537208, 2147483648: 4422.7570365}}

import matplotlib.pyplot as plt

if __name__ == "__main__":   
    sizes = list(data["bench_cl"].keys())
    cl_times = list(data["bench_cl"].values())
    cpu_times = list(data["bench_cpu"].values())
    ni_times = list(data["bench_ni"].values())

    plt.loglog(sizes, cpu_times, "bo",
               sizes, cl_times, "rs",
               sizes, ni_times, "g^")
    
    plt.legend(["Plain C", "OpenCL/GPU", "AES-NI"])

    plt.xlabel("File Size (bytes)")
    plt.ylabel("Average time to encrypt across 10 executions (msec)");
    plt.title("Runtime Comparison for AES-128 Encryption Implementations")
    
    plt.show()