#!/usr/bin/env python3

# Raw data from run_bench.py output
data = {'bench_cpu': {1024: 191.5639678,
                      2048: 2.0660702,
                      4096: 2.1390817,
                      8192: 2.088988,
                      16384: 2.2778252,
                      32768: 2.4199116000000003,
                      65536: 3.1043021,
                      131072: 4.1321514,
                      262144: 5.4424169000000004,
                      524288: 8.925559,
                      1048576: 15.5840303,
                      2097152: 26.055050899999998,
                      4194304: 50.7831056,
                      8388608: 98.024356,
                      16777216: 190.039568,
                      33554432: 385.7121885,
                      67108864: 753.1454973,
                      134217728: 1486.8233513,
                      268435456: 2950.8113488000004,
                      536870912: 6019.013841399999,
                      1073741824: 12396.6244436},
        'bench_cl': {1024: 185.8054539,
                     2048: 10.412938,
                     4096: 10.2067076,
                     8192: 13.584432199999998,
                     16384: 11.2058599,
                     32768: 11.6779356,
                     65536: 11.655893,
                     131072: 11.4839275,
                     262144: 14.462511699999999,
                     524288: 14.562726300000001,
                     1048576: 18.5692882,
                     2097152: 28.4969003,
                     4194304: 41.5362563,
                     8388608: 73.8196452,
                     16777216: 133.01865940000002,
                     33554432: 249.3200605,
                     67108864: 501.7169051,
                     134217728: 982.716728,
                     268435456: 1853.1153393,
                     536870912: 3687.4249363000004,
                     1073741824: 7921.8452108},
        'bench_ni': {1024: 155.4228399,
                     2048: 2.2290289,
                     4096: 2.6437367000000003,
                     8192: 2.7325455,
                     16384: 2.647233,
                     32768: 2.8182141,
                     65536: 2.8742042999999997,
                     131072: 3.0311522,
                     262144: 3.237309,
                     524288: 3.5554259,
                     1048576: 3.4699259,
                     2097152: 4.2226603,
                     4194304: 6.567779099999999,
                     8388608: 10.676449400000001,
                     16777216: 18.3532331,
                     33554432: 34.480831200000004,
                     67108864: 66.6387454,
                     134217728: 127.4691117,
                     268435456: 222.1000984,
                     536870912: 441.0272061,
                     1073741824: 1357.182711}}



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
