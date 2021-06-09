# Detection of Brute-Force Attacks in End-to-End Encrypted Network Traffic

This repository contains the Zeek reference implementation of our brute-force attack detection method for end-to-end encrypted network traffic.
The full scripts are contained within the `compiled` directory.

The source scripts are split into several files that use a custom `@import-static` command. Unlike the regular Zeek imports, this duplicates the imported fragments rather than reusing them. Furthermore, the name of the current module can be used as a constant at any place in the code.
To resolve this custom syntax, the script `compile.py` is used.


The [research paper is published at the 10th International Workshop on Cyber Crime (IWCC 2021), held in conjunction with ARES 2021](https://doi.org/10.1145/3465481.3470113).
