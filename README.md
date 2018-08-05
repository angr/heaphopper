# Overview

![Overview](overview.png)

# Setup

``` bash
git clone https://github.com/angr/heaphopper.git && cd ./heaphopper
mkvirtualenv -ppython2 heaphopper
pip install -r requirements.txt
```

# Examples

``` bash
# Gen zoo of permutations
src/check_heap.py gen -c src/analysis.yaml

#  Trace instance
src/check_heap.py  trace -c tests/how2heap_fastbin_dup/analysis.yaml -b tests/how2heap_fastbin_dup/fastbin_dup.bin

# Gen PoC
src/check_heap.py poc -c tests/how2heap_fastbin_dup/analysis.yaml -r tests/how2heap_fastbin_dup/fastbin_dup.bin-result.yaml -d tests/how2heap_fastbin_dup/fastbin_dup.bin-desc.yaml -s tests/how2heap_fastbin_dup/fastbin_dup.c -b tests/how2heap_fastbin_dup/fastbin_dup.bin

# Tests
# Show source
cat how2heap_fastbin_dup/fastbin_dup.c
# Run tests
./run_tests.py
# Show PoC source
cat pocs/malloc_non_heap/fastbin_dup.bin/poc_0_0.c
# Run PoC
./run_poc.sh pocs/malloc_non_heap/fastbin_dup.bin/bin/poc_0_0.bin
```

# Publication
This work has been published at the [27th USENIX Security Symposium](https://www.usenix.org/conference/usenixsecurity18/presentation/eckert).

You can read the paper [here](https://seclab.cs.ucsb.edu/media/uploads/papers/sec2018-heap-hopper.pdf).

Cite:
```
@inproceedings {heaphopper,
author = {Eckert, Moritz and Bianchi, Antonio and Wang, Ruoyu and Shoshitaishvili, Yan and Kruegel, Christopher and Vigna, Giovanni},
title = {HeapHopper: Bringing Bounded Model Checking to Heap Implementation Security},
booktitle = {27th {USENIX} Security Symposium ({USENIX} Security 18)},
year = {2018},
address = {Baltimore, MD},
url = {https://www.usenix.org/conference/usenixsecurity18/presentation/eckert},
publisher = {{USENIX} Association},
}
```
