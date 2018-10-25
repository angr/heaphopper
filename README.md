heaphopper
===

[![Build Status](https://travis-ci.org/angr/heaphopper.svg?branch=master)](https://travis-ci.org/angr/heaphopper)
[![License](https://img.shields.io/github/license/angr/angr.svg)](https://github.com/angr/heaphopper/blob/master/LICENSE)

HeapHopper is a bounded model checking framework for Heap-implementations.

# Overview

![Overview](overview.png)

# Setup

``` bash
sudo apt update && sudo apt install build-essential python3-dev virtualenvwrapper
git clone https://github.com/angr/heaphopper.git && cd ./heaphopper
mkvirtualenv -ppython3 heaphopper
pip install -e .
```

#### Required Packages
``` bash
build-essential python3-dev virtualenvwrapper
```

#### Required Python-Packages
``` bash
ana angr cle claripy IPython psutil pyelftools pyyaml
```

# Examples

``` bash
# Gen zoo of permutations
./heaphopper.py gen -c analysis.yaml

#  Trace instance
make -C tests
./heaphopper.py  trace -c tests/how2heap_fastbin_dup/analysis.yaml -b tests/how2heap_fastbin_dup/fastbin_dup.bin

# Gen PoC
./heaphopper.py poc -c tests/how2heap_fastbin_dup/analysis.yaml -r tests/how2heap_fastbin_dup/fastbin_dup.bin-result.yaml -d tests/how2heap_fastbin_dup/fastbin_dup.bin-desc.yaml -s tests/how2heap_fastbin_dup/fastbin_dup.c -b tests/how2heap_fastbin_dup/fastbin_dup.bin

# Tests
## Show source
cat tests/how2heap_fastbin_dup/fastbin_dup.c
## Run tests
tests/test_heaphopper.py
## Show PoC source
cat tests/how2heap_fastbin_dup/pocs/malloc_non_heap/fastbin_dup.bin/poc_0_0.c
## Run PoC
cd tests
./run_poc.sh tests/how2heap_fastbin_dup/pocs/malloc_non_heap/fastbin_dup.bin/bin/poc_0_0.bin
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
