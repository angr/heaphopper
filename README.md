HeapHopper
====

HeapHopper is a bounded model checking framework for Heap-implementations, presented in the [HeapHopper](TODO) paper.

# Overview

![Overview](overview.png)

# Setup

```
git clone https://github.com/shellphish/heaphopper && cd ./heaphopper
mkvirtualenv -ppython2 heaphopper
pip install -r requirements.txt
```

# Example

```
# Gen zoo
src/check_heap.py gen -c src/analysis.yaml

#  Trace instance
src/check_heap.py  trace -c tests/how2heap_fastbin_dup/analysis.yaml -b tests/how2heap_fastbin_dup/fastbin_dup.bin

# Gen PoC
src/check_heap.py poc -c tests/how2heap_fastbin_dup/analysis.yaml -r tests/how2heap_fastbin_dup/fastbin_dup.bin-result.yaml -d tests/how2heap_fastbin_dup/fastbin_dup.bin-desc.yaml -s tests/how2heap_fastbin_dup/fastbin_dup.c -b tests/how2heap_fastbin_dup/fastbin_dup.bin

# Tests
# show test source e.g.
cat cat how2heap_fastbin_dup/fastbin_dup.c
# run tests
./run_tests.py
# show poc source e.g.
cat pocs/malloc_non_heap/fastbin_dup.bin/poc_0_0.c
# run poc
./run_poc.sh pocs/malloc_non_heap/fastbin_dup.bin/bin/poc_0_0.bin
```
