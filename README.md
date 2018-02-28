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
```
