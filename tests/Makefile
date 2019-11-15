.PHONY: all, clean
CC = gcc
CFLAGS += -std=c99 -g -O0
LDFLAGS += -no-pie

BINS = how2heap_fastbin_dup/fastbin_dup.bin how2heap_house_of_einherjar/house_of_einherjar.bin
BINS += how2heap_house_of_lore/house_of_lore.bin how2heap_house_of_spirit/house_of_spirit.bin
BINS += how2heap_overlapping_chunks/overlapping_chunks.bin how2heap_overlapping_chunks/overlapping_chunks_2.bin
BINS += how2heap_poison_null_byte/poison_null_byte.bin how2heap_unsafe_unlink/unsafe_unlink.bin
BINS += how2heap_unsorted_bin_attack/unsorted_bin_attack.bin how2heap_tcache_poisoning/tcache_poisoning.bin
OBJECTS = $(BINS:.bin=.o)
SOURCES = $(BINS:.bin=.c)
RESULTS = $(BINS:.bin=.bin-result.yaml)
DESCS = $(BINS:.bin=.bin-desc.yaml)
POCS = ./*/pocs

all: $(BINS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^

%.bin: %.o
	$(CC) -L. -o $@ $^ $(LDFLAGS) -lc

clean:
	rm -rf $(OBJECTS) $(RESULTS) $(DESCS) $(POCS)

distclean:
	rm -rf $(BINS) $(OBJECTS) $(RESULTS) $(DESCS) $(POCS)
