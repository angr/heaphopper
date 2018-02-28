.PHONY: all, clean, distclean

BINARYS = identify
all: $(BINARYS)

identify: identify.o
	gcc -o $@ $^ -no-pie

%.o: %.c
	gcc -O0 -c $^

clean:
	rm -rf *.o

distclean: clean
	rm -rf $(BINARYS)
