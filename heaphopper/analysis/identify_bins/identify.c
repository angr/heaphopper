#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

size_t malloc_sizes;

void main(void) {

	void *ptr = malloc(malloc_sizes);

	free(ptr);
}
