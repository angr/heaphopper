#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct __attribute__((__packed__)) {
	uint64_t * global_var;
} controlled_data;

typedef struct __attribute__((__packed__)) {
	uint64_t data[0x0];
} symbolic_data;

void winning(void) {
	puts("You win!");
}

size_t write_target[4];
size_t offset;
size_t header_size;
size_t mem2chunk_offset;
size_t malloc_sizes[5];
size_t fill_sizes[5];
size_t overflow_sizes[0];
size_t arw_offsets[0];
size_t bf_offsets[0];
controlled_data __attribute__((aligned(16))) ctrl_data_0;
controlled_data __attribute__((aligned(16))) ctrl_data_1;
controlled_data __attribute__((aligned(16))) ctrl_data_2;
controlled_data __attribute__((aligned(16))) ctrl_data_3;
controlled_data __attribute__((aligned(16))) ctrl_data_4;

symbolic_data __attribute__((aligned(16))) sym_data;

int main(void){
	void *dummy_chunk = malloc(0x200);
	free(dummy_chunk);

	// Allocation
	ctrl_data_0.global_var = malloc(malloc_sizes[0]);
	for (int i=0; i < fill_sizes[0]; i+=8) {
		read(0, ((uint8_t *)ctrl_data_0.global_var)+i, 8);
	}

	// Allocation
	ctrl_data_1.global_var = malloc(malloc_sizes[1]);
	for (int i=0; i < fill_sizes[1]; i+=8) {
		read(0, ((uint8_t *)ctrl_data_1.global_var)+i, 8);
	}

	free(ctrl_data_0.global_var);

	// Allocation
	ctrl_data_2.global_var = malloc(malloc_sizes[2]);
	for (int i=0; i < fill_sizes[2]; i+=8) {
		read(0, ((uint8_t *)ctrl_data_2.global_var)+i, 8);
	}

	//// VULN: UAF
	read(3, ctrl_data_0.global_var, header_size);
	//ctrl_data_0.global_var[1] = &sym_data_0.data;
	//sym_data_0.data[0] = 0;
	//sym_data_0.data[1] = 0;
	//sym_data_0.data[2] = ctrl_data_0.global_var-2;
	//sym_data_0.data[3] = &sym_data_1.data;
	//sym_data_1.data[2] = &sym_data_0.data;
	//sym_data_1.data[3] = 0;

	// Allocation
	ctrl_data_3.global_var = malloc(malloc_sizes[3]);
	for (int i=0; i < fill_sizes[3]; i+=8) {
		read(0, ((uint8_t *)ctrl_data_3.global_var)+i, 8);
	}

	//Allocation
	ctrl_data_4.global_var = malloc(malloc_sizes[4]);
	for (int i=0; i < fill_sizes[4]; i+=8) {
		read(0, ((uint8_t *)ctrl_data_4.global_var)+i, 8);
	}

	winning();
	return 0;
}
