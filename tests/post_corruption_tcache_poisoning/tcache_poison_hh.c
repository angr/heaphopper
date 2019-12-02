#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

typedef struct __attribute__((__packed__)) {
	uint64_t * global_var;
} controlled_data;

typedef struct __attribute__((__packed__)) {
	uint64_t ctrl_0[0x40];
	uint64_t ctrl_1[0x40];
	uint64_t ctrl_2[0x40];
} symbolic_data;

typedef void (*func_ptr)(void);
typedef struct __attribute__((__packed__)) {
	func_ptr func;
} target_struct;

target_struct __attribute__((aligned(16))) alloc_target;
size_t offset;
size_t header_size;
size_t mem2chunk_offset;
size_t write_target[4];
size_t malloc_sizes[3];
size_t overflow_sizes[1];
size_t fill_sizes[3];
size_t arw_offsets[0];
size_t bf_offsets[0];
controlled_data __attribute__((aligned(16))) ctrl_data_0;
controlled_data __attribute__((aligned(16))) ctrl_data_1;
controlled_data __attribute__((aligned(16))) ctrl_data_2;

// Custom functions
void my_awesome_exit_handler(){
	fprintf(stderr, "So Long, and Thanks for All the Fish");
	exit(0);
}

void ops_I_drop_a_shell(){
	system("echo 'BOOMO!'");
}

void winning(){
	fprintf(stderr, "Done.");
}

int main()
{
	void *dummy_chunk = malloc(0x200);
	free(dummy_chunk);

	alloc_target.func = my_awesome_exit_handler;

	ctrl_data_0.global_var = malloc(malloc_sizes[0]);
	for (int i=0; i < fill_sizes[0]; i+=8) {
		read(0, ((uint8_t *)ctrl_data_0.global_var)+i, 8);
	}
	
	free(ctrl_data_0.global_var);

	// UAF	
	read(3, ctrl_data_0.global_var, header_size);

	ctrl_data_1.global_var = malloc(malloc_sizes[1]);
	for (int i=0; i < fill_sizes[1]; i+=8) {
		read(0, ((uint8_t *)ctrl_data_1.global_var)+i, 8);
	}

	ctrl_data_2.global_var = malloc(malloc_sizes[2]);
	for (int i=0; i < fill_sizes[2]; i+=8) {
		read(0, ((uint8_t *)ctrl_data_2.global_var)+i, 8);
	}
	
	(*alloc_target.func)();
	
	winning();

	return 0;
}