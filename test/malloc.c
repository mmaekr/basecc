#include <stdlib.h>

int main(void) {
	
	char* mem = malloc(0x40);
	mem[0] = 'A';

	return 1;
}
