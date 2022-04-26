#include <stdio.h>
#include <stdlib.h>

int pop_rdi() {
	asm("pop %rdi\n"
		"ret");
}

int vuln() {
	char buf[40];

	puts("What is your name?\n");

	gets(buf);
	
	return 1;
}

int main(void) {
	int x = 0;
	x = vuln();
	return x;
}
