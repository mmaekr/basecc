#include <unistd.h>

int main(void) {
	char buf[10];
	return read(0, buf, 10);
}
