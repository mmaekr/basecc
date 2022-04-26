BINARIES=gets_poc simple read malloc
LDFLAGS=

all: $(BINARIES)

gets_poc:
	gcc gets_poc.c -no-pie -fno-stack-protector -o gets_poc

read:
	gcc read.c -o read

simple:
	gcc simple.c -o simple

malloc:
	gcc malloc.c -o malloc

.PHONY: clean

clean:
	rm $(OBJECTS) $(BINARIES)
