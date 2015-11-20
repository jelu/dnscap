CFLAGS=-Wall -g -fPIC -std=gnu11

all: csvout.so

csvout.so: csvout.o
	gcc -g -shared -o $@ csvout.o

clean:
	rm -f csvout.o
	rm -f csvout.so
