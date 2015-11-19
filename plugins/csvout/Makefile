CFLAGS=-Wall -g -fPIC

all: csvout.so

csvout.so: csvout.o
	gcc -g -shared -o $@ csvout.o

clean:
	rm -f csvout.o
	rm -f csvout.so
