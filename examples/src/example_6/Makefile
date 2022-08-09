CC=gcc

default: program_kitteh

program_kitteh.o: program_kitteh.c $(HEADERS)
	$(CC) -O2 -c program_kitteh.c -o program_kitteh.o

program_kitteh: program_kitteh.o
	$(CC) program_kitteh.o -o program_kitteh

clean:
	-rm -f program_kitteh.o
	-rm -f program_kitteh
