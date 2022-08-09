CC=gcc

default: program

program.o: program.c $(HEADERS)
	$(CC) -c program.c -o program.o

program: program.o
	$(CC) program.o -o program

clean:
	-rm -f program.o
	-rm -f program
