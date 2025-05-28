CC=gcc

default: program

program.o: program.c $(HEADERS)
	$(CC) -c program.c -fno-asynchronous-unwind-tables -o program.o

program: program.o
	$(CC) program.o -o program

program_no_reloc: program.o
	$(CC) program.o -no-pie -o program_no_reloc

program_relocated: program_relocated.o
	$(CC) program_relocated.o -o program_relocated

large_elf.o: large_elf.c $(HEADERS)
	$(CC) -c large_elf.c -o large_elf.o

large_elf: large_elf.o
	$(CC) large_elf.o -no-pie -o large_elf 

permstest_elf:
	ld -T perms.ld -o permstest_elf /dev/null
