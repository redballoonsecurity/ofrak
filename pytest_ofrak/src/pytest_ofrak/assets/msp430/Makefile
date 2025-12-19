CC=msp430-elf-gcc
CFLAGS=-Os -Wall -g -mmcu=msp430g2231
INCLUDE_DIR=/opt/ti/msp430/gcc/include

OBJS=main.o

all: $(OBJS)
	$(CC) $(CFLAGS) -o main.elf $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -c $<

clean:
	rm -fr main.elf $(OBJS)
