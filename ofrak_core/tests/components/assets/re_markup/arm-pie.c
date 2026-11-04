/*
 * A position-independent ARM program for the referenced strings tests: some functions of a small
 * tool that writes firmware images to flash.
 *
 * Position-independent ARM code computes the address of a string by adding an offset, which it
 * loads from a literal pool, to the program counter. Read as addresses, the offsets of the
 * functions after `print_help` fall inside the help texts, which come first in .rodata: only an
 * analysis that follows the computation, as the backend's does, finds the string each function
 * uses.
 *
 * Built with gcc-arm-linux-gnueabi 15.2.0-16ubuntu1 (Ubuntu), as arm-pie.elf:
 *   arm-linux-gnueabi-gcc -O2 -marm -fPIE -pie -nostdlib -nostartfiles -Wl,--build-id=none \
 *       -Wl,-e,main -o arm-pie.elf arm-pie.c
 */
const char *volatile last_message;
volatile unsigned flash_control;

/* Where the messages of the tool go */
__attribute__((noinline)) void report(const char *message)
{
    last_message = message;
}

/* The help comes first, so its texts come first in .rodata */
__attribute__((noinline)) void print_help(void)
{
    report("Usage: flashtool [OPTION]... IMAGE");
    report("Write a firmware image to the flash of a device.");
    report("-d, --device=PATH      the flash device to write to (default: /dev/mtd0)");
    report("-o, --offset=BYTES     where on the device to write the image (default: 0)");
    report("-l, --length=BYTES     how much of the image to write (default: all of it)");
    report("-e, --erase            erase the sectors the image covers before writing");
    report("-E, --erase-all        erase the whole device before writing");
    report("-v, --verify           read the image back after writing and compare it");
    report("-c, --checksum=CRC     the CRC-32 the image must have to be written");
    report("-s, --sector-size=N    the size of the device's erase sectors, in bytes");
    report("-p, --page-size=N      the size of the device's write pages, in bytes");
    report("-b, --baud=RATE        the speed of the serial link to the bootloader");
    report("-t, --timeout=SECONDS  how long to wait for the bootloader to answer");
    report("-r, --reset            reset the device once the image is written");
    report("-u, --unlock           clear the device's write protection first");
    report("-k, --keep-config      keep the configuration sector as it is");
    report("-n, --dry-run          check the image and the device, but write nothing");
    report("-f, --force            write even if the image is meant for another board");
    report("-q, --quiet            only report errors");
    report("    --progress         report the progress of long operations");
    report("    --log=FILE         also write the messages to FILE");
    report("-V, --version          print the version of the tool and exit");
    report("-h, --help             print this help and exit");
}

__attribute__((noinline)) int erase_sectors(unsigned first, unsigned count)
{
    if (first + count > 4096) {
        report("Cannot erase past the end of the device");
        return -1;
    }
    report("Erasing sectors");
    flash_control = first;
    return 0;
}

__attribute__((noinline)) int write_image(unsigned length)
{
    if (length == 0) {
        report("The image is empty");
        return -1;
    }
    report("Writing the image");
    flash_control = length;
    return 0;
}

__attribute__((noinline)) int verify_image(unsigned crc, unsigned expected)
{
    if (crc != expected) {
        report("The flash does not hold the image that was written");
        return -1;
    }
    report("Image verified");
    return 0;
}

/* One step of the CRC-32 of the image: the polynomial comes from a literal pool too */
__attribute__((noinline)) unsigned crc32_update(unsigned crc, unsigned char byte)
{
    crc ^= byte;
    for (int bit = 0; bit < 8; bit++) {
        crc = (crc >> 1) ^ (0xedb88320 & -(crc & 1));
    }
    return crc;
}

int main(void)
{
    print_help();
    if (erase_sectors(0, 16) || write_image(flash_control)) {
        return 1;
    }
    return verify_image(crc32_update(0xffffffff, 0x5a), flash_control);
}
