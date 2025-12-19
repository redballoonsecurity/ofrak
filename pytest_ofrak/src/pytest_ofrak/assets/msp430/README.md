Goal: build an MSP430 minimal example to test the disassembler backend support.

This simple blink source code was only slightly modified from https://adventurist.me/posts/0040.

The toolchain to build this test file downloaded from https://www.ti.com/tool/MSP430-GCC-OPENSOURCE.

Here are the instructions for installing and building that example:
```
$ wget https://dr-download.ti.com/software-development/ide-configuration-compiler-or-debugger/MD-LlCjWuAbzH/9.3.1.2/msp430-gcc-9.3.1.11_linux64.tar.bz2
$ tar xf msp430-gcc-9.3.1.11_linux64.tar.bz2
$ sudo mkdir -p /opt/ti/msp430
$ sudo mv msp430-gcc-9.3.1.11_linux64 /opt/ti/msp430/gcc
$ vim ~/.bashrc
export PATH=$PATH:/opt/ti/msp430/gcc/bin
$ source ~/.bashrc
$ rm msp430-gcc-9.3.1.11_linux64.tar.bz2
$ wget https://dr-download.ti.com/software-development/ide-configuration-compiler-or-debugger/MD-LlCjWuAbzH/9.3.1.2/msp430-gcc-support-files-1.212.zip
$ unzip -a msp430-gcc-support-files-1.212.zip
$ mv msp430-gcc-support-files/include/*.ld /opt/ti/msp430/gcc/msp430-elf/lib/
$ mv msp430-gcc-support-files/include/*.h /opt/ti/msp430/gcc/include/
$ rm -rf msp430-gcc-support-files*
$ make
```
