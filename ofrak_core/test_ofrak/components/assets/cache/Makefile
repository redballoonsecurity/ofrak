pyghidra: clean
	python3 -m ofrak_pyghidra analyze -i ../simple_pie_thumb_bin -o simple_pie_thumb_bin
	python3 -m ofrak_pyghidra analyze -i ../simple_arm_gcc.o.elf -o simple_arm_gcc.o.elf
	python3 -m ofrak_pyghidra analyze -i ../hello.out -o hello.out
	python3 -m ofrak_pyghidra analyze -i ../hello_nosections.out -o hello_nosections.out
	python3 -m ofrak_pyghidra analyze -i ../kernel_address_space.out -o kernel_address_space.out
	python3 -m ofrak_pyghidra analyze -i ../arm_reloc_relocated.elf -o arm_reloc_relocated.elf

clean:
	rm -f simple_pie_thumb_bin simple_arm_gcc.o.elf hello.out hello_nosections.out kernel_address_space.out arm_reloc_relocated.elf
