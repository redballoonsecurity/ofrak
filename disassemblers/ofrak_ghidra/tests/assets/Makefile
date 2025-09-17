pyghidra: clean fib-pyghidra fib-thumb-pyghidra hello.x64.elf-pyghidra

fib-pyghidra:
	python3 -m ofrak_pyghidra analyze -i fib -o fib.json

fib-thumb-pyghidra:
	python3 -m ofrak_pyghidra analyze -i fib_thumb -o fib_thumb.json

hello.x64.elf-pyghidra:
	python3 -m ofrak_pyghidra analyze -i hello.x64.elf -o hello.x64.elf.json -d

clean:
	rm -f fib.json fib_thumb.json hello.x64.elf.json 
