example_8.tar.gz: example_8_inner.tar.gz
	tar -czvf example_8.tar.gz example_8_inner.tar.gz

example_8_inner.tar.gz: hello_world.txt
	tar -czvf example_8_inner.tar.gz hello_world.txt

hello_world.txt:
	echo "Hello, world\!" > hello_world.txt

.PHONY: clean
clean:
	rm -rf hello_world.txt example_8_inner.tar.gz example_8.tar.gz
