# To build, install lz4 from https://github.com/lz4/lz4 and run "make all".
LZ4 = lz4

all: default.lz4 no_frame_crc.lz4 with_size.lz4 legacy.lz4 \
     block_checksum.lz4 block_dependency.lz4 high_compression.lz4 \
     large_block.lz4 small_block.lz4 combined_flags.lz4 \
     ultra_fast.lz4 best_compression.lz4

default.lz4:
	$(LZ4) input.txt default.lz4

no_frame_crc.lz4:
	$(LZ4) --no-frame-crc input.txt no_frame_crc.lz4

with_size.lz4:
	$(LZ4) --content-size input.txt with_size.lz4

legacy.lz4:
	$(LZ4) -l large_input.txt legacy.lz4

block_checksum.lz4:
	$(LZ4) -BX input.txt block_checksum.lz4

block_dependency.lz4:
	$(LZ4) -BD input.txt block_dependency.lz4

high_compression.lz4:
	$(LZ4) -9 large_input.txt high_compression.lz4

large_block.lz4:
	$(LZ4) -B7 input.txt large_block.lz4

small_block.lz4:
	$(LZ4) -B4 input.txt small_block.lz4

combined_flags.lz4:
	$(LZ4) --content-size -BX input.txt combined_flags.lz4

ultra_fast.lz4:
	$(LZ4) --fast large_input.txt ultra_fast.lz4

best_compression.lz4:
	$(LZ4) --best large_input.txt best_compression.lz4
