COMPILER = gcc
FILESYSTEM_FILES = lsysfs.c
CFLAGS = -D_FILE_OFFSET_BITS=64 `pkg-config fuse --cflags` -lssl -lcrypto

build: $(FILESYSTEM_FILES)
	$(COMPILER) $(CFLAGS) $(FILESYSTEM_FILES) -o lsysfs `pkg-config fuse --libs`
	echo 'To Mount: ./lsysfs -f [mount point]'

clean:
	rm ssfs
