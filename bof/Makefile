CC64 := x86_64-w64-mingw32-gcc
STRIP64 := x86_64-w64-mingw32-strip
CFLAGS := -c -Os -std=gnu11 -fms-extensions -fdollars-in-identifiers \
	-Wno-incompatible-pointer-types -Wno-int-conversion -Wno-unused-parameter
INC := -I .

.PHONY: all clean

all: mesh_install.x64.o

mesh_install.x64.o: mesh_install.c beacon.h
	$(CC64) $(CFLAGS) $(INC) -o $@ mesh_install.c
	-$(STRIP64) --strip-unneeded $@

clean:
	rm -f mesh_install.x64.o ObjectFiles/*.o
