PKG := libnl-3.0 libnl-route-3.0 yaml-0.1 jansson
CC ?= cc
CFLAGS += -std=gnu11 -Wall -Wextra -O2 -g -Iinclude $(shell pkg-config --cflags $(PKG))
LDLIBS += $(shell pkg-config --libs $(PKG))

SRCS := $(wildcard src/*.c)
OBJS := $(SRCS:src/%.c=build/%.o)

ha-dhcpc: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDLIBS)

build/%.o: src/%.c | build
	$(CC) $(CFLAGS) -c -o $@ $<

build:
	mkdir -p build

test: tests_sha256
	./tests_sha256

tests_sha256: tests/sha256_test.c src/sha256.c
	$(CC) $(CFLAGS) -o $@ tests/sha256_test.c src/sha256.c $(LDLIBS)

clean:
	rm -rf build tests_sha256 ha-dhcpc

.PHONY: clean test
