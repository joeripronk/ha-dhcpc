# Native build: make
# Cross build (OpenWrt ARM):
#   make CROSS_COMPILE=$(ls .../staging_dir/toolchain-*/bin/*-linux-*- | grep gcc-$ | head -1 | sed 's/-gcc$//') \
#        SYSROOT=.../staging_dir/target-arm_*/rootfs-arm_*
# i.e. the SDK toolchain prefix and the target rootfs; deps libnl/jansson/libyaml
# must be installed into the target rootfs (all are OpenWrt packages).
PKG := libnl-3.0 libnl-route-3.0 yaml-0.1 jansson
CROSS_COMPILE ?=
SYSROOT ?=
ifneq ($(CROSS_COMPILE),)
CC := $(CROSS_COMPILE)gcc
endif
SYSROOT_FLAGS := $(if $(SYSROOT),--sysroot=$(SYSROOT))
PKGENV := $(if $(SYSROOT),PKG_CONFIG_SYSROOT_DIR=$(SYSROOT) PKG_CONFIG_PATH=$(SYSROOT)/usr/lib/pkgconfig)
PKG_CONFIG ?= pkg-config
override CFLAGS += -std=gnu11 -D_GNU_SOURCE -Wall -Wextra -O2 -g -Iinclude -Isrc -Isrc/dhcp -MMD -MP $(SYSROOT_FLAGS) $(shell $(PKGENV) $(PKG_CONFIG) --cflags $(PKG))
override LDLIBS += $(shell $(PKGENV) $(PKG_CONFIG) --libs $(PKG)) $(LDFLAGS)

SRCS := $(wildcard src/*.c) $(wildcard src/dhcp/*.c)
OBJS := $(patsubst src/%.c,build/%.o,$(SRCS))

ha-dhcpc: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDLIBS)

build/%.o: src/%.c | build
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

build:
	mkdir -p build

test: tests_sha256 tests_persist
	./tests_sha256
	./tests_persist

tests_sha256: tests/sha256_test.c src/sha256.c
	$(CC) $(CFLAGS) -o $@ tests/sha256_test.c src/sha256.c $(LDLIBS)

tests_persist: tests/persist_test.c src/persist.c src/log.c
	$(CC) $(CFLAGS) -o $@ tests/persist_test.c src/persist.c src/log.c $(LDLIBS)

clean:
	rm -rf build tests_sha256 tests_persist ha-dhcpc

-include $(OBJS:.o=.d)

.PHONY: clean test
