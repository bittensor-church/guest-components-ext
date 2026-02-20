ARCH ?= $(shell uname -m)
LIBC ?= gnu
DEBUG ?=
DESTDIR ?= /usr/local/bin
RUSTFLAGS_ARGS ?=

ifeq ($(LIBC), musl)
    MUSL_ADD := $(shell rustup target add ${ARCH}-unknown-linux-musl)
endif

LIBC_FLAG := --target $(ARCH)-unknown-linux-$(LIBC)
TARGET_DIR := target/$(ARCH)-unknown-linux-$(LIBC)

ifdef DEBUG
    release :=
    TARGET_DIR := $(TARGET_DIR)/debug
else
    release := --release
    TARGET_DIR := $(TARGET_DIR)/release
endif

ifneq ($(RUSTFLAGS_ARGS),)
    RUST_FLAGS := RUSTFLAGS="$(RUSTFLAGS_ARGS)"
endif

KLP_BINARY := $(TARGET_DIR)/kbs-local-provider
AAI_BINARY := $(TARGET_DIR)/attestation-agent-init

build: $(KLP_BINARY) $(AAI_BINARY)
	@echo guest-components-ext built successfully

$(KLP_BINARY):
	$(RUST_FLAGS) cargo build $(release) $(LIBC_FLAG) -p kbs-local-provider

$(AAI_BINARY):
	$(RUST_FLAGS) cargo build $(release) $(LIBC_FLAG) -p attestation-agent-init

install: build
	install -D -m0755 $(KLP_BINARY) $(DESTDIR)/kbs-local-provider
	install -D -m0755 $(AAI_BINARY) $(DESTDIR)/attestation-agent-init

clean:
	cargo clean

help:
	@echo "build: make [DEBUG=1] [LIBC=(gnu|musl)] [ARCH=x86_64]"
	@echo "install: make install [DESTDIR=/path/to/target] [LIBC=(gnu|musl)]"
