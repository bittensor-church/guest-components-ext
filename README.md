# guest-components-ext

Extensions for [guest-components](https://github.com/confidential-containers/guest-components) used in confidential containers.

## Components

- **kbs-local-provider (KLP)** - Local resource provider for KBS
- **attestation-agent-init (AAI)** - Initialization helper for the attestation agent

## Build

```sh
make
```

Build options:

```sh
make DEBUG=1          # debug build
make LIBC=musl        # musl instead of gnu
make ARCH=x86_64      # target architecture
```

## Install

```sh
make install                        # default: /usr/local/bin
make install DESTDIR=/custom/path   # custom destination
```
