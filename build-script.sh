#!/bin/bash -ex

# Updated for building with OpenSSL-1.1.1 (Macports moved to OpenSSL v1.1.1)

make distclean || true
autoreconf -iv && ./configure --prefix=/opt/local --with-pkcs11-module=/opt/local/lib/p11-kit-proxy.dylib --with-enginesdir=/opt/local/lib/engines-1.1 && make clean && make all && make check && sudo make install && sudo chown -R uri *

