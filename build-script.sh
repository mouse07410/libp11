#!/bin/bash -ex

make distclean || true
autoreconf -iv && CFLAGS="$CFLAGS -g" LDFLAGS="-g $LDFLAGS" ./configure --disable-silent-rules --prefix=/opt/local --with-pkcs11-module=/opt/local/lib/p11-kit-proxy.dylib --with-enginesdir=/opt/local/lib/engines && make clean && make all && make check && sudo make install && sudo chown -R uri *

