#!/bin/bash -ex

DEBUG=-g

make distclean || true
autoreconf -iv && CFLAGS="$CFLAGS ${DEBUG}" LDFLAGS="${DEBUG} $LDFLAGS" ./configure --disable-silent-rules --prefix=/opt/local --with-pkcs11-module=/opt/local/lib/p11-kit-proxy.dylib --with-enginesdir=/opt/local/lib/engines-1.1 && make clean && make all && make check && sudo make install && sudo chown -R ur20980 *

