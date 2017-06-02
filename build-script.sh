#!/bin/bash -x

make distclean
autoreconf -iv && ./configure --prefix=/opt/local --with-pkcs11-module=/opt/local/lib/p11-kit-proxy.dylib --with-enginesdir=/opt/local/lib/engines && make clean && make all && make check && sudo make install && sudo chown -R uri *

