#!/bin/bash -ex

unset OPENSSL_CFLAGS
unset OPENSSL_LIBS
unset LDFLAGS
unset CPPFLAGS

DEBUG="-g"

make distclean || true

# Build libp11 flexible, using URI via p11-kit
#autoreconf -ivf && OPENSSL_CFLAGS="${CFLAGS} -I${HOME}/openssl-1.1/include" OPENSSL_LIBS="-L${HOME}/openssl-1.1/lib -lssl -lcrypto" LDFLAGS="-g" CPPFLAGS="${DEBUG}" ./configure --disable-silent-rules --prefix=${HOME}/openssl-1.1 --with-pkcs11-module=/opt/local/lib/p11-kit-proxy.dylib --with-enginesdir=${HOME}/openssl-1.1/lib/engines-3/ && make clean && make -j 2  all && make check && make install

# Build libp11 fixed for OpenSC PKCS#11 library (seems necessary for OpenSSL-3.0 master)
autoreconf -iv && OPENSSL_CFLAGS="${CFLAGS} ${DEBUG} -I${HOME}/openssl-1.1/include" OPENSSL_LIBS="-L${HOME}/openssl-1.1/lib -lssl -lcrypto" LDFLAGS="-g" CPPFLAGS="${DEBUG}" ./configure --disable-silent-rules --prefix=${HOME}/openssl-1.1 --with-pkcs11-module=/Library/OpenSC/lib/opensc-pkcs11.dylib --with-enginesdir=${HOME}/openssl-1.1/lib/engines-3/ && make clean && make -j 2  all && make check && make install

