#!/bin/bash -ex

unset OPENSSL_CFLAGS
unset OPENSSL_LIBS
unset LDFLAGS
unset CPPFLAGS

DEBUG="-g"

make distclean || true

# Build libp11 flexible, using URI via p11-kit

# Build libp11 fixed for OpenSC PKCS#11 library (seems necessary for OpenSSL-3.0 master)
autoreconf -ivf 
OPENSSL_CFLAGS="${CFLAGS} ${DEBUG} -I${HOME}/openssl-3/include" OPENSSL_LIBS="-L${HOME}/openssl-3/lib -lssl -lcrypto" LDFLAGS="-g" CPPFLAGS="${DEBUG}" ./configure --disable-silent-rules --prefix=${HOME}/openssl-3 --with-pkcs11-module=/Library/OpenSC/lib/opensc-pkcs11.dylib --with-enginesdir="${HOME}/openssl-3/lib/engines-3/"  2>&1 | tee conf-3-out.txt && make clean && make -j 2  all 2>&1 | tee make-3-out.txt && make check 2>&1 check-3-out.txt && make install

#
