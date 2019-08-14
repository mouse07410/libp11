#!/bin/bash -ex

unset OPENSSL_CFLAGS
unset OPENSSL_LIBS
unset LDFLAGS
unset CPPFLAGS

DEBUG="-g"

export OPENSSL_DIR="$HOME/openssl-3"

export OPENSSL_CFLAGS="${CFLAGS} ${DEBUG} -I${OPENSSL_DIR}/include"
export OPENSSL_LIBS="-L${OPENSSL_DIR}/lib -lssl -lcrypto"
export LDFLAGS="${DEBUG} "
export CPPFLAGS="${DEBUG} "
export PKG_CONFIG_PATH="${OPENSSL_DIR}/lib/pkgconfig:${PKG_CONFIG_PATH}"

make distclean || true

# Build libp11 flexible, using URI via p11-kit

# Build libp11 fixed for OpenSC PKCS#11 library (seems necessary for OpenSSL-3.0 master)
autoreconf -ivf 
./configure --disable-silent-rules --prefix=${OPENSSL_DIR} --with-pkcs11-module=/Library/OpenSC/lib/opensc-pkcs11.dylib --with-enginesdir="${OPENSSL_DIR}/lib/engines-3/"  2>&1 | tee conf-3-out.txt && make clean && make -j 2  all 2>&1 | tee make-3-out.txt && make check 2>&1 check-3-out.txt && make install

#
