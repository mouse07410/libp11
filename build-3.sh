#!/bin/bash -ex

unset OPENSSL_CFLAGS
unset OPENSSL_LIBS
unset LDFLAGS
unset CPPFLAGS

DEBUG="-g"

if [ "z${OPENSSL_DIR}" == "z" ]; then
  OPENSSL_DIR="${HOME}/openssl-3"
fi
if [ "z${ENGINESDIR}" == "z" ]; then
  ENGINESDIR="${OPENSSL_DIR}/lib/engines-3"
fi

echo ""
echo "OPENSSL_DIR=${OPENSSL_DIR}"
echo "ENGINESDIR=${ENGINESDIR}"
echo ""

export OPENSSL_CFLAGS="${CFLAGS} ${DEBUG} -I${OPENSSL_DIR}/include"
export OPENSSL_LIBS="-L${OPENSSL_DIR}/lib -lssl -lcrypto"
export LDFLAGS="${DEBUG} "
export CPPFLAGS="${DEBUG} "
export PKG_CONFIG_PATH="${OPENSSL_DIR}/lib/pkgconfig:${PKG_CONFIG_PATH}"

make distclean || true

# Build libp11 flexible, using URI via p11-kit

# Build libp11 fixed for OpenSC PKCS#11 library (seems necessary for OpenSSL-3.0 master)
autoreconf -ivf 
./configure --disable-silent-rules --prefix=${OPENSSL_DIR} --with-pkcs11-module=/Library/OpenSC/lib/opensc-pkcs11.dylib --with-enginesdir="${ENGINESDIR}/"  2>&1 | tee conf-3-out.txt && make clean && make -j 2  all 2>&1 | tee make-3-out.txt && make check 2>&1 | tee check-3-out.txt && make install

if [ -z "$CI" ]; then
	if [ -e ${ENGINESDIR}/pkcs11.dylib ]; then
		codesign -s "Mac Developer: uri@mit.edu (7TWWJNH7TG)" ${ENGINESDIR}/pkcs11.dylib
	fi
fi
#
