#!/bin/bash -ex

make distclean || true

unset OPENSSL_INCLUDE_DIR
unset OPENSSL_LIB_DIR
unset OPENSSL_CFLAGS
unset OPENSSL_LIBS
unset OPENSSL_LIB_DIR
unset OPENSSL_INCLUDE_DIR
unset OPENSSL_CONF
unset LDFLAGS
unset CPPFLAGS

DEBUG="-g"

if [ "z${OPENSSL_DIR}" == "z" ]; then
  OPENSSL_DIR="${HOME}/openssl-3"
  export PATH="${OPENSSL_DIR}/openssl-3/bin:${PATH}"
  export OPENSSL="${OPENSSL_DIR}/bin/openssl"
fi
if [ "z${ENGINESDIR}" == "z" ]; then
  ENGINESDIR="${OPENSSL_DIR}/lib/engines-3"
fi

if [ "z${THREE}" == "z" ]; then
    THREE=""
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

# Build libp11 flexible, using URI via p11-kit

# Build libp11 fixed for OpenSC PKCS#11 library (seems necessary for OpenSSL-3.0 master)
autoreconf -ivf 
./configure --disable-silent-rules --prefix=${OPENSSL_DIR} --with-pkcs11-module=/opt/local/lib/p11-kit-proxy.dylib --with-enginesdir="${ENGINESDIR}/"  2>&1 | tee conf-${THREE}out.txt && make clean && make -j 2  all 2>&1 | tee make-${THREE}out.txt && OPENSSL_DIR="${OPENSSL_DIR}" make check 2>&1 | tee check-${THREE}out.txt
# && make install

#if [ -z "$CI" ]; then
#	if [ -e ${ENGINESDIR}/pkcs11.dylib ]; then
#		codesign -s "Apple Development: uri@mit.edu (7TWWJNH7TG)" ${ENGINESDIR}/pkcs11.dylib
#	fi
#fi
#
