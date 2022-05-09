#!/bin/bash

make distclean || true

# build engine for Macports-installed OpenSSL-3
make distclean || true
O_DIR="/opt/local/libexec/openssl3"
E_DIR="/opt/local/libexec/openssl3/lib/engines-3"
THREE="3m-" OPENSSL_DIR=${O_DIR} ENGINESDIR=${E_DIR} ./build-3.sh 2>&1 | tee ossl3m-build.txt
sudo make install
if [ -z "$CI" ]; then
	if [ -e ${E_DIR}/pkcs11.dylib ]; then
		sudo codesign -s "Apple Development: uri@mit.edu (7TWWJNH7TG)" ${E_DIR}/pkcs11.dylib
		sudo rm /opt/local/lib/engines-3/pkcs11.dylib
		sudo ln -sf ${E_DIR}/pkcs11.dylib /opt/local/lib/engines-3/
	fi
fi

exit 0
#
