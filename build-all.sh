#!/bin/bash

make distclean || true

## build engine for Macports-installed OpenSSL-1.1.1
O_DIR="/opt/local/libexec/openssl11"
E_DIR="/opt/local/libexec/openssl11/lib/engines-1.1"
THREE="" OPENSSL_DIR=${O_DIR} ENGINESDIR=${E_DIR} ./build-3.sh 2>&1 | tee ossl1-build.txt
sudo make install
if [ -z "$CI" ]; then
	if [ -e ${E_DIR}/pkcs11.dylib ]; then
	sudo codesign -s "Apple Development: uri@mit.edu (7TWWJNH7TG)" ${E_DIR}/pkcs11.dylib
		sudo rm /opt/local/lib/engines-1.1/pkcs11.dylib
		sudo ln -sf ${E_DIR}/pkcs11.dylib /opt/local/lib/engines-1.1/
	fi
fi

# build engine for Macports-installed OpenSSL-3.0.0
make distclean || true
O_DIR="/opt/local/libexec/openssl3"
E_DIR="/opt/local/libexec/openssl3/lib/engines-3"
THREE="3m-" OPENSSL_DIR=${O_DIR} ENGINESDIR=${E_DIR} ./build-3.sh 2>&1 | tee ossl3m-build.txt
sudo make install
if [ -z "$CI" ]; then
	if [ -e ${E_DIR}/pkcs11.dylib ]; then
		sudo codesign -s "Apple Development: Uri Blumenthal (UU7Y5L3S5L)" ${E_DIR}/pkcs11.dylib
		sudo rm /opt/local/lib/engines-3/pkcs11.dylib
		sudo ln -sf ${E_DIR}/pkcs11.dylib /opt/local/lib/engines-3/
	fi
fi

# Build engine for locally-tracked OpenSSL-3 master
make distclean || true
O_DIR="/Users/ur20980/openssl-3/"
E_DIR="${O_DIR}/lib/engines-3"
THREE="3-" OPENSSL_DIR="" ENGINESDIR="" ./build-3.sh 2>&1 | tee ossl3-build.txt
make install
if [ -z "$CI" ]; then
	if [ -e ${E_DIR}/pkcs11.dylib ]; then
		codesign -s "Apple Development: Uri Blumenthal (UU7Y5L3S5L)" ${E_DIR}/pkcs11.dylib
	fi
fi

date

exit 0
#
