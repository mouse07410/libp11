#!/bin/bash -e

#DEBUG=-g

make distclean || true

# Updated for building with OpenSSL-1.1.1 (Macports moved to OpenSSL v1.1.1)
autoreconf -iv && CFLAGS="$CFLAGS ${DEBUG}" LDFLAGS="${DEBUG} $LDFLAGS" ./configure --disable-silent-rules \
	--prefix=/opt/local \
	--with-pkcs11-module=/opt/local/lib/p11-kit-proxy.dylib \
	--with-enginesdir=/opt/local/libexec/openssl11/lib/engines-1.1 && make clean && make all && make check 
sudo make install && sudo chown -R ${USER} *

if [ -z "$CI" ]; then
	if [ -e /opt/local/libexec/openssl11/lib/engines-1.1/pkcs11.dylib ]; then
        sudo ln -sf /opt/local/libexec/openssl11/lib/engines-1.1/pkcs11.dylib /opt/local/lib/engines-1.1/
        security unlock-keychain
		sudo codesign -s "Apple Development: uri@mit.edu (7TWWJNH7TG)" /opt/local/lib/engines-1.1/pkcs11.dylib
	fi
fi
