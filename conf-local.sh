#!/bin/bash

./configure --prefix=/opt/local --with-pkcs11-module=/opt/local/lib/p11-kit-proxy.dylib --with-enginesdir=/opt/local/lib/engines CC=clang CFLAGS='-maes -mpclmul -mrdrnd -msse2 -mssse3 -msse4.2 -mtune=native -Os -Ofast' LDFLAGS=-L/opt/local/lib CPPFLAGS=-I/opt/local/include PKG_CONFIG_PATH='/opt/local/lib/pkgconfig:/opt/local/share/pkgconfig:/usr/local/lib/pkgconfig:/usr/lib/pkgconfig' OPENSSL_CFLAGS=-I/opt/local/include OPENSSL_LIBS='-L/opt/local/lib -lssl -lcrypto' --no-create --no-recursion
