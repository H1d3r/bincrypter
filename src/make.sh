#! /bin/bash

# Create bincrypter.sh

# TO test use:
# CMD=id
# CMD=bash
# src/make.sh && cp "$(command -v ${CMD:?})" "${CMD##*/}" && ./bincrypter.sh "${CMD##*/}" && ./"${CMD##*/}"

cd "$(dirname "$0")" || exit 1

# Backward compatibility with old systems which don't have -pbkdf2:
osslopts='-aes-256-cbc -md sha256 -nosalt -k'
# osslopts='-aes-256-cbc -pbkdf2 -nosalt -k'

grep -v ^#X bin_stub >../bincrypter.sh
sed -i "s/%%HOOK%%/$(grep -v ^# <hook_stub |sed "s|%%SSL_OPTS%%|${osslopts}|"| base64 -w0)/; s/%%SSL_OPTS%%/${osslopts}/" ../bincrypter.sh
chmod 755 ../bincrypter.sh