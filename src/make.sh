#! /bin/bash

# Creates bincrypter.sh

# TO test use:
# CMD=id
# CMD=bash
# src/make.sh && cp "$(command -v ${CMD:?})" "${CMD##*/}" && ./bincrypter.sh "${CMD##*/}" && ./"${CMD##*/}"

set -e
cd "$(dirname "$0")"

# 1. Backward compatibility with old systems which don't have -pbkdf2.
# 2. Use nosalt to avoid known patterns. Instead, add a SALT to the password.
#    -k <SALT>-<PASSWORD> (SALT is random, PASSWORD is user defined)
osslopts='-aes-256-cbc -md sha256 -nosalt -k'
# osslopts='-aes-256-cbc -pbkdf2 -nosalt -k'

grep -v ^#X bin_stub >../bincrypter.sh
hook_str="$(grep -v '^\s*$\|^\s*\#'<hook_stub |sed 's/#.*$//'|sed "s|%%SSL_OPTS%%|${osslopts}|"| openssl base64 -A)"
# sed -i "s|%%HOOK%%|${hook_str}|; s/%%SSL_OPTS%%/${osslopts}/; /%%BC_ID_HOOK%%/r bc_id_stub" ../bincrypter.sh
sed -i "s|%%HOOK%%|${hook_str}|; s/%%SSL_OPTS%%/${osslopts}/" ../bincrypter.sh
# bc_id_hook_str="$(grep -v '^\s*$\|^\s*\#'<bc_id_stub |sed 's/#.*$//'| openssl base64 -A)"
# sed -i "s/%%HOOK%%/${hook_str}/; s/%%SSL_OPTS%%/${osslopts}/; s/%%BC_ID_HOOK%%/${bc_id_hook_str}/" ../bincrypter.sh
chmod 755 ../bincrypter.sh
