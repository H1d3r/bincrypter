#! /bin/bash

# TO test use:
# CMD=id
# CMD=bash
# src/make.sh && cp "$(command -v ${CMD:?})" "${CMD##*/}" && ./bincrypter.sh "${CMD##*/}" && ./"${CMD##*/}"

cd "$(dirname "$0")" || exit 1

# Create bincrypter.sh
grep -v ^#X bin_stub >../bincrypter.sh
sed -i "s|%%HOOK%%|$(grep -v ^# <hook_stub | base64 -w0)|" ../bincrypter.sh
chmod 755 ../bincrypter.sh