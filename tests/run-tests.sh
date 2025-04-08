#! /usr/bin/env bash

TEST_PASSWORD="1234567890"

set -e
command -v bincrypter >/dev/null

cat >test.sh <<'EOF'
#!/bin/bash
BC_TEST=1
echo "Output $BC_TEST"
[ $# -ne 0 ] && exit 244
:
EOF
chmod +x test.sh

echo ">>> Test: File"
cp test.sh t.sh
chmod +x t.sh
bincrypter t.sh
unset BC_TEST
./t.sh
set +e
./t.sh 244
[ $? -ne 244 ] && { echo "Error code is not 244"; exit 255; }
set -e
source ./t.sh
[ "$BC_TEST" -ne 1 ] && exit 255

echo ">>> Test: Pipe"
cat test.sh | bincrypter >t.sh
chmod +x t.sh
unset BC_TEST
ls -al test.sh t.sh
./t.sh
source ./t.sh
[ "$BC_TEST" -ne 1 ] && exit 255

echo ">>> Test: Double"
cp test.sh t.sh
chmod +x t.sh
bincrypter t.sh 
bincrypter t.sh 
./t.sh

echo ">>> Test: Triple Pipe"
cat test.sh | bincrypter | bincrypter | bincrypter >t.sh
chmod +x t.sh
./t.sh

echo ">>> Test: Set password (by environment variable)"
cp test.sh t.sh; chmod +x t.sh
PASSWORD="${TEST_PASSWORD}" ./bincrypter t.sh
PASSWORD="${TEST_PASSWORD}" ./t.sh
echo "${TEST_PASSWORD}" | ./t.sh 2>/dev/null

echo ">>> Test: Set password (by command line)"
cp test.sh t.sh; chmod +x t.sh
bincrypter t.sh "${TEST_PASSWORD}"
PASSWORD="${TEST_PASSWORD}" ./t.sh
echo "${TEST_PASSWORD}" | ./t.sh 2>/dev/null

echo ">>> Test: Password by env (nested) & Double pipe"
PASSWORD="${TEST_PASSWORD}" ./bincrypter <test.sh | bincrypter - "${TEST_PASSWORD}" >t.sh
BCP="${TEST_PASSWORD}" ./t.sh

:
