#! /usr/bin/env bash

# set PASSWORD=<password> to use a specific password. This password will be asked
# for at execution unless provided by PASSWORD=<password> environment variable.

CDR="\033[0;31m" # red
CDG="\033[0;32m" # green
CDY="\033[0;33m" # yellow
CDM="\033[0;35m" # magenta
CDC="\033[0;36m" # cyan
CN="\033[0m"     # none
CF="\033[2m"     # faint

# DEBUG=1
[ -n "$DEBUG" ] && count=0

err() { echo -e >&2 "${CDR}ERROR${CN}: $*"; exit 255; }
# Obfuscate a string with non-printable characters at random intervals.
ob64() {
    local i
    local h="$1"
    local str
    local x
    local s

    while [ ${#h} -gt 0 ]; do
        i=$((1 + RANDOM % 4))
        s=$((1 + RANDOM % 3))
        str+=${h:0:$s}
        [ ${#x} -le $i ] && x=$(dd bs=128 count="${count:-1}" if=/dev/urandom 2>/dev/null | tr -d '[:print:]\000\n')
        str+=${x:0:$i}
        x=${x:$i}
        h=${h:$s}
    done
    echo "$str"
}

# Obfuscate a string with `#\b`
obbell() {
    local h="$1"
    local str
    local x
    local s

    while [ ${#h} -gt 0 ]; do
        s=$((1 + RANDOM % 4))
        str+=${h:0:$s}
        if [ $((RANDOM % 2)) -eq 0 ]; then
            str+='`#'$'\b''`' #backspace
        else
            str+='`:||'$'\a''`' #alert/bell
        fi
        h=${h:$s}
    done
    echo "$str"
}

command -v openssl >/dev/null || err "openssl is required"
fn="-"
[ -t 0 ] && [ $# -eq 0 ] && err "Usage: ${CDC}$0 <file> [<password>]${CN} ${CF}#[use - for stdin]${CN}"
[ -t 0 ] && fn="$1"
[ -n "$2" ] && PASSWORD="$2"
[ "$fn" != "-" ] && [ ! -f "$fn" ] && err "File not found: $fn"

# Auto-generate password if not provided
[ -z "$PASSWORD" ] && {
    _P="$(head -c 32 < /dev/urandom | base64 | tr -dc '[:alnum:]' | head -c 16)"
    echo -e >&2 "${CDY}NOTE:${CN} ${CDM}The password is stored in ${CDC}$fn${CDM} and can easily be recovered.
Use ${CDC}$0 $fn $_P${CDM} otherwise.${CN}"
}
PASSWORD="${PASSWORD:-$_P}"
# [ -z "$_P" ] && echo -e >&2 "Using ${CDY}${PASSWORD}${CN}"
[ -z "$PASSWORD" ] && err "No PASSWORD=<password> provided and failed to generate one."

HOOK='ZXJyKCkgeyBlY2hvID4mMiAiRVJST1I6ICQqIjsgZXhpdCAyNTU7fQpjKCkgeyBjb21tYW5kIC12ICIkMSIgPi9kZXYvbnVsbHx8ZXJyICJDb21tYW5kIG5vdCBmb3VuZDogJDEiO30KYyBvcGVuc3NsCmMgcGVybApjIGd1bnppcApQQVNTV09SRD0iJHtQQVNTV09SRDotJChlY2hvICIkX1AifHN0cmluZ3MgLW4xfG9wZW5zc2wgYmFzZTY0IC1kKX0iClsgLXogIiRQQVNTV09SRCIgXSAmJiByZWFkIC1yIC1wICJFbnRlciBwYXNzd29yZDogIiBQQVNTV09SRApwcmc9InRhaWwgLW4rMyAnJDAnfG9wZW5zc2wgZW5jIC1kIC1hZXMtMjU2LWNiYyAtcGJrZGYyIC1ub3NhbHQgLWsgJyRQQVNTV09SRCd8Z3VuemlwIgpleGVjIHBlcmwgJy1ldXNlIEZjbnRsO2ZvcigzMTksMjc5KXsoJGY9c3lzY2FsbCRfLCQiLDApPjAmJmxhc3R9O29wZW4oJG8sIj4mPSIuJGYpO29wZW4oJGksIiciJHByZyInfCIpO3ByaW50JG8oPCRpPik7Y2xvc2UoJGkpO2ZjbnRsKCRvLEZfU0VURkQsMCk7ZXhlY3siL3Byb2MvJCQvZmQvJGYifSInIiR7MDotcHl0aG9uM30iJyIsQEFSR1YnIC0tICIkQCIK'
HOOK="$(ob64 "$HOOK")"

# Bash strings are not binary safe. Instead, store the binary as base64 in memory:
[ "$fn" != "-" ] && { 
    s="$(stat -c %s "$fn")"
    [ $s -gt 0 ] || err "Empty file: $fn"
}
DATA="$(base64 -w0 "$fn")" || exit

[ "$fn" = "-" ] && fn="/dev/stdout"

# Create the encrypted binary: /bin/sh + Decrypt-Hook + Encrypted binary
{ 
# printf '#!/bin/bash'

printf '#!/bin/sh\0#'
# Add some binary data after shebang, including \0 (sh reads past \0 but does not process. \0\n count as new line).
dd count="${count:-1}" bs=$((1024 + RANDOM % 1024)) if=/dev/urandom 2>/dev/null| tr -d "[:print:]\n'"

echo "" # Newline
# Add dummy variable containing garbage (for obfuscation) (2nd line)
echo -n "_='" 
dd count="${count:-1}" bs=$((1024 + RANDOM % 4096)) if=/dev/urandom 2>/dev/null| tr -d "[:print:]\n'" 
echo -n "';"
# far far far after garbage
## Add Password (obfuscated) to script (dangerous: readable)
[ -n "$_P" ] && echo -n "_P='$(ob64 "$(echo "$_P"|openssl base64 2>/dev/null)")' "
## Add my hook to decrypt/execute binary
# echo "eval \"\$(echo $HOOK|strings -n1|openssl base64 -d)\""
# echo "$(obbell 'eval "')\$($(obbell 'echo ')$HOOK$(obbell '|strings -n1|openssl base64 -d'))\""
echo "$(obbell 'eval "')\$$(obbell '(echo ')$HOOK$(obbell '|strings -n1|openssl base64 -d'))\""
# Add the encrypted binary (from memory)
base64 -d<<<"$DATA" |gzip|openssl enc -aes-256-cbc -pbkdf2 -nosalt -k "$PASSWORD"
} > "$fn"

[ -n "$s" ] && {
    c="$(stat -c %s "$fn")"
    echo -e >&2 "${CDY}Compressed:${CN} ${CDM}$s ${CF}-->${CN}${CDM} $c ${CN}[${CDG}$((c * 100 / s))%${CN}]"
    echo -e >&2 "${CDY}>>> ${CDG}$(ls -al "$fn")${CN}"
}
