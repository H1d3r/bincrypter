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
USE_PERL=1

# vampiredaddy wants this to work if dd + tr are not available:
if [ -n "$USE_PERL" ]; then
    xdd() { [ -z "$DEBUG" ] && LANG=C perl -e 'read(STDIN,$_, '"$1"'); print;'; }
    xtr() { LANG=C perl -pe 's/['"${1}${2}"']//g;'; }
    xprintf() { LANG=C perl -e "print(\"$1\")"; }
else
    xdd() { [ -z "$DEBUG" ] && dd bs="$1" count=1 2>/dev/null;}
    xtr() { tr -d"${1:+c}" "${2}";}
    xprintf() { printf "$@"; }
fi

err() { echo -e >&2 "${CDR}ERROR${CN}: $*"; exit 255; }
# Obfuscate a string with non-printable characters at random intervals.
# Input must not contain \ (or sh gets confused)
ob64() {
    local i
    local h="$1"
    local str
    local x
    local s

    # Always start with non-printable character
    s=0
    while [ ${#h} -gt 0 ]; do
        i=$((1 + RANDOM % 4))
        str+=${h:0:$s}
        [ ${#x} -le $i ] && x=$(xdd 128 </dev/urandom | xtr '' '[:print:]\0\n\t')
        str+=${x:0:$i}
        x=${x:$i}
        h=${h:$s}
        s=$((1 + RANDOM % 3))
    done
    echo "$str"
}

# Obfuscate a string with `#\b`
obbell() {
    local h="$1"
    local str
    local x
    local s

    [ -n "$DEBUG" ] && { echo "$h"; return; }
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
[ -n "$1" ] && fn="$1"
[ -n "$2" ] && PASSWORD="$2"
[ "$fn" != "-" ] && [ ! -f "$fn" ] && err "File not found: $fn"

# Auto-generate password if not provided
[ -z "$PASSWORD" ] && P="$(DEBUG='' xdd 32 </dev/urandom | openssl base64 | xtr '^' '[:alnum:]' | DEBUG='' xdd 16)"
PASSWORD="${PASSWORD:-$P}"
[ -z "$PASSWORD" ] && err "No PASSWORD=<password> provided and failed to generate one."

HOOK='ZXJyKCkgeyBlY2hvID4mMiAiRVJST1I6ICQqIjsgZXhpdCAyNTU7fQpjKCkgeyBjb21tYW5kIC12ICIkMSIgPi9kZXYvbnVsbHx8ZXJyICJDb21tYW5kIG5vdCBmb3VuZDogJDEiO30KYyBvcGVuc3NsCmMgcGVybApjIGd1bnppcApQQVNTV09SRD0iJHtQQVNTV09SRDotJChlY2hvICIkUCJ8TEFORz1DIHBlcmwgLXBlICdzL1teWzpwcmludDpdXG5dLy9nOyd8b3BlbnNzbCBiYXNlNjQgLWQpfSIKWyAteiAiJFBBU1NXT1JEIiBdICYmIHJlYWQgLXIgLXAgIkVudGVyIHBhc3N3b3JkOiAiIFBBU1NXT1JECnByZz0icGVybCAtZSAnPD47PD47cHJpbnQoPD4pJzwnJDAnfG9wZW5zc2wgZW5jIC1kIC1hZXMtMjU2LWNiYyAtbWQgc2hhMjU2IC1ub3NhbHQgLWsgJyRQQVNTV09SRCcgMj4vZGV2L251bGx8Z3VuemlwIgpMQU5HPUMgZXhlYyBwZXJsICctZSReRj0yNTU7Zm9yKDMxOSwyNzksMzg1LDQzMTQsNDM1NCl7KCRmPXN5c2NhbGwkXywkIiwwKT4wJiZsYXN0fTtvcGVuKCRvLCI+Jj0iLiRmKTtvcGVuKCRpLCInIiRwcmciJ3wiKTtwcmludCRvKDwkaT4pO2Nsb3NlKCRpKTskRU5WeyJMQU5HIn09IiciJExBTkciJyI7ZXhlY3siL3Byb2MvJCQvZmQvJGYifSInIiR7MDotcHl0aG9uM30iJyIsQEFSR1YnIC0tICIkQCIK'
HOOK="$(ob64 "$HOOK")"

[ "$fn" != "-" ] && { 
    s="$(stat -c %s "$fn")"
    [ "$s" -gt 0 ] || err "Empty file: $fn"
}
# Bash strings are not binary safe. Instead, store the binary as base64 in memory:
ifn="$fn"
[ "$fn" = "-" ] && ifn="/dev/stdin"
DATA="$(openssl base64 <"$ifn")" || exit

[ "$fn" = "-" ] && fn="/dev/stdout"

# Create the encrypted binary: /bin/sh + Decrypt-Hook + Encrypted binary
{ 
# printf '#!/bin/sh\0#'
# Add some binary data after shebang, including \0 (sh reads past \0 but does not process. \0\n count as new line).
# dd count="${count:-1}" bs=$((1024 + RANDOM % 1024)) if=/dev/urandom 2>/dev/null| tr -d "[:print:]\n'"
# echo "" # Newline
# => Unfortunately some systems link /bin/sh -> bash.
# 1. Bash checks that the first line is binary free.
# 2. and no \0 in the first 80 bytes (including the #!/bin/sh)
echo '#!/bin/sh'
# Add dummy variable containing garbage (for obfuscation) (2nd line)
echo -n "_='" 
xdd 66 </dev/urandom | xtr '' "[:print:]\0\n'"
xdd "$((1024 + RANDOM % 4096))" </dev/urandom| xtr '' "[:print:]\n'" 
xprintf "' \x00" # alternative to: echo -n "';"
# far far far after garbage
## Add Password (obfuscated) to script (dangerous: readable)
[ -n "$P" ] && echo -n "P=$(ob64 "$(echo "$P"|openssl base64 2>/dev/null)") "
## Add my hook to decrypt/execute binary
# echo "eval \"\$(echo $HOOK|strings -n1|openssl base64 -d)\""
# echo "eval \"\$(echo $HOOK|{ strings -n1;echo;}|openssl base64 -d)\""
# Note: openssl expects \n at the end. Perl filters it. Add it with echo.
echo "$(obbell 'eval "')\$$(obbell '(echo ')$HOOK|{ LANG=C $(obbell "perl -pe \"s/[^[:print:]]//g\";echo");}$(obbell "|openssl base64 -d)")\""
# Add the encrypted binary (from memory)
openssl base64 -d<<<"$DATA" |gzip|openssl enc -aes-256-cbc -md sha256 -nosalt -k "$PASSWORD" 2>/dev/null
} > "$fn"

[ -n "$s" ] && {
    c="$(stat -c %s "$fn")"
    echo -e >&2 "${CDY}Compressed:${CN} ${CDM}$s ${CF}-->${CN}${CDM} $c ${CN}[${CDG}$((c * 100 / s))%${CN}]"
}
