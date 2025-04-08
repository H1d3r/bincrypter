#! /usr/bin/env bash

# set PASSWORD=<password> to use a specific password. This password will be asked
# for at execution unless provided by PASSWORD=<password> environment variable.
#
# https://github.com/hackerschoice/bincrypter

CDR="\033[0;31m" # red
CDG="\033[0;32m" # green
CDY="\033[0;33m" # yellow
CDM="\033[0;35m" # magenta
CDC="\033[0;36m" # cyan
CN="\033[0m"     # none
CF="\033[2m"     # faint

# %%BEGIN_BC_FUNC%%
bincrypter() {
    local str ifn fn s c DATA P _P S HOOK _PASSWORD
    # local DEBUG=1
    local USE_PERL=1

    # vampiredaddy wants this to work if dd + tr are not available:
    if [ -n "$USE_PERL" ]; then
        _bc_xdd() { [ -z "$DEBUG" ] && LANG=C perl -e 'read(STDIN,$_, '"$1"'); print;'; }
        _bc_xtr() { LANG=C perl -pe 's/['"${1}${2}"']//g;'; }
        _bc_xprintf() { LANG=C perl -e "print(\"$1\")"; }
    else
        _bc_xdd() { [ -z "$DEBUG" ] && dd bs="$1" count=1 2>/dev/null;}
        _bc_xtr() { tr -d"${1:+c}" "${2}";}
        _bc_xprintf() { printf "$@"; }
    fi

    _bc_err() { echo -e >&2 "${CDR}ERROR${CN}: $*"; exit 255; }
    # Obfuscate a string with non-printable characters at random intervals.
    # Input must not contain \ (or sh gets confused)
    _bc_ob64() {
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
            [ ${#x} -le $i ] && x=$(_bc_xdd 128 </dev/urandom | _bc_xtr '' '[:print:]\0\n\t')
            str+=${x:0:$i}
            x=${x:$i}
            h=${h:$s}
            s=$((1 + RANDOM % 3))
        done
        echo "$str"
    }

    # Obfuscate a string with `#\b`
    _bc_obbell() {
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

    command -v openssl >/dev/null || _bc_err "openssl is required"
    fn="-"
    [ -t 0 ] && [ $# -eq 0 ] && _bc_err "Usage: ${CDC}$0 <file> [<password>]${CN} ${CF}#[use - for stdin]${CN}"
    [ -n "$1" ] && fn="$1"
    [ "$fn" != "-" ] && [ ! -f "$fn" ] && _bc_err "File not found: $fn"

    # Auto-generate password if not provided
    _PASSWORD="${2:-${BCP:-$PASSWORD}}"
    [ -z "$_PASSWORD" ] && P="$(DEBUG='' _bc_xdd 32 </dev/urandom | openssl base64 -A | _bc_xtr '^' '[:alnum:]' | DEBUG='' _bc_xdd 16)"
    _P="${_PASSWORD:-$P}"
    [ -z "$_P" ] && _bc_err "No ${CDC}PASSWORD=<password>${CN} provided and failed to generate one."
    unset _PASSWORD

    # Auto-generate SALT
    S="$(DEBUG='' _bc_xdd 32 </dev/urandom | openssl base64 -A | _bc_xtr '^' '[:alnum:]' | DEBUG='' _bc_xdd 16)"

    HOOK='Zm9yIHggaW4gb3BlbnNzbCBwZXJsIGd1bnppcDsgZG8KICAgIGNvbW1hbmQgLXYgIiR4IiA+L2Rldi9udWxsIHx8IHsgZWNobyA+JjIgIkVSUk9SOiBDb21tYW5kIG5vdCBmb3VuZDogJHgiOyByZXR1cm4gMjU1OyB9CmRvbmUKX1BBU1NXT1JEPSIke0JDUDotJFBBU1NXT1JEfSIKWyAtbiAiJFAiIF0gJiYgewogICAgX1BBU1NXT1JEPSIkKGVjaG8gIiRQInxMQU5HPUMgcGVybCAtcGUgJ3MvW15bOnByaW50Ol1cbl0vL2c7J3xvcGVuc3NsIGJhc2U2NCAtQSAtZCkiCiAgICB1bnNldCBQCn0KWyAteiAiJF9QQVNTV09SRCIgXSAmJiB7CiAgICBlY2hvID4mMiAtbiAiRW50ZXIgcGFzc3dvcmQ6ICIKICAgIHJlYWQgLXIgX1BBU1NXT1JECn0KaWYgWyAtbiAiJFpTSF9WRVJTSU9OIiBdOyB0aGVuCiAgICBbICIkWlNIX0VWQUxfQ09OVEVYVCIgIT0gIiR7WlNIX0VWQUxfQ09OVEVYVCUiOmZpbGU6Iip9IiBdICYmIGZuPSIkMCIKZWxpZiBbIC1uICIkQkFTSF9WRVJTSU9OIiBdOyB0aGVuCiAgICAocmV0dXJuIDAgMj4vZGV2L251bGwpICYmIGZuPSIke0JBU0hfU09VUkNFWzBdfSIKZWxzZQogICAgWyAhIC1mICIkMCIgXSAmJiB7IGVjaG8gPiYyICdFUlJPUjogU2hlbGwgbm90IHN1cHBvcnRlZC4gVXNlIEJhc2ggb3IgWnNoIGluc3RlYWQuJzsgcmV0dXJuIDI1NTsgfQpmaQpwcmc9InBlcmwgLWUgJzw+Ozw+O3ByaW50KDw+KSc8JyR7Zm46LSQwfSd8b3BlbnNzbCBlbmMgLWQgLWFlcy0yNTYtY2JjIC1tZCBzaGEyNTYgLW5vc2FsdCAtayAnJHtTfS0ke19QQVNTV09SRH0nIDI+L2Rldi9udWxsfGd1bnppcCIKWyAtbiAiJGZuIiBdICYmIHsKICAgIGV2YWwgInVuc2V0IF8gX1BBU1NXT1JEIFMgcHJnIGZuOyQoTEFORz1DIHBlcmwgLWUgJzw+Ozw+O3ByaW50KDw+KSc8IiR7Zm59InxvcGVuc3NsIGVuYyAtZCAtYWVzLTI1Ni1jYmMgLW1kIHNoYTI1NiAtbm9zYWx0IC1rICIke1N9LSR7X1BBU1NXT1JEfSIgMj4vZGV2L251bGx8Z3VuemlwKSIKICAgIHJldHVybgp9CnVuc2V0IF8gUEFTU1dPUkQgUyAKTEFORz1DIGV4ZWMgcGVybCAnLWUkXkY9MjU1O2ZvcigzMTksMjc5LDM4NSw0MzE0LDQzNTQpeygkZj1zeXNjYWxsJF8sJCIsMCk+MCYmbGFzdH07b3BlbigkbywiPiY9Ii4kZik7b3BlbigkaSwiJyIkcHJnIid8Iik7cHJpbnQkbyg8JGk+KTtjbG9zZSgkaSl8fGV4aXQoJD8vMjU2KTskRU5WeyJMQU5HIn09IiciJExBTkciJyI7ZXhlY3siL3Byb2MvJCQvZmQvJGYifSInIiR7MDotcHl0aG9uM30iJyIsQEFSR1YnIC0tICIkQCIK'
    unset str
    ## Add Password (obfuscated) to script (dangerous: readable)
    [ -n "$P" ] && str="P=$(echo "$P"|openssl base64 -A 2>/dev/null)"$'\n'

    ## Add SALT to script
    str+="S='$S'"$'\n'"$(echo "$HOOK"|openssl base64 -A -d)"
    [ -n "$DEBUG" ] && echo >&2 "DEBUG: code='$str'"

    ## Encode & obfuscate the HOOK
    HOOK="$(echo "$str" | openssl base64 -A)"
    HOOK="$(_bc_ob64 "$HOOK")"

    [ "$fn" != "-" ] && { 
        s="$(stat -c %s "$fn")"
        [ "$s" -gt 0 ] || _bc_err "Empty file: $fn"
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
        _bc_xdd 66 </dev/urandom | _bc_xtr '' "[:print:]\0\n'"
        # \0\0 confuses some shells.
        _bc_xdd "$((1024 + RANDOM % 4096))" </dev/urandom| _bc_xtr '' "[:print:]\0{2,}\n'"
        # _bc_xprintf "' \x00" # WORKS ON BASH ONLY
        _bc_xprintf "';" # works on BASH + ZSH
        # far far far after garbage
        ## Add my hook to decrypt/execute binary
        # echo "eval \"\$(echo $HOOK|strings -n1|openssl base64 -d)\""
        echo "$(_bc_obbell 'eval "')\$$(_bc_obbell '(echo ')$HOOK|{ LANG=C $(_bc_obbell "perl -pe \"s/[^[:print:]]//g\"");}$(_bc_obbell "|openssl base64 -A -d)")\""
        # Note: openssl expects \n at the end. Perl filters it. Add it with echo.
        # echo "$(_bc_obbell 'eval "')\$$(_bc_obbell '(echo ')$HOOK|{ LANG=C $(_bc_obbell "perl -pe \"s/[^[:print:]]//g\";echo");}$(_bc_obbell "|openssl base64 -A -d)")\""
        # Add the encrypted binary (from memory)
        openssl base64 -d<<<"$DATA" |gzip|openssl enc -aes-256-cbc -md sha256 -nosalt -k "${S}-${_P}" 2>/dev/null
    } > "$fn"

    [ -n "$s" ] && {
        c="$(stat -c %s "$fn" 2>/dev/null)"
        [ -n "$c" ] && echo -e >&2 "${CDY}Compressed:${CN} ${CDM}$s ${CF}-->${CN}${CDM} $c ${CN}[${CDG}$((c * 100 / s))%${CN}]"
    }
    unset -f _bc_err _bc_ob64 _bc_obbell _bc_xdd _bc_xtr _bc_xprintf
}
# %%END_BC_FUNC%%

# Execute if not sourced:
[ -n "$ZSH_VERSION" ] && [ "$ZSH_EVAL_CONTEXT" != "${ZSH_EVAL_CONTEXT%":file:"*}" ] && _sourced=1
(return 0 2>/dev/null) && _sourced=1
[ -z "$_sourced" ] && bincrypter "$@"
unset _sourced
