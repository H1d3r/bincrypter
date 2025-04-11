#! /usr/bin/env bash

# set PASSWORD=<password> to use a specific password. This password will be asked
# for at execution unless provided by PASSWORD=<password> environment variable.
#
# https://github.com/hackerschoice/bincrypter

[ -t 2 ] && {
CDR="\033[0;31m" # red
CDG="\033[0;32m" # green
CDY="\033[0;33m" # yellow
CDM="\033[0;35m" # magenta
CM="\033[1;35m" # magenta
CDC="\033[0;36m" # cyan
CN="\033[0m"     # none
CF="\033[2m"     # faint
}

# %%BEGIN_BC_FUNC%%
_bincrypter() {
    local str ifn fn s c DATA P _P S HOOK _PASSWORD
    local USE_PERL=1
    local _BC_QUIET="${_OPT_BC_QUIET:-$BC_QUIET}"
    local _BC_LOCK="${_OPT_BC_LOCK:-$BC_LOCK}"

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

    _bc_err() {
        echo -e >&2 "${CDR}ERROR${CN}: $*"
        # Be opportunistic: Try to obfuscate but if that fails then just copy data
        # without obfuscation (cat).
        # Consider a system where there is no 'openssl' or 'perl' but the install
        # pipeline looks like this:
        # curl -fL https://foo.com/script | bincrypter -l >script
        # => We rather have a non-obfuscated binary than NONE.
        [ "$fn" = "-" ] && {
            cat    # Pass through
            exit 0 # Make pipe succeed
        }
        exit 255
    }
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

    # Sets _P
    # Return 0 to continue. Otherwise caller should return.
    # May exit if bin is executed on another host (BC_LOCK).
    _bcl_gen_p() {
        local _k
        # Binary is LOCKED to this host. Check if this is the same host to allow execution.
        [ -z "$BC_BCL_TEST_FAIL" ] && _k="$(_bcl_get)" && _P="$(echo "$1" | openssl enc -d -aes-256-cbc -md sha256 -nosalt -k "$_k" -a -A 2>/dev/null)"

        [ -n "$_P" ] && return 0
        [ -n "$fn" ] && {
            # sourced
            unset BCL BCV _P P S fn
            unset -f _bcl_get _bcl_verify _bcl_verify_dec
            return 255
        }
        # base64 to string
        BCL="$(echo "$BCL" | openssl base64 -d -A 2>/dev/null)"
        [ "$BCL" -eq "$BCL" ] 2>/dev/null && exit "$BCL"
        exec /bin/sh -c "$BCL"
        exit 255 # FATAL
    }
    _bcl_gen() {
        local _k
        local p
        # P:=Encrypt(P) using _bcl_get as key
        _k="$(_bcl_get)"
        [ -z "$_k" ] && { echo -e >&2 "${CDR}ERROR${CN}: BC_LOCK not supported on this system"; return 255; }
        p="$(echo "$P" | openssl enc -aes-256-cbc -md sha256 -nosalt -k "${_k}" -a -A 2>/dev/null)"
        [ -z "$p" ] && { echo -e >&2 "${CDR}ERROR${CN}: Failed to generate BC_LOCK password"; return 255; }
        P="$p"
        str+="$(declare -f _bcl_verify_dec)"$'\n'
        str+="_bcl_verify() { _bcl_verify_dec \"\$@\"; }"$'\n'
        str+="$(declare -f _bcl_get)"$'\n'
        str+="$(declare -f _bcl_gen_p)"$'\n'
        str+="BCL='$(openssl base64 -A <<<"${_BC_LOCK}")'"$'\n'
        # Add test value
        str+="BCV='$(echo TEST-VALUE-VERIFY | openssl enc -aes-256-cbc -md sha256 -nosalt -k "${_k}" -a -A 2>/dev/null)'"$'\n'
    }
    # Test a key candidate and on success output the candidate to STDOUT.
    _bcl_verify_dec() {
        [ "TEST-VALUE-VERIFY" != "$(echo "$BCV" | openssl enc -d -aes-256-cbc -md sha256 -nosalt -k "${1}-${UID}" -a -A 2>/dev/null)" ] && return 255
        echo "$1-${UID}"
    }
    # Encrypt & Decrypt BCV for testing.
    _bcl_verify() {
        # [ "TEST-VALUE-VERIFY" != "$(echo "$BCV" | openssl enc -d -aes-256-cbc -md sha256 -nosalt -k "${1}" -a -A 2>/dev/null)" ] && return 255
        echo "$1-${UID}"
    }
    # Generate a LOCK key and output it to STDOUT (if valid).
    # This script uses the above bcl_verify but the decoder uses its own
    # bcl_verify as a trampoline to call bcl_verify_dec.
    # FIXME: Consider cases where machine-id changes. Fallback to dmidecode and others....
    _bcl_get() {
        [ -z "$UID" ] && UID="$(id -u 2>/dev/null)"
        [ -f "/etc/machine-id" ] && _bcl_verify "$(cat "/etc/machine-id")" && return
        command -v dmidecode >/dev/null && _bcl_verify "$(dmidecode -t 1 2>/dev/null | LANG=C perl -ne '/UUID/ && print')" && return
        _bcl_verify "$({ ip l sh dev "$(ip route show match 1.1.1.1 | sed -E 's/.*dev ([^ ]*) .*/\1/')" | grep -o 'ether [^ ]*';} 2>/dev/null)" && return
        _bcl_verify "$({ fdisk -l | grep -i identifier | head -n1;} 2>/dev/null)" && return
    }

    fn="-"
    [ -n "${1:?}" ] && fn="$1" # $1 might be '-'
    [ "$fn" != "-" ] && [ ! -f "$fn" ] && _bc_err "File not found: $fn"

    command -v openssl >/dev/null || _bc_err "openssl is required"
    command -v perl >/dev/null || _bc_err "perl is required"
    [ ! -c "/dev/urandom" ] && _bc_err "/dev/urandom is required"

    # Auto-generate password if not provided
    _PASSWORD="${2:-${BC_PASSWORD:-$PASSWORD}}"
    [ -n "$_BC_LOCK" ] && [ -n "$_PASSWORD" ] && { echo -e >&2 "${CDR}WARN${CN}: ${CDY}PASSWORD${CN} is ignored when using ${CDY}BC_LOCK${CN}."; unset _PASSWORD; }
    [ -z "$_PASSWORD" ] && P="$(DEBUG='' _bc_xdd 32 </dev/urandom | openssl base64 -A | _bc_xtr '^' '[:alnum:]' | DEBUG='' _bc_xdd 16)"
    _P="${_PASSWORD:-$P}"
    [ -z "$_P" ] && _bc_err "No ${CDC}PASSWORD=<password>${CN} provided and failed to generate one."
    unset _PASSWORD

    # Auto-generate SALT
    S="$(DEBUG='' _bc_xdd 32 </dev/urandom | openssl base64 -A | _bc_xtr '^' '[:alnum:]' | DEBUG='' _bc_xdd 16)"

    # base64 encoded decrypter
    HOOK='Zm9yIHggaW4gb3BlbnNzbCBwZXJsIGd1bnppcDsgZG8KICAgIGNvbW1hbmQgLXYgIiR4IiA+L2Rldi9udWxsIHx8IHsgZWNobyA+JjIgIkVSUk9SOiBDb21tYW5kIG5vdCBmb3VuZDogJHgiOyByZXR1cm4gMjU1OyB9CmRvbmUKaWYgWyAtbiAiJFpTSF9WRVJTSU9OIiBdOyB0aGVuCiAgICBbICIkWlNIX0VWQUxfQ09OVEVYVCIgIT0gIiR7WlNIX0VWQUxfQ09OVEVYVCUiOmZpbGU6Iip9IiBdICYmIGZuPSIkMCIKZWxpZiBbIC1uICIkQkFTSF9WRVJTSU9OIiBdOyB0aGVuCiAgICAocmV0dXJuIDAgMj4vZGV2L251bGwpICYmIGZuPSIke0JBU0hfU09VUkNFWzBdfSIKZWxzZQogICAgWyAhIC1mICIkMCIgXSAmJiB7IGVjaG8gPiYyICdFUlJPUjogU2hlbGwgbm90IHN1cHBvcnRlZC4gVXNlIEJhc2ggb3IgWnNoIGluc3RlYWQuJzsgcmV0dXJuIDI1NTsgfQpmaQpfUD0iJHtCQ19QQVNTV09SRDotJFBBU1NXT1JEfSIKdW5zZXQgXyBQQVNTV09SRCAKaWYgWyAtbiAiJFAiIF07IHRoZW4KICAgIGlmIFsgLW4gIiRCQ1YiIF0gJiYgWyAtbiAiJEJDTCIgXTsgdGhlbgogICAgICAgIF9iY2xfZ2VuX3AgIiRQIiB8fCByZXR1cm4KICAgIGVsc2UKICAgICAgICBfUD0iJChlY2hvICIkUCJ8b3BlbnNzbCBiYXNlNjQgLUEgLWQpIgogICAgZmkKZWxzZQogICAgWyAteiAiJF9QIiBdICYmIHsKICAgICAgICBlY2hvID4mMiAtbiAiRW50ZXIgcGFzc3dvcmQ6ICIKICAgICAgICByZWFkIC10IDYwIC1yIF9QCiAgICB9CmZpCnByZz0icGVybCAtZSAnPD47PD47cHJpbnQoPD4pJzwnJHtmbjotJDB9J3xvcGVuc3NsIGVuYyAtZCAtYWVzLTI1Ni1jYmMgLW1kIHNoYTI1NiAtbm9zYWx0IC1rICcke1N9LSR7X1B9JyAyPi9kZXYvbnVsbHxwZXJsIC1lICdyZWFkKFNURElOLFxcXCRfLCAkUik7cHJpbnQoPD4pJ3xndW56aXAiClsgLW4gIiRmbiIgXSAmJiB7CiAgICB1bnNldCAtZiBfYmNsX2dldCBfYmNsX3ZlcmlmeSBfYmNsX3ZlcmlmeV9kZWMKICAgIGV2YWwgInVuc2V0IEJDTCBCQ1YgXyBfUCBQIFMgUiBwcmcgZm47JChMQU5HPUMgcGVybCAtZSAnPD47PD47cHJpbnQoPD4pJzwiJHtmbn0ifG9wZW5zc2wgZW5jIC1kIC1hZXMtMjU2LWNiYyAtbWQgc2hhMjU2IC1ub3NhbHQgLWsgIiR7U30tJHtfUH0iIDI+L2Rldi9udWxsfHBlcmwgLWUgInJlYWQoU1RESU4sXCRfLCAkUik7cHJpbnQoPD4pInxndW56aXApIgogICAgcmV0dXJuCn0KTEFORz1DIGV4ZWMgcGVybCAnLWUkXkY9MjU1O2ZvcigzMTksMjc5LDM4NSw0MzE0LDQzNTQpeygkZj1zeXNjYWxsJF8sJCIsMCk+MCYmbGFzdH07b3BlbigkbywiPiY9Ii4kZik7b3BlbigkaSwiJyIkcHJnIid8Iik7cHJpbnQkbyg8JGk+KTtjbG9zZSgkaSl8fGV4aXQoJD8vMjU2KTskRU5WeyJMQU5HIn09IiciJExBTkciJyI7ZXhlY3siL3Byb2MvJCQvZmQvJGYifSInIiR7MDotcHl0aG9uM30iJyIsQEFSR1YnIC0tICIkQCIK'

    # _P - used with openssl below
    #  P - stored in P=$P
    unset str
    [ -n "$_BC_LOCK" ] && _bcl_gen
    # Fallback
    [ -z "$str" ] && {
        str="unset BCV BCL"$'\n'
        P="$(echo "$_P"|openssl base64 -A 2>/dev/null)"
    }

    ## Add Password to script ($P might be encrypted if BC_LOCK is set)
    [ -n "$P" ] && {
        str+="P=${P}"$'\n'
        unset P
    }

    ## Add SALT to script
    str+="S='$S'"$'\n'

    # Bash strings are not binary safe. Instead, store the binary as base64 in memory:
    ifn="$fn"
    [ "$fn" = "-" ] && ifn="/dev/stdin"
    DATA="$(gzip <"$ifn" | openssl base64)" || exit

    ## Add size of random padding to script (up to roughly 25% of the file size)).
    [ "$BC_PADDING" != "0" ] && {
        local sz="${#DATA}"
        [ "$sz" -lt 31337 ] && sz=31337
        local R="$(( (RANDOM * 32768 + RANDOM) % ((sz / 100) * ${BC_PADDING:-25})))"
    }
    str+="R=${R:-0}"$'\n'

    str+="$(echo "$HOOK"|openssl base64 -A -d)"
    [ -n "$DEBUG" ] && { echo -en >&2 "DEBUG: ===code===\n${CDM}${CF}"; echo >&2 "$str"; echo -en >&2 "${CN}"; }
    ## Encode & obfuscate the HOOK
    HOOK="$(echo "$str" | openssl base64 -A)"
    HOOK="$(_bc_ob64 "$HOOK")"

    [ -z "$_BC_QUIET" ] && [ "$fn" != "-" ] && { 
        s="$(stat -c %s "$fn")"
        [ "$s" -gt 0 ] || _bc_err "Empty file: $fn"
    }

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
        # Add the encrypted binary (from memory)
        ( DEBUG='' _bc_xdd "$R" </dev/urandom; openssl base64 -d<<<"$DATA") |openssl enc -aes-256-cbc -md sha256 -nosalt -k "${S}-${_P}" 2>/dev/null
    } > "$fn"

    [ -n "$s" ] && {
        c="$(stat -c %s "$fn" 2>/dev/null)"
        [ -n "$c" ] && echo -e >&2 "${CDY}Compressed:${CN} ${CDM}$s ${CF}-->${CN}${CDM} $c ${CN}[${CDG}$((c * 100 / s))%${CN}]"
    }
    # [ -z "$_BC_QUIET" ] && [ -n "$_BC_LOCK" ] && echo -e >&2 "${CDY}PASSWORD=${CF}${_P}${CN}"
    unset -f _bcl_get _bcl_verify _bcl_verify_dec _bc_err _bc_ob64 _bc_obbell _bc_xdd _bc_xtr _bc_xprintf
}
# %%END_BC_FUNC%%

# Check if sourced or executed
[ -n "$ZSH_VERSION" ] && [ "$ZSH_EVAL_CONTEXT" != "${ZSH_EVAL_CONTEXT%":file:"*}" ] && _sourced=1
(return 0 2>/dev/null) && _sourced=1
[ -z "$_sourced" ] && {
    # Execute if not sourced:
    _bc_usage() {
        local bc="${0##*/}"
        echo -en >&2 "\
${CM}Encrypt or obfuscate a binary or script.${CDM}

${CDG}Usage:${CN}
${CDC}${bc} ${CDY}[-hql] [file] [password]${CN}
   -h   This help
   -q   Quiet mode (no output)
   -l   Lock binary to this system & UID or fail if copied.
        It will exit with BC_LOCK if set to a numerical value.
        Otherwise it will execute BC_LOCK as a command.
        The default is to exit with 0 if copied.

${CDG}Environment variables (optional):${CN}
${CDY}PASSWORD=${CN}     Password to encrypt/decrypt.
${CDY}BC_PASSWORD=${CN}  Password to encrypt/decrypt (exported to callee).
${CDY}BC_PADDING=n${CN}  Add 0..n% of random data to the binary [default: 25].
${CDY}BC_QUIET=${CN}     See -q
${CDY}BC_LOCK=${CN}      See -l

${CDG}Examples:${CN}
Obfuscate myfile.sh:
  ${CDC}${bc} ${CDY}myfile.sh${CN}

Obfuscate /usr/bin/id (via pipe):
  ${CDC}cat ${CDY}/usr/bin/id${CN} | ${CDC}${bc}${CN} >${CDY}id.enc${CN}

Obfuscate & Lock to system. Execute 'id; ls -al' if copied:
  ${CDY}BC_LOCK='id; ls -al' ${CDC}${bc} ${CDY}myfile.sh${CN}

Encrypt myfile.sh with password 'mysecret':
  ${CDC}${bc} ${CDY}myfile.sh ${CDY}mysecret${CN}

Encrypt by passing the password as environment variable:
  ${CDY}PASSWORD=mysecret ${CDC}${bc} ${CDY}myfile.sh${CN}
"
        exit 0
    }
    [ -t 0 ] && [ $# -eq 0 ] && _bc_usage
    while getopts "hql" opt; do
        case $opt in
            h) _bc_usage ;;
            q) _OPT_BC_QUIET=1 ;;
            l) _OPT_BC_LOCK=0 ;;
            *) ;;
        esac
    done
    shift $((OPTIND - 1))

    _bincrypter "$@"
}

### HERE: sourced
unset _sourced
