#!/bin/bash
# Makes the keys a droidtop plugin publisher needs (droidtop docs/plugin-api.md 1.5, "A third-party publisher"),
# on your own computer, with openssl. Nothing here is uploaded anywhere.
#
#   make_keys.sh root <origin> <dir>
#       Your root: <dir>/root.key (KEEP IT OFFLINE, never commit it), <dir>/root.crt (the root certificate),
#       <dir>/catalog-root.pub (its public key, which a catalog commits) and <dir>/droidtop-plugin-key.json (which each
#       plugin repository commits and publishes on its releases).
#   make_keys.sh catalog <owner>/<repo> <dir>
#       A catalog-signing leaf issued by the root in <dir>: <dir>/catalog.key and <dir>/catalog.crt. Their contents
#       go into the catalog repository's secrets CATALOG_SIGNING_KEY and CATALOG_SIGNING_CERT.
#   make_keys.sh revocation <owner>/<repo> <dir>
#       A revocation-signing leaf issued by the root in <dir>: <dir>/revocation.key and <dir>/revocation.crt, for the
#       catalog's revocations.jws (docs/CATALOG-FORMAT.md). Make it only when you need to revoke something.
#   make_keys.sh plugin <origin> <plugin id or prefix.*> <dir> <name>
#       A plugin-signing leaf issued by the root in <dir>: <dir>/<name>.key and <dir>/<name>.crt. Their contents go
#       into the plugin repository's secrets PLUGIN_SIGNING_KEY and PLUGIN_SIGNING_CERT. Make one per repository.
#
# The keys are P-256. Certificate dates are not checked by droidtop, so the certificates are long-lived.
set -euo pipefail
# Git Bash on Windows would otherwise rewrite a "/CN=..." subject into a file path. Only arguments starting with
# "/CN=" are left alone, so a key directory given as /c/... is still converted for openssl. Harmless elsewhere.
export MSYS2_ARG_CONV_EXCL="/CN="

EKU_BASE=2.25.230248497294207031301727532441854392946
DAYS=36500

usage() { sed -n '2,19p' "$0" >&2; exit 2; }
[ $# -ge 3 ] || usage
kind=$1

valid_origin() {
    case "$1" in
        ''|*[!a-z0-9-]*) echo "origin: lower-case letters, digits and '-' only" >&2; exit 2 ;;
        droidtop) echo "origin: 'droidtop' is droidtop's own; choose yours" >&2; exit 2 ;;
    esac
}

leaf() { # dir name subject eku san
    local dir=$1 name=$2 subject=$3 eku=$4 san=$5 ext
    [ -f "$dir/root.key" ] && [ -f "$dir/root.crt" ] || { echo "no root in $dir: run 'make_keys.sh root' first" >&2; exit 1; }
    [ ! -e "$dir/$name.key" ] || { echo "$dir/$name.key exists; not overwriting it" >&2; exit 1; }
    umask 077
    # Beside the keys, not in /tmp: openssl on Windows cannot read a Git Bash /tmp path.
    ext="$dir/.$name.ext"
    printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=%s\nsubjectAltName=%s\n' \
        "$EKU_BASE.$eku" "$san" > "$ext"
    # The key is written only once the certificate is made, so a failure leaves nothing half done.
    openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out "$dir/.$name.key.new"
    openssl req -new -key "$dir/.$name.key.new" -subj "$subject" |
        openssl x509 -req -CA "$dir/root.crt" -CAkey "$dir/root.key" -CAcreateserial -days "$DAYS" -sha256 \
            -extfile "$ext" -out "$dir/$name.crt"
    mv -- "$dir/.$name.key.new" "$dir/$name.key"
    rm -f -- "$ext"
    echo "$dir/$name.key and $dir/$name.crt written"
}

case "$kind" in
    root)
        origin=$2 dir=$3
        valid_origin "$origin"
        mkdir -p "$dir"
        [ ! -e "$dir/root.key" ] || { echo "$dir/root.key exists; not overwriting it" >&2; exit 1; }
        umask 077
        openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out "$dir/root.key"
        openssl req -x509 -new -key "$dir/root.key" -subj "/CN=$origin droidtop plugin root" -days "$DAYS" -sha256 \
            -addext "basicConstraints=critical,CA:TRUE" \
            -addext "keyUsage=critical,keyCertSign,cRLSign" \
            -addext "subjectAltName=URI:urn:droidtop:origin:$origin" \
            -out "$dir/root.crt"
        openssl pkey -in "$dir/root.key" -pubout -out "$dir/catalog-root.pub"
        # What each plugin repository publishes so droidtop can anchor the origin: the root certificate, public.
        python3 -c 'import json, sys; print(json.dumps({"origin": sys.argv[1], "certificate": open(sys.argv[2]).read()}, indent=2))' \
            "$origin" "$dir/root.crt" > "$dir/droidtop-plugin-key.json"
        echo "$dir/root.key (keep offline), $dir/root.crt, $dir/catalog-root.pub and $dir/droidtop-plugin-key.json written"
        echo "root fingerprint (SHA-256 of the public key):"
        openssl pkey -in "$dir/root.key" -pubout -outform DER | openssl dgst -sha256 | sed 's/^.*= //'
        ;;
    catalog)
        repo=$2 dir=$3
        case "$repo" in */*) ;; *) echo "catalog: give it as <owner>/<repo>" >&2; exit 2 ;; esac
        # A "/" would start a new name field in the subject; the URN below keeps the real <owner>/<repo>.
        leaf "$dir" catalog "/CN=${repo//\// } droidtop catalog" 2 "URI:urn:droidtop:catalog:$repo"
        ;;
    revocation)
        repo=$2 dir=$3
        case "$repo" in */*) ;; *) echo "revocation: give it as <owner>/<repo>" >&2; exit 2 ;; esac
        leaf "$dir" revocation "/CN=${repo//\// } droidtop revocations" 3 "URI:urn:droidtop:catalog:$repo"
        ;;
    plugin)
        [ $# -ge 5 ] || usage
        origin=$2 plugin=$3 dir=$4 name=$5
        valid_origin "$origin"
        case "$plugin" in "$origin".*) ;; *) echo "plugin: its id must start with '$origin.'" >&2; exit 2 ;; esac
        leaf "$dir" "$name" "/CN=$plugin droidtop plugin" 1 "URI:urn:droidtop:origin:$origin,URI:urn:droidtop:plugin:$plugin"
        ;;
    *) usage ;;
esac
