#!/usr/bin/env bash
# Re-resolve every tag the tool catalogue pins, and rewrite any pin that moved.
#
# The catalogue pins by digest so a moved tag can never change what a cell is
# lent without celln changing. Keeping those pins current is therefore a code
# change: this rewrites them in place and the caller opens a pull request, so
# the update arrives with a diff and a review rather than at pull time.
#
# Writes `changed=1` to $GITHUB_OUTPUT when any pin moved. Exits non-zero if a
# tag could not be resolved, so a half-checked catalogue never becomes a PR.
#
# Test it without touching a registry:
#   scripts/refresh-tool-digests.sh --self-test

set -euo pipefail

f=${1:-crates/celln-cli/tools.toml}

resolve() { skopeo inspect --format '{{.Digest}}' "docker://$1"; }

# `docker.io/library/python:3.12-slim` -> `docker.io/library/python`, without
# eating the port in `registry:5000/team/tool:v1`. Only a colon in the last
# path segment starts a tag.
repo_of() {
    case "${1##*/}" in
    *:*) printf '%s' "${1%:*}" ;;
    *) printf '%s' "$1" ;;
    esac
}

# A registry can answer with something that is not a digest — an empty string
# on a hiccup, an error on a rate limit. Writing that produces a ref no pull
# can ever satisfy, so nothing unverified reaches the file.
is_digest() {
    local hex=${1#sha256:}
    [ "$1" != "$hex" ] && [ ${#hex} -eq 64 ] &&
        case "$hex" in *[!0-9a-f]*) false ;; *) true ;; esac
}

refresh() {
    local f=$1 changed=0 failed=0 tag name old new digest
    while IFS= read -r tag; do
        [ -n "$tag" ] || continue
        if ! digest=$(resolve "$tag" 2>&1); then
            echo "  ! $tag: could not resolve: $digest" >&2
            failed=1
            continue
        fi
        if ! is_digest "$digest"; then
            echo "  ! $tag: not a digest: ${digest:-<empty>}" >&2
            failed=1
            continue
        fi
        name=$(repo_of "$tag")
        old=$(grep -A1 "^tag = \"$tag\"$" "$f" | grep -oP '^ref = "\K[^"]+' || true)
        new="$name@$digest"
        [ "$old" = "$new" ] && continue
        echo "  $tag: $old -> $new"
        python3 - "$f" "$tag" "$new" <<'PY'
import sys, re
path, tag, new = sys.argv[1:4]
s = open(path).read()
s, n = re.subn(rf'(^tag = "{re.escape(tag)}"$\n)ref = "[^"]+"',
               rf'\g<1>ref = "{new}"', s, flags=re.M)
if n != 1:
    sys.exit(f"  ! {tag}: rewrote {n} pins, expected exactly 1")
open(path, "w").write(s)
PY
        changed=1
    done < <(grep -oP '^tag = "\K[^"]+' "$f")

    [ -n "${GITHUB_OUTPUT:-}" ] && echo "changed=$changed" >>"$GITHUB_OUTPUT"
    [ "$failed" -eq 0 ] || {
        echo "one or more tags could not be resolved; not proposing a change" >&2
        return 1
    }
    return 0
}

# ── self-test ────────────────────────────────────────────────────────────────
# The real thing runs weekly against a live registry, so it is exactly the kind
# of code that is only ever exercised in production. These stub the registry.

self_test() {
    local dir rc=0
    dir=$(mktemp -d)
    trap 'rm -rf "$dir"' RETURN
    mkdir -p "$dir/bin"
    export PATH="$dir/bin:$PATH"

    _stub() { printf '#!/bin/sh\n%s\n' "$1" >"$dir/bin/skopeo"; chmod +x "$dir/bin/skopeo"; }
    _fixture() {
        cat >"$dir/t.toml" <<EOF
[[image]]
name = "python"
tag = "docker.io/library/python:3.12-slim"
ref = "docker.io/library/python@sha256:$(printf '2%.0s' {1..64})"

[[image]]
name = "internal"
tag = "reg.example.com:5000/team/tool:v1"
ref = "reg.example.com:5000/team/tool@sha256:$(printf '3%.0s' {1..64})"
EOF
    }
    _check() {
        if [ "$2" = "$3" ]; then echo "  ok   $1"; else
            echo "  FAIL $1"; echo "        want: $3"; echo "        got:  $2"; rc=1
        fi
    }

    local a b ec GITHUB_OUTPUT=$dir/out

    # A moved tag is rewritten; an unmoved one is left alone.
    _fixture
    a=$(printf '2%.0s' {1..64}); b=$(printf 'a%.0s' {1..64})
    _stub "case \"\$4\" in *python*) echo sha256:$b ;; *) echo sha256:$(printf '3%.0s' {1..64}) ;; esac"
    : >"$GITHUB_OUTPUT"
    refresh "$dir/t.toml" >/dev/null
    _check "a moved pin is rewritten" \
        "$(grep -c "python@sha256:$b" "$dir/t.toml")" "1"
    _check "an unmoved pin is untouched" \
        "$(grep -c "tool@sha256:$(printf '3%.0s' {1..64})" "$dir/t.toml")" "1"
    _check "it reports that something changed" "$(cat "$GITHUB_OUTPUT")" "changed=1"

    # Running again with nothing moved must be a no-op.
    : >"$GITHUB_OUTPUT"
    refresh "$dir/t.toml" >/dev/null
    _check "a second run reports no change" "$(cat "$GITHUB_OUTPUT")" "changed=0"

    # A registry hiccup must not become a pin. This is the one that matters:
    # an empty answer used to be written as `ref = "reg.example.com@"`.
    _fixture
    _stub 'echo ""'
    : >"$GITHUB_OUTPUT"
    refresh "$dir/t.toml" >/dev/null 2>&1 && ec=0 || ec=$?
    _check "an empty digest fails the run" "exit $ec" "exit 1"
    _check "an empty digest is never written" "$(grep -c '@"' "$dir/t.toml")" "0"

    # A registry port is not a tag.
    _fixture
    b=$(printf 'b%.0s' {1..64})
    _stub "case \"\$4\" in *5000*) echo sha256:$b ;; *) echo sha256:$a ;; esac"
    : >"$GITHUB_OUTPUT"
    refresh "$dir/t.toml" >/dev/null
    _check "a registry port survives" \
        "$(grep -c "^ref = \"reg.example.com:5000/team/tool@sha256:$b\"$" "$dir/t.toml")" "1"

    # A tag that resolves to a non-digest is refused.
    _fixture
    _stub 'echo "unauthorized: authentication required"'
    : >"$GITHUB_OUTPUT"
    refresh "$dir/t.toml" >/dev/null 2>&1 && ec=0 || ec=$?
    _check "an error string fails the run" "exit $ec" "exit 1"
    _check "an error string is never written" "$(grep -c 'unauthorized' "$dir/t.toml")" "0"

    [ "$rc" -eq 0 ] && echo "  all checks passed"
    return "$rc"
}

if [ "${1:-}" = "--self-test" ]; then
    self_test
else
    refresh "$f"
fi
