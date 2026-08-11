#!/usr/bin/env bash
# Publish the workspace to crates.io, in an order that cannot break.
#
# Cargo resolves a dependency requirement to the newest version satisfying it,
# so publishing a crate before a sibling it depends on does not fail — it
# succeeds, and breaks later for whoever runs `cargo install`. That happened
# on the way to 0.5.4: `celln-cli` called a new `celln-spec` function while
# published `celln-spec` was still 0.5.0.
#
# Two things prevent it here. Inter-crate requirements track the workspace
# version exactly, so a missing sibling is a publish-time refusal rather than a
# broken release; `--check` enforces that and runs in ci. And publish order is
# derived from the dependency graph, not from a list someone maintains.
#
#   scripts/release.sh --check          verify versions agree (ci runs this)
#   scripts/release.sh --bump 0.5.5     move every version together
#   scripts/release.sh --dry-run        show what would be published
#   scripts/release.sh --publish        publish, in dependency order

set -euo pipefail

cd "$(dirname "$0")/.."

ws_version() { grep -m1 '^version = ' Cargo.toml | cut -d'"' -f2; }

# Workspace members in an order where every crate follows what it depends on.
publish_order() {
    cargo metadata --format-version 1 --no-deps 2>/dev/null | python3 -c '
import json, sys
m = json.load(sys.stdin)
names = {p["name"] for p in m["packages"]}
deps = {p["name"]: {d["name"] for d in p["dependencies"]} & names for p in m["packages"]}
out = []
while deps:
    ready = sorted(n for n, d in deps.items() if not d - set(out))
    if not ready:
        sys.exit("dependency cycle: " + ", ".join(sorted(deps)))
    out += ready
    for n in ready:
        del deps[n]
print("\n".join(out))
'
}

# Every inter-crate requirement must equal the workspace version.
check() {
    local v rc=0 name req
    v=$(ws_version)
    echo "workspace version ${v}"

    local seen=0
    while IFS='=' read -r name req; do
        seen=$((seen + 1))
        if [ "$req" = "$v" ]; then
            echo "  ok   $name = \"$req\""
        else
            echo "  FAIL $name = \"$req\", expected \"$v\""
            rc=1
        fi
    done < <(sed -n 's/^\(celln-[a-z]*\) = { version = "\([^"]*\)".*/\1=\2/p' Cargo.toml)

    # An empty list would make this pass while checking nothing.
    [ "$seen" -gt 0 ] || {
        echo "  FAIL no inter-crate versions found in Cargo.toml"
        rc=1
    }

    # A crate that changed but kept its version ships nothing; catch the case
    # where the tag exists already.
    if git rev-parse -q --verify "refs/tags/v${v}" >/dev/null 2>&1 &&
        [ "$(git rev-parse "v${v}")" != "$(git rev-parse HEAD)" ]; then
        echo "  note v${v} is already tagged at a different commit"
    fi

    grep -q "^## ${v}\$" CHANGELOG.md || {
        echo "  FAIL CHANGELOG.md has no '## ${v}' entry"
        rc=1
    }
    return "$rc"
}

# Move the workspace version and every inter-crate requirement together, so
# they cannot drift apart in the first place.
bump() {
    local from to
    to=$1
    from=$(ws_version)
    [ "$from" != "$to" ] || {
        echo "already at ${to}"
        return 0
    }
    sed -i "0,/^version = \"${from}\"/s//version = \"${to}\"/" Cargo.toml
    sed -i "s/^\(celln-[a-z]* = { version = \)\"${from}\"/\1\"${to}\"/" Cargo.toml
    echo "${from} -> ${to}"
    grep -E '^(version|celln-[a-z]+) = ' Cargo.toml | sed 's/^/  /'
}

published() {
    local crate=$1 version=$2 path
    path=$(printf '%s' "$crate" | cut -c1-2)/$(printf '%s' "$crate" | cut -c3-4)/"$crate"
    curl -sf -A "celln-release" "https://index.crates.io/${path}" 2>/dev/null |
        grep -q "\"vers\":\"${version}\""
}

publish() {
    local dry=$1 v crate
    v=$(ws_version)
    check >/dev/null || {
        check
        echo "refusing to publish with versions that disagree" >&2
        return 1
    }
    for crate in $(publish_order); do
        if published "$crate" "$v"; then
            echo "  · ${crate} ${v} already on crates.io"
            continue
        fi
        if $dry; then
            echo "  → would publish ${crate} ${v}"
            continue
        fi
        echo "  → publishing ${crate} ${v}"
        # No --no-verify: verification builds the packaged crate against the
        # registry, which is what catches a sibling that is not there yet.
        cargo publish -p "$crate"
        # The next crate's requirement cannot resolve until this one is in the
        # index, so wait rather than racing it.
        for _ in $(seq 1 60); do
            published "$crate" "$v" && break
            sleep 5
        done
        published "$crate" "$v" || {
            echo "  ! ${crate} ${v} did not appear in the index" >&2
            return 1
        }
    done
    echo "  all crates at ${v}"
}

case "${1:---check}" in
--check) check ;;
--bump) bump "${2:?usage: release.sh --bump X.Y.Z}" ;;
--dry-run) publish true ;;
--publish) publish false ;;
*)
    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
    ;;
esac
