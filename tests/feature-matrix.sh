#!/bin/sh
#
# Build the library under each meaningful feature combination.
#
# A `use` in an ungated module that names a gated one compiles fine in
# every combination that happens to enable the gate, so only building
# the narrow combinations catches it.
#
# Usage: feature-matrix.sh [-q]
#   -q  print only failures and the final tally

set -u

QUIET=no
while getopts qh opt; do
    case "$opt" in
        q) QUIET=yes ;;
        *)
            sed -n '2,/^set -u/p' "$0" | sed 's/^# \{0,1\}//'
            exit 1
            ;;
    esac
done

COMBOS="
read
fuse
read,zstd
read,lzma
read,lzma-native
read,lz4
read,brotli
read,mmap
read,parallel
read,tar
read,cli
read,zstd,lzma,lz4,brotli
read,cli,parallel,zstd,tar,mmap
"

# Warnings count as failures. A helper left ungated when the feature
# that uses it is off shows up as dead code long before anything breaks.
build() {
    RUSTFLAGS="-D warnings" cargo build --quiet "$@" 2>/dev/null
}

pass=0
fail=0
failed=""

for combo in $COMBOS; do
    if build --no-default-features --features "$combo"; then
        pass=$((pass + 1))
        [ "$QUIET" = yes ] || printf '  %-42s builds\n' "$combo"
    else
        fail=$((fail + 1))
        failed="$failed $combo"
        printf '  %-42s FAILS\n' "$combo"
    fi
done

for extra in "--no-default-features" "--all-features"; do
    if build $extra; then
        pass=$((pass + 1))
        [ "$QUIET" = yes ] || printf '  %-42s builds\n' "$extra"
    else
        fail=$((fail + 1))
        failed="$failed $extra"
        printf '  %-42s FAILS\n' "$extra"
    fi
done

echo
if [ "$fail" -eq 0 ]; then
    echo "$pass/$pass feature combinations build"
else
    echo "$pass/$((pass + fail)) build, failures:$failed"
    exit 1
fi
