#!/bin/sh
#
# Regenerate the committed test images under tests/vectors.
#
# This crate is read-only, so its tests cannot build the images they
# read. The images are produced here by upstream mkdwarfs and committed
# as binary fixtures. Running a released binary to produce test data
# does not derive this implementation from its source.
#
# Requires upstream mkdwarfs on PATH. Run only when a fixture needs to
# change, and commit the result.

set -eu

OUT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/vectors"
command -v mkdwarfs >/dev/null 2>&1 || { echo "upstream mkdwarfs not on PATH" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM
SRC="$WORK/src"

# A tree exercising the metadata shapes the reader has to handle:
# nested directories, a symlink, hardlinks, duplicate content that the
# writer shares, a sparse file, and a file spanning several chunks.
mkdir -p "$SRC/dir/nested" "$SRC/empty"
printf 'top level\n'    > "$SRC/top.txt"
printf 'shared body\n'  > "$SRC/dup-a.txt"
printf 'shared body\n'  > "$SRC/dir/dup-b.txt"
printf 'nested\n'       > "$SRC/dir/nested/deep.txt"
ln -sf ../top.txt "$SRC/dir/link-to-top"
ln "$SRC/top.txt" "$SRC/hardlink.txt"
python3 -c '
import sys
with open(sys.argv[1] + "/sparse.bin", "wb") as f:
    f.truncate(1 << 20)
    f.seek(1 << 19)
    f.write(b"middle")
    f.truncate(1 << 21)
with open(sys.argv[1] + "/wide.bin", "wb") as f:
    for i in range(4096):
        f.write(bytes([i % 251]) * 512)
' "$SRC"

# A second, tiny tree. Storing the full tree uncompressed would commit
# a multi-megabyte fixture for the sake of one codec case.
mkdir -p "$WORK/small/dir/nested"
printf 'top level\n' > "$WORK/small/top.txt"
printf 'nested\n'    > "$WORK/small/dir/nested/deep.txt"

gen_from() {
    g_src="$1"
    g_name="$2"
    shift 2
    mkdwarfs -i "$g_src" -o "$OUT/$g_name.dwarfs" -f --no-progress \
        --no-history-timestamps --no-history-command-line "$@" >/dev/null 2>&1
    printf '  %-26s %s bytes\n' "$g_name.dwarfs" "$(wc -c < "$OUT/$g_name.dwarfs")"
}

gen() {
    g_n="$1"
    shift
    gen_from "$SRC" "$g_n" "$@"
}

mkdir -p "$OUT"
echo "regenerating fixtures with $(mkdwarfs -H 2>&1 | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)"

gen upstream-default
gen_from "$WORK/small" upstream-uncompressed -l 0
gen upstream-zstd          -C zstd:level=11
gen upstream-lzma          -C lzma:level=1
gen upstream-lz4           -C lz4
gen upstream-brotli        -C brotli:quality=4
gen upstream-small-blocks  -S 16
gen upstream-no-index      --no-section-index
gen upstream-unpacked      --pack-metadata=none
gen upstream-packed        --pack-metadata=all
gen upstream-history       -l 3
gen upstream-categorized   --categorize

echo "done"
