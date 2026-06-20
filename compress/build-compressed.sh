#!/usr/bin/env bash
# Wrap every tar/ slip archive in the common tarball compressors.
#
# The compression layer is ORTHOGONAL to the slip primitive: gzip/bzip2/xz/zstd
# do not change archive semantics, they only wrap the byte stream. These exist
# to test that an extractor's auto-decompress path (`tar xzf`, libarchive
# sniffing a magic byte, a library that pipes through zlib then untars) still
# applies its traversal/symlink checks AFTER decompression. A checker that runs
# on `.tar` but is bypassed by a `.tar.gz` front-end is a real bug class.
#
# Output is byte-stable across runs (gzip -n drops name/mtime) so rebuilds don't
# churn git. Decompressing any variant yields the exact original tar/<case>.tar.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tars="$here/../tar"
for c in gz bz2 xz zst; do mkdir -p "$here/$c"; done
n=0
for t in "$tars"/*.tar; do
  base="$(basename "$t" .tar)"
  gzip  -9 -n -c "$t" >  "$here/gz/$base.tar.gz"
  bzip2 -9    -c "$t" >  "$here/bz2/$base.tar.bz2"
  xz    -9    -c "$t" >  "$here/xz/$base.tar.xz"
  zstd  -19 -q -c "$t" > "$here/zst/$base.tar.zst"
  n=$((n+1))
done
echo "wrapped $n tar archives into {gz,bz2,xz,zst}/ under $here"
