#!/bin/sh
# Builds nordtv for the TV's ARMv7 userland and writes dist/nordtv.gz and dist/SHA256SUMS.
#
#   ./build.sh                                   build
#   ./build.sh --pin URL path/to/index.js        also write URL and the SHA-256 of dist/nordtv.gz into a Shard's
#                                                index.js (the line starting with "var BINARY =")
#
# Reproducible: the same source gives the same bytes. The compiler is pinned below; any Go 1.21 or later fetches
# exactly that version by itself (GOTOOLCHAIN), so the go installed on the machine does not matter.
# Exact command:
#   GOTOOLCHAIN=go1.26.0 CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 \
#     go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o dist/nordtv-armv7 .
#   gzip -9 -n -c dist/nordtv-armv7 > dist/nordtv.gz
set -e
cd "$(dirname "$0")"
export GOTOOLCHAIN=go1.26.0 CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 GOFLAGS=-mod=readonly
mkdir -p dist
echo "compiler: $(go version)"
go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o dist/nordtv-armv7 .
gzip -9 -n -c dist/nordtv-armv7 > dist/nordtv.gz
rm -f dist/nordtv-armv7
sum() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
SUM=$(sum dist/nordtv.gz)
echo "$SUM  nordtv.gz" > dist/SHA256SUMS
echo "dist/nordtv.gz  $(wc -c < dist/nordtv.gz | tr -d ' ') bytes  sha256 $SUM"
if [ "$1" = "--pin" ]; then
  case "$2" in https://*) ;; *) echo "--pin needs an https URL" >&2; exit 2;; esac
  [ -f "$3" ] || { echo "--pin needs the Shard's index.js" >&2; exit 2; }
  node -e '
    const fs=require("fs"),[url,sum,f]=process.argv.slice(1),s=fs.readFileSync(f,"utf8");
    const line="var BINARY = { url: \x27"+url+"\x27, sha256: \x27"+sum+"\x27 };   // written by nordtv build.sh --pin";
    if(!/^var BINARY = \{.*\};.*$/m.test(s))throw Error("no var BINARY line in "+f);
    fs.writeFileSync(f,s.replace(/^var BINARY = \{.*\};.*$/m,line));console.log("pinned in "+f);
  ' "$2" "$SUM" "$3"
fi
