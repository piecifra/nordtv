#!/bin/sh
# Builds nordtv (NordLynx/WireGuard client on userspace wireguard-go) for the TV's ARMv7 userland and writes
# dist/nordtv.gz. Deterministic: same source and Go version give the same bytes (Go version from go.mod).
#
#   ./nordtv/build.sh                 build only
#   ./nordtv/build.sh --pin URL       also write URL and the SHA-256 of dist/nordtv.gz into nordvpn/index.js,
#                                     so the plugin can download and verify it. URL is where nordtv.gz will be
#                                     published (https, for example a GitHub release asset).
set -e
cd "$(dirname "$0")"
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o ../dist/nordtv-armv7 .
gzip -9 -n -c ../dist/nordtv-armv7 > ../dist/nordtv.gz
rm -f ../dist/nordtv-armv7
SUM=$(shasum -a 256 ../dist/nordtv.gz 2>/dev/null | cut -d' ' -f1 || sha256sum ../dist/nordtv.gz | cut -d' ' -f1)
echo "dist/nordtv.gz  $(wc -c < ../dist/nordtv.gz | tr -d ' ') bytes  sha256 $SUM"
if [ "$1" = "--pin" ]; then
  case "$2" in https://*) ;; *) echo "--pin needs an https URL" >&2; exit 2;; esac
  node -e '
    const fs=require("fs"),f="../nordvpn/index.js",s=fs.readFileSync(f,"utf8");
    const line="var BINARY = { url: "+JSON.stringify(process.argv[1]).replace(/"/g,"\x27")+", sha256: \x27"+process.argv[2]+"\x27 };";
    const out=s.replace(/^var BINARY = \{.*\};.*$/m,line+"   // written by nordtv/build.sh --pin");
    if(out===s&&!s.includes(line))throw Error("BINARY line not found");fs.writeFileSync(f,out);console.log("pinned in nordvpn/index.js");
  ' "$2" "$SUM"
fi
