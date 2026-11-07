# VPN for Vetro

A Shard (plugin) for [Vetro](https://github.com/andrearicci93/vetro) 0.5+ that runs **NordVPN (NordLynx/WireGuard)
on a Samsung Tizen TV itself**, with no router or USB stick: on/off, country, kill switch, access token, and reconnect
after a restart or a drop. It adds a **VPN** tab inside Vetro Shards.

> It runs as root, like any Shard with `exec`, and it drives a native program (below). Read the source before
> installing.

## Install (Vetro 0.5+)

1. Download `nordvpn-1.0.0.vplugin` from the [latest release](https://github.com/piecifra/vetro-vpn/releases/latest)
   and check it against `SHA256SUMS`.
2. **Vetro Shards → Install from a file or develop a plugin → Developer mode** on, pick the file, switch it on.
3. In the **VPN** tab: paste a NordVPN access token (Nord Account → NordVPN → Set up NordVPN manually → Generate new
   token), choose a country, switch the VPN on. "Keep connected" brings it back after a restart.

It is not in the official Shard catalog: the catalog accepts text only, and the VPN needs a native program. The
question of how it could fit is open with the catalog's maintainer
([vetro-plugins#6](https://github.com/andrearicci93/vetro-plugins/issues/6)).

## How it works

- **`nordvpn/`** — the Shard (ES5). Its page and routes drive `nordtv` through Vetro's root agent (`ctx.execute`),
  confirm every change by reading the state back, and restart the tunnel when it was left on and "Keep connected"
  is on (checked when the Shard starts and every 60 s; a failed start waits 2 minutes).
- **`nordtv/`** — the VPN program, in Go on userspace [wireguard-go](https://git.zx2c4.com/wireguard-go), for the TV's
  ARMv7 userland. Node cannot drive `/dev/net/tun` without native code, hence a separate program.
  Details in [nordtv/README.md](nordtv/README.md).
- **The binary.** A plugin bundle is limited to 512 KB of text, so `nordtv` (about 2.8 MB gzipped) is not inside.
  The Shard uses `/opt/nordtv/nordtv` when it is there. Otherwise it downloads `nordtv.gz` from this repository's
  v1.0.0 release and installs it only if its SHA-256 is the one pinned in `nordvpn/index.js`. It copies the program
  to `/dev/shm` before running it.
- **Reproducible:** `./nordtv/build.sh` with the Go version in `nordtv/go.mod` gives the same bytes. Compare its
  checksum with the release's.

What it changes while the VPN is on, all removed on stop: a `nordtun` interface, `ip rule`/`ip route` entries in
its own table (fwmark 51820), and iptables chains: DNS redirected to NordVPN's resolver, IPv6 egress blocked, the
optional kill switch. Network: `api.nordvpn.com` (the account's NordLynx key with your token, server
recommendations) and the chosen WireGuard server. Settings and the token (mode 600) stay in `/opt/nordtv`.

Tested on a Samsung QE43Q60BAUXXN (Q60B, 2022, Tizen 6.5) with Vetro 0.5.0: about 130 Mbit/s through the tunnel.

## Develop

```sh
VETRO_DIR=<vetro 0.5 checkout> node tests/run.cjs              # tests (host.test needs VETRO_DIR)
./nordtv/build.sh [--pin <https url of nordtv.gz>]              # build dist/nordtv.gz, optionally pin it
(cd dist && node $VETRO_DIR/app/scripts/vetro-plugin.cjs pack ../nordvpn)   # bundle + sha256
```

Plain ES5 in `nordvpn/`: older TVs run Node 4.4.

## Licences

MIT for this repository. `dist/nordtv.gz` statically links wireguard-go (MIT, Copyright (C) 2017-2025 WireGuard LLC)
and the Go standard library and golang.org/x/{crypto,net,sys} (BSD-3-Clause, Copyright 2009 The Go Authors); keep
their notices when redistributing it. NordVPN and NordLynx are trademarks of their owners; this project is not
affiliated with them.
