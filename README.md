# nordtv

A small NordVPN (NordLynx/WireGuard) client for Samsung Tizen TVs, built on userspace
[wireguard-go](https://git.zx2c4.com/wireguard-go) for the TVs' ARMv7 userland. It is the program behind the
**NordVPN** Shard for [Vetro](https://github.com/andrearicci93/vetro); the same commands also work from the TV's
shell as root.

This repository holds the full source and the released binary. The Shard downloads `nordtv.gz` from a release here
only when `/opt/nordtv/nordtv` is missing, and installs it only if its SHA-256 is the one pinned in the Shard's code.

## Build (reproducible)

```sh
./build.sh
```

It writes `dist/nordtv.gz` and `dist/SHA256SUMS`. Any Go 1.21 or later works: `build.sh` sets
`GOTOOLCHAIN=go1.26.0`, so `go` fetches exactly that compiler by itself. The exact commands are:

```sh
GOTOOLCHAIN=go1.26.0 CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 GOFLAGS=-mod=readonly \
  go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o dist/nordtv-armv7 .
gzip -9 -n -c dist/nordtv-armv7 > dist/nordtv.gz
```

Dependencies are pinned in `go.mod` and `go.sum`. Compare your `dist/SHA256SUMS` with the release's:

| Release | `nordtv.gz` SHA-256 |
|---|---|
| v1.0.0 | `a7f033196957c03ae867ce5d4791b8590ac9cf024b15fcf4392abe9e30622af3` |

Any change to the binary gets a new release and a new hash; the Shard pins one exact hash per version.

## What it does

- Asks NordVPN's API, with the user's access token, for the account's NordLynx private key and a recommended server
  (optionally in one country), then brings up a `nordtun` interface on `/dev/net/tun`.
- Routes like `wg-quick`: everything goes through the tunnel (fwmark 51820, table 51820,
  `suppress_prefixlength 0`), so the home network stays reachable.
- Redirects DNS (port 53) to NordVPN's resolver and blocks IPv6 egress (the tunnel is IPv4).
- **Kill switch, on by default:** while it runs, internet traffic outside the tunnel is rejected. If the VPN drops,
  the TV has no internet until it reconnects; the home network keeps working. `set killswitch off` disables it.
- `down`, `stop` and SIGTERM remove every route, rule, firewall chain and the `nordtun` interface it added.

### Commands it runs on the TV

`ip addr/link/route/rule`, `iptables` (filter and nat, chains `NORDTV` and `NORDTV_DNS` in `OUTPUT`) and
`ip6tables` (chain `NORDTV` in `OUTPUT`). Nothing else.

### Network

- `api.nordvpn.com`: `/v1/users/services/credentials` (the NordLynx key, with the token),
  `/v1/servers/recommendations` and `/v1/servers` (server and its public key), `/v1/servers/countries`,
  `/v1/helpers/ips/insights` (public IP for the status).
- The chosen NordVPN server, UDP 51820 (WireGuard).

### Files

`/opt/nordtv`, root only (folder `0700`, files `0600`, the binary `0700`): `config` (country, kill switch,
enabled, keep connected), `token` (the NordVPN access token), `log`. While running: `/tmp/nordtv.pid`,
`/tmp/nordtv.server`.

## Commands

```text
nordtv start [CC] [--ks|--no-ks]   start in the background with the saved settings (and save "VPN on")
nordtv stop                        stop and save "VPN off"
nordtv down                        stop, keeping "VPN on" saved (used when the Shard is switched off)
nordtv restart | log [N] | countries | uninstall
nordtv set country CC | set killswitch on|off | set autostart on|off | set token TOKEN
nordtv state | status -json        machine-readable state (status adds the public IP)
nordtv verify                      check the saved token with NordVPN
nordtv up [-token T | -conf wg.conf] [-country CC] [-server HOST] [-killswitch]   foreground
```

`-conf` accepts a plain WireGuard (`wg-quick`) file, for a provider other than NordVPN.

## Tested

Samsung QE43Q60BAUXXN (Q60B, 2022, firmware T-NKLBDEUC-1720.7), Tizen 6.5, kernel 5.4, ARMv7, no `xt_mark`:
about 130 Mbit/s through the tunnel; after `down`, `ip rule`, the routing table, the interfaces and the iptables /
ip6tables rules are identical to before the start. Other models are untested.

## Licences

MIT (this repository). The binary statically links wireguard-go (MIT, Copyright (C) 2017-2025 WireGuard LLC) and the
Go standard library and golang.org/x/{crypto,net,sys} (BSD-3-Clause, Copyright 2009 The Go Authors): see
[NOTICE](NOTICE). NordVPN and NordLynx are trademarks of their owners; this project is not affiliated with them.
