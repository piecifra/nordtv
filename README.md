# nordtv

A small WireGuard client for Samsung Tizen TVs, built on userspace [wireguard-go](https://git.zx2c4.com/wireguard-go)
for the TVs' ARMv7 userland: NordVPN (NordLynx, through its API) or saved WireGuard configs for any other provider or
your own server. It is the program behind the **VPN** Shard for [Vetro](https://github.com/andrearicci93/vetro)
(formerly **NordVPN**); the same commands also work from the TV's shell as root.

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

Dependencies are pinned in `go.mod` and `go.sum`. Compare your `dist/SHA256SUMS` with the release's (the `.gz` hash also depends on the gzip in use; `gunzip -c dist/nordtv.gz | shasum -a 256` compares the program itself):

| Release | `nordtv.gz` SHA-256 |
|---|---|
| v1.0.0 | `a7f033196957c03ae867ce5d4791b8590ac9cf024b15fcf4392abe9e30622af3` |
| v1.1.0 | `5e1156501e49bcb6077c056cea404b1c6bc7aeba6a923db0be4291c718189866` |
| v1.1.1 | `d9ce340d9accd43f95f83d7c48e5be5e3ada721c23804a7b5a80e70bf45620b9` (program: `92058145d71583e46393453070a8324b1e85d8ff971ab4e438d2aa5fe9ef8444`) |

Any change to the binary gets a new release and a new hash; the Shard pins one exact hash per version.

## What it does

- **NordVPN:** asks NordVPN's API, with the user's access token, for the account's NordLynx private key and a
  recommended server (optionally in one country).
- **WireGuard:** uses a saved profile, a `wg-quick` config in `/opt/nordtv/profiles/NAME.conf`. Supported:
  `PrivateKey`, `Address`, `DNS`, `MTU`, and one `[Peer]` with `PublicKey`, `PresharedKey`, `AllowedIPs`, `Endpoint`
  (address or host name, looked up again when the connection drops) and `PersistentKeepalive`. IPv4 only: IPv6
  entries are skipped, and a config without an IPv4 address or `AllowedIPs`, or with an IPv6 endpoint, is refused.
- Brings up a `nordtun` interface on `/dev/net/tun` and routes like `wg-quick` (fwmark 51820, table 51820,
  `suppress_prefixlength 0`), so the home network always stays reachable. **Full tunnel** (`AllowedIPs = 0.0.0.0/0`,
  NordVPN, or no `AllowedIPs`): everything goes through the VPN. **Split** (narrower `AllowedIPs`): only those
  addresses do; the rest uses the normal connection.
- Redirects DNS (port 53) to NordVPN's resolver or the profile's `DNS` (a full-tunnel profile without one: Quad9,
  9.9.9.9; a split profile without one: no redirect), and blocks IPv6 egress (the tunnel is IPv4).
- **Kill switch, on by default:** while it runs, internet traffic outside the tunnel is rejected. If the VPN drops,
  the TV has no internet until it reconnects; the home network keeps working. `set killswitch off` disables it. Not
  used with a split profile, whose point is to leave the rest outside.
- `down`, `stop` and SIGTERM remove every route, rule, firewall chain and the `nordtun` interface it added.

### Commands it runs on the TV

`ip addr/link/route/rule`, `iptables` (filter and nat, chains `NORDTV` and `NORDTV_DNS` in `OUTPUT`) and
`ip6tables` (chain `NORDTV` in `OUTPUT`). Nothing else.

### Network

- NordVPN: `api.nordvpn.com`: `/v1/users/services/credentials` (the NordLynx key, with the token),
  `/v1/servers/recommendations` and `/v1/servers` (server and its public key), `/v1/servers/countries`. The chosen
  NordVPN server, UDP 51820 (WireGuard).
- WireGuard: the profile's `Endpoint` (UDP), and the DNS lookup of its name.
- Both: `api.nordvpn.com/v1/helpers/ips/insights`, without the token, for the public IP in `status`.

### Files

`/opt/nordtv`, root only (folders `0700`, files `0600`, the binary `0700`): `config` (provider, profile, country,
kill switch, enabled, keep connected), `token` (the NordVPN access token), `profiles/NAME.conf` (WireGuard configs,
keys included), `log`. While running: `/tmp/nordtv.pid`, `/tmp/nordtv.server`, `/tmp/nordtv.mode`.

## Commands

```text
nordtv start [CC] [--ks|--no-ks]   start in the background with the saved settings (and save "VPN on")
nordtv stop                        stop and save "VPN off"
nordtv down                        stop, keeping "VPN on" saved (used when the Shard is switched off)
nordtv restart | log [N] | countries | uninstall
nordtv set country CC | set killswitch on|off | set autostart on|off | set token TOKEN
nordtv set provider nordvpn|wireguard | set profile NAME
nordtv profile list                JSON: name, endpoint, address, AllowedIPs, DNS of each profile (never the keys)
nordtv profile add NAME < x.conf   check and save a WireGuard config (NAME: letters, digits, - and _, up to 32)
nordtv profile remove NAME
nordtv state | status -json        machine-readable state (status adds the public IP)
nordtv verify                      check the saved token with NordVPN
nordtv up [-token T | -conf wg.conf] [-country CC] [-server HOST] [-killswitch]   foreground
```

`-conf` runs any `wg-quick` file directly, with the same checks as a profile.

**Your own server at home:** a config whose `Endpoint` is your public address or a dynamic-DNS name only works from
inside your home if the router loops that traffic back (hairpin NAT). Many routers do not: then save a second
profile with the server's LAN address as `Endpoint`.

## Tested

Samsung QE43Q60BAUXXN (Q60B, 2022, firmware T-NKLBDEUC-1720.7), Tizen 6.5, kernel 5.4, ARMv7, no `xt_mark`:
about 130 Mbit/s through the tunnel with NordVPN (v1.0.0); with v1.1.0, NordVPN again, and WireGuard profiles against
a wg-easy 15.3 server with a `PresharedKey`, full tunnel with the kill switch and split (`AllowedIPs = 10.8.0.0/24`).
After `down`, `ip rule`, the routing table, the interfaces and the iptables / ip6tables rules are identical to
before the start. `go test` covers the config checks. Other models are untested.

## Licences

MIT (this repository). The binary statically links wireguard-go (MIT, Copyright (C) 2017-2025 WireGuard LLC) and the
Go standard library and golang.org/x/{crypto,net,sys} (BSD-3-Clause, Copyright 2009 The Go Authors): see
[NOTICE](NOTICE). NordVPN and NordLynx are trademarks of their owners; this project is not affiliated with them.
