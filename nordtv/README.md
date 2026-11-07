# nordtv: NordVPN on the TV

A NordLynx (WireGuard) client for the TV's ARMv7 userland, built on userspace
[wireguard-go](https://git.zx2c4.com/wireguard-go). the **nordvpn** plugin drives it
(`../nordvpn/index.js`); the same commands work from the TV's shell.

```sh
./build.sh   # builds and writes ../dist/nordtv.gz
```

## On the TV

- The plugin uses `/opt/nordtv/nordtv` (or downloads it, see the top-level README) and copies it to
  `/dev/shm/nordtv` before each command, where the TV lets it run (also after every boot).
- Settings and the token stay in `/opt/nordtv` (`config`, `token`, mode 600, `log`).
- With "Keep connected" on, the plugin starts the VPN again once Vetro's root agent is connected after a boot,
  and after a drop, if it was left on. It never starts a VPN that was turned off.

## What it does

- Asks NordVPN's API, with the user's access token, for the account's NordLynx key and a recommended
  server (optionally in one country), then brings up `nordtun` on `/dev/net/tun`.
- Routing like `wg-quick`: everything goes through the tunnel (fwmark 51820, table 51820,
  `suppress_prefixlength 0`), so the home network, the dashboard included, stays reachable.
- DNS on port 53 is redirected to NordVPN's resolver, IPv6 egress is blocked (the tunnel is IPv4),
  and the optional kill switch rejects internet traffic outside the tunnel while it runs.
- `stop` (or SIGTERM) removes every route, rule and firewall chain it added.

## Commands

```text
nordtv start [CC] [--ks|--no-ks]   start in the background with the saved settings
nordtv stop | restart | log [N] | countries
nordtv set country CC | set killswitch on|off | set autostart on|off | set token TOKEN
nordtv state | status -json        machine-readable state (status adds the public IP)
nordtv verify                      check the saved token with NordVPN
nordtv up [-token T | -conf wg.conf] [-country CC] [-server HOST] [-killswitch]   foreground
```

`-conf` accepts a plain WireGuard (`wg-quick`) file, for a provider other than NordVPN.

Tested on a Tizen 6.5 TV (kernel 5.4, ARMv7, no `xt_mark`): about 130 Mbit/s through the tunnel.
