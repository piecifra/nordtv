# Vetro Shards: Shell and NordVPN

Two plugins ("Shards") for [Vetro](https://github.com/andrearicci93/vetro) 0.5+ on Samsung Tizen TVs.

| Plugin | Tab | What it does |
|---|---|---|
| `shell` | Shell | Root commands on the TV, one at a time; `cd` is remembered, history kept by the plugin. 1–120 s limit. |
| `nordvpn` | VPN | NordVPN (NordLynx/WireGuard) on the TV itself: on/off, country, kill switch, access token, reconnect after a restart or a drop. |

Both declare `exec` (root commands). As Vetro says, a plugin runs inside Vetro with Vetro's full access:
install only code you have read.

## Install

- **Shell** is submitted to the official Shard catalog
  ([vetro-plugins#4](https://github.com/andrearicci93/vetro-plugins/pull/4)). Once it is merged, install it from
  **Vetro Shards → Load plugin catalog**. Until then, use the file below.
- **NordVPN** is not in the catalog: it needs a native program, which the catalog does not accept
  (see [the question there](https://github.com/andrearicci93/vetro-plugins/issues)). Install it from a file.

From a file (Vetro 0.5+):

1. Download `nordvpn-1.0.0.vplugin` (or `shell-1.0.0.vplugin`) from the
   [latest release](https://github.com/piecifra/vetro-shards/releases/latest) and check it against `SHA256SUMS`.
2. **Vetro Shards → Install from a file or develop a plugin → Developer mode** on, pick the file, switch it on.
3. NordVPN: paste an access token (Nord Account → NordVPN → Set up NordVPN manually), choose a country, switch on.

The VPN program (`nordtv/`, Go, about 2.8 MB) does not fit in a plugin bundle (512 KB, text only). The plugin uses
`/opt/nordtv/nordtv` when it is there; otherwise it downloads `nordtv.gz` from this repository's v1.0.0 release and
installs it only if its SHA-256 is the one pinned in `nordvpn/index.js`. The build is reproducible: run
`./nordtv/build.sh` with the Go version in `nordtv/go.mod` and compare the checksum yourself.

## Develop

```sh
node tests/run.cjs                                          # all tests; host.test needs VETRO_DIR=<vetro 0.5 checkout>
node $VETRO_DIR/app/scripts/vetro-plugin.cjs check nordvpn  # Vetro's own checks
(cd dist && node $VETRO_DIR/app/scripts/vetro-plugin.cjs pack ../nordvpn)   # bundle + sha256
```

Bump `version` in the plugin's `manifest.json`, pack, and install the file again: Vetro updates it in place
(switched off, settings kept). Plain ES5: older TVs run Node 4.4.

## Licences

The plugins and `nordtv` are MIT. `dist/nordtv.gz` statically links wireguard-go (MIT,
Copyright (C) 2017-2025 WireGuard LLC) and the Go standard library and golang.org/x/{crypto,net,sys}
(BSD-3-Clause, Copyright 2009 The Go Authors); keep their notices when redistributing it.
NordVPN and NordLynx are trademarks of their owners; this project is not affiliated with them.
