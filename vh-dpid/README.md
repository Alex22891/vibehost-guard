# vh-dpid

The analyser of the torrent guard. It reads copies of the first packets of each connection and marks the
connections it judges BitTorrent; a rule of `guard.sh` drops what carries the mark. Traffic never waits
for it: if it stops, nothing changes on the network.

It stores no payload and sends none anywhere. What leaves the server is counts and port numbers.

## How it decides

| Tier | What | Action |
|---|---|---|
| Strong | The protocol's own bytes in their place: handshake, DHT, tracker request, UDP tracker, LSD, handshake in uTP | Blocks; the peer is remembered for 30 min, the source for 15 |
| Weak | The library says BitTorrent, nothing confirms it | Blocks only if this source or peer had a strong hit; otherwise only counted |
| Ignored | Guessed from a port or an address | Never blocks |

TLS, QUIC and DNS are never judged.

## Build

```sh
docker buildx build --platform linux/amd64 --target out -o out/amd64 .
docker buildx build --platform linux/arm64 --target out -o out/arm64 .
```

`out/<arch>/vh-dpid.gz` is what servers download; its SHA-256 goes into `guard.sh`.

## Tests

```sh
# On a real kernel, as root in a privileged container, with iptables, iproute2, python3, conntrack-tools, procps:
sh tests/live-test.sh ./vh-dpid
sh tests/guard-test.sh guard.sh vh-dpid.gz
```

## License

vh-dpid is LGPL-3.0-or-later, see `COPYING`. It links statically against
[nDPI](https://github.com/ntop/nDPI) by ntop.org (LGPLv3), in `NDPI_LICENSE_FOR_PROFIT_LGPL` mode: the
dual-licensed dissectors are not used. To relink against a modified nDPI, change `NDPI_REF` or the source
tree in the `Dockerfile` and build. nDPI is a registered trademark of ntop.org; this project is not
affiliated with or endorsed by ntop.
