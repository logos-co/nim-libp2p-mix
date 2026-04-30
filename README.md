# libp2p_mix

Reference Nim implementation of the **LIBP2P-MIX** specification (LIP-99) — an
anonymous routing protocol for [nim-libp2p](https://github.com/vacp2p/nim-libp2p)
based on the Sphinx packet format with Single Use Reply Blocks (SURBs),
LIONESS payload encryption, cover traffic, and pluggable spam protection.

This package was extracted from `nim-libp2p`'s `libp2p/protocols/mix/` tree to
let mix evolve independently. Full extraction history is preserved — every
commit that ever touched mix retains its original author, date, and message,
with PR references rewritten to `vacp2p/nim-libp2p#NNNN` form so reviewers
can click through to the original threads.

## Specifications

This implementation tracks the following Logos LIPs published at
[lip.logos.co](https://lip.logos.co). The specs are the authoritative
reference for protocol behaviour, packet formats, and security properties —
code follows the spec, not the other way round.

| Spec | LIP | Link |
|---|---|---|
| **LIBP2P-MIX** — core mix protocol, Sphinx packet construction & handling | 99 | [lip.logos.co/ift-ts/raw/mix.html](https://lip.logos.co/ift-ts/raw/mix.html) |
| **Mix Cover Traffic** — constant-rate cover traffic, slot accounting, epoch handling | TBD | [lip.logos.co/ift-ts/raw/mix-cover-traffic.html](https://lip.logos.co/ift-ts/raw/mix-cover-traffic.html) |
| **RLN DoS Protection for Mixnet** — per-hop RLN proof, membership tree | 144 | [lip.logos.co/ift-ts/raw/mix-spam-protection-rln.html](https://lip.logos.co/ift-ts/raw/mix-spam-protection-rln.html) |
| **Mix DoS Protection** — abstract spam-protection interface | TBD | [lip.logos.co/ift-ts/raw/mix-dos-protection.html](https://lip.logos.co/ift-ts/raw/mix-dos-protection.html) |

## Repository layout

```
libp2p_mix.nim            Top-level facade — re-exports the public API
libp2p_mix/               Protocol implementation (23 modules)
  ├── mix_protocol.nim    Core mix protocol (mounts on a libp2p Switch)
  ├── sphinx.nim          Sphinx packet format with LIONESS payload encryption
  ├── cover_traffic.nim   Constant-rate cover-traffic generator
  ├── exit_layer.nim      Exit-node behaviour & dest read framing
  ├── entry_connection.nim/exit_connection.nim/reply_connection.nim
  ├── fragmentation.nim   Packet fragmentation
  ├── pool.nim            Mix node pool / route selection
  ├── spam_protection.nim Pluggable spam-protection abstract base
  ├── delay_strategy.nim  Per-hop delay strategies
  ├── timedcache.nim      Replay-cache primitive (vendored from libp2p pubsub)
  ├── lioness.nim         LIONESS block cipher
  └── …                   crypto, mix_node, multiaddr, serialization, etc.

tests/                    Unit tests
  ├── component/          Integration tests using real libp2p switches
  └── tools/              Test helpers (vendored from nim-libp2p tests/tools/)

examples/
  └── mix_ping.nim        End-to-end demo: ping over a 10-node mix network

config.nims               Project-wide compiler config (--mm:refc, paths)
tests/config.nims         Test-only defines (-d:metrics, libp2p subsystems)
libp2p_mix.nimble         Package metadata & nimble tasks
```

## Installation

Add the dependency to your `.nimble` file:

```nim
requires "libp2p_mix"
```

Or pin a specific revision:

```nim
requires "https://github.com/logos-co/nim-libp2p-mix.git#<commit-or-tag>"
```

## Integration

Mounting mix on a libp2p switch:

```nim
import libp2p_mix
import libp2p_mix/mix_protocol
import libp2p_mix/mix_node

let mixNodeInfo = initMixNodeInfo(
  peerId, multiAddr, mixPubKey, mixPrivKey, libp2pPubKey, libp2pPrivKey
)

let mix = MixProtocol.new(mixNodeInfo, switch).valueOr:
  return err("mix init failed: " & error)

# Optional: configure how the exit layer reads payloads for a given proto
mix.registerDestReadBehavior("/your/proto/1.0.0", readLp(maxSize = -1))

# Optional: bootstrap the node pool
for bootstrapNode in bootstrapNodes:
  mix.nodePool.add(bootstrapNode)

# Mount and start
switch.mount(mix)
await mix.start()

# Open a mix-routed connection. `toConnection` does NOT send anything yet —
# it returns a libp2p `Connection` whose subsequent writes/reads are wrapped
# into Sphinx packets and routed through the mix overlay. Use it like any
# other libp2p connection.
let conn = mix.toConnection(
  MixDestination.init(targetPeerId, targetMultiAddr),
  proto = "/your/proto/1.0.0",
  MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(1.byte)),
).valueOr:
  return err(error)

# Now write/read as usual — the mix layer handles Sphinx wrapping, routing,
# and (when expectReply is set) collecting the response via SURBs.
await conn.writeLp(requestBytes)
let response = await conn.readLp(maxBytes)
```

For a complete worked example, see [`examples/mix_ping.nim`](examples/mix_ping.nim).

### Pluggable spam protection

Spam protection is a `SpamProtection` abstract base class
([`libp2p_mix/spam_protection`](libp2p_mix/spam_protection.nim)). Pass an
implementation at construction time:

```nim
let mix = MixProtocol.new(
  mixNodeInfo,
  switch,
  spamProtection = Opt.some(SpamProtection(myImpl)),
)
```

A reference RLN-based implementation lives in
[`mix-rln-spam-protection-plugin`](https://github.com/logos-co/mix-rln-spam-protection-plugin).

### Cover traffic & delay strategies

```nim
let ct = ConstantRateCoverTraffic.new(
  totalSlots = 10, epochDuration = 10.seconds, useInternalEpochTimer = true
)
let delay = DelayStrategy(
  ExponentialDelayStrategy.new(meanDelay = 100, rng = newRng())
)

let mix = MixProtocol.new(
  mixNodeInfo, switch,
  coverTraffic = Opt.some(CoverTraffic(ct)),
  delayStrategy = Opt.some(delay),
)
```

## Building & running

The package depends on `nim-libp2p`. While we're not yet on a published
release, point at a local clone with `nimble develop`:

```bash
git clone https://github.com/vacp2p/nim-libp2p.git
git clone https://github.com/logos-co/nim-libp2p-mix.git
cd nim-libp2p-mix
nimble develop --add=../nim-libp2p   # registers libp2p as a develop dep
nimble setup                          # generates nimble.paths
```

### Tests

```bash
nimble test            # 14 unit-test files (~143 individual checks)
nimble testComponent   # 6 component (integration) tests, ~26 checks
nimble testAll         # both
```

The `tests/config.nims` enables `-d:metrics` and several
`libp2p_*_metrics` defines so tests can assert on metric counters.

### Example

```bash
nimble example
```

This compiles `examples/mix_ping.nim`, which spins up 10 mix nodes locally,
mounts the libp2p `Ping` protocol on a destination, sends a ping through the
mix network, and waits for the reply via SURBs. Expected output:

```
INF Ping response received through mix network rtt=41ms…
```

To build the binary without auto-cleanup:

```bash
nim c -d:libp2p_mix_experimental_exit_is_dest -d:metrics -o:mix_ping examples/mix_ping.nim
./mix_ping
```

## Compile-time flags

| Flag | Purpose |
|---|---|
| `-d:libp2p_mix_experimental_exit_is_dest` | Allow exit nodes to also be the message destination (waku/lightpush usage). Enabled by default in `libp2p_mix.nimble`. |
| `-d:metrics` | Enable Prometheus-style metric counters (test-time default). |
| `-d:enable_mix_benchmarks` | Compile in benchmark/timing helpers from `libp2p_mix/benchmark.nim`. |

## License

Licensed under either of:

- Apache License 2.0 ([LICENSE-APACHEv2](LICENSE-APACHEv2))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
