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
| **Mix Key Rotation** — local-timer mix key rotation, grace window, per-key replay tables | TBD | [lip.logos.co/anoncomms/raw/mix-key-rotation.html](https://lip.logos.co/anoncomms/raw/mix-key-rotation.html) |
| **RLN DoS Protection for Mixnet** — per-hop RLN proof, membership tree | 144 | [lip.logos.co/ift-ts/raw/mix-spam-protection-rln.html](https://lip.logos.co/ift-ts/raw/mix-spam-protection-rln.html) |
| **Mix DoS Protection** — abstract spam-protection interface | TBD | [lip.logos.co/ift-ts/raw/mix-dos-protection.html](https://lip.logos.co/ift-ts/raw/mix-dos-protection.html) |

## Repository layout

```
libp2p_mix.nim            Top-level facade — re-exports the public API
libp2p_mix/               Protocol implementation (25 modules)
  ├── mix_protocol.nim    Core mix protocol (mounts on a libp2p Switch)
  ├── sphinx.nim          Sphinx packet format with LIONESS payload encryption
  ├── key_rotation.nim    Mix key ring, replay tables, and rotation config
  ├── cover_traffic.nim   Constant-rate cover-traffic generator
  ├── exit_layer.nim      Exit-node behaviour & dest read framing
  ├── entry_connection.nim/exit_connection.nim/reply_connection.nim
  ├── padding.nim         Fixed-size payload padding
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

let mix = MixProtocol.new(mixNodeInfo, switch)

# Optional: configure how the exit layer reads payloads for a given codec
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
  codec = "/your/proto/1.0.0",
  MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(1.byte)),
).valueOr:
  return err(error)

# Now write/read as usual — the mix layer handles Sphinx wrapping, routing,
# and (when expectReply is set) collecting the response via SURBs.
await conn.writeLp(requestBytes)
let response = await conn.readLp(maxBytes)
```

For a complete worked example, see [`examples/mix_ping.nim`](examples/mix_ping.nim).

### Hop address policy

Each node on a mix path is dialed by the node before it, at the address that the sender wrote in the packet. For example, a node at home has the address `192.168.1.20`, and a sender on the internet puts that node on a path. The node before it dials `192.168.1.20` from another network, the dial fails, and the message is lost.

`hopAddressPolicy` tells Mix which addresses it can put on a path. It is nim-libp2p's `PeerAddressPolicy`, a procedure that accepts or rejects one address. Mix never puts a pool member (a mix node that this node can put on a path) on a path if the policy rejects all of its addresses.

The default accepts any address, so tests, a single host and a private network work with no setting. A node on the public network uses `publicHopAddressPolicy`:

```nim
let mix =
  MixProtocol.new(mixNodeInfo, switch, hopAddressPolicy = publicHopAddressPolicy)
```

`publicHopAddressPolicy` accepts an IPv4 address that the public network routes, and a circuit relay route through a relay with such an address. nim-libp2p's `publicRoutableAddressPolicy` also accepts a circuit relay route through a relay with a private address. That route works only when the previous hop is already connected to the relay, and the sender cannot know whether it is.

Mix asks the policy only about an IPv4 address with a TCP or QUIC-v1 transport and a port other than 0, and never about a multicast or broadcast address.

When the policy accepts more than one of a pool member's addresses, Mix prefers a direct address over a circuit relay route, because a relayed connection has a time limit and a data limit, and a write past the data limit silently loses the packet. Within each group, Mix first tries the address of its last outbound connection to that pool member, and then the AddressBook in order. `hopAddressPolicy` does not check this node's own address, so give Mix an address that other nodes can dial, or replies will not reach this node.

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

By default `MixProtocol` uses `ExponentialDelayStrategy` (mean 100 ms) for
per-hop delays and the sender pre-send hold (mix.md §8.5.2 step 3.f). When
`spamProtection` is enabled the default is `SpamProtectionDelayStrategy`
instead, which adds a 100 ms delay floor so proof generation cannot set the
send time. Override only when you need a different mean, a different floor, or
a lab-only strategy such as `NoSamplingDelayStrategy`. Cover transmissions
apply the same pre-send hold, sampled from the configured strategy, so cover
is not the only traffic class departing exactly on its emission schedule.

```nim
let ct = ConstantRateCoverTraffic.new(
  totalSlots = 10, epochDuration = 10.seconds, useInternalEpochTimer = true
)

# Optional: custom means (hop mean vs independent sender-hold mean)
let delay = DelayStrategy(
  ExponentialDelayStrategy.new(
    meanDelay = 100,
    rng = switch.rng,
    initialMeanDelay = 100,
  )
)

let mix = MixProtocol.new(
  mixNodeInfo, switch,
  coverTraffic = Opt.some(CoverTraffic(ct)),
  delayStrategy = Opt.some(delay),
)
```

Custom cover-traffic integrations must use the asynchronous, epoch-aware
callback signatures introduced in this release. Builders now have the form
`proc(epoch: uint64): Future[Result[CoverPacketBuild, string]]`, and senders
receive the claimed epoch as a fourth argument. The epoch must be preserved so
proof work can be discarded safely when an epoch changes. Proof generators
return the packet and the token of its proof as a `CoverProofResult`. A node
with spam protection must set a token reclaimer with `setProofTokenReclaimer`.

## Message-oriented transport integration

| | Connection API | Message API |
|---|---|---|
| Use it for | A libp2p protocol that reads and writes a stream | A plug-in that defines its own message framing and manages its reply blocks |
| Send | Open a stream with `toConnection` | Send bytes with `send(destination, service, payload)` |
| Receive and reply | A mounted protocol reads and writes the connection | A delivery handler receives the payload and can reply with `sendWithSurb` |
| Destination | Exit node or forwarding address | The destination is the exit node |

### A one-request ping

This example uses two started Mix nodes with populated relay pools and rotation
disabled. Install `installPing(responder)` once on the destination. On the
requester, call `await ping(requester, MixDestination.exitNode(responderId))`.
The entire request is a serialized SURB. The responder uses it to send back
one byte (`42`), and only the requester retains the reply credential.

```nim
import chronos, results
import libp2p_mix

const Service = "/example/ping/1.0.0"

proc installPing(responder: MixProtocol) =
  let handler: MixDeliveryHandler = proc(
      delivery: MixDelivery
  ): Future[void] {.async: (raises: [CancelledError]).} =
    var surb = deserializeSurb(delivery.payload).valueOr:
      return
    discard await responder.sendWithSurb(move(surb), @[42.byte])
  responder.registerMixDeliveryHandler(Service, handler).expect("register ping")

proc ping(requester: MixProtocol, destination: MixDestination): Future[seq[byte]] {.async.} =
  var build = requester.createSurb(destination)
  let request = serializeSurb(build.get().surb).get()
  var credential = move(build.get().credential)
  defer:
    credential.wipe()

  let received = newFuture[seq[byte]]("ping")
  let handler: RawSurbReplyHandler = proc(
      reply: RawSurbReply
  ): Future[RawSurbReplyDisposition] {.async: (raises: [CancelledError]).} =
    if reply.identifier != credential.identifier:
      return RawSurbReplyDisposition.Unhandled
    if not received.finished:
      let payload = recoverReply(credential, reply).valueOr:
        return RawSurbReplyDisposition.Handled
      credential.wipe()
      received.complete(payload)
    return RawSurbReplyDisposition.Handled

  requester.registerRawSurbReplyHandler(handler).expect("register reply handler")
  defer:
    requester.unregisterRawSurbReplyHandler()
  (await requester.send(destination, Service, request)).expect("send ping")
  return await received.wait(2.seconds)
```

### Sharing a node with connection-based protocols

Choose a dedicated service name. A registered delivery handler gets every
delivery for its codec, including connection traffic with a SURB envelope.
Each node has one raw reply handler. The example owns that handler for a
single request. A host running several plug-ins should register it once and
route replies by identifier. Return `Unhandled` for unknown identifiers so
Mix can deliver replies to its own connections.

Both APIs draw on the same slot pool, cover traffic and spam protection. A
send rejected for lack of slots is not queued. Use
`getMaxServicePayloadSize(service)` when sizing message frames, including any
serialized SURBs carried inside the payload.

### Explicit destinations and key rotation

The `MixPubInfo` destination overload does not add the destination to the relay pool
or change the peer store. It applies the configured hop-address policy to the
explicit address. Relays use normal usable-address selection and first-hop backoff.

With key rotation disabled, the explicit destination may be outside the pool.
With rotation enabled, the supplied Mix public key must match a locally
unexpired pool record for that peer. Mix measures the record's age from the
last local update. If that update supplied an obsolete key and the destination
has already retired it, the local check can pass but the destination cannot
process its layer of the packet.

`createSurb` returns a `SurbBuild` containing a `surb` and a separate
`ReplyCredential`. Move the credential into its owner at the requester. Wipe it
after use, by `credentialsExpireAt` when present, or on shutdown, whichever
comes first. Serialize only the SURB and send a reply with `sendWithSurb`.
Treat the supplied SURB as consumed even when the send fails. A registered raw
reply handler can recover its payload with `recoverReply(credential, reply)`;
return `Unhandled` to retain the embedded connection fallback. Each embedded
SURB is consumed independently, so other replies in its group remain usable.
This replaces the lower-level key/secret reply interface; connection-based
consumers can continue using `toConnection`.

With key rotation enabled, `SurbBuild` also exposes `dispatchBefore`,
`replyHoldTime`, `replyTransitAllowance` and `credentialsExpireAt`. These are
local monotonic-clock bounds: dispatch before the first deadline, limit how long
the recipient holds the block, and wipe retained credentials by their expiry.
The transit allowance covers supply delivery and reply transit under the
configured Mix timing assumptions. Plug-ins must account for time spent waiting
and retrying; passing a SURB to `sendWithSurb` does not enforce these bounds.
Without rotation these fields are absent. Call `wipe` when retiring a credential.

Both service-send overloads and `sendWithSurb` participate in protocol shutdown.
Stopping the protocol ends pending sends with an error; caller cancellation
propagates. Slots and completed proofs are refunded only when no write was
attempted. An interrupted proof can retain its slot because its provider may
already have spent the message ID. Delivery and raw-reply callbacks must handle
recoverable errors internally; their effect types allow only cancellation to
escape. Exit-is-destination dispatch is available without a compile-time flag.

## Building & running

> You can set up the project and run the tests in either a native or Nix shell.
> The Nix shell pins Nim v2.2.12 and Nimble v0.22.3. CI tests Nim v2.2.6 (`refc`) and
> v2.2.14 (`refc` and `orc`). A native shell can use a newer supported
> toolchain.

To set up the project:

```bash
git clone https://github.com/logos-co/nim-libp2p-mix.git
cd nim-libp2p-mix
make setup        # generates nimble.paths
```

`make setup` runs Nimble with `--useSystemNim` and `--nim:$NIMBLE_NIM`. When
choosenim is available, `NIMBLE_NIM` defaults to the real compiler under the
toolchain path reported by `choosenim show path`; otherwise it uses `nim` from
`PATH`. This is necessary because choosenim's `~/.nimble/bin/nim` proxy does not
live in a Nim installation containing `nim.nimble`, so Nimble cannot recognize
that proxy as a system compiler. The Nix shell sets `NIMBLE_NIM` to its
underlying pinned Nim derivation for the same reason. This uses project-local
dependency mode, keeps the selected compiler instead of downloading a different
Nim version, and adds `--noNimblePath` to the generated `nimble.paths`.

If the default SAT solver reports an invalid dependency even though a suitable
package or tag exists, its registry or tag index may be stale. Nimble does not
automatically refresh this metadata when new packages or tags are published.

If metadata cleanup is not enough, completely reset Nimble's downloaded package
and resolver state before retrying:

```bash
nimble_dir="${NIMBLE_DIR:-$HOME/.nimble}"
rm -rf "$nimble_dir/pkgcache" "$nimble_dir/pkgs2" "$nimble_dir/buildtemp"
rm -f "$nimble_dir/nimbledata2.json" \
  "$nimble_dir/packages_official.json" "$nimble_dir/packages_temp.json"
make clean
make setup NIMBLE_FLAGS="-y"
```

This is destructive global cleanup. It affects other projects, removes globally
installed package sources, and can leave launchers in `$nimble_dir/bin` that
need to be reinstalled. It deliberately leaves the Nim and Nimble executables
themselves untouched.

For the less destructive metadata-only retry, use:

```bash
make clean-all
make setup
```

`clean-nimble-cache` affects global Nimble metadata shared by other projects,
so it is kept separate from the normal `clean` target. It removes the package
registry and SAT tag index, not downloaded packages or other global Nimble
state. The legacy solver does not use the SAT index; removing it is harmless
but unnecessary when using the legacy solver.

To verify resolution without changing either global Nimble state or the
project's generated paths, use a fresh directory:

```bash
tmpdir="$(mktemp -d)"
cp libp2p_mix.nimble "$tmpdir/"
(
  cd "$tmpdir"
  nimble --nimbleDir:"$tmpdir/nimble" setup -l --useSystemNim \
    --nim:"${NIMBLE_NIM:-nim}" -y
)
rm -rf "$tmpdir"
```

This redownloads package metadata and sources without replacing the project's
`nimble.paths`, so it is intentionally not provided as a routine Make target.

You can override the `NIMBLE_FLAGS` variable to pass extra flags to nimble:

```bash
make setup NIMBLE_FLAGS="-y"          # non-interactive
make setup NIMBLE_FLAGS=--solver:legacy # legacy solver
```

### Tests

```bash
make test            # 14 unit-test files (~143 individual checks)
make testComponent   # 6 component (integration) tests, ~26 checks
make testAll         # both
```

The Make targets pass the same system-compiler selection flags used by
`make setup`, preventing each Nimble task invocation from selecting a different
Nim package.

The `tests/config.nims` enables `-d:metrics` and several
`libp2p_*_metrics` defines so tests can assert on metric counters.

### Formatting

```bash
make format
```

`make format` runs `nph` over tracked Nim files. It assumes `nph` version
`0.7.0` is installed globally in the native shell, matching CI:

```bash
nimble -y install nph@0.7.0
```

Check the installed package version with `nimble dump nph` and look for
`version: "0.7.0"`. The `nph --version` output may still show a prerelease
string for this release, so prefer the Nimble package metadata.

### Example

```bash
make example
```

This compiles `examples/mix_ping.nim`, which spins up 10 mix nodes locally,
mounts the libp2p `Ping` protocol on a destination, sends a ping through the
mix network, and waits for the reply via SURBs. Expected output:

```
INF Ping response received through mix network rtt=41ms…
```

To build the binary without auto-cleanup:

```bash
nim c -d:metrics -o:mix_ping examples/mix_ping.nim
./mix_ping
```

### Cleaning

- `make clean` removes local generated artifacts: `nimble.lock`,
  `nimbledeps/`, and `nimble.paths`.
- `make clean-nimbledeps` only removes `nimbledeps/` and `nimble.paths`,
  leaving the Nix dependency lock untouched.
- `make clean-nimble-cache` removes the cached package registry and
  `$NIMBLE_DIR/pkgcache/tagged_versions.json`; `NIMBLE_DIR` defaults to
  `~/.nimble`. It leaves downloaded packages intact.
- `make clean-all` is equivalent to `make clean` plus `make clean-nimble-cache`.
- `make refresh-deps` runs `make clean-all` and then forces regeneration of
  the committed `nix/deps.nix` snapshot. Because this removes `nimbledeps/`
  and `nimble.paths`, run `make setup` afterwards before building or testing.

### Nix

A flake is provided for reproducible dev shells and builds.

```bash
nix develop          # drops you into a shell with nim 2.2 + nimble
nix build            # type-checks libp2p_mix.nim against locked deps
```

The development shell uses Nimble v0.22.3 because the v0.18.2 release in
nixos-25.05 cannot reliably resolve the current dependency graph from a cold
cache.

The flake reads `nix/deps.nix`, which is the **committed** snapshot of all
pinned transitive dependencies. Refresh it after bumping the libp2p pin in
`libp2p_mix.nimble`:

```bash
make deps   # regenerates nix/deps.nix
```

To force regeneration from clean project-local dependencies and Nimble
metadata, run:

```bash
make refresh-deps
```

This removes `nimbledeps/` and `nimble.paths`. Run `make setup` afterwards
before building or testing.

`NIMBLE_FLAGS` can be passed to `make refresh-deps` the same way as
`make setup`; command-line variables are forwarded to the recursive
`make deps` invocation:

```bash
make refresh-deps NIMBLE_FLAGS="-y"
```

`NIMBLE_FLAGS` can also be passed to `make build` when dependency generation
may be triggered as part of the build:

```bash
make build NIMBLE_FLAGS="-y"
```

For predictable forced regeneration, prefer `make refresh-deps`; `make build`
only uses `NIMBLE_FLAGS` if `nimble.lock` or `nix/deps.nix` need to be
regenerated.

After regenerating dependencies, review any changes to `nix/deps.nix`. A
change means that the newly resolved dependency snapshot differs from the
committed one; commit it only when the update is intentional. Otherwise,
restore the committed snapshot before running `nix build`, which consumes this
file.

`--solver:legacy` was needed while `libp2p` was pinned as a git dependency.
With a tagged dependency such as `libp2p == 2.1.4`, Nimble's default SAT solver
should resolve the graph, and CI passes only `-y`. If the SAT solver reports an
invalid dependency, first retry with a fresh tag index as described above. Use
the legacy solver only as a temporary workaround or diagnostic fallback.

To quickly check that you are in the nix shell run:

```bash
echo "${IN_NIX_SHELL:-not in nix shell}"
```

`$IN_NIX_SHELL` is set by both `nix develop` and `nix-shell`. Typical
values: `impure` (default) or `pure` (when invoked with `--pure`). Any
non-empty value means you're inside a nix shell. Empty or unset means
you're not.

`make deps` requires `nix-prefetch-git` and `jq` on `$PATH`. Make generates a
fresh `nimble.lock`, forwards `NIMBLE_FLAGS` to `nimble lock`, and then passes
the existing lock file to `tools/gen-deps.sh`. When invoked directly, the
script requires its lock file argument to exist; it does not run Nimble or
generate lock files itself.

`nimble.lock` itself is **not** committed — it's an intermediate build
artefact regenerated on demand and removed after `nix/deps.nix` is generated
(it lives in `.gitignore`). The long-lived pinning artefact for this repo is
`nix/deps.nix`. Downstream consumers that need an exact dep set should pin
libp2p_mix by URL+SHA in their own `.nimble`. See
logos-co/nim-libp2p-mix#13 for the discussion behind this.

## Compile-time flags

| Flag | Purpose |
|---|---|
| `-d:metrics` | Enable Prometheus-style metric counters (test-time default). |
| `-d:enable_mix_benchmarks` | Compile in benchmark/timing helpers from `libp2p_mix/benchmark.nim`. |

## License

Licensed under either of:

- Apache License 2.0 ([LICENSE-APACHEv2](LICENSE-APACHEv2))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
