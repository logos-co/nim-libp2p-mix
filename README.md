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

> You can set up the project and run the tests in either a native or Nix shell.
> The Nix shell pins Nim v2.2.4 and Nimble v0.22.2. CI tests Nim v2.2.4 and
> v2.2.10 with Nimble v0.22.2. A native shell can use a newer supported
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
nim c -d:libp2p_mix_experimental_exit_is_dest -d:metrics -o:mix_ping examples/mix_ping.nim
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

The development shell uses Nimble v0.22.2 because the v0.18.2 release in
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
| `-d:libp2p_mix_experimental_exit_is_dest` | Allow exit nodes to also be the message destination (waku/lightpush usage). Enabled by default in `libp2p_mix.nimble`. |
| `-d:metrics` | Enable Prometheus-style metric counters (test-time default). |
| `-d:enable_mix_benchmarks` | Compile in benchmark/timing helpers from `libp2p_mix/benchmark.nim`. |

## License

Licensed under either of:

- Apache License 2.0 ([LICENSE-APACHEv2](LICENSE-APACHEv2))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
