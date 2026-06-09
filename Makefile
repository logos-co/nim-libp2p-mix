.PHONY: all build deps clean

all: build

# `nimble.lock` is an intermediate build artefact, not committed to git
# (see .gitignore and issue #13). It's regenerated here from
# `libp2p_mix.nimble` only as input to `./tools/gen-deps.sh`, which
# produces the committed `nix/deps.nix`. The Nim-matrix CI jobs install
# deps via `nimble setup --localdeps -y` and don't read `nimble.lock`;
# only the `ci / nix` job regenerates `nimble.lock` on the fly (via
# `make deps`) and uses it as input to `gen-deps.sh`.
nimble.lock: libp2p_mix.nimble
	nimble lock

nix/deps.nix: nimble.lock tools/gen-deps.sh
	./tools/gen-deps.sh nimble.lock nix/deps.nix

deps: nix/deps.nix

build: deps
	nix build

clean:
	$(RM) nimble.lock nix/deps.nix
