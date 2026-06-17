.PHONY: all build deps refresh-deps clean clean-nimbledeps setup format

NIMBLE_FLAGS ?=
NPH_FILES = $(shell git ls-files '*.nim' '*.nimble' '*.nims')

RMDIR := rm -rf

all: build

setup:
	nimble setup -l $(NIMBLE_FLAGS)

# `nimble.lock` is an intermediate build artefact, not committed to git
# (see .gitignore and issue #13). It's regenerated here from
# `libp2p_mix.nimble` only as input to `./tools/gen-deps.sh`, which
# produces the committed `nix/deps.nix`. The Nim-matrix CI jobs install
# deps via `make setup NIMBLE_FLAGS="$NIMBLE_FLAGS"`, with `NIMBLE_FLAGS`
# defined once at workflow level, and don't read `nimble.lock`;
# only the `ci / nix` job regenerates `nimble.lock` on the fly (via
# `make deps`) and uses it as input to `gen-deps.sh`.
nimble.lock: libp2p_mix.nimble
	nimble lock $(NIMBLE_FLAGS)

nix/deps.nix: nimble.lock tools/gen-deps.sh
	NIMBLE_FLAGS='$(NIMBLE_FLAGS)' ./tools/gen-deps.sh nimble.lock nix/deps.nix

deps: nix/deps.nix

build: deps
	nix build

format:
	nph $(NPH_FILES)

clean:
	$(RMDIR) nimble.lock nimbledeps nimble.paths

clean-nimbledeps:
	$(RMDIR) nimbledeps nimble.paths

refresh-deps:
	$(RMDIR) nimble.lock
	$(MAKE) deps
