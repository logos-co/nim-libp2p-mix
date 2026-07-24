.PHONY: all build deps refresh-deps clean clean-all clean-nimble-cache clean-nimbledeps setup test testComponent testAll example benchmarkBuild format
.INTERMEDIATE: nimble.lock

NIMBLE_FLAGS ?=
NIMBLE_DIR ?= $(HOME)/.nimble
# Choosenim puts a proxy in ~/.nimble/bin, but Nimble needs the underlying
# installation containing nim.nimble in order to recognize a system compiler.
# `choosenim show path` can print Nimble diagnostics before the requested path.
ifeq ($(origin NIMBLE_NIM), undefined)
NIMBLE_NIM := $(shell if command -v choosenim >/dev/null 2>&1; then printf '%s/bin/nim' "$$(choosenim show path | tail -n 1)"; else command -v nim; fi)
endif
NIMBLE = nimble --useSystemNim --nim:"$(NIMBLE_NIM)"
NPH_FILES = $(shell git ls-files '*.nim' '*.nimble' '*.nims')

RMDIR := rm -rf

all: build

setup:
	$(NIMBLE) setup -l $(NIMBLE_FLAGS)

test:
	$(NIMBLE) test $(NIMBLE_FLAGS)

testComponent:
	$(NIMBLE) testComponent $(NIMBLE_FLAGS)

testAll:
	$(NIMBLE) test $(NIMBLE_FLAGS)
	$(NIMBLE) testComponent $(NIMBLE_FLAGS)

example:
	$(NIMBLE) example $(NIMBLE_FLAGS)

benchmarkBuild:
	$(NIMBLE) benchmarkBuild $(NIMBLE_FLAGS)

# `nimble.lock` is an intermediate build artefact, not committed to git
# (see .gitignore and issue #13). It's regenerated here from
# `libp2p_mix.nimble` only as input to `./tools/gen-deps.sh`, which
# produces the committed `nix/deps.nix`. The Nim-matrix CI jobs install
# deps via `make setup NIMBLE_FLAGS="$NIMBLE_FLAGS"`, with `NIMBLE_FLAGS`
# defined once at workflow level, and don't read `nimble.lock`;
# only the `ci / nix` job regenerates `nimble.lock` on the fly (via
# `make deps`) and uses it as input to `gen-deps.sh`.
nimble.lock: libp2p_mix.nimble
	$(NIMBLE) lock $(NIMBLE_FLAGS)
	@test -f "$@" || { echo "error: Nimble did not create $@" >&2; exit 1; }

nix/deps.nix: nimble.lock tools/gen-deps.sh
	./tools/gen-deps.sh nimble.lock nix/deps.nix

deps: nix/deps.nix

build: deps
	nix build

format:
	nph $(NPH_FILES)

clean:
	$(RMDIR) nimble.lock nimbledeps nimble.paths

clean-all: clean clean-nimble-cache

# Nimble's package registry and SAT tag index have no automatic invalidation
# and can omit packages or versions published after they were created. Keep
# this global metadata cleanup explicit.
clean-nimble-cache:
	$(RM) "$(NIMBLE_DIR)/pkgcache/tagged_versions.json"
	$(RM) "$(NIMBLE_DIR)/packages_official.json"
	$(RM) "$(NIMBLE_DIR)/packages_temp.json"

clean-nimbledeps:
	$(RMDIR) nimbledeps nimble.paths

refresh-deps: clean-all
	$(MAKE) -B deps
	@printf '\033[34m%s\033[0m\n' \
		"Dependency snapshot refreshed. Run 'make setup' before building or testing."
