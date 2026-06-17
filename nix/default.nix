{ pkgs, src }:

let
  deps = import ./deps.nix { inherit pkgs; };
  pathArgs =
    builtins.concatStringsSep " "
      (map (p: "--path:${p}") (builtins.attrValues deps));
in
pkgs.stdenv.mkDerivation {
  pname = "nim-libp2p-mix";
  version = "dev";

  inherit src;

  nativeBuildInputs = [
    pkgs.nim-2_2
    pkgs.git
    pkgs.nimble
  ];

  buildPhase = ''
    export HOME=$TMPDIR
    export XDG_CACHE_HOME=$TMPDIR/.cache
    export NIMBLE_DIR=$TMPDIR/.nimble

    echo "== Building libp2p_mix =="
    nim c \
      --noNimblePath \
      ${pathArgs} \
      --compileOnly \
      --styleCheck:usages \
      --styleCheck:error \
      --skipUserCfg \
      --threads:on \
      --opt:speed \
      -d:libp2p_mix_experimental_exit_is_dest \
      libp2p_mix.nim
  '';

  # `--compileOnly` produces no binary; the build verifies the package
  # type-checks. Mark the derivation as built without trying `make install`.
  installPhase = "mkdir -p $out";
}
