{
  description = "nim-libp2p-mix dev shell flake";

  nixConfig = {
    extra-substituters = [ "https://nix-cache.status.im/" ];
    extra-trusted-public-keys = [
      "nix-cache.status.im-1:x/93lOfLU+duPplwMSBR+OlY4+mo+dCN7n0mr4oPwgY="
    ];
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux" "aarch64-linux" "armv7a-linux"
        "x86_64-darwin" "aarch64-darwin"
        "x86_64-windows"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in {
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
        in {
          default = import ./nix/default.nix {
            inherit pkgs;
            src = ./.;
          };
        }
      );

      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          # nixos-25.05 ships Nimble 0.18.2, whose resolver cannot reliably
          # select a single version from the current dependency graph.
          nimble_0_22_2 = pkgs.nimble.overrideAttrs (_: {
            version = "0.22.2";
            src = pkgs.fetchgit {
              url = "https://github.com/nim-lang/nimble.git";
              rev = "aa03f886e4a111d6af9090c6a1f1271d64b66f7b";
              sha256 = "1i2hs52vc7ig3z7dj2w4czqkhsiyv991mw20xyfd615q7ll0k09y";
              fetchSubmodules = true;
            };
          });
        in {
          default = pkgs.mkShell {
            NIMBLE_NIM = "${pkgs.nim-2_2.nim}/nim/bin/nim";
            nativeBuildInputs = [
              pkgs.nim-2_2
              nimble_0_22_2
              pkgs.git
              pkgs.jq
              pkgs.makeWrapper
              pkgs.nix-prefetch-git
            ];
          };
        }
      );
    };
}
