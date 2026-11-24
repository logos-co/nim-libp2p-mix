{
  description = "nim-libp2p-mix dev shell flake";

  nixConfig = {
    extra-substituters = [ "https://nix-cache.status.im/" ];
    extra-trusted-public-keys = [
      "nix-cache.status.im-1:x/93lOfLU+duPplwMSBR+OlY4+mo+dCN7n0mr4oPwgY="
    ];
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
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
          # Keep the resolver aligned with CI.
          nimble_0_22_3 = pkgs.nimble.overrideAttrs (_: {
            version = "0.22.3";
            nimFlags = [ "--define:git_revision_override=42ef70c2102a942c46f13eb76872326edd525cec" ];
            src = pkgs.fetchgit {
              url = "https://github.com/nim-lang/nimble.git";
              rev = "42ef70c2102a942c46f13eb76872326edd525cec";
              sha256 = "1q3mpv0b5a0hhvdfn2c1f03hjbdwfam894vym14i3dm23qin2i5z";
              fetchSubmodules = true;
            };
          });
        in {
          default = pkgs.mkShell {
            NIMBLE_NIM = "${pkgs.nim.nim}/nim/bin/nim";
            nativeBuildInputs = [
              pkgs.nim
              nimble_0_22_3
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
