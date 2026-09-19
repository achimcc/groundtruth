{
  description = "Measures the state a unit's status only promises: nftables sets, DNAT leftovers, proxy neighbours, addresses, sysctls";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs =
    { self, nixpkgs }:
    let
      # /proc/sys, nftables, network namespaces: Linux only.
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAll = f: nixpkgs.lib.genAttrs systems (s: f nixpkgs.legacyPackages.${s});
    in
    {
      packages = forAll (pkgs: {
        default = pkgs.rustPlatform.buildRustPackage {
          pname = "groundtruth";
          # Read out of Cargo.toml so the store path and the crate cannot disagree.
          version = (nixpkgs.lib.importTOML ./Cargo.toml).package.version;
          src = self;
          cargoLock.lockFile = ./Cargo.lock;
          nativeBuildInputs = [ pkgs.makeWrapper ];
          # The tools whose JSON the probes read. As a SUFFIX: on a host that
          # has its own nft and machinectl, those are the ones to ask.
          postInstall = ''
            wrapProgram $out/bin/groundtruth --suffix PATH : ${
              pkgs.lib.makeBinPath [
                pkgs.nftables
                pkgs.iptables
                pkgs.iproute2
                pkgs.util-linux
                pkgs.systemd
              ]
            }
          '';
          meta = {
            description = "Measures the state a unit's status only promises: nftables sets, DNAT leftovers, proxy neighbours, addresses, sysctls";
            homepage = "https://github.com/achimcc/groundtruth";
            license = pkgs.lib.licenses.agpl3Only;
            mainProgram = "groundtruth";
            platforms = pkgs.lib.platforms.linux;
          };
        };
      });

      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            rustc
            rustfmt
            clippy
          ];
        };
      });

      checks = forAll (
        pkgs:
        let
          package = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
        in
        {
          inherit package;
          clippy = package.overrideAttrs (old: {
            pname = "groundtruth-clippy";
            nativeBuildInputs = old.nativeBuildInputs ++ [ pkgs.clippy ];
            buildPhase = "cargo clippy --all-targets -- -D warnings";
            doCheck = false;
            installPhase = "touch $out";
          });
          fmt = package.overrideAttrs (old: {
            pname = "groundtruth-fmt";
            nativeBuildInputs = old.nativeBuildInputs ++ [ pkgs.rustfmt ];
            buildPhase = "cargo fmt --check";
            doCheck = false;
            installPhase = "touch $out";
          });
        }
      );
    };
}
