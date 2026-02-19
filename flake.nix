{
  description = "rustcrypto-fv - RustCrypto formally-verified";

  nixConfig = {
    extra-substituters = [ "https://hax.cachix.org" ];
    extra-trusted-public-keys = [ "hax.cachix.org-1:Oe3CtQr+8tJqpb+QNErHccOgkoA11sMm4/D4KHxOkY8=" ];
  };

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    hax.url = "github:cryspen/hax/hax-lib-v0.3.6";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, hax, ... } @ inputs:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
        rustToolchain = pkgs.rust-bin.nightly.latest.default;

        # Packages from nixpkgs
        nixpkgsPackages = with pkgs; [
          cargo
          cargo-expand
          cargo-flamegraph
          cargo-show-asm
          clippy
          jq
          pkg-config
          rust-analyzer
          rustToolchain
          rustfmt
        ];

        # Packages from flakes
        flakePackages = [
          hax.inputs.fstar.packages.${system}.default  # Use F* from hax
          hax.packages.${system}.default
        ];
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = nixpkgsPackages ++ flakePackages;

          shellHook = ''
            export RUST_BACKTRACE=1
            export FSTAR_HOME=${hax.inputs.fstar.packages.${system}.default}
            export HAX_HOME=${hax.packages.${system}.default}
            export HAX_LIB=${hax}/hax-lib
          '';
        };

        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "rustcrypto-fv";
          version = "0.1.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
        };
      }
    );
}
