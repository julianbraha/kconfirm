{
  description = "Rust with GCC codegen backend (rustc_codegen_gcc)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        rust-nightly = pkgs.rust-bin.selectLatestNightlyWith (toolchain:
          toolchain.default.override {
            extensions = [ "rust-src" "rustc-codegen-gcc-preview" ];
          });

        gccBackend = pkgs.stdenv.mkDerivation {
          name = "rustc-codegen-gcc";
          src = pkgs.fetchFromGitHub {
            owner = "rust-lang";
            repo = "rustc_codegen_gcc";
            rev = "master";
            sha256 = pkgs.lib.fakeSha256;
          };

          nativeBuildInputs = [ pkgs.cargo pkgs.rustc pkgs.gcc pkgs.git ];

          buildPhase = ''
            cargo build --release
          '';

          installPhase = ''
            mkdir -p $out/lib
            cp target/release/librustc_codegen_gcc.so $out/lib/
          '';
        };

      in {
        devShells.default = pkgs.mkShell {
          packages = [
            rust-nightly
            pkgs.gcc
            pkgs.cargo
            pkgs.rustc
          ];

          shellHook = ''
            export RUSTUP_TOOLCHAIN=nightly
            export RUSTFLAGS="-Zcodegen-backend=${gccBackend}/lib/librustc_codegen_gcc.so"
            export CARGO_TARGET_DIR=target
            echo "Rust GCC backend ready"
          '';
        };
      });
}
