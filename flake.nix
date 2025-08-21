{
  description = "osh-oxy: fzf shell history search";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:NixOS/nixpkgs";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs =
    { self
    , flake-utils
    , nixpkgs
    , rust-overlay
    }:

    flake-utils.lib.eachDefaultSystem (system:
    let
      overlays = [
        (import rust-overlay)
        (self: super: {
          rustToolchain =
            let
              rust = super.rust-bin;
            in
            if builtins.pathExists ./rust-toolchain.toml then
              rust.fromRustupToolchainFile ./rust-toolchain.toml
            else if builtins.pathExists ./rust-toolchain then
              rust.fromRustupToolchainFile ./rust-toolchain
            else
              rust.stable.latest.default;
        })
      ];

      pkgs = import nixpkgs { inherit system overlays; };

      app = pkgs.rustPlatform.buildRustPackage {
        pname = "osh-oxy";
        version = "0.0.1";
        src = ./.;

        cargoLock = {
          lockFile = ./Cargo.lock;
        };

        nativeBuildInputs = [ pkgs.pkg-config ];
        PKG_CONFIG_PATH = "${pkgs.openssl.dev}/lib/pkgconfig";
      };

    in
    rec
    {
      packages = {
        app = app;
        all = pkgs.symlinkJoin {
          name = "all";
          paths = [ pkgs.fzf app ];
        };
        default = packages.all;
      };

      devShells.default = pkgs.mkShell {
        nativeBuildInputs = with pkgs; [
          rustToolchain
          openssl
          pkg-config
          cargo-deny
          cargo-edit
          cargo-watch
          rust-analyzer
        ];

        shellHook = ''
          ${pkgs.rustToolchain}/bin/cargo --version
        '';
      };
    });
}
