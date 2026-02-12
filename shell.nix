let
  pkgs =
    import (builtins.fetchTarball "https://github.com/NixOS/nixpkgs/archive/nixos-25.11.tar.gz")
      {
        overlays = [
          (import (builtins.fetchTarball "https://github.com/oxalica/rust-overlay/archive/master.tar.gz"))
        ];
      };

  rustToolchain = pkgs.rust-bin.stable."1.88.0".default.override {
    extensions = [ "rust-src" ];
    targets = [ "wasm32-unknown-unknown" ];
  };
in
pkgs.mkShell {
  packages = [
    rustToolchain
    pkgs.rust-analyzer
    pkgs.just
    pkgs.foundry

    pkgs.cargo-bloat
    pkgs.cargo-machete
    pkgs.binaryen
  ];
}
