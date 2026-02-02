let
  pkgs = import <nixpkgs> {
    overlays = [
      (import (builtins.fetchTarball "https://github.com/oxalica/rust-overlay/archive/master.tar.gz"))
    ];
  };

  rustToolchain = pkgs.rust-bin.stable."1.87.0".default.override {
    extensions = [ "rust-src" ];
  };

  circom = pkgs.callPackage ./flakes/circom.nix { };
in
pkgs.mkShell {
  packages = with pkgs; [
    rustToolchain
    rust-analyzer
    circom
  ];
}
