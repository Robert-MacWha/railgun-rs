{
  description = "Rust + Circom + Foundry dev shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    unstable.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs =
    {
      nixpkgs,
      unstable,
      rust-overlay,
      ...
    }:
    let
      system = "x86_64-linux";

      pkgs = import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      };

      unstable = import unstable { inherit system; };

      rust = pkgs.rust-bin.stable."1.87.0".default.override {
        extensions = [ "rust-src" ];
      };

      circom = pkgs.callPackage ./flakes/circom.nix { };
    in
    {
      devShells.${system}.default = pkgs.mkShell {
        packages = [
          rust
          pkgs.rust-analyzer
          circom
          unstable.foundry
        ];
      };
    };
}
