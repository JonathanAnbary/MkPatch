{
  description = "Patch binary files with ease";
  inputs = {
    nixpkgs-stable.url = "github:NixOS/nixpkgs/nixos-24.11";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    zig-overlay.url = "github:mitchellh/zig-overlay";
    # zls-overlay.url = "github:zigtools/zls";
    zls-overlay.url = "github:zigtools/zls/0.16.0";
  };

  outputs =
    inputs@{
      self,
      nixpkgs,
      nixpkgs-stable,
      ...
    }:
    let
      pkgs = import nixpkgs {
        system = "x86_64-linux";
        config.allowUnfree = true;
      };
      pkgs-stable = import nixpkgs-stable {
        system = "x86_64-linux";
        config.allowUnfree = true;
      };
      # zig = inputs.zig-overlay.packages.x86_64-linux.master;
      zig = inputs.zig-overlay.packages.x86_64-linux."0.16.0";
      zls = inputs.zls-overlay.packages.x86_64-linux.zls.overrideAttrs (old: {
        nativeBuildInputs = [ zig ];
      });
    in
    {
      devShells.x86_64-linux.default = pkgs.mkShell {
        packages = [
          pkgs.claude-code
          zls
          zig
          pkgs.git
          pkgs-stable.qemu
          pkgs-stable.wine64
          pkgs-stable.wineWowPackages.stable
          (pkgs.python3.withPackages (
            python-pkgs: with python-pkgs; [
              # select Python packages here
              ipython
              python-lsp-server
            ]
          ))
        ];
      };
    };
}
