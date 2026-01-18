{
  description = "YOUR DESCRIPTION HERE";

  inputs = {
    # grab nixpkgs, I use unstable!
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";

    # for 'foreach' system
    utils.url = "github:numtide/flake-utils";

    # grab zig overlay for zig
    zig-flake.url = "github:mitchellh/zig-overlay";

    # put our zig into zls to ensure it matches
    zls-flake = {
      url = "github:zigtools/zls?ref=master";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.zig-overlay.follows = "zig-flake";
    };
  };

  outputs = { self, nixpkgs, utils, zig-flake, zls-flake }:
    utils.lib.eachSystem [
      "x86_64-linux"
      "aarch64-linux"
      "x86_64-darwin"
      "aarch64-darwin"
    ] (system:
      let

        # packages for the given system
        pkgs = import nixpkgs {
          inherit system;

          # use overlays
          overlays = [
            (final: prev: {
              zig = zig-flake.packages.${system}."master";
              zls = zls-flake.packages.${system}.default.overrideAttrs (old: {
                nativeBuildInputs = (old.nativeBuildInputs or [ ])
                  ++ [ final.zig ];
              });
            })
          ];
        };
      in {
        # on `nix develop`
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = [ pkgs.zig pkgs.zls ];

          # puts a nice hook, I like this
          shellHook = ''
            PS1="(dev) $PS1"
          '';
        };
      });
}
