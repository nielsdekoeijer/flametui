{
  description = "flametui: flamegraphs in the tui";

  inputs = {
    # grab nixpkgs, I use unstable!
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";

    # for 'foreach' system
    utils.url = "github:numtide/flake-utils";

    # grab zig overlay for zig
    zig-flake.url = "github:mitchellh/zig-overlay";

    # put our zig into zls to ensure it matches
    zls-flake = {
      url = "github:zigtools/zls?ref=0.15.0";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.zig-overlay.follows = "zig-flake";
    };
  };

  outputs = { self, nixpkgs, utils, zig-flake, zls-flake }:
    utils.lib.eachSystem [
      "x86_64-linux"
      "aarch64-linux"
    ] (system:
      let

        # packages for the given system
        pkgs = import nixpkgs {
          inherit system;

          # use overlays
          overlays = [
            (final: prev: {
              zig = zig-flake.packages.${system}."0.15.1";
              zls = zls-flake.packages.${system}.default.overrideAttrs (old: {
                nativeBuildInputs = (old.nativeBuildInputs or [ ])
                  ++ [ final.zig ];
              });
            })
          ];
        };
      in {
        # on `nix build`
        packages.default = pkgs.stdenv.mkDerivation {
          pname = "flametui";
          version = "0.0.1-alpha";
          src = ./.;

          nativeBuildInputs = [ pkgs.zig ];


          preBuild = ''
            export ZIG_GLOBAL_CACHE_DIR=$src/.zig-cache
          '';

          buildPhase = ''
            # Release build
            zig build -Doptimize=ReleaseSafe --prefix $out
          '';

          dontInstall = true;
        };

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
