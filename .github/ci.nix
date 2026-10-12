{ pkgs ? import <nixpkgs>
  { overlays =
    [ (import ../overlay.nix)
    ];
  }
}:
pkgs.mold-macho.override
  { incremental = true;
    doCheck = true;
    buildType = "debug";
  }
