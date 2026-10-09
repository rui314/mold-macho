{ lib
, stdenv
, rustPlatform
, pkg-config
, zlib
, incremental ? false
, doCheck ? false
, buildType ? "release"
}:

let
  manifest = builtins.fromTOML (builtins.readFile ./Cargo.toml);

  platformSpecific =
    let inherit (stdenv.hostPlatform) system; in
    { aarch64-darwin =
        { cargoBuildFlags = [ "--no-default-features" "--features" "arm64" ];
        };
      x86_64-darwin = lib.warn
        "Support for the x86_64-darwin platform ended with nixpkgs-26.11"
        { cargoBuildFlags = [ "--no-default-features" "--features" "x86_64" ];
        };
    }.${system};
in
rustPlatform.buildRustPackage
  ( finalAttrs:
    let
      vendorDeps = finalAttrs: prevAttrs:
        let
          outputHashes =
            { # git dependencies are manually vendored
              "libmimalloc-sys-0.1.49" = "sha256-IF7/1rS0Pazst3rll691hhbB4QZkLHVAr7nv8Uqaf1s=";
            };
        in
        lib.mergeAttrs
          prevAttrs
          ( if incremental then
            { cargoDeps = rustPlatform.importCargoLock
              { lockFile = "${finalAttrs.src}/Cargo.lock";
                outputHashes = finalAttrs.cargoLock.outputHashes or outputHashes;
              };
            }
          else
            { cargoLock =
              { lockFile = "${finalAttrs.src}/Cargo.lock";
                outputHashes = finalAttrs.cargoLock.outputHashes or outputHashes;
              };
            }
          );
    in
    vendorDeps
      finalAttrs
      { inherit (manifest.package) name version;
        src = lib.fileset.toSource
          { root = ./.;
            fileset = lib.fileset.unions
              [ ./Cargo.toml
                ./Cargo.lock
                ./src
                ./targets
                ./cli
                ./tests
              ];
          };

        strictDeps = true;
        __structuredAttrs = true;

        inherit buildType;
        cargoBuildFlags = [ "--bin" "mold" ] ++ platformSpecific.cargoBuildFlags;

        inherit doCheck;
        nativeCheckInputs = [ pkg-config ];
        checkInputs = [ zlib ];
        # Some tools shipped with macOS that are not redistributed via
        # nixpkgs are necessary for the test suite.
        preCheck =
          '' export LDFLAGS="-L${zlib}/lib:$LDFLAGS"
             export PATH="/usr/bin:$PATH"
          '';

        postInstall =
          '' mkdir -p $out
             mv ${./LICENSE} $out/
          '';

        meta =
          { mainProgram = "mold";
            inherit (manifest.package) description;
            license = lib.getLicenseFromSpdxId manifest.package.license;
          };
      }
  )
