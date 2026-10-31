{
  description = "CredGate: governance layer for LLM requests with Indian PII detection";

  # Same nixpkgs branch as the maintainers' bundle overlay; it also supports
  # Intel Macs, which nixos-unstable has dropped.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-26.05-darwin";

  outputs = { self, nixpkgs }:
    let
      systems = [ "aarch64-darwin" "x86_64-darwin" "x86_64-linux" "aarch64-linux" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      maintainers = import ./nix/maintainers.nix;

      # The R package, built the same way nixpkgs builds CRAN packages.
      credgateR = pkgs:
        pkgs.rPackages.buildRPackage {
          name = "credgate";
          version = "0.0.0.9000";
          src = ./pkg/credgate;
          propagatedBuildInputs = with pkgs.rPackages; [ cli rlang stringi yaml ];
          nativeBuildInputs = with pkgs.rPackages; [ cli rlang stringi yaml ];
          meta = {
            description = "Governance layer for LLM requests with Indian PII detection";
            license = pkgs.lib.licenses.asl20;
            maintainers = with maintainers; [ bharatsikka aishwaryabais ];
            platforms = pkgs.lib.platforms.unix;
          };
        };
    in
    {
      packages = forAll (pkgs: rec {
        credgate-r = credgateR pkgs;
        default = credgate-r;
      });

      checks = forAll (pkgs:
        let
          rTest = pkgs.rWrapper.override {
            packages = [ (credgateR pkgs) ] ++ (with pkgs.rPackages; [ testthat withr ]);
          };
        in
        {
          # Runs the test suite against the installed package inside the
          # build sandbox: no network, read-only HOME, no IDE.
          credgate-r-tests = pkgs.runCommand "credgate-r-tests" {
            nativeBuildInputs = [ rTest ];
          } ''
            cp -r ${./pkg/credgate/tests} tests
            chmod -R u+w tests
            cd tests
            Rscript testthat.R
            touch $out
          '';

          # The R package ships a copy of spec/; fail if it is stale.
          spec-in-sync = pkgs.runCommand "credgate-spec-in-sync" { } ''
            diff -r ${./spec} ${./pkg/credgate/inst/spec} \
              || { echo "inst/spec is stale: run tools/sync-spec.sh"; exit 1; }
            touch $out
          '';
        });

      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = [
            (pkgs.rWrapper.override {
              packages = with pkgs.rPackages; [
                cli rlang stringi yaml jsonlite
                testthat withr roxygen2 rcmdcheck pkgload
              ];
            })
            (pkgs.python3.withPackages (ps: [ ps.regex ps.pyyaml ]))
            pkgs.qpdf
          ];
          # The maintainers' ~/.Renviron pins R_LIBS_SITE to their bundle;
          # ignore it so this shell's packages are used.
          shellHook = ''
            export R_ENVIRON_USER=/dev/null
          '';
        };
      });
    };
}
