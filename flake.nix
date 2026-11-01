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
          version = "0.1.0.9000";
          src = ./pkg/credgate;
          propagatedBuildInputs = with pkgs.rPackages; [ cli jsonlite rlang stringi yaml ];
          nativeBuildInputs = with pkgs.rPackages; [ cli jsonlite rlang stringi yaml ];
          meta = {
            description = "Governance layer for LLM requests with Indian PII detection";
            homepage = "https://github.com/dwarpal/credgate";
            license = pkgs.lib.licenses.asl20;
            maintainers = with maintainers; [ bharatsikka aishwaryabais ];
            platforms = pkgs.lib.platforms.unix;
          };
        };

      # The Python package, written as a nixpkgs python-modules derivation
      # (pkgs/development/python-modules/credgate). Tests run in checkPhase.
      credgatePy = python3Packages:
        python3Packages.buildPythonPackage {
          pname = "credgate";
          version = "0.4.0";
          pyproject = true;
          src = ./pkg/python;
          build-system = [ python3Packages.hatchling ];
          dependencies = with python3Packages; [ regex pyyaml ];
          # PyNaCl (saved vaults) on 3.12+: in nixpkgs 26.05 its docs need a
          # Sphinx that no longer supports 3.11. The vault tests skip without it.
          nativeCheckInputs = [ python3Packages.pytestCheckHook ]
            ++ nixpkgs.lib.optional (python3Packages.pythonAtLeast "3.12") python3Packages.pynacl;
          pythonImportsCheck = [ "credgate" ];
          meta = {
            description = "Governance layer for LLM requests with Indian PII detection";
            homepage = "https://github.com/dwarpal/credgate";
            license = nixpkgs.lib.licenses.asl20;
            maintainers = with maintainers; [ bharatsikka aishwaryabais ];
            mainProgram = "credgate";
          };
        };
    in
    {
      packages = forAll (pkgs: rec {
        credgate-r = credgateR pkgs;
        credgate-py = credgatePy pkgs.python3Packages;
        # The CLI on its own (top-level `credgate` in nixpkgs).
        credgate = pkgs.python3Packages.toPythonApplication credgate-py;
        default = credgate;
      });

      checks = forAll (pkgs:
        let
          rTest = pkgs.rWrapper.override {
            packages = [ (credgateR pkgs) ] ++ (with pkgs.rPackages; [ testthat withr sodium ]);
          };
        in
        {
          # Runs the test suite against the installed package inside the
          # build sandbox: no network, read-only HOME, no IDE.
          credgate-r-tests = pkgs.runCommand "credgate-r-tests" {
            nativeBuildInputs = [ rTest ];
            # Servers and Linux builders often run R under the C locale;
            # test there on every platform so encoding bugs show up early.
            LC_ALL = "C";
          } ''
            cp -r ${./pkg/credgate/tests} tests
            chmod -R u+w tests
            cd tests
            Rscript testthat.R
            touch $out
          '';

          # Python tests run inside the package build, on the oldest and
          # newest Python in nixpkgs (requires-python is >=3.11).
          credgate-py = credgatePy pkgs.python3Packages;
          credgate-py311 = credgatePy pkgs.python311Packages;
          credgate-py314 = credgatePy pkgs.python314Packages;

          # Both packages ship copies of spec/ and the licence files;
          # fail if a copy is stale.
          spec-in-sync = pkgs.runCommand "credgate-spec-in-sync" { } ''
            fail() { echo "$1 is stale: run tools/sync-spec.sh"; exit 1; }
            diff -r ${./spec} ${./pkg/credgate/inst/spec} || fail "R inst/spec"
            diff -r ${./spec} ${./pkg/python/src/credgate/spec} || fail "Python spec"
            for f in LICENSE NOTICE AUTHORS; do
              diff ${./.}/$f ${./pkg/python}/$f || fail "Python $f"
            done
            for f in NOTICE AUTHORS; do
              diff ${./.}/$f ${./pkg/credgate/inst}/$f || fail "R inst/$f"
            done
            touch $out
          '';

          # Lint and formatting of the Python package, examples and benchmark
          # scripts (config in pkg/python/pyproject.toml).
          ruff = pkgs.runCommand "credgate-ruff" { nativeBuildInputs = [ pkgs.ruff ]; } ''
            cp -r ${./pkg/python} python
            cp -r ${./examples} examples
            cp -r ${./benchmark} benchmark
            chmod -R u+w python examples benchmark
            export RUFF_CACHE_DIR=$TMPDIR/ruff-cache
            (cd python && ruff check . && ruff format --check .)
            for dir in examples benchmark; do
              ruff check --config python/pyproject.toml $dir
              ruff format --check --config python/pyproject.toml $dir
            done
            touch $out
          '';
        });

      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = [
            (pkgs.rWrapper.override {
              packages = with pkgs.rPackages; [
                cli rlang stringi yaml jsonlite
                testthat withr roxygen2 rcmdcheck pkgload knitr rmarkdown sodium askpass
              ];
            })
            (pkgs.python3.withPackages (ps: [ ps.regex ps.pyyaml ps.pytest ps.pynacl ps.hatchling ps.build ]))
            pkgs.ruff
            pkgs.qpdf
            pkgs.pandoc # lets R CMD check validate README.md
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
