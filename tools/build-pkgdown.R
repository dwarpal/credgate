# Builds the R package's pkgdown site without network access (as in the Nix
# build of the documentation, flake.nix `docs`). Usage:
#   Rscript tools/build-pkgdown.R <package source> <destination>
args <- commandArgs(trailingOnly = TRUE)

# downlit links package names in code to their websites, looking up CRAN for
# packages that are not installed; without network, leave those unlinked.
ns <- asNamespace("downlit")
unlockBinding("CRAN_urls", ns)
assign("CRAN_urls", function() data.frame(Package = character(), URL = character()), envir = ns)

# bslib copies Bootstrap's JavaScript out of its (read-only) installed files
# into a folder that keeps their permissions, then fails to write into it:
# use a writable copy of bslib.
lib <- file.path(tempdir(), "writable-lib")
dir.create(lib)
file.copy(system.file(package = "bslib"), lib, recursive = TRUE)
Sys.chmod(list.files(lib, recursive = TRUE, full.names = TRUE, include.dirs = TRUE), "755")
Sys.chmod(file.path(lib, "bslib"), "755")
unloadNamespace("bslib")
.libPaths(c(lib, .libPaths()))

pkgdown::build_site(
  args[[1]],
  override = list(destination = args[[2]]),
  install = FALSE, new_process = FALSE, preview = FALSE, devel = FALSE
)
