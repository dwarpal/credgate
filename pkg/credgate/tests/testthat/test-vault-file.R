pass <- "a test passphrase"

test_that("a saved vault opens again and continues numbering", {
  skip_if_not_installed("sodium")
  path <- withr::local_tempfile(fileext = ".cgvault")
  vault <- cg_vault()
  tokenise("PAN ABCPE1234F, mobile 9876543210", vault)
  vault_save(vault, path, passphrase = pass)
  expect_identical(format(file.mode(path)), "600")
  expect_identical(readBin(path, "raw", 8L), c(charToRaw("CGVAULT"), as.raw(1L)))
  opened <- vault_open(path, passphrase = pass)
  expect_identical(opened$entries, vault$entries)
  expect_identical(tokenise("PAN XYZPQ9876R, abcpe1234f", opened), "PAN [PAN_2], [PAN_1]")
  expect_identical(restore("[MOBILE_IN_1]", opened), "9876543210")
})

test_that("an empty vault round-trips", {
  skip_if_not_installed("sodium")
  path <- withr::local_tempfile(fileext = ".cgvault")
  vault_save(cg_vault(), path, passphrase = pass)
  expect_equal(length(vault_open(path, passphrase = pass)), 0)
})

test_that("the passphrase can come from the environment", {
  skip_if_not_installed("sodium")
  path <- withr::local_tempfile(fileext = ".cgvault")
  withr::local_envvar(CREDGATE_VAULT_PASSPHRASE = pass)
  vault <- cg_vault()
  tokenise("PAN ABCPE1234F", vault)
  vault_save(vault, path)
  expect_equal(length(vault_open(path)), 1)
})

test_that("bad passphrases, damaged files and other files are refused", {
  skip_if_not_installed("sodium")
  withr::local_envvar(CREDGATE_VAULT_PASSPHRASE = "")
  path <- withr::local_tempfile(fileext = ".cgvault")
  vault <- cg_vault()
  tokenise("PAN ABCPE1234F", vault)
  expect_error(vault_save(vault, path, passphrase = "short"), "at least 12", class = "credgate_vault_file")
  expect_error(vault_save(vault, path), "No passphrase", class = "credgate_vault_file")
  vault_save(vault, path, passphrase = pass)
  expect_error(vault_open(path, passphrase = "the wrong passphrase"), "Wrong passphrase", class = "credgate_vault_file")

  bytes <- readBin(path, "raw", file.size(path))
  bytes[length(bytes)] <- xor(bytes[length(bytes)], as.raw(1L))
  damaged <- withr::local_tempfile(fileext = ".cgvault")
  writeBin(bytes, damaged)
  expect_error(vault_open(damaged, passphrase = pass), "damaged or altered", class = "credgate_vault_file")

  bytes[8] <- as.raw(9L)
  writeBin(bytes, damaged)
  expect_error(vault_open(damaged, passphrase = pass), "version 9", class = "credgate_vault_file")

  other <- withr::local_tempfile(fileext = ".txt")
  writeLines("not a vault", other)
  expect_error(vault_open(other, passphrase = pass), "Not a credgate vault", class = "credgate_vault_file")
  expect_error(vault_save(vault, other, passphrase = pass), "not replacing", class = "credgate_vault_file")
  expect_identical(readLines(other), "not a vault")
})
