key <- strrep("0123456789abcdef", 4)

test_that("parallel workers merge into one vault", {
  skip_if_not_installed("openssl")
  rows <- c("PAN ABCPE1234F", "mobile 9876543210", "PAN abcpe1234f again", "PAN AAACR5055K")
  w1 <- cg_vault(key)
  w2 <- cg_vault(key)
  out <- c(tokenise(rows[1:2], w1), tokenise(rows[3:4], w2))
  merged <- cg_vault(key)
  vault_merge(merged, w1)
  vault_merge(merged, w2)
  expect_equal(length(merged), 3)
  expect_identical(tokenise(rows, cg_vault(key)), out)
  expect_identical(restore(out[3], merged), "PAN ABCPE1234F again")
})

test_that("merge refuses numbered vaults and other keys", {
  skip_if_not_installed("openssl")
  expect_error(vault_merge(cg_vault(key), cg_vault()), "Only keyed")
  expect_error(vault_merge(cg_vault(key), cg_vault(strrep("ff", 32))), "different token keys")
})

test_that("collisions are errors", {
  skip_if_not_installed("openssl")
  vault <- cg_vault(key)
  tokenise("PAN ABCPE1234F", vault)
  other <- cg_vault(key)
  other$entries <- data.frame(
    token = tolower(vault$entries$token), type = "pan", class = "identity_strong",
    canonical = "XYZPQ9876R", value = "XYZPQ9876R"
  )
  expect_error(vault_merge(vault, other), class = "credgate_token_collision")
})

test_that("keys come from the argument or the environment", {
  skip_if_not_installed("openssl")
  withr::local_envvar(CREDGATE_TOKEN_KEY = key)
  expect_identical(tokenise("PAN ABCPE1234F", cg_vault(keyed = TRUE)), "PAN [PAN_bpg46o6x465d4]")
  expect_identical(cg_key_fingerprint(), "f6b1b6493c30fead")
  raw_key <- as.raw(strtoi(substring(key, seq(1, 63, 2), seq(2, 64, 2)), 16L))
  expect_identical(tokenise("PAN ABCPE1234F", cg_vault(raw_key)), "PAN [PAN_bpg46o6x465d4]")
  withr::local_envvar(CREDGATE_TOKEN_KEY = "")
  expect_error(cg_vault(keyed = TRUE), "No token key")
  expect_error(cg_vault("xyz"), "hex digits")
  expect_error(cg_vault(42), "hex text or a raw vector")
})

test_that("new keys are random and valid", {
  skip_if_not_installed("openssl")
  a <- cg_new_token_key()
  expect_false(identical(a, cg_new_token_key()))
  expect_equal(nchar(a), 64)
  expect_silent(cg_vault(a))
})

test_that("a saved keyed vault needs its key", {
  skip_if_not_installed("openssl")
  skip_if_not_installed("sodium")
  withr::local_envvar(CREDGATE_TOKEN_KEY = "")
  path <- withr::local_tempfile(fileext = ".cgvault")
  vault <- cg_vault(key)
  tokenise("PAN ABCPE1234F", vault)
  vault_save(vault, path, passphrase = "a test passphrase")
  expect_error(vault_open(path, passphrase = "a test passphrase"), "No token key")
  opened <- vault_open(path, passphrase = "a test passphrase", key = key)
  expect_identical(restore("[PAN_bpg46o6x465d4]", opened), "ABCPE1234F")
})
