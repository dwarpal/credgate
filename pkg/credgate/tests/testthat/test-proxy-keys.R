test_that("R manages the proxy keys file as Python does", {
  skip_if_not_installed("openssl")
  keys <- withr::local_tempfile(fileext = ".json")
  priya <- proxy_add_user(keys, "priya", days = 30)
  expect_match(priya, "^cgk_[A-Za-z0-9_-]{43}$")
  expect_false(grepl(priya, paste(readLines(keys), collapse = ""), fixed = TRUE))
  expect_identical(file.mode(keys), as.octmode("600"))
  arjun <- proxy_add_user(keys, "arjun", days = 3)
  u <- proxy_users(keys)
  expect_identical(u$status[u$name == "priya"], "active")
  expect_identical(u$status[u$name == "arjun"], "expires soon")
  expect_false(any(grepl("sha256", unlist(u))))
  expect_error(proxy_add_user(keys, "priya"), "already exists")
  expect_error(proxy_add_user(keys, "x", days = 365), "1 to 180")
  new <- proxy_rotate_key(keys, "priya")
  expect_false(identical(new, priya))
  proxy_remove_user(keys, "arjun")
  expect_error(proxy_remove_user(keys, "priya"), "last user")
  data <- jsonlite::fromJSON(keys)
  expect_identical(data$users$priya$hash, credgate:::proxy_key_hash(new))
})

test_that("Python's proxy reads a keys file written by R", {
  skip_if_not_installed("openssl")
  py <- Sys.which("python3")
  skip_if(!nzchar(py) || system2(py, c("-c", shQuote("import credgate.proxy_keys")), stdout = FALSE, stderr = FALSE) != 0,
          "Python credgate with proxy_keys not available")
  keys <- withr::local_tempfile(fileext = ".json")
  key <- proxy_add_user(keys, "priya", days = 30)
  out <- system2(py, c("-c", shQuote(sprintf(
    "from credgate.proxy_keys import read_keys, hash_key; e = read_keys('%s')['priya']; print(e.hash == hash_key('%s'), e.expires is not None)",
    keys, key
  ))), stdout = TRUE)
  expect_identical(out, "True True")
})
