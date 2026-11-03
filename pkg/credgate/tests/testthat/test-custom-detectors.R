# Custom detectors from YAML files: loading rules and policies that name
# them. Detection results are covered by the shared conformance cases.

loan_file <- function() {
  list(
    kind = "credgate-detectors", version = 1L,
    detectors = list(list(
      id = "loan_account", class = "financial", label = "Loan account number",
      patterns = list("LN[0-9]{10}"), bounded = TRUE, context = "loan|\\ba/c\\b",
      base = 0.6, base_without_context = 0.4,
      examples = list(match = list("Loan a/c LN0012345678"), no_match = list("LN00123"))
    ))
  )
}

fresh <- function(env = parent.frame()) {
  credgate:::register_builtin_detectors()
  withr::defer(credgate:::register_builtin_detectors(), envir = env)
}

test_that("a file registers everything or nothing", {
  fresh()
  two <- loan_file()
  second <- two$detectors[[1]]
  second$id <- "emp_code"
  second$patterns <- list("EMP[0-9]{6}")
  second$examples <- list(match = list("EMP12345"))
  two$detectors[[2]] <- second
  expect_error(load_detectors(two), "EMP12345")
  expect_false("loan_account" %in% cg_detectors()$id)
})

test_that("loading the same file again changes nothing; a different one needs replace", {
  fresh()
  path <- withr::local_tempfile(fileext = ".yaml")
  yaml::write_yaml(loan_file(), path)
  expect_identical(load_detectors(path), "loan_account")
  expect_identical(load_detectors(path), "loan_account")
  changed <- loan_file()
  changed$detectors[[1]]$base <- 0.7
  expect_error(load_detectors(changed), "already registered")
  load_detectors(changed, replace = TRUE)
  expect_equal(detect_pii("Loan a/c LN0012345678", "loan_account")$confidence, 0.94)
})

test_that("a policy names its detector files, relative to the policy", {
  fresh()
  dir <- withr::local_tempdir()
  dir.create(file.path(dir, "detectors"))
  yaml::write_yaml(loan_file(), file.path(dir, "detectors", "bank.yaml"))
  yaml::write_yaml(list(
    policy = "credgate-policy", version = 1L, id = "bank", revision = 1L,
    detectors = list("detectors/bank.yaml"),
    destinations = list(claude = list(tier = "frontier")),
    rules = list(list(id = "loans-tokenised", when = list(types = list("loan_account")), action = "tokenise")),
    default_action = "allow"
  ), file.path(dir, "policy.yaml"))
  p <- cg_policy(file.path(dir, "policy.yaml"))
  d <- policy_apply(p, "Loan a/c LN0012345678 overdue", "claude", vault = cg_vault())
  expect_identical(d$text, "Loan a/c [LOAN_ACCOUNT_1] overdue")
  expect_identical(d$matches$rule, "loans-tokenised")

  # the editor's writer keeps the detectors list, and reports changes to it
  x <- yaml::read_yaml(file.path(dir, "policy.yaml"))
  policy_write(x, file.path(dir, "policy.yaml"), user = "infosec-1")
  expect_identical(unlist(yaml::read_yaml(file.path(dir, "policy.yaml"))$detectors), "detectors/bank.yaml")
  y <- x
  y$detectors <- NULL
  expect_true(any(grepl("^detectors: detectors/bank.yaml -> none", policy_diff(x, y))))
})

test_that("a policy with a missing detector file does not load", {
  fresh()
  expect_error(cg_policy(list(
    policy = "credgate-policy", version = 1L, id = "bank", revision = 1L,
    detectors = list("missing.yaml"),
    destinations = list(claude = list(tier = "frontier")), rules = list(), default_action = "allow"
  ), dir = tempdir()), "missing.yaml", class = "credgate_policy_error")
})
