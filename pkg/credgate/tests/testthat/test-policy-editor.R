template <- function() {
  path <- withr::local_tempfile(fileext = ".yaml", .local_envir = parent.frame())
  file.copy(system.file("policies", "bank-default.yaml", package = "credgate"), path)
  path
}

test_that("policy_write saves a new revision with a change log entry", {
  skip_if_not_installed("openssl")
  path <- template()
  x <- yaml::read_yaml(path)
  x$destinations$copilot$blocked <- NULL
  x$rules[1:2] <- rev(x$rules[1:2])
  written <- policy_write(x, path, user = "infosec-1", note = "Copilot approved for code")
  expect_identical(written$revision, 2L)
  reread <- cg_policy(path) # strict: the proxy would load it
  expect_identical(attr(reread, "source")$revision, 2L)
  expect_null(yaml::read_yaml(path)$destinations$copilot$blocked)
  log <- policy_changes(path)
  expect_true(attr(log, "intact"))
  expect_identical(log$user, "infosec-1")
  expect_identical(log$note, "Copilot approved for code")
  expect_true(any(grepl("endpoint copilot: blocked true -> false", log$changes[[1]])))
  expect_true(any(grepl("moved from 2 to 1", log$changes[[1]])))

  # a second save chains on; editing the log is detected
  x <- yaml::read_yaml(path)
  x$default_action <- "block"
  policy_write(x, path, user = "infosec-2")
  expect_identical(policy_changes(path)$revision, c(2L, 3L))
  log_file <- file.path(dirname(path), paste0(tools::file_path_sans_ext(basename(path)), ".changes.jsonl"))
  lines <- readLines(log_file)
  writeLines(sub("infosec-1", "someone-else", lines, fixed = TRUE), log_file)
  expect_false(attr(policy_changes(path), "intact"))
})

test_that("an invalid policy is never written", {
  skip_if_not_installed("openssl")
  path <- template()
  before <- readLines(path)
  x <- yaml::read_yaml(path)
  x$rules[[1]]$when$destinations <- list("no-such-endpoint")
  expect_error(policy_write(x, path, user = "infosec-1"), class = "credgate_policy_error")
  expect_identical(readLines(path), before)
})

test_that("the YAML layout keeps the policy exactly", {
  x <- yaml::read_yaml(system.file("policies", "bank-default.yaml", package = "credgate"))
  x$description <- "Line one\nLine two: with 'quotes' and \"more\""
  y <- yaml::yaml.load(credgate:::policy_yaml(x))
  strip <- function(p) {
    attr(p, "source") <- NULL
    p
  }
  expect_identical(strip(cg_policy(y)), strip(cg_policy(x)))
  expect_identical(y$description, x$description)
  expect_length(policy_diff(x, y), 0)
})

test_that("the editor edits, checks, tries and saves", {
  skip_if_not_installed("shiny")
  skip_if_not_installed("bslib")
  skip_if_not_installed("openssl")
  path <- template()
  shiny::testServer(credgate:::policy_editor_server(path, user = "infosec-1"), {
    expect_null(problem())
    expect_length(changes(), 0)

    # a new endpoint, then a rule that uses it
    session$setInputs(ep_pick = "", ep_name = "vllm-new", ep_tier = "internal",
                      ep_provider = "", ep_url = "http://gpu.internal:8000/v1",
                      ep_description = "", ep_blocked = FALSE)
    session$setInputs(ep_apply = 1)
    expect_identical(policy()$destinations[["vllm-new"]]$tier, "internal")
    session$setInputs(rule_pick = "", rule_id = "no-cards-to-vllm-new", rule_description = "",
                      rule_destinations = "vllm-new", rule_tiers = NULL, rule_types = "card",
                      rule_classes = NULL, rule_all_of = NULL, rule_action = "block")
    session$setInputs(rule_apply = 1)
    expect_identical(utils::tail(rule_ids(), 1), "no-cards-to-vllm-new")
    expect_null(problem())
    expect_true(any(grepl("rule no-cards-to-vllm-new added", changes())))

    # an endpoint still named by a rule is not removed
    session$setInputs(ep_pick = "vllm-new")
    session$setInputs(ep_delete = 1)
    expect_true("vllm-new" %in% names(policy()$destinations))

    # try it: card, CVV and expiry to a frontier endpoint are blocked
    session$setInputs(try_endpoint = "claude",
                      try_text = "Card 4111 1111 1111 1111, CVV 123, expiry 08/29")
    expect_false(decision()$allowed)
    # first match wins: below "in-house-models" (allow internal), the new rule
    # never applies - which "Try it" shows - and moved above it, it does
    session$setInputs(try_endpoint = "vllm-new", try_text = "Card 4111 1111 1111 1111")
    expect_true(decision()$allowed)
    expect_identical(decision()$matches$rule, "in-house-models")
    session$setInputs(rule_pick = "no-cards-to-vllm-new")
    session$setInputs(rule_up = 1)
    expect_identical(utils::tail(rule_ids(), 1), "in-house-models")
    expect_true("no-cards-to-vllm-new" %in% decision()$blocked_by)

    # the minimum confidence in Try it is the policy's
    session$setInputs(try_min_confidence = 0.7)
    session$setInputs(min_confidence = 0.7)
    expect_identical(policy()$min_confidence, 0.7)
    session$setInputs(try_text = "call 9876543210")
    expect_equal(nrow(decision()$matches), 0)
    session$setInputs(try_min_confidence = 0.5, min_confidence = 0.5)
    expect_identical(decision()$matches$type, "mobile_in")

    # an invalid policy cannot be saved
    session$setInputs(policy_id = "")
    expect_false(is.null(problem()))
    session$setInputs(user = "infosec-1", note = "x", save = 1)
    expect_identical(yaml::read_yaml(path)$revision, 1L)

    # fixed, it saves revision 2 with a change log entry
    session$setInputs(policy_id = "bank-default", note = "New GPU endpoint", save = 2)
    expect_identical(yaml::read_yaml(path)$revision, 2L)
    log <- policy_changes(path)
    expect_identical(log$note, "New GPU endpoint")
    expect_true(any(grepl("endpoint vllm-new added", log$changes[[1]])))
    expect_length(changes(), 0)
  })
})

test_that("the editor runs the policy's tests and refuses a save that breaks one", {
  skip_if_not_installed("shiny")
  skip_if_not_installed("bslib")
  skip_if_not_installed("openssl")
  path <- template()
  tests_file <- credgate:::policy_tests_path(path)
  shiny::testServer(credgate:::policy_editor_server(path, user = "infosec-1"), {
    expect_null(test_results())

    # save what the policy does now as a test
    session$setInputs(try_endpoint = "claude",
                      try_text = "Card 4111 1111 1111 1111, CVV 123, expiry 08/29")
    session$setInputs(test_id = "card-blocked-for-claude", test_add = 1)
    expect_true(file.exists(tests_file))
    session$setInputs(try_endpoint = "claude", try_text = "Customer PAN ABCPE1234F")
    session$setInputs(test_id = "pan-to-claude", test_add = 2)
    expect_identical(test_results()$passed, c(TRUE, TRUE))
    expect_true(all(run_policy_tests(path)$passed)) # the file is what CI runs

    # a change that breaks a test: the save is refused ...
    session$setInputs(default_action = "allow")
    x <- policy()
    x$rules <- Filter(function(r) r$id != "card-with-cvv-and-expiry", x$rules)
    policy(x)
    expect_identical(failing(), "card-blocked-for-claude")
    expect_false(can_save())
    session$setInputs(user = "infosec-1", note = "", save = 1)
    expect_identical(yaml::read_yaml(path)$revision, 1L)

    # ... unless "save anyway" is ticked with a reason, which the log records
    session$setInputs(save_anyway = TRUE)
    expect_true(can_save())
    session$setInputs(save = 2)
    expect_identical(yaml::read_yaml(path)$revision, 1L) # no reason given
    session$setInputs(note = "Cards handled by the gateway now", save = 3)
    expect_identical(yaml::read_yaml(path)$revision, 2L)
    expect_match(policy_changes(path)$note, "saved with failing tests: card-blocked-for-claude", fixed = TRUE)

    # removing a test rewrites the file
    session$setInputs(test_pick = "card-blocked-for-claude", test_delete = 1)
    expect_identical(run_policy_tests(path)$id, "pan-to-claude")
  })
})

test_that("the detector workbench checks, tries and saves a custom detectors file", {
  skip_if_not_installed("shiny")
  skip_if_not_installed("bslib")
  skip_if_not_installed("openssl")
  path <- template()
  withr::defer(credgate:::register_builtin_detectors())
  shiny::testServer(credgate:::policy_editor_server(path, user = "infosec-1"), {
    session$setInputs(det_file = "", det_yaml = det_template,
                      det_sample = "Loan a/c LN0012345678 overdue\nRef LN00123")
    session$elapse(500)
    x <- det_check()
    expect_null(x$error)
    expect_true(all(x$examples$ok))

    # a wrong example is shown, not saved
    bad <- sub("no_match: ['LN00123']", "no_match: ['LN0099999999']", det_template, fixed = TRUE)
    session$setInputs(det_yaml = bad)
    session$elapse(500)
    expect_identical(det_check()$examples$ok, c(TRUE, FALSE))
    session$setInputs(det_name = "bank-detectors.yaml", det_save = 1)
    expect_false(file.exists(file.path(dirname(path), "bank-detectors.yaml")))

    # a built-in id is refused
    session$setInputs(det_yaml = sub("id: loan_account", "id: pan", det_template, fixed = TRUE))
    session$elapse(500)
    expect_match(det_check()$error, "built-in")

    # saved: written beside the policy, loaded, and added to the draft policy
    session$setInputs(det_yaml = det_template, det_save = 2)
    expect_true(file.exists(file.path(dirname(path), "bank-detectors.yaml")))
    expect_true("loan_account" %in% cg_detectors()$id)
    expect_identical(unlist(policy()$detectors), "bank-detectors.yaml")
    expect_null(problem())
    # a file name with folders is refused
    session$setInputs(det_file = "", det_name = "../x.yaml", det_save = 3)
    expect_false(file.exists(file.path(dirname(dirname(path)), "x.yaml")))
  })
})

test_that("the editor page loads again when its scripts came from a read-only library", {
  skip_if_not_installed("shiny")
  skip_if_not_installed("bslib")
  dir <- file.path(tempdir(), "cg-readonly-asset")
  dir.create(dir, showWarnings = FALSE)
  f <- file.path(dir, "script.js")
  writeLines("// copied from a read-only store", f)
  Sys.chmod(f, "0444", use_umask = FALSE)
  credgate:::writable_temp_assets()
  expect_identical(unname(file.access(f, 2)), 0L)
  unlink(dir, recursive = TRUE)

  ui <- credgate:::policy_editor_ui(file.path(tempdir(), "none.yaml"))
  expect_true(is.function(ui))
  html <- as.character(htmltools::renderTags(ui(NULL))$html)
  expect_match(html, "credgate")
  expect_match(html, "try_endpoint")
  credgate:::writable_temp_assets() # so R can remove its temporary directory
})

test_that("the workbench form writes a detector that loads", {
  det <- credgate:::detector_from_form(
    id = "staff_code", class = "personal", label = "", pattern = "EMP-[0-9]{5}",
    keywords = "staff, a/c no.", required = TRUE,
    match = "staff EMP-12345", no_match = "EMP-12345\nstaff EMP-1234"
  )
  expect_identical(det$context, "staff|a/c no\\.")
  expect_true(det$context_required)
  data <- list(kind = "credgate-detectors", version = 1L, detectors = list(det))
  compiled <- credgate:::compile_detector_file(yaml::yaml.load(credgate:::detectors_yaml(data)))
  expect_identical(compiled[[1]]$detector$id, "staff_code")

  expect_match(credgate:::detector_from_form("Staff", "personal", "", "x", "", FALSE, "", ""), "lower-case")
  expect_match(credgate:::detector_from_form("s", "personal", "", "(", "", FALSE, "", ""), "not a valid")
  expect_match(credgate:::detector_from_form("s", "personal", "", "x", "", TRUE, "", ""), "keyword")
})

test_that("the workbench keeps one-item lists as lists", {
  data <- yaml::yaml.load("kind: credgate-detectors\nversion: 1\ndetectors:\n  - id: a\n    class: financial\n    label: A\n    patterns: ['X[0-9]{3}']\n    examples: {match: ['X123']}\n")
  out <- credgate:::detectors_yaml(data)
  expect_match(out, "patterns:\n      - X[0-9]{3}", fixed = TRUE)
  expect_match(out, "match:\n        - X123", fixed = TRUE)
})
