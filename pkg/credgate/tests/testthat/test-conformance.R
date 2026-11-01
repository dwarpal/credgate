# Runs the shared conformance cases in inst/spec/conformance, which every
# CredGate implementation must pass.

conformance <- function(file) {
  credgate:::read_yaml_utf8(file.path(cg_spec_path(), "conformance", file))
}

test_that("the shipped spec is in sync with the repository spec", {
  repo <- test_path("..", "..", "..", "..", "spec")
  skip_if_not(dir.exists(repo), "repository spec/ not available (installed package)")
  shipped <- cg_spec_path()
  files <- list.files(repo, recursive = TRUE)
  expect_setequal(list.files(shipped, recursive = TRUE), files)
  for (f in files) {
    expect_identical(
      readLines(file.path(shipped, f), encoding = "UTF-8"),
      readLines(file.path(repo, f), encoding = "UTF-8"),
      info = paste(f, "differs; run tools/sync-spec.sh")
    )
  }
})

test_that("checksum vectors", {
  v <- conformance("checksums.yaml")
  na_if_null <- function(x) if (is.null(x)) NA_character_ else x
  for (case in v$verhoeff$check_digit) {
    expect_identical(verhoeff_check_digit(case$input), na_if_null(case$output), info = case$input)
  }
  for (case in v$verhoeff$valid) {
    expect_identical(verhoeff_valid(case$input), case$valid, info = case$input)
  }
  for (case in v$luhn$valid) {
    expect_identical(luhn_valid(case$input), case$valid, info = case$input)
  }
  for (case in v$gstin$check_char) {
    expect_identical(gstin_check_char(case$input), na_if_null(case$output), info = case$input)
  }
  for (case in v$gstin$valid) {
    expect_identical(gstin_valid(case$input), case$valid, info = case$input)
  }
})

for (case in conformance("detect.yaml")$cases) {
  test_that(paste("detect:", case$id), {
    got <- detect_pii(case$text, context = case$context)
    shown <- paste0(got$type, "=", got$value, " (", got$confidence, ")", collapse = ", ")
    expect_equal(nrow(got), length(case$expect), info = paste("got:", shown))
    for (e in case$expect) {
      row <- got[got$type == e$type & got$value == e$value, , drop = FALSE]
      expect_equal(nrow(row), 1, info = paste(e$type, e$value, "| got:", shown))
      if (nrow(row) != 1) next
      if (!is.null(e$confidence)) {
        expect_equal(row$confidence, e$confidence, info = e$type)
      }
      if (!is.null(e$canonical)) {
        expect_identical(row$canonical, e$canonical, info = e$type)
      }
      if (!is.null(e$span)) {
        # spec spans are 0-based, end-exclusive; R spans are 1-based, inclusive
        expect_identical(c(row$start - 1L, row$end), as.integer(unlist(e$span)), info = e$type)
      }
      if (!is.null(e$reason)) {
        expect_true(grepl(e$reason, row$reasons, fixed = TRUE), info = row$reasons)
      }
    }
  })
}

for (case in conformance("scan.yaml")$cases) {
  test_that(paste("scan:", case$id), {
    as_column <- function(v) vapply(v, function(x) if (is.null(x)) NA_character_ else x, "")
    data <- as.data.frame(lapply(case$columns, as_column), check.names = FALSE)
    got <- scan_pii(data, sample = case$sample %||% 10000L, min_rate = case$min_rate %||% 0)
    got <- as.data.frame(unclass(got))
    expect_equal(nrow(got), length(case$expect))
    for (i in seq_along(case$expect)) {
      e <- case$expect[[i]]
      for (field in names(e)) {
        expect_equal(got[[field]][i], e[[field]], info = paste("row", i, field))
      }
    }
  })
}

for (case in conformance("redact.yaml")$cases) {
  test_that(paste("redact:", case$id), {
    got <- redact(case$text, context = case$context, min_confidence = case$min_confidence %||% 0)
    expect_identical(got, case$redacted)
    expect_identical(preview(case$text, context = case$context, min_confidence = case$min_confidence %||% 0)$redacted, case$redacted)
  })
}

negatives <- conformance("negatives.yaml")

for (case in negatives$negatives) {
  test_that(paste("hard negative:", case$id), {
    limit <- case$max_confidence %||% 0.5
    got <- detect_pii(case$text)
    confident <- got[got$confidence >= limit, , drop = FALSE]
    expect_equal(nrow(confident), 0, info = paste(confident$type, confident$value, confident$confidence))
  })
}

for (case in negatives$known_false_positives) {
  test_that(paste("known false positive still present:", case$id), {
    expect_true(case$type %in% detect_pii(case$text)$type,
      info = "fixed? move this case to `negatives` in the spec"
    )
  })
}

for (case in conformance("evaluate.yaml")$cases) {
  test_that(paste("evaluate:", case$id), {
    got <- cg_evaluate(case$documents,
      min_confidence = case$min_confidence %||% 0,
      match = case$match %||% "exact"
    )
    got <- as.data.frame(unclass(got))
    expect_equal(nrow(got), length(case$expect))
    for (i in seq_along(case$expect)) {
      e <- case$expect[[i]]
      for (field in names(e)) {
        want <- e[[field]] %||% NA_real_
        expect_equal(got[[field]][i], want, info = paste(case$id, "row", i, field))
      }
    }
  })
}

for (case in conformance("tokenise.yaml")$cases) {
  test_that(paste("tokenise:", case$id), {
    if (!is.null(case$key)) skip_if_not_installed("openssl")
    if (!is.null(case$fingerprint)) {
      expect_identical(cg_key_fingerprint(case$key), case$fingerprint)
    }
    vault <- cg_vault(case$key)
    for (step in case$steps) {
      if (isTRUE(step$new_vault)) {
        vault <- cg_vault(case$key)
      } else if (!is.null(step$tokenise)) {
        got <- tokenise(unlist(step$tokenise), vault,
          context = step$context, min_confidence = step$min_confidence %||% 0
        )
        expect_identical(got, unlist(step$expect))
      } else if (!is.null(step$restore)) {
        strict <- isTRUE(step$strict)
        if (isTRUE(step$error)) {
          expect_error(restore(step$restore, vault, strict = strict), class = "credgate_unknown_token")
        } else {
          expect_identical(restore(step$restore, vault, strict = strict), step$expect)
        }
      } else {
        entries <- vault$entries
        got <- lapply(seq_len(nrow(entries)), function(i) {
          c(entries$token[i], entries$type[i], entries$canonical[i])
        })
        expect_identical(got, lapply(step$expect, unlist))
      }
    }
  })
}

vault_spec <- conformance("vault.yaml")
for (f in vault_spec$files) {
  test_that(paste("vault file:", f$file), {
    skip_if_not_installed("sodium")
    path <- file.path(cg_spec_path(), "conformance", f$file)
    if (!is.null(f$key)) skip_if_not_installed("openssl")
    vault <- vault_open(path, passphrase = f$passphrase, key = f$key)
    e <- vault$entries
    got <- lapply(seq_len(nrow(e)), function(i) {
      c(e$token[i], e$type[i], e$class[i], e$canonical[i], e$value[i])
    })
    expect_identical(got, lapply(f$entries, unlist))
    expect_error(
      vault_open(path, passphrase = vault_spec$wrong_passphrase, key = f$key),
      class = "credgate_vault_file"
    )
    if (!is.null(f$key)) {
      expect_error(
        vault_open(path, passphrase = f$passphrase, key = vault_spec$other_key),
        "token key does not match", class = "credgate_vault_file"
      )
      # the reopened vault keeps making the same keyed tokens
      expect_identical(tokenise("PAN ABCPE1234F", vault), "PAN [PAN_bpg46o6x465d4]")
    } else {
      expect_error(
        vault_open(path, passphrase = f$passphrase, key = vault_spec$other_key),
        "numbered", class = "credgate_vault_file"
      )
    }
  })
}

policy_spec <- conformance("policy.yaml")
policy_of <- function(p) if (is.character(p)) policy_spec$policies[[p]] else p
for (case in policy_spec$cases) {
  test_that(paste("policy:", case$id), {
    policy <- cg_policy(policy_of(case$policy))
    d <- policy_apply(policy, unlist(case$texts), case$destination, vault = cg_vault())
    expect_identical(d$allowed, case$allowed)
    got <- lapply(seq_len(nrow(d$matches)), function(i) {
      c(d$matches$type[i], d$matches$action[i], d$matches$rule[i])
    })
    expect_identical(got, lapply(case$matches, unlist))
    expect_identical(d$blocked_by, as.character(unlist(case$blocked_by)))
    if (isTRUE(case$allowed)) {
      expect_identical(d$text, unlist(case$output))
    } else {
      expect_null(d$text)
    }
  })
}
for (case in policy_spec$invalid) {
  test_that(paste("invalid policy:", case$id), {
    err <- tryCatch(cg_policy(case$policy), credgate_policy_error = function(e) e)
    expect_s3_class(err, "credgate_policy_error")
    expect_match(conditionMessage(err), case$error, ignore.case = TRUE, fixed = FALSE)
  })
}
test_that("policy: unknown destination is an error", {
  u <- policy_spec$unknown_destination
  expect_error(
    policy_decide(cg_policy(policy_of(u$policy)), "PAN ABCPE1234F", u$destination),
    "Unknown destination", class = "credgate_policy_error"
  )
})


audit_spec <- conformance("audit.yaml")
for (case in audit_spec$id_hashes) {
  test_that(paste("audit id hash:", case$type, case$id), {
    skip_if_not_installed("openssl")
    expect_identical(
      credgate:::audit_id_hash(credgate:::token_key(audit_spec$key), case$type, case$canonical),
      case$id
    )
  })
}
for (case in audit_spec$logs) {
  test_that(paste("audit log verifies:", case$file), {
    skip_if_not_installed("openssl")
    check <- audit_verify(file.path(cg_spec_path(), "conformance", case$file))
    expect_true(check$ok)
    expect_equal(check$records, case$records)
    expect_identical(check$head, case$head)
  })
}
tampered <- function(lines, change, at) {
  i <- at
  switch(change,
    edit = {
      lines[i] <- sub('"actor":"', '"actor":"x', lines[i], fixed = TRUE)
      lines
    },
    delete = lines[-i],
    swap = {
      lines[c(i, i + 1)] <- lines[c(i + 1, i)]
      lines
    },
    duplicate = append(lines, lines[i], after = i)
  )
}
for (case in audit_spec$tamper$cases) {
  test_that(paste("audit tampering detected:", case$id), {
    skip_if_not_installed("openssl")
    src <- file.path(cg_spec_path(), "conformance", audit_spec$tamper$file)
    lines <- readLines(src, encoding = "UTF-8")
    path <- withr::local_tempfile(fileext = ".jsonl")
    writeLines(enc2utf8(tampered(lines, case$change, case$at)), path, useBytes = TRUE)
    check <- audit_verify(path)
    expect_false(check$ok)
    expect_equal(check$line, case$line)
  })
}

inventory_spec <- conformance("inventory.yaml")
inventory_case <- function(case) {
  as_column <- function(v) {
    if (all(vapply(v, function(x) is.null(x) || is.numeric(x), TRUE))) {
      return(vapply(v, function(x) if (is.null(x)) NA_real_ else x, 0))
    }
    vapply(v, function(x) if (is.null(x)) NA_character_ else x, "")
  }
  data <- as.data.frame(lapply(case$columns, as_column), check.names = FALSE)
  pii_inventory(
    data,
    source = case$source, table = case$table,
    sample = case$sample %||% 10000L, min_rate = case$min_rate %||% 0
  )
}

for (case in inventory_spec$cases) {
  test_that(paste("inventory:", case$id), {
    got <- inventory_case(case)
    expect_equal(nrow(got), length(case$expect))
    fields <- c(
      "v", "source", "table", "column", "type", "class", "n_rows", "n_sampled",
      "n_matched", "n_full", "rate", "mean_confidence", "sample_method"
    )
    for (i in seq_along(case$expect)) {
      e <- case$expect[[i]]
      for (field in fields) {
        info <- paste("row", i, field)
        if (is.null(e[[field]])) {
          expect_true(is.na(got[[field]][i]), info = info)
        } else {
          expect_equal(got[[field]][i], e[[field]], info = info)
        }
      }
    }
  })
}

test_that("inventory file is written identically by R and Python", {
  spec <- inventory_spec$file
  case <- Filter(function(c) c$id == spec$case, inventory_spec$cases)[[1]]
  inv <- inventory_case(case)
  inv$scanned_at <- spec$scanned_at
  inv$credgate <- spec$credgate
  path <- withr::local_tempfile(fileext = ".csv")
  write_inventory(inv, path)
  expected <- file.path(cg_spec_path(), "conformance", spec$path)
  expect_identical(readBin(path, "raw", 1e5), readBin(expected, "raw", 1e5))
  expect_equal(as.data.frame(read_inventory(expected)), as.data.frame(inv))
})
