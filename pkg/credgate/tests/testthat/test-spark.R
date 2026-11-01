# sparklyr: sampling in the cluster (spec: "Spark tables"). Needs sparklyr,
# Java and a Spark installation in SPARK_HOME; skipped otherwise.

spark_connection <- function() {
  skip_if_not_installed("sparklyr")
  skip_if(!nzchar(Sys.getenv("SPARK_HOME")), "SPARK_HOME is not set")
  sc <- tryCatch(suppressWarnings(
    sparklyr::spark_connect(
      master = "local[1]", spark_home = Sys.getenv("SPARK_HOME"),
      config = list(
        "spark.ui.enabled" = "false", "spark.driver.host" = "127.0.0.1",
        "spark.sql.shuffle.partitions" = "1",
        "sparklyr.connect.enablehivesupport" = FALSE
      )
    )),
    error = function(e) skip(paste("Spark cannot start:", conditionMessage(e)))
  )
  withr::defer(sparklyr::spark_disconnect(sc), envir = parent.frame(2))
  sc
}

strip <- function(inv) as.data.frame(inv)[, setdiff(names(inv), c("scanned_at", "credgate"))]

test_that("Spark tables: same results as in memory, sampled in the cluster, every digit kept", {
  sc <- spark_connection()

  customers <- data.frame(
    cust_pan = c("ABCPE1234F", "AAACR5055K", "XYZPQ9876R", NA),
    notes = c("Called, Aadhaar 542229371182", "no issues", "mobile 9876543210", "ok")
  )
  small <- dplyr::copy_to(sc, customers, "customers", overwrite = TRUE)
  expect_equal(
    strip(pii_inventory(small, source = "hive", table = "crm.customers")),
    strip(pii_inventory(customers, source = "hive", table = "crm.customers"))
  )
  expect_equal(
    as.data.frame(unclass(scan_pii(small))),
    as.data.frame(unclass(scan_pii(customers)))
  )

  pans <- data.frame(pan = synth_indian_pii(3000, seed = 1)$pan, status = "ok")
  big <- dplyr::copy_to(sc, pans, "pans", overwrite = TRUE)
  inv <- pii_inventory(big, source = "hive", table = "t", sample = 500)
  expect_identical(unique(inv$sample_method), "spark-sample")
  expect_identical(unique(inv$n_rows), 3000L)
  pan <- inv[!is.na(inv$type) & inv$type == "pan", ]
  expect_true(pan$n_sampled > 0 && pan$n_sampled <= 500)
  expect_equal(pan$rate, 1)
  expect_equal(strip(pii_inventory(big, source = "hive", table = "t", sample = 500)), strip(inv))

  cards <- dplyr::copy_to(sc, data.frame(card = synth_indian_pii(5, seed = 2)$card), "cards", overwrite = TRUE)
  cards <- dplyr::mutate(cards, card_no = dplyr::sql("CAST(card AS BIGINT)"))  # a long column
  found <- scan_pii(dplyr::select(cards, card_no))
  expect_identical(found$type, "card")
  expect_identical(found$n_full, 5L)
})
