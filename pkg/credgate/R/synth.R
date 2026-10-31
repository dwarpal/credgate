#' Generate synthetic Indian identifiers
#'
#' Produces random identifiers that pass the same structural and checksum
#' validation as real ones, for tests, demos and detector benchmarks. They
#' are random, not taken from any real record. A random number with a valid
#' checksum can still coincide with a real one by chance, so treat generated
#' data as test data and never as anonymised data.
#'
#' @param n Number of rows.
#' @param seed Optional random seed; the global RNG state is restored
#'   afterwards.
#' Names are random combinations of common Indian first names and surnames;
#' email addresses use the reserved `example.com`/`example.in` domains.
#'
#' @return A data frame with columns `name`, `name_hi` (Devanagari),
#'   `aadhaar`, `aadhaar_vid`, `pan`, `gstin`, `card`, `voter_epic`,
#'   `passport`, `driving_licence`, `mobile`, `email`, `upi_id`, `ifsc`,
#'   `bank_account`, `abha_number`, `abha_address`, `pincode` and `address`.
#' @export
#' @examples
#' synth_indian_pii(3, seed = 1)
synth_indian_pii <- function(n = 10, seed = NULL) {
  if (!is.null(seed)) {
    old <- get0(".Random.seed", envir = globalenv(), inherits = FALSE)
    on.exit(restore_rng(old), add = TRUE)
    set.seed(seed)
  }
  first <- sample(synth_first_names, n, replace = TRUE)
  last <- sample(synth_last_names, n, replace = TRUE)
  pincode <- synth_pincode(n)
  data.frame(
    name = paste(first, last),
    name_hi = paste(
      sample(synth_first_names_hi, n, replace = TRUE),
      sample(synth_last_names_hi, n, replace = TRUE)
    ),
    aadhaar = synth_aadhaar(n),
    aadhaar_vid = synth_aadhaar_vid(n),
    pan = synth_pan(n),
    gstin = synth_gstin(n),
    card = synth_card(n),
    voter_epic = synth_voter_epic(n),
    passport = synth_passport(n),
    driving_licence = synth_driving_licence(n),
    mobile = paste0(sample(6:9, n, replace = TRUE), rand_digits(n, 9)),
    email = paste0(
      tolower(first), ".", tolower(last), sample(10:99, n, replace = TRUE),
      "@", sample(c("example.com", "example.in"), n, replace = TRUE)
    ),
    upi_id = paste0(
      tolower(first), sample(10:99, n, replace = TRUE), "@",
      sample(c("okaxis", "ybl", "oksbi", "paytm", "ibl"), n, replace = TRUE)
    ),
    ifsc = paste0(
      sample(c("HDFC", "ICIC", "SBIN", "UTIB", "PUNB", "KKBK"), n, replace = TRUE),
      "0", rand_digits(n, 6)
    ),
    bank_account = vapply(sample(9:18, n, replace = TRUE), function(k) rand_digits(1, k), character(1)),
    abha_number = paste0(
      rand_digits(n, 2), "-", rand_digits(n, 4), "-", rand_digits(n, 4), "-", rand_digits(n, 4)
    ),
    abha_address = paste0(tolower(first), ".", tolower(substr(last, 1, 1)), sample(10:99, n, replace = TRUE), "@abdm"),
    pincode = pincode,
    address = paste0(
      "House No ", sample(1:250, n, replace = TRUE), ", ",
      sample(synth_localities, n, replace = TRUE), ", ",
      sample(synth_cities, n, replace = TRUE), " ", pincode
    )
  )
}

synth_first_names <- c(
  "Aarav", "Vivaan", "Aditya", "Priya", "Ananya", "Lakshmi", "Rohan", "Sneha",
  "Arjun", "Kavya", "Imran", "Fatima", "Gurpreet", "Harpreet", "Joseph",
  "Mary", "Venkatesh", "Meenakshi", "Subhash", "Anjali"
)
synth_last_names <- c(
  "Sharma", "Verma", "Patel", "Reddy", "Iyer", "Nair", "Singh", "Khan", "Das",
  "Banerjee", "Gupta", "Joshi", "Kulkarni", "Menon", "Fernandes",
  "Chatterjee", "Rao", "Yadav", "Mishra", "Pillai"
)
synth_first_names_hi <- c("\u0930\u092e\u0947\u0936", "\u0938\u0941\u0928\u0940\u0924\u093e", "\u0905\u0928\u093f\u0932", "\u092a\u094d\u0930\u093f\u092f\u093e", "\u0930\u093e\u091c\u0947\u0936", "\u092a\u0942\u091c\u093e", "\u0935\u093f\u0915\u093e\u0938", "\u0928\u0947\u0939\u093e")
synth_last_names_hi <- c("\u0915\u0941\u092e\u093e\u0930", "\u0936\u0930\u094d\u092e\u093e", "\u0935\u0930\u094d\u092e\u093e", "\u0938\u093f\u0902\u0939", "\u092f\u093e\u0926\u0935", "\u0917\u0941\u092a\u094d\u0924\u093e", "\u0926\u0947\u0935\u0940")
synth_localities <- c(
  "Laxmi Nagar", "Shanti Colony", "MG Road", "Sector 21", "Gandhi Marg",
  "Shivaji Park", "Anna Salai", "Civil Lines"
)
synth_cities <- c("Pune", "Delhi", "Chennai", "Kolkata", "Lucknow", "Jaipur", "Bengaluru", "Indore")

synth_pincode <- function(n) paste0(sample(1:8, n, replace = TRUE), rand_digits(n, 5))

restore_rng <- function(old) {
  if (is.null(old)) {
    rm(".Random.seed", envir = globalenv())
  } else {
    assign(".Random.seed", old, envir = globalenv())
  }
}

rand_digits <- function(n, k) {
  vapply(seq_len(n), function(i) paste0(sample(0:9, k, replace = TRUE), collapse = ""), character(1))
}

rand_letters <- function(n, k, from = LETTERS) {
  vapply(seq_len(n), function(i) paste0(sample(from, k, replace = TRUE), collapse = ""), character(1))
}

synth_aadhaar <- function(n) {
  body <- paste0(sample(2:9, n, replace = TRUE), rand_digits(n, 10))
  paste0(body, verhoeff_check_digit(body))
}

synth_aadhaar_vid <- function(n) {
  body <- rand_digits(n, 15)
  paste0(body, verhoeff_check_digit(body))
}

synth_pan <- function(n, holder = "P") {
  holder <- rep_len(holder, n)
  paste0(rand_letters(n, 3), holder, rand_letters(n, 1), rand_digits(n, 4), rand_letters(n, 1))
}

synth_gstin <- function(n) {
  state <- sprintf("%02d", sample(1:37, n, replace = TRUE))
  pan <- synth_pan(n, holder = sample(names(the$tables$pan_holder_types), n, replace = TRUE))
  body <- paste0(state, pan, sample(1:9, n, replace = TRUE), "Z")
  paste0(body, gstin_check_char(body))
}

synth_card <- function(n) {
  body <- paste0("4", rand_digits(n, 14))
  paste0(body, luhn_check_digit(body))
}

synth_voter_epic <- function(n) {
  paste0(rand_letters(n, 3), rand_digits(n, 7))
}

synth_passport <- function(n) {
  first <- setdiff(LETTERS, c("Q", "X", "Z"))
  paste0(
    rand_letters(n, 1, first), sample(1:9, n, replace = TRUE),
    rand_digits(n, 5), sample(1:9, n, replace = TRUE)
  )
}

synth_driving_licence <- function(n) {
  paste0(
    sample(the$lists$india_state_codes, n, replace = TRUE), rand_digits(n, 2),
    sample(1990:2025, n, replace = TRUE), rand_digits(n, 7)
  )
}
