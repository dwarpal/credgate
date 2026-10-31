# credgate

Detects personal data before it leaves the machine, with Indian identifiers
built in: Aadhaar (with Verhoeff checksum), Aadhaar Virtual ID, PAN, GSTIN,
voter ID, passport, driving licence, UPI IDs, IFSC, bank accounts, payment
cards, +91 mobile numbers, ABHA, and names and addresses in Latin and Indic
scripts.

The detection rules live in a shared, language-neutral spec, so this package
and the Python package `credgate` find exactly the same matches. Part of the
[CredGate](https://github.com/dwarpal/credgate) project; early development.

## Installation

CRAN submission of 0.1.0 is under review. Until it is accepted, install
from GitHub (this also gets the development version):

```r
# install.packages("remotes")
remotes::install_github("dwarpal/credgate", subdir = "pkg/credgate")
```

With Nix: `nix build github:dwarpal/credgate#credgate-r`.

## Usage

```r
library(credgate)

x <- detect_pii("Name: Priya Nair; PAN: ABCPN1234K; UPI: priya.n@oksbi")
x
#> 3 PII matches (values masked; use `x$value` to see them):
#>  doc start end        type         value confidence
#>    1     7  16 person_name    XXXXX Nair       0.80
#>    1    24  33         pan    XXXXXX234K       0.97
#>    1    41  53      upi_id XXXXX.X@Xksbi       0.99

x$reasons[2]
#> [1] "matched PAN pattern; context 'PAN'; holder type: individual"
```

`detect_pii()` takes a character vector and returns one row per match with
the document index, character positions, type, data class, value, canonical
form (for consistent tokenisation), confidence and reasons. Printing masks
the values.

Context makes generic patterns trustworthy. Pass extra context, such as a
column name, with `context`:

```r
detect_pii("ABC1234567")                       # nothing: could be anything
detect_pii("ABC1234567", context = "voter_id") # Voter ID, confidence 0.97
```

Indic digits, fullwidth characters and zero-width characters are normalised
before matching, and positions refer to your original text:

```r
detect_pii("आधार: ५४२२ २९३७ ११८२")$type
#> [1] "aadhaar"
```

### Scanning data frames

`scan_pii()` reports which columns hold PII and how much, without sending
anything anywhere. Column names count as context, so a column called
`voter_id` or `cust_pan` supports those types:

```r
customers <- data.frame(
  cust_pan = c("ABCPE1234F", "AAACR5055K", "XYZPQ9876R"),
  notes = c("Called, Aadhaar 542229371182", "no issues", "mobile 9876543210")
)
scan_pii(customers)
#> Scanned 2 columns; PII found in 2: cust_pan and notes
#>    column      type rate matched whole confidence      example
#>  cust_pan       pan 100%  3 of 3     3       0.97   XXXXXX234F
#>     notes   aadhaar  33%  1 of 3     0       0.97 XXXXXXXX1182
#>     notes mobile_in  33%  1 of 3     0       0.93   XXXXXX3210
```

`whole` counts values that are entirely the identifier (an ID column)
rather than containing it (free text). Large columns are sampled
(`sample = 10000` values by default).

### Checksums and test data

```r
verhoeff_valid("542229371182")    # Aadhaar / VID checksum
luhn_valid("4111 1111 1111 1111") # payment cards
gstin_valid("27AAPFU0939F1ZV")    # GSTIN check character

synth_indian_pii(5, seed = 1)     # synthetic records for tests and demos
```

Synthetic values pass the same validation as real ones but are random; use
them for tests, never as anonymised data.

### Your own detectors

```r
register_detector(new_detector(
  id = "employee_id", class = "internal", label = "Employee ID",
  pattern = bounded("EMP[0-9]{6}")
))
cg_detectors() # all registered detectors
```

## Limits

Names and addresses are found only next to a cue: an honorific (Shri, Smt,
श्रीमती), a relation (S/o, D/o), a field label (`Name:`, `पता:`) or a
house/village keyword followed by a PIN code. A bare 12-digit number may pass
the Aadhaar checksum by chance and is reported with lower confidence.

## Licence

Apache License 2.0.
