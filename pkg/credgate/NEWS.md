# credgate 0.1.0

* First release.
* `detect_pii()` finds Indian identifiers (Aadhaar, Aadhaar Virtual ID, PAN,
  GSTIN, voter ID, passport, driving licence), financial identifiers (UPI
  IDs, IFSC codes, bank accounts, payment cards), contact details (mobile
  numbers, email addresses, PIN codes), ABHA health IDs, and names and
  addresses next to an honorific, relation or field label.
* Matches are validated with checksums (Verhoeff, Luhn, GSTIN mod-36),
  scored from surrounding context, normalised across Indic digits, fullwidth
  and invisible characters, and printed with values masked.
* Detection rules are read from a specification shared with the Python
  package (`cg_spec_path()`); `new_detector()` and `register_detector()` add
  your own.
* `synth_indian_pii()` generates synthetic test records.
