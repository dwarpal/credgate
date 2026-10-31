# Find the PII columns of a data frame, then build model prompts only from
# redacted text. No model is called; this shows the data preparation step.
#
# Requires: install.packages("credgate")
# Run: Rscript examples/r/scan_then_redact.R
#
# All data below is synthetic.

library(credgate)

complaints <- data.frame(
  cust_pan = c("ABCPE1234F", "AAACR5055K", "XYZPQ9876R"),
  mobile = c(9876543210, 8826781145, 9123456780),
  complaint = c(
    "EMI debited twice from A/c 50100123456789; please refund.",
    "Shri Mohan Lal wants the statement sent to mohan.lal@example.com.",
    "App crashes when opening the cards tab."
  )
)

# 1. Inventory: which columns hold PII?
print(scan_pii(complaints))

# 2. Send only what the task needs (the complaint text), redacted.
prompts <- paste("Categorise this complaint:", redact(complaints$complaint, min_confidence = 0.5))
writeLines(prompts)
