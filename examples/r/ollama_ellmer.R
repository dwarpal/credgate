# Redact PII before sending text to a local Ollama model with ellmer.
#
# Requires: install.packages(c("credgate", "ellmer")) and a running Ollama
# server. Run: Rscript examples/r/ollama_ellmer.R [model]  (default gemma3:1b)
#
# All data below is synthetic.

library(credgate)
library(ellmer)

args <- commandArgs(trailingOnly = TRUE)
model <- if (length(args) > 0) args[[1]] else "gemma3:1b"

note <- paste(
  "Customer name: Priya Nair. Called about her home-loan EMI. PAN ABCPN1234K,",
  "mobile +91 98765 43210, UPI priya.n@oksbi. She wants the EMI date moved",
  "to the 10th because her salary is credited late."
)

# 1. See exactly what would leave the session, and why. Always check this:
#    names in running text without an honorific or label (e.g. "Customer
#    Priya Nair called") are not detected yet.
print(preview(note, min_confidence = 0.5))

# 2. Only the redacted text reaches the model.
safe <- redact(note, min_confidence = 0.5)
chat <- chat_ollama(model = model, echo = "none")
reply <- chat$chat(paste("Summarise this call note in one sentence:", safe, sep = "\n"))
cat("\nModel reply:\n", reply, "\n", sep = "")
