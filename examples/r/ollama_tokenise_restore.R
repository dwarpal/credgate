# Tokenise PII, let a local Ollama model draft a reply, then restore the values.
#
# The model only sees tokens such as [PERSON_NAME_1] and [PAN_1]; the real
# values go back into its draft afterwards, on this machine.
#
# Requires: install.packages(c("credgate", "ellmer")) and a running Ollama server
# Run:      Rscript examples/r/ollama_tokenise_restore.R [model]   (default: gemma3:1b)
#
# All data below is synthetic.

library(credgate)
library(ellmer)

args <- commandArgs(trailingOnly = TRUE)
model <- if (length(args) > 0) args[[1]] else "gemma3:1b"

note <- paste(
  "Customer name: Priya Nair. PAN ABCPN1234K, mobile +91 98765 43210.",
  "She wants the EMI date moved to the 10th because her salary is credited late."
)

# 1. Tokenise: the vault remembers which value each token stands for.
vault <- cg_vault()
safe <- tokenise(note, vault, min_confidence = 0.5)
cat("Sent to the model:\n ", safe, "\n\n")

# 2. Only tokens reach the model. Ask it to keep them as they are.
chat <- chat_ollama(
  model = model,
  system_prompt = "Keep tokens such as [PERSON_NAME_1] exactly as written."
)
draft <- chat$chat(paste("Draft a two-line reply to this customer:", safe, sep = "\n"), echo = "none")
cat("Model's draft:\n ", draft, "\n\n")

# 3. Restore on this machine. strict = TRUE would stop on a token the model
#    invented; here unknown tokens are simply left as they are.
cat("Restored:\n ", restore(draft, vault), "\n")
