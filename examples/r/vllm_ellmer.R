# Redact PII before calling a vLLM server (or any OpenAI-compatible server)
# with ellmer.
#
# Requires: install.packages(c("credgate", "ellmer")) and a vLLM server, e.g.
#   python -m vllm.entrypoints.openai.api_server --model <model>
# Run: Rscript examples/r/vllm_ellmer.R
# Settings: CREDGATE_BASE_URL (default http://localhost:8000/v1), CREDGATE_MODEL,
# and VLLM_API_KEY if your server checks keys.
# The same code works with Ollama's OpenAI-compatible endpoint:
#   CREDGATE_BASE_URL=http://localhost:11434/v1 CREDGATE_MODEL=gemma3:1b Rscript examples/r/vllm_ellmer.R
#
# All data below is synthetic.

library(credgate)
library(ellmer)

base_url <- Sys.getenv("CREDGATE_BASE_URL", "http://localhost:8000/v1")
model <- Sys.getenv("CREDGATE_MODEL", "meta-llama/Llama-3.1-8B-Instruct")

tickets <- c(
  "Shri Ramesh Kumar (Aadhaar 5422 2937 1182) reports a failed UPI payment to ramesh@okaxis.",
  "Account 50100987654321, IFSC HDFC0004567: customer asks to update email to priya.nair@example.org.",
  "General question about branch timings on Saturday."
)

# Local servers usually ignore the key, but ellmer requires one.
if (!nzchar(Sys.getenv("VLLM_API_KEY"))) Sys.setenv(VLLM_API_KEY = "unused")

for (ticket in tickets) {
  safe <- redact(ticket, min_confidence = 0.5)
  chat <- chat_vllm(
    base_url = base_url, model = model, echo = "none",
    system_prompt = "Classify the ticket as PAYMENTS, PROFILE or GENERAL. Answer with one word."
  )
  cat(safe, "\n  -> ", trimws(chat$chat(safe)), "\n\n", sep = "")
}
