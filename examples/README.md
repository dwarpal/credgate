# Examples: credgate with local LLMs

Runnable examples of redacting or tokenising PII before text reaches a model served
locally by **Ollama** or **vLLM** (or any OpenAI-compatible server). All
data is synthetic.

| Example | What it shows |
|---|---|
| [`python/ollama_redact.py`](python/ollama_redact.py) | Preview and redact a call note, then summarise it with Ollama |
| [`python/ollama_tokenise_restore.py`](python/ollama_tokenise_restore.py) | Tokenise a call note, let Ollama draft a reply, restore the real values |
| [`python/openai_compatible_redact.py`](python/openai_compatible_redact.py) | Classify redacted tickets with vLLM (or Ollama's `/v1`, LM Studio, a gateway) |
| [`python/rag_ingest_redacted.py`](python/rag_ingest_redacted.py) | Scan documents, then redact before chunking for a RAG index |
| [`r/ollama_ellmer.R`](r/ollama_ellmer.R) | The call-note example in R with ellmer's `chat_ollama()` |
| [`r/ollama_tokenise_restore.R`](r/ollama_tokenise_restore.R) | The tokenise-and-restore example in R with ellmer |
| [`r/vllm_ellmer.R`](r/vllm_ellmer.R) | Ticket classification in R with ellmer's `chat_vllm()` |
| [`r/scan_then_redact.R`](r/scan_then_redact.R) | Find PII columns in a data frame, build prompts from redacted text only |
| [`shell/redact_pipeline.sh`](shell/redact_pipeline.sh) | `credgate preview` / `credgate redact` piped into `ollama run` |

## Running them

```sh
pip install credgate ollama openai          # Python examples
python examples/python/ollama_redact.py gemma3:1b
CREDGATE_BASE_URL=http://localhost:8000/v1 CREDGATE_MODEL=<model> \
  python examples/python/openai_compatible_redact.py
```

```r
install.packages(c("credgate", "ellmer"))  # R examples
# Rscript examples/r/ollama_ellmer.R gemma3:1b
```

The examples were run against Ollama with `gemma3:1b` on macOS; the
OpenAI-compatible (vLLM) examples were run against Ollama's
OpenAI-compatible endpoint, which speaks the same API as vLLM. A small
model like `gemma3:1b` gives rough summaries and labels; that is the model,
not the redaction.

## Before you rely on it

- **Look at the preview.** Names are found next to an honorific, relation or
  field label (`Shri`, `S/o`, `Name:`, `नाम:`). A name in running text
  without such a cue ("Customer Priya Nair called") is not detected yet and
  would reach the model.
- **Redaction is irreversible**: the model's answer cannot mention the real
  values. Reversible tokenisation and a proxy mode that does all of this
  automatically are on the roadmap.
- `min_confidence = 0.5` (used throughout) leaves low-confidence matches,
  such as order numbers that happen to pass the Aadhaar checksum, alone.
  Measured accuracy at that threshold: [benchmark/README.md](../benchmark/README.md).
