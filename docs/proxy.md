# The proxy

The credgate proxy sits between people's tools and the model endpoints. Every
request goes through the policy: what may be sent is sent, identifiers are
redacted or tokenised as the policy says, requests the policy blocks never
leave, and every decision is written to the audit log. Tokenised values are
put back into the answer, so people see the real values while the model
never did.

```
Positron / VS Code / Jupyter / scripts ──► credgate proxy ──► Ollama · vLLM · SGLang · gateway
                                           policy: allow / redact / tokenise / block
                                           values restored in the answer
                                           audit log
```

It speaks the **OpenAI-compatible API** (`POST /v1/chat/completions`,
`GET /v1/models`), which vLLM, SGLang, Ollama (`/v1`), LM Studio and most
company gateways use, and which most tools can be pointed at. It needs only
the Python standard library.

## Set up the endpoints

The endpoints are the destinations of the [policy](https://github.com/dwarpal/credgate/blob/main/examples/policies/bank-default.yaml),
each with its tier and its OpenAI-compatible base URL:

```yaml
destinations:
  ollama-local: {tier: local, url: "http://localhost:11434/v1"}
  vllm-gpu: {tier: internal, url: "https://llm.bank.internal/v1"}
  claude: {tier: frontier, url: "https://ai-gateway.bank.internal/anthropic/v1"}
  copilot: {tier: frontier, blocked: true}
```

The endpoints' own API keys stay with the proxy, in environment variables
named after the destination: `CREDGATE_UPSTREAM_KEY_VLLM_GPU`,
`CREDGATE_UPSTREAM_KEY_CLAUDE`. People using the proxy never see them.

## Run it

**On each analyst's machine** (localhost mode): the proxy listens on
`127.0.0.1` only, and requests are recorded as the operating-system user.

```sh
credgate proxy serve --policy bank-default.yaml --audit audit.jsonl
```

**For a team** (shared mode): the proxy listens on a network address and
every client needs its own key; requests are recorded by user name. The proxy
refuses to start on a network address without a keys file.

```sh
credgate proxy add-user priya --keys keys.json      # prints Priya's key, once
credgate proxy serve --policy bank-default.yaml --audit audit.jsonl \
  --host 0.0.0.0 --keys keys.json --certfile proxy.pem --keyfile proxy.key
```

The keys file holds only hashes of the keys. Use TLS (`--certfile`,
`--keyfile`) or put the proxy behind the organisation's TLS-terminating
reverse proxy.

## Point tools at it

Clients ask for a model as `<endpoint>/<model>`:

```python
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:8790/v1", api_key="unused")  # shared mode: the user's key
client.chat.completions.create(
    model="vllm-gpu/llama-3.1-70b",
    messages=[{"role": "user", "content": "Summarise: customer PAN ABCPN1234K wants ..."}],
)
```

In R with ellmer:

```r
chat <- ellmer::chat_openai_compatible(
  base_url = "http://127.0.0.1:8790/v1", model = "ollama-local/gemma3:1b",
  credentials = function() "unused"   # shared mode: function() Sys.getenv("CREDGATE_PROXY_KEY")
)
chat$chat("Summarise this call note: ...")
```

Any tool with an "OpenAI-compatible base URL" setting works the same way.

## What it does with a request

1. **Who**: the operating-system user (localhost mode) or the user whose key
   was sent (shared mode); otherwise `401`.
2. **Where**: the endpoint named in `model`; an endpoint not in the policy is
   refused (`404`).
3. **What**: every value in the request is checked with the policy for that
   endpoint - message contents and text parts, tool results, tool-call
   arguments from earlier turns, names, `metadata`, `user`, stop sequences,
   tool and schema descriptions, and any field the proxy does not know -
   except structural ones (`model`, `role`, `type`, ids, function names).
   Whole numbers of 6 digits or more are checked too (an Aadhaar number can
   be sent as a number); a numeric setting shaped like an identifier would
   be redacted and the request fail, never leak. Requests with personal data
   in a field name, content credgate cannot read (images, audio, files) or
   unexpected shapes are refused (`400`) rather than sent unchecked.
4. **Decision**: blocked requests get `403` with the rule that blocked them
   and are never forwarded; otherwise identifiers are redacted or tokenised
   as the policy says. Every decision, blocked or not, is written to the
   audit log - without the text or the values.
5. **Answer**: tokens in the answer's text are replaced by their values -
   only tokens made for this request, never in tool calls (which the tool
   would run with real values). Streaming requests get the complete answer as
   one streamed message (token-by-token streaming comes in a later version).

It fails closed: if anything goes wrong before the request is forwarded -
including a failure to write the audit record - nothing is sent and the
client gets an error. Requests go only to the URL in the policy (`http` or
`https`): redirects are not followed. Bodies must have a `Content-Length`
(at most 20 MB), connections are closed after any refused request, slow
clients are dropped after 2 minutes, and answers above 50 MB are refused. The proxy's own log line per
request has who, where, the status and the time taken - never the text.

## What it does not protect

- **Deliberate evasion.** Someone determined to get data out can disguise
  it (spelling a PAN with spaces between letters, splitting it across
  messages, encoding it). Detection handles accidental variation (case,
  invisible characters, full-width and Indic digits), not an insider trying
  to evade it; network rules and the audit log address that.
- **What detection misses.** The policy can only act on what credgate
  detects. Names without a cue ("Customer Priya Nair called", rather than
  "Name: Priya Nair") are often not detected and would be sent as they are.
  Test your prompts with `credgate preview`, and prefer policies that redact
  free text for frontier models.
- **Requests that do not go through it.** Network rules, not credgate, must
  make the proxy the only way to reach frontier endpoints.
- **The model's own behaviour.** A model can still answer badly or leak what
  it was legitimately sent; the policy decides what it is sent.

See also the [threat model](threat-model.md).
