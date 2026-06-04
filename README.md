# tome

Technical OSINT Mining Engine: embedded corpus of 19 AI/ML infrastructure platforms, each with Shodan dorks, API paths, auth defaults, default credentials, misconfiguration patterns, and aimap-compatible probe configs.

tome is a Go binary that embeds 19 platform JSON files at compile time. Given a platform name, it emits Shodan dorks at three specificity tiers, a full OSINT profile, or an aimap-compatible probe config JSON. Given an IP, it fingerprints the host against all 19 passive signatures using Shodan's host API and returns confidence-scored findings. An optional `--active` flag sends a single HTTP probe per matched platform for verification. The corpus was built from O'Reilly sources and vendor documentation; each platform file records its source references.

## Install

```
go install github.com/nuclide-research/tome@latest
```

Go 1.22.2+. Dependencies: `cobra`, `pflag` (resolved at build time).

## Commands

### `tome list`

List all 19 platforms in the corpus.

```
tome list
tome list -f json
```

### `tome profile <platform>`

Full OSINT profile: ports, API paths, auth default, Shodan dorks, default credentials, misconfiguration patterns, pivot paths, known vulnerabilities, and sources.

```
tome profile ollama
tome profile weaviate -f json
tome profile n8n -f csv
```

### `tome dorks <platform>`

Shodan dork string at the selected tier, formatted for paste or JAXEN import.

```
tome dorks ollama                      # strict tier (default)
tome dorks chromadb --dork-tier basic
tome dorks vllm --dork-tier version
```

### `tome probe <platform>`

aimap-compatible probe config JSON. Pipe directly into aimap.

```
tome probe weaviate
tome probe ollama | aimap probe --stdin
```

### `tome scan <ip>`

Passive fingerprint via Shodan API. Matches the host's banner data against all 19 platform passive signatures, scores confidence as matched-filters / total-filters, and returns findings above the confidence threshold. With `--active`, sends one HTTP probe per matched platform to verify.

```
export SHODAN_API_KEY=your_key
tome scan 192.0.2.10
tome scan 192.0.2.10 --confidence 0.5
tome scan 192.0.2.10 --active
tome scan 192.0.2.10 -f json
```

`--active` sends traffic to the target and requires interactive confirmation. Use only with written authorization from the target owner.

## Global flags

| Flag | Default | Effect |
|------|---------|--------|
| `-f, --format` | `table` (tty) / `json` (pipe) | output format: `table`, `json`, `csv` |
| `--confidence` | `0.0` | filter `scan` findings below threshold (0.0-1.0) |
| `--dork-tier` | `strict` | dork specificity: `basic`, `strict`, `version` |

## Platforms (19)

| Platform | Category | Default auth |
|----------|----------|--------------|
| Ollama | inference_serving | none |
| vLLM | inference_serving | none |
| SGLang | inference_serving | none |
| llama.cpp | inference_serving | none |
| TGI | inference_serving | none |
| KServe | inference_serving | none |
| NVIDIA NIM | inference_serving | none |
| Ray Serve | inference_serving | none |
| Custom Embedding API (FastAPI/uvicorn) | embedding_serving | none |
| OpenVINO Model Server | embedding_serving | none |
| Weaviate | vector_db | none |
| ChromaDB | vector_db | none |
| Qdrant | vector_db | none |
| Milvus | vector_db | none |
| n8n | orchestration | none |
| LangServe | orchestration | none |
| MLflow | observability | none |
| LangFuse | observability | api_key |
| LangSmith | observability | api_key |

## Platform schema

Each platform file contains:

```
platform, display_name, category
default_ports[]
api_paths[]
auth_default, auth_config_env[]
default_creds[]: {user, pass, context}
install_tell
misconfig_patterns[]
fingerprint:
  passive[]: Shodan filter strings (AND within compound filters)
  active_probe: {path, method, response_markers[], false_positive_check}
shodan_dorks: {basic, strict, version}
deployment_tells[]
pivot_paths[]
vulnerabilities[]
sources[]
```

## Scan finding shape (JSON)

```json
{
  "platform": "ollama",
  "ip": "192.0.2.10",
  "port": 11434,
  "discovery_method": "shodan_passive",
  "auth_required": false,
  "version": "",
  "verified": false,
  "confidence": 0.67,
  "active_probe_used": false,
  "pivot_paths": [
    "GET /api/tags -> model inventory -> infer org focus from model names",
    "GET /api/show -> system prompt leakage (reveals deployment context)",
    "GET /api/version -> exact version -> CVE matching"
  ]
}
```

## Example

```
$ tome profile ollama

Platform:        Ollama
Category:        inference_serving
Default ports:   11434
Auth default:    NONE
Shodan (strict): product:Ollama port:11434
Key misconfig:   OLLAMA_HOST=0.0.0.0 exposes to all interfaces (+2 more)
Pivot:           GET /api/tags -> model inventory -> infer org focus from model names
Sources:         Generative AI on Kubernetes (9781098171919) ch01; Hands-On LLM Serving and Optimization (9798341621480) ch08
```

```
$ tome dorks ollama

product:Ollama port:11434

$ tome dorks ollama --dork-tier basic

"ollama" port:11434
```

## Fits into the chain

```
tome dorks <platform> | jaxen import -
tome probe <platform> | aimap probe --stdin
```

tome runs before JAXEN to generate targeted dorks and before aimap to supply probe configs for a known platform.

## What tome is not

tome is a corpus lookup and passive fingerprinter. The `scan` command reads Shodan's cached data; it does not sweep the target. The `--active` flag sends one HTTP request per matched platform; it does not brute-force credentials or exploit vulnerabilities. tome has no knowledge of hosts it has not been pointed at.

## License

MIT. Part of the NuClide toolchain. Contact: [nuclide-research.com](https://nuclide-research.com)
