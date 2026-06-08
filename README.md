<h1 align="center">tome</h1>

<h4 align="center">Technical OSINT Mining Engine. Canonical AI/ML platform corpus.</h4>

<p align="center">
  <a href="https://github.com/nuclide-research/tome/releases"><img src="https://img.shields.io/github/v/release/nuclide-research/tome?style=flat-square" alt="release"></a>
  <a href="https://github.com/nuclide-research/tome/blob/main/LICENSE"><img src="https://img.shields.io/github/license/nuclide-research/tome?style=flat-square" alt="license"></a>
  <a href="https://golang.org"><img src="https://img.shields.io/badge/go-1.22%2B-00ADD8?style=flat-square&logo=go" alt="go"></a>
  <a href="https://nuclide-research.com"><img src="https://img.shields.io/badge/by-NuClide-blue?style=flat-square" alt="NuClide"></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#commands">Commands</a> •
  <a href="#platforms">Platforms</a> •
  <a href="#platform-schema">Schema</a> •
  <a href="#scope">Scope</a>
</p>

---

tome is a Go binary with an embedded corpus of AI and ML infrastructure platforms. Each platform file records default ports, API paths, auth defaults, default credentials, misconfiguration patterns, Shodan dorks at three specificity tiers, aimap-compatible probe configs, pivot paths, known vulnerabilities, and source references. Given a platform name, tome emits a profile, a dork string, or a probe config. Given an IP, it scores the host against every passive signature using Shodan's host API and returns confidence-scored findings. Optional `--active` sends one HTTP probe per matched platform.

tome is the canonical registry behind the NuClide assessment chain. Stage -1 writes researched platforms into it. Stage 0 reads dorks from it. Stage 0d scaffolds aimap fingerprints from it. One corpus, not three that drift.

# Features

- 50 AI/ML platforms in the embedded corpus, growing
- Three dork tiers per platform: `basic`, `strict`, `version`. Paste into Shodan or pipe to JAXEN
- aimap-compatible probe config JSON, ready for `aimap probe --stdin`
- Confidence-scored passive fingerprinting from Shodan host data
- Optional single-shot active verification probe per matched platform
- Per-platform source references (O'Reilly chapters, vendor docs) for every claim in the corpus
- Three output formats: `table` (tty default), `json` (pipe default), `csv`
- Single static Go binary, no external runtime deps

# Installation

```bash
go install -v github.com/nuclide-research/tome@latest
```

Or build from source:

```bash
git clone https://github.com/nuclide-research/tome
cd tome
go build -o tome .
```

Requires Go 1.22 or later. Runtime deps resolved at build: `cobra`, `pflag`.

# Commands

### `tome list`

List every platform in the corpus.

```bash
tome list
tome list -f json
```

### `tome profile <platform>`

Full OSINT profile: ports, API paths, auth default, Shodan dorks, default credentials, misconfiguration patterns, pivot paths, known vulnerabilities, sources.

```bash
tome profile ollama
tome profile weaviate -f json
tome profile n8n -f csv
```

### `tome dorks <platform>`

Shodan dork at the selected tier, formatted for paste or JAXEN import.

```bash
tome dorks ollama                      # strict tier (default)
tome dorks chromadb --dork-tier basic
tome dorks vllm --dork-tier version
```

### `tome probe <platform>`

aimap-compatible probe config JSON. Pipe straight into aimap.

```bash
tome probe weaviate
tome probe ollama | aimap probe --stdin
```

### `tome scan <ip>`

Passive fingerprint via the Shodan host API. Matches the cached banner against every platform passive signature, scores confidence as `matched_filters / total_filters`, returns findings above the threshold. `--active` sends one HTTP probe per matched platform.

```bash
export SHODAN_API_KEY=your_key
tome scan 192.0.2.10
tome scan 192.0.2.10 --confidence 0.5
tome scan 192.0.2.10 --active
tome scan 192.0.2.10 -f json
```

`--active` sends traffic and requires interactive confirmation. Use only with written authorization.

# Global flags

| Flag | Default | Effect |
|------|---------|--------|
| `-f, --format` | `table` (tty), `json` (pipe) | output format: `table`, `json`, `csv` |
| `--confidence` | `0.0` | filter `scan` findings below threshold (0.0 to 1.0) |
| `--dork-tier` | `strict` | dork specificity: `basic`, `strict`, `version` |

# Platforms

Initial 19-platform release covered inference serving, vector DBs, orchestration, and observability. Corpus now stands at 50 platforms across the same categories plus embedding serving, agent platforms, and MCP. `tome list` is authoritative; the snapshot below is a sample.

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

# Platform schema

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

# Scan finding shape (JSON)

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

# Example

```
$ tome profile ollama

Platform:        Ollama
Category:        inference_serving
Default ports:   11434
Auth default:    NONE
Shodan (strict): product:Ollama port:11434
Key misconfig:   OLLAMA_HOST=0.0.0.0 exposes to all interfaces (+2 more)
Pivot:           GET /api/tags -> model inventory -> infer org focus from model names
Sources:         Generative AI on Kubernetes (9781098171919) ch01;
                 Hands-On LLM Serving and Optimization (9798341621480) ch08
```

```
$ tome dorks ollama

product:Ollama port:11434

$ tome dorks ollama --dork-tier basic

"ollama" port:11434
```

# Fits into the chain

```
tome dorks <platform>  | jaxen import -
tome probe <platform>  | aimap probe --stdin
tome scan  <ip>        # passive Shodan fingerprint per host
```

tome runs before JAXEN to generate targeted dorks, before aimap to supply probe configs, and on its own to passively score any host against the full corpus.

# Scope

tome is a corpus lookup and passive fingerprinter. The `scan` command reads Shodan's cached data; it does not sweep the target. `--active` sends one HTTP request per matched platform. It does not brute credentials, exploit vulnerabilities, or persist state on the target. tome has no knowledge of hosts it has not been pointed at. Only point it at hosts you own or have explicit written authorization to assess.

# Our other projects

- [aimap](https://github.com/nuclide-research/aimap) — AI/ML infrastructure fingerprint scanner
- [scanner](https://github.com/nuclide-research/scanner) — active-banner stage between passive discovery and deep enumeration
- [VisorLog](https://github.com/nuclide-research/visorlog) — finding ledger and ingest pipeline
- [VisorGraph](https://github.com/nuclide-research/visorgraph) — cert-pivot to operator attribution
- [BARE](https://github.com/nuclide-research/BARE) — semantic exploit-module ranking over scanner findings

# License

MIT. Part of the NuClide toolchain. Contact: [nuclide-research.com](https://nuclide-research.com)
