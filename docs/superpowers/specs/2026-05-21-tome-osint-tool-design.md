# TOME Design Spec
# Technical OSINT Mining Engine — AI/ML Infrastructure

**Date**: 2026-05-21  
**Status**: Draft for review

---

## Overview

TOME is a Go CLI that bundles a book-derived intelligence corpus of AI/ML infrastructure platforms. Given a platform name, it outputs Shodan dorks, API probe configs, default credentials, and common misconfiguration patterns. Given an IP, it runs passive fingerprinting and returns a classified finding with confidence score.

Slots into the Visor chain as step -1 (pre-JAXEN): TOME generates the dorks JAXEN uses to harvest.

```
go install github.com/Nicholas-Kloster/tome@latest
```

---

## Two Distinct Systems

**Research pipeline** (internal, never ships):
- oreilly-reader Playwright skill reads O'Reilly books
- Claude extraction → `platforms/*.json`
- Committed to repo, reviewed, merged

**TOME binary** (ships to the world):
- Embeds the `platforms/` JSON corpus at compile time
- No O'Reilly access needed at runtime
- Offline, single binary, zero dependencies

---

## CLI Commands

```
tome profile <platform>          # full OSINT profile — ports, paths, auth, dorks, creds
tome dorks <platform>            # Shodan dorks, formatted for paste or JAXEN import
tome probe <platform>            # aimap-compatible probe config JSON
tome list                        # all known platforms + brief status
tome scan <ip> [--active]        # fingerprint live target (passive default, active opt-in)
```

### Flags

```
--format json|csv|table          # output format (default: table for human, json for pipe)
--confidence <0.0-1.0>           # filter findings below threshold (default: 0.0)
--active                         # enable active probing (sends traffic to target; requires authorization)
--dork-tier basic|strict|version # dork specificity level (default: strict)
```

### Passive vs. active split

Default mode sends zero packets to any target. All intelligence comes from the embedded corpus and public passive sources (Shodan API, DNS, WHOIS).

`--active` enables live service probing. When used, TOME prints:

```
WARNING: Active mode sends traffic to the target and may be detected.
Only use with explicit written authorization from the target owner.
Press Enter to continue or Ctrl+C to abort.
```

---

## Platform Corpus Schema

Each platform is a JSON file at `platforms/<name>.json`:

```json
{
  "platform": "weaviate",
  "display_name": "Weaviate",
  "category": "vector_db",
  "default_ports": [8080, 50051],
  "api_paths": [
    "/v1/meta",
    "/v1/schema",
    "/v1/graphql",
    "/v1/objects",
    "/.well-known/ready"
  ],
  "auth_default": "none",
  "auth_config_env": [
    "AUTHENTICATION_APIKEY_ENABLED",
    "AUTHORIZATION_ADMIN_LIST"
  ],
  "default_creds": [],
  "install_tell": "docker run -p 8080:8080 -p 50051:50051 semitechnologies/weaviate:latest",
  "misconfig_patterns": [
    "GraphQL introspection not disabled",
    "CORS allows any origin",
    "/v1/schema accessible unauthenticated",
    "gRPC port 50051 exposed without TLS"
  ],
  "fingerprint": {
    "passive": [
      "product:Weaviate",
      "http.html:\"/v1/graphql\"",
      "http.headers:\"weaviate\""
    ],
    "active_probe": {
      "path": "/v1/meta",
      "method": "GET",
      "response_markers": ["\"version\"", "\"modules\"", "\"hostname\""],
      "false_positive_check": "response must include 'modules' field as array"
    }
  },
  "shodan_dorks": {
    "basic": "port:8080 \"weaviate\"",
    "strict": "product:Weaviate port:8080",
    "version": "product:Weaviate http.html:\"v1/meta\""
  },
  "deployment_tells": [
    "/v1/meta reveals version + modules loaded",
    "/v1/graphql explorer accessible",
    "gRPC port 50051 open alongside 8080"
  ],
  "pivot_paths": [
    "GET /v1/schema → class names → query for records via GraphQL",
    "GET /v1/objects → raw record dump with no auth",
    "cert CN pivot → identify operator org → check job postings"
  ],
  "vulnerabilities": [],
  "sources": [
    "Learning LangChain (9781098167271) ch02",
    "AI-Native LLM Security (9781836203759) ch04"
  ]
}
```

### Schema field notes

- `fingerprint.passive` — Shodan filters that produce this platform, no target traffic
- `fingerprint.active_probe` — endpoint + response markers for live verification (active mode only)
- `fingerprint.false_positive_check` — human-readable FP filter; implemented in probe code
- `shodan_dorks.strict` — default dork (best signal-to-noise per NSA methodology)
- `shodan_dorks.version` — narrows to specific version strings in HTML
- `pivot_paths` — post-discovery follow-up actions (all passive unless noted)
- `default_creds` — array of `{"user": "admin", "pass": "changeme", "context": "basic auth"}` objects

---

## Dork Tier System

From NSA Ch4 + OSINT Handbook Ch4 research: dork specificity has three tiers.

| Tier | Field Priority | Noise | Use Case |
|------|---------------|-------|----------|
| `basic` | port + keyword | High | Initial sweep, unknown population size |
| `strict` | product + port + title | Low | Production JAXEN harvest |
| `version` | strict + html version string | Very low | Target specific vulnerable releases |

`--dork-tier strict` is the default for `tome dorks`. JAXEN receives strict-tier dorks. Basic tier is available for initial population sizing.

Dorks are stored in the platform JSON (not compiled in), so they update without a new release when maintainers submit PRs.

---

## Platform Coverage (v0.1 Launch)

**Inference serving (8 platforms)**
- Ollama — port 11434, no auth, `/api/tags`
- vLLM — port 8080, no auth, `/v1/models`
- TGI — ports 8080+3000, no auth, dual-port exposure
- llama.cpp — port 8000, no auth, GGUF fingerprint
- SGLang — port 8000, no auth, RadixAttention tells
- Ray Serve — ports 8000+8265, no auth, dashboard at 8265
- NVIDIA NIM — port 8000, no auth, container-optimized
- KServe — inherits runtime ports, Kubernetes CRD fingerprint

**Orchestration (2 platforms)**
- n8n — port 5678, basic auth (often disabled), webhook exposure
- LangServe — port 8000, no auth, FastAPI /playground

**Vector DBs (4 platforms)**
- ChromaDB — port 8000, no auth, `/api/v1` heartbeat
- Weaviate — ports 8080+50051, no auth, GraphQL introspection
- Qdrant — ports 6333+6334, API key (dashboard often open)
- Milvus — port 19530, no auth in single-node

**Observability (3 platforms)**
- MLflow — port 5000, no auth, `/api/2.0/experiments`
- Langfuse — port 3000, API key, self-hosted traces contain creds
- LangSmith — SaaS primary, API key, traces contain PII

**Cross-platform signals**
- OpenAI-compat API (`/v1/chat/completions`) → present in vLLM, TGI, llama.cpp, SGLang, NIM — single probe detects all
- Port cluster 8000-8080 covers ~90% of open-source inference serving

---

## Output Format

### `tome profile weaviate` (table)
```
Platform:     Weaviate
Category:     vector_db
Default ports: 8080 (REST/GraphQL), 50051 (gRPC)
Auth default: NONE
Shodan (strict): product:Weaviate port:8080
Key misconfig: /v1/schema accessible unauthenticated; GraphQL introspection open
Pivot:        GET /v1/objects → record dump; cert CN → operator org
Sources:      Learning LangChain ch02, AI-Native LLM Security ch04
```

### `tome scan <ip> --format json` (JSON Lines)
```json
{
  "platform": "weaviate",
  "ip": "203.0.113.42",
  "port": 8080,
  "discovery_method": "shodan_strict",
  "auth_required": false,
  "version": "1.3.1",
  "verified": true,
  "confidence": 0.95,
  "active_probe_used": false,
  "pivot_paths": ["GET /v1/schema", "GET /v1/objects"]
}
```

---

## Visor Chain Integration

```
[-1] TOME      →  dorks ready for harvest
[ 0] JAXEN     →  Shodan harvest using TOME strict dorks → empire.db
[ 1] aimap     →  service fingerprint using TOME probe config
[ 2] VisorGraph → cert pivot → operator attribution
```

`tome probe weaviate` outputs an aimap-compatible probe config JSON that aimap consumes directly:

```json
{
  "platform": "weaviate",
  "port": 8080,
  "probe_path": "/v1/meta",
  "response_markers": ["version", "modules"],
  "confidence_threshold": 0.90
}
```

---

## Repository Structure

```
tome/
├── cmd/
│   ├── profile.go
│   ├── dorks.go
│   ├── probe.go
│   ├── list.go
│   └── scan.go
├── platforms/
│   ├── ollama.json
│   ├── vllm.json
│   ├── chromadb.json
│   ├── weaviate.json
│   └── ... (16 total at v0.1)
├── internal/
│   ├── corpus/        # embed FS loading
│   ├── fingerprint/   # passive + active probe logic
│   └── output/        # JSON/CSV/table formatters
├── research/          # synthesis docs, raw chapter extracts (not embedded)
│   ├── SYNTHESIS.md
│   ├── SYNTHESIS-2.md
│   └── SYNTHESIS-3.md
└── main.go
```

The `platforms/` directory is embedded via `//go:embed platforms/*.json` — no file I/O at runtime.

---

## Distribution

```
go install github.com/Nicholas-Kloster/tome@latest
```

Same pattern as aimap. Single binary, cross-platform (linux/darwin/windows AMD64 + ARM64).

GitHub Actions publishes release binaries on tag push. BlackArch PKGBUILD submitted alongside aimap.

---

## Research Provenance

Every platform profile cites exact O'Reilly book + chapter. Intelligence is primary-source, not scraped or inferred.

```json
"sources": [
  "Learning LangChain (9781098167271) ch02",
  "AI-Native LLM Security (9781836203759) ch04",
  "Network Security Assessment 3rd Ed (9781491911044) ch15"
]
```

This is the novel angle vs. existing tools: cited intelligence with a verifiable reading list (O'Reilly playlist: https://learning.oreilly.com/playlists/ce628633-f3fa-488c-9d0f-2f8a4dfe1a7f/).
