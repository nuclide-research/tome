# TOME — Technical OSINT Mining Engine

AI/ML infrastructure intelligence for Shodan operators. TOME embeds a 17-platform corpus derived from vendor documentation and O'Reilly research: default ports, API paths, auth defaults, default credentials, Shodan dorks, and misconfiguration patterns.

## Install

```bash
go install github.com/Nicholas-Kloster/tome@latest
```

## Commands

### `tome list`
List all platforms in the corpus.

```
$ tome list
NAME                 CATEGORY           AUTH       PORTS
----------------------------------------------------------------------
chromadb             vector_db          none       8000
huggingface-tei      inference_serving  none       80, 443
kserve               inference_serving  api_key    8080, 8081
langfuse             observability      api_key    3000
...
```

### `tome profile <platform>`
Full OSINT profile — ports, paths, auth, dorks, default creds, misconfigs.

```bash
tome profile ollama
tome profile weaviate -f json
tome profile n8n -f csv
```

### `tome dorks <platform>`
Shodan dorks formatted for paste or JAXEN import.

```bash
tome dorks ollama                      # strict tier (default)
tome dorks chromadb --dork-tier basic  # broad sweep
tome dorks vllm --dork-tier version    # version-pinned
```

### `tome probe <platform>`
aimap-compatible probe config JSON. Pipe directly into aimap.

```bash
tome probe weaviate
tome probe ollama | aimap probe --stdin
```

### `tome scan <ip>`
Passive fingerprint via Shodan API. Matches host banner data against all 17 platform signatures and returns confidence-scored findings.

```bash
export SHODAN_API_KEY=your_key
tome scan 1.2.3.4
tome scan 1.2.3.4 --confidence 0.5        # filter low-confidence hits
tome scan 1.2.3.4 --active                # direct HTTP probe (requires authorization)
tome scan 1.2.3.4 -f json | jq .
```

## Platforms

| Platform | Category | Default Auth |
|---|---|---|
| Ollama | inference_serving | none |
| vLLM | inference_serving | none |
| SGLang | inference_serving | none |
| llama.cpp | inference_serving | none |
| TGI | inference_serving | none |
| KServe | inference_serving | api_key |
| NVIDIA NIM | inference_serving | api_key |
| HuggingFace TEI | inference_serving | none |
| Weaviate | vector_db | none |
| ChromaDB | vector_db | none |
| Qdrant | vector_db | none |
| Milvus | vector_db | none |
| n8n | orchestration | none |
| Ray Serve | orchestration | none |
| MLflow | mlops | none |
| LangFuse | observability | api_key |
| LangSmith | observability | api_key |

## Flags

| Flag | Default | Description |
|---|---|---|
| `-f`, `--format` | table (tty) / json (pipe) | Output format: `table`, `json`, `csv` |
| `--confidence` | `0.0` | Filter findings below threshold (0.0–1.0) |
| `--dork-tier` | `strict` | Dork specificity: `basic`, `strict`, `version` |

## Fits Into

TOME is step -1 in the NuClide Visor chain — run it before JAXEN to generate targeted dorks and aimap probe configs for a known platform.

```
tome dorks <platform> | jaxen import -
tome probe <platform> | aimap probe --stdin
```

## License

MIT
