# TOME — O'Reilly Research Synthesis Round 2
# 9 chapters · 3 books · 468K chars

## New platform profiles

### n8n
- port: 5678
- api_paths: /api/v1, /, webhooks (no fixed path)
- auth_default: basic (N8N_BASIC_AUTH_USER + N8N_BASIC_AUTH_PASSWORD)
- default_creds: admin / [env-set password — often left at default]
- install: docker run -p 5678:5678 n8nio/n8n
- misconfig: basic auth not enabled, webhooks exposed unauthenticated, credentials in workflow JSON plaintext
- deployment_tells: http.title:"n8n", /api/v1 returns workflow list, PostgreSQL backend
- shodan_dorks: http.title:"n8n" port:5678, port:5678 "n8n"
- source: Agentic AI for Offensive Cybersecurity ch03

### LangServe
- port: 8000
- api_paths: /chain, /invoke, /stream, /docs (FastAPI OpenAPI), /playground
- auth_default: none
- install: pip install langserve
- misconfig: no input validation on /invoke, /playground exposes model behavior
- deployment_tells: FastAPI /docs endpoint, /playground UI, uvicorn server headers
- shodan_dorks: http.html:"/playground" port:8000, http.title:"FastAPI" port:8000 "invoke"
- source: Learning LangChain ch09

### ChromaDB
- port: 8000
- api_paths: /api/v1/collections, /api/v1/query, /api/v1/ (heartbeat — unauthenticated)
- auth_default: none (server mode — no auth by default)
- install: docker run -p 8000:8000 ghcr.io/chroma-core/chroma:latest
- misconfig: no auth in server mode, collection metadata contains sensitive data, persistent storage world-readable
- deployment_tells: /api/v1/ heartbeat, JSON collection list, error messages reveal storage backend
- shodan_dorks: port:8000 "chromadb", http.html:"/api/v1/collections"
- source: Learning LangChain ch02

### Weaviate
- ports: 8080 (REST + GraphQL), 50051 (gRPC)
- api_paths: /v1/graphql, /v1/objects, /v1/schema, /v1/meta (version + modules — unauthenticated)
- auth_default: none (AUTHENTICATION_APIKEY_ENABLED env required to enable auth)
- auth_config_env: AUTHENTICATION_APIKEY_ENABLED, AUTHORIZATION_ADMIN_LIST
- install: docker run -p 8080:8080 -p 50051:50051 semitechnologies/weaviate:latest
- misconfig: GraphQL introspection not disabled, CORS allows any origin, schema at /v1/schema unauthenticated
- deployment_tells: /v1/meta reveals version + modules loaded, /v1/graphql explorer
- shodan_dorks: port:8080 "weaviate", http.html:"/v1/graphql" weaviate
- source: Learning LangChain ch02

### Qdrant
- ports: 6333 (REST + dashboard), 6334 (gRPC)
- api_paths: /collections, /points/search, /collections/{name}/points, /health, /dashboard (web UI)
- auth_default: api_key (but web UI at /dashboard often open)
- auth_config_env: QDRANT_API_KEY, QDRANT_READ_ONLY_API_KEY
- install: docker run -p 6333:6333 qdrant/qdrant
- misconfig: API key exposed in Docker logs, /dashboard accessible without credentials, read-write and read-only keys not distinguished
- deployment_tells: /health unauthenticated, /dashboard web UI, /openapi.json schema
- shodan_dorks: port:6333 "qdrant", http.html:"/dashboard" qdrant
- source: Learning LangChain ch02

### MLflow Tracking Server
- port: 5000
- api_paths: /api/2.0/experiments, /api/2.0/runs, /metrics/, / (UI)
- auth_default: none (no auth in default deployment)
- install: pip install mlflow && mlflow server --host 0.0.0.0 --port 5000
- misconfig: no auth, artifact storage world-readable, backend store credentials in environment
- deployment_tells: http.title:"MLflow", /api/2.0/experiments returns all experiments, /metrics path
- shodan_dorks: http.title:"MLflow" port:5000, port:5000 "/api/2.0/experiments"
- source: round 2 synthesis (MLflow standard deployment patterns from LLMOps context)

### Langfuse (self-hosted)
- port: 3000
- api_paths: /api/public, /api/v1, /traces, /sessions
- auth_default: api_key (LANGFUSE_PUBLIC_KEY + LANGFUSE_SECRET_KEY)
- install: docker run -p 3000:3000 ghcr.io/langfuse/langfuse:latest
- misconfig: keys in client-side code, traces contain unmasked credentials, no SSL in self-hosted
- deployment_tells: http.title:"Langfuse" port:3000, /api/public endpoint
- shodan_dorks: http.title:"langfuse" port:3000
- source: round 2 synthesis

### LangSmith
- deployment: SaaS primary; self-hosted via Docker Compose
- api_paths: /api/v1, /runs, /datasets, /deployments, /traces
- auth_default: api_key (LANGCHAIN_API_KEY required)
- misconfig: API keys committed to source code, traces contain unmasked PII, dataset contains reference answers
- source: Learning LangChain ch09 + ch10

## Security intelligence from Agentic AI for Offensive Cybersecurity

### Recon tools mentioned in the book (ch04 Attack Surface Management)
- subfinder: subdomain enumeration
- assetfinder: asset discovery
- aiodnsbrute: DNS brute force
- shuffledns: parallel DNS resolution
- httpx: web service fingerprinting
- dnsx: DNS metadata extraction (CDN, ASN)
- Shodan API: infrastructure search

### Shodan dorks from the book (ch04)
- "n8n" "Workflow" port:5678
- Nuclei templates for default credential checks
- HTTP header fingerprinting: X-Powered-By, Weaviate-Version, MLflow-Version

### OWASP Top 10 LLM 2025 — key deployment vectors
LLM01: Prompt injection via n8n /invoke, LangServe /invoke — no input sanitization
LLM02: Output exposure via ChromaDB query results, LangSmith public traces
LLM04: DoS via LangServe streaming without rate limiting
LLM06: Sensitive data in ChromaDB embeddings, LangSmith traces with API keys
LLM07: n8n tool nodes execute arbitrary code with full system access
LLM08: Excessive agency — n8n agents with DB/API access perform unauthorized operations

## Trust boundary mapping (AI-Native LLM Security ch04)
- n8n webhooks trigger without credential validation
- LangServe playground exposes model behavior analysis surface
- Qdrant /dashboard accessible without dashboard password (even with API key auth on REST)
- LangSmith traces contain full conversation history including system prompts
- RAG vector stores queryable without per-user auth (ChromaDB, Weaviate)

## Books researched (round 2)
7. Agentic AI for Offensive Cybersecurity (9781806114474) — ch02 + ch03 + ch04
8. AI-Native LLM Security (9781836203759) — ch04 + ch07 + ch09
9. Learning LangChain (9781098167271) — ch02 + ch09 + ch10
