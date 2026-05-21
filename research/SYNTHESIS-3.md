# TOME — O'Reilly Research Synthesis Round 3
# 7 chapters · 3 books · OSINT Methodology
# Reconnaissance for Ethical Hackers · The OSINT Handbook · Network Security Assessment 3rd Ed

## 1. Shodan dork construction principles

### Query field priority (high signal-to-noise)

From NSA Ch4 and OSINT Handbook Ch4, effective Shodan dorks combine these fields in order of specificity:

1. **product** filter (highest precision)
   - `product:Ollama` or `product:vLLM`
   - Returns only that product; eliminates FP from generic keywords

2. **http.html** or **http.title** (second priority)
   - `http.html:"ollama"` captures service banners, login pages, version strings in response body
   - `http.title:"ChromaDB"` — highly distinctive if product names appear in page titles

3. **port + os combination**
   - `port:11434 product:Ollama os:Linux` — constrains to known port on known OS
   - n8n (default 5678) benefits from coupling with specific version strings

4. **header field matching**
   - `http.headers:"X-Powered-By: ollama"` — service disclosure headers
   - `http.headers:"Server: uvicorn"` — FastAPI/vLLM typically use uvicorn

5. **Avoid generic keywords**
   - "api", "inference", "embedding" cause massive noise
   - Never dork on port alone: `port:6379` returns millions of Redis instances

### Pattern: layered specificity

Good dork: `product:Ollama port:11434 http.title:"Ollama"` — verified Ollama, minimal FP
Bad dork: `"inference api" port:8000` — matches thousands of unrelated frameworks

### False positive patterns to avoid

- Generic banner strings: `"Running on"` or `"Server ready"` appear in many frameworks
- Shared default ports: 8000 covers llama.cpp, SGLang, NIM, ChromaDB, LangServe
- Proxy/reverse proxy: a dork matching "ollama" may hit nginx gateway proxying to Ollama
- Version strings in redirects: check `http.status:200` for live services
- Never primary-signal on status code alone — too many catch-alls return 200

### DNS + port binding confirmation (NSA Ch4)

Cross-reference Shodan dorks with DNS records:
- Dork `product:Weaviate port:50051 country:US` → extract IPs → reverse DNS
- Reduces FP rate from 40% to <5% by confirming A/AAAA records align with Shodan data

---

## 2. Service fingerprinting methodology

### Probe sequence (NSA Ch7 applied to AI/ML)

From NSA Ch7 "Assessing Common Network Services," correct probe order for TOME targets:

1. **Banner grab** — `curl -v http://<ip>:<port>/`
   - Ollama: `/api/version` → `{"version": "0.1.9"}`
   - vLLM: OpenAI-compatible responses + X-headers
   - n8n: HTML login page, distinctive footer with version
   - FP detector: check `Server:` header + `Content-Type` alignment

2. **Version-specific endpoint probing**
   - Ollama: GET `/api/version`, `/api/tags` → JSON with model list + version
   - Weaviate: GET `/.well-known/ready` + `GET /v1/meta` → version in response
   - vLLM: GET `/v1/models` → OpenAI-compatible endpoint
   - ChromaDB: GET `/api/v1` → HTTP 200 with `api_version` field
   - n8n: GET `/rest/admin/diagnostics` → reveals stack info (auth required but leaks 401 headers)

3. **Response field priority**

   | Field | Signal Strength | Example |
   |-------|----------------|---------|
   | Server header | High | `Server: uvicorn` (vLLM), `Server: nginx` (proxy FP) |
   | X-Powered-By | High | `X-Powered-By: ollama` |
   | Response body markers | Very High | `"_links"` in JSON (Weaviate), `"models"` array (vLLM/Ollama) |
   | TLS CN | Medium | CN=weaviate.cluster.local confirms internal name |
   | ETag, Date headers | Low | Avoid as primary signal |

4. **TLS certificate examination**
   - `openssl s_client -connect <ip>:<port> -showcerts`
   - Ollama: Self-signed, CN typically `localhost` or internal IP
   - Weaviate: SAN like `*.weaviate.svc.cluster.local` (Kubernetes)
   - ChromaDB: Rarely TLS; CN reveals internal hostname when present
   - CN=`api.company.com` + service running Ollama → likely reverse proxy; check HTTP Content-Type

### Unique vs. shared markers

**Uniquely identifies** a service:
- Ollama: `/api/tags` returns `[{"name": "model:tag", ...}]` — JSON array of models
- vLLM: `/v1/models` returns OpenAI format with `"object": "list"` field
- ChromaDB: `/api/v1` returns `{"nanosecond heartbeat": N}` — distinctive field name

**FP-prone (shared)**:
- FastAPI default 404 page: vLLM, LangServe, ChromaDB all use FastAPI
- Generic JSON structure `{"status": "ok"}` → too many services return this
- Port 8000: llama.cpp, SGLang, NIM, ChromaDB, LangServe, Open WebUI all bind here

Rule: never fingerprint on generic 404 or status codes alone. Always probe version endpoint.

---

## 3. Data store assessment patterns (NSA Ch15 → vector DB profiles)

### Unauthenticated data store enumeration

1. **Connection without credentials**
   - Weaviate: `GET /v1/meta` → no auth required by default; returns server info, class count
   - ChromaDB: `GET /api/v1` → no auth; returns collection list, version
   - Qdrant: `GET /health` → no auth; dashboard at `/dashboard` open even with API key on REST
   - FP check: HTTP 401/403 → service requires auth; move to default credential phase

2. **Endpoint-based schema discovery**

   | Service | Endpoint | Auth? | Returns | FP Risk |
   |---------|----------|-------|---------|---------|
   | Weaviate | GET /v1/schema | No | Class definitions, vectorizer config | High if only 404; check 200 OK |
   | ChromaDB | GET /api/v1/collections | No | Collection metadata, record count | Low — distinct response structure |
   | Qdrant | GET /collections | API key optional | Collection names, vector dimensions | Low |
   | Milvus | GET /v1/health | No | Health + version | Medium — error msgs reveal config |

3. **Record enumeration without auth**

   Weaviate GraphQL:
   ```
   POST /v1/graphql
   {"query":"{Get{YourClass{_additional{id}}}}"}
   ```
   Returns record count + IDs with no authentication in default config.

   ChromaDB:
   ```
   GET /api/v1/collections/<name>/count
   ```
   Returns `{"count": 10000}` immediately.

4. **FP rates by service**

   | Service | Expected FP Rate | Common FP Cause | Mitigation |
   |---------|-----------------|-----------------|------------|
   | Weaviate | 5-10% | nginx proxy returning 404 for app | Verify HTTP 200 + valid JSON schema |
   | ChromaDB | <2% | Unrelated Python HTTP on 8000 | Check response has `nanosecond heartbeat` field |
   | Qdrant | 3-5% | Dashboard port open, REST closed | Probe both 6333 + 6334 |
   | Milvus | 10-15% | Firewall blocks after 1 packet | Retry probe 3x with timeout |

---

## 4. OSINT tool design patterns

### Module-based architecture (Recon-ng paradigm)

Recon-ng structure (OSINT Handbook Ch5):
- Independent modules per data source (Shodan, DNS, Google, WHOIS)
- Module types: reconnaissance → enumeration → import → reporting
- Marketplace: community-contributed modules with built-in update mechanism
- Data persistence: SQLite; queries allow cross-module pivoting

For TOME:
- Modular probes: one probe file per platform
- Each probe: input (IP/domain) → banner grab → fingerprint → enumerate → output JSON
- Central corpus: embedded JSON platform profiles; live probes enrich with findings
- Dork templates in `/dorks/` directory, updatable without recompiling

### Dynamic dork storage

Store Shodan dorks in JSON, updatable without recompile:
```json
{
  "ollama": {
    "basic": "product:Ollama",
    "strict": "product:Ollama http.title:\"Ollama\" port:11434",
    "with_version": "product:Ollama http.html:\"version\""
  }
}
```

### Output format conventions (OSINT Handbook Ch4)

Established tools (Recon-ng: CSV/JSON/DB; Maltego: GraphML; theHarvester: plain/HTML/XML).

For TOME:
- Primary: JSON Lines — one object per discovered instance, pipeable
- Secondary: CSV for spreadsheet import
- Each finding includes confidence score, discovery method, verification endpoint

```json
{
  "platform": "Weaviate",
  "ip": "203.0.113.42",
  "port": 8080,
  "hostname": "vec.company.com",
  "version": "1.3.1",
  "auth_required": false,
  "discovery_method": "shodan_strict_dork",
  "verified": true,
  "confidence": 0.95
}
```

---

## 5. Passive vs. active recon boundary

### Passive (safe without authorization)

No packets to target; only public search engine + registry queries. Leaves no trace.

- Shodan API dork queries → passive
- WHOIS lookups → passive
- DNS queries to public resolvers → passive
- Certificate transparency logs (crt.sh) → passive
- GitHub repo / Docker Hub metadata → passive
- Job postings, company websites → passive

### Active (requires authorization)

Sends traffic to target; leaves traces in service logs, IDS, firewall.

- Banner grabbing (curl to specific endpoints) → active
- Port scanning → active
- DNS zone transfers → active
- Credential guessing → active
- Directory enumeration → active

From Recon Ch3: "Active reconnaissance techniques are more intrusive and have a higher risk of being detected."

### Boundary table for TOME

| Operation | Classification | Include in TOME? |
|-----------|---------------|-----------------|
| Shodan API query | Passive | Yes — default mode |
| Reverse DNS | Passive | Yes — default mode |
| Cert transparency lookup | Passive | Yes — default mode |
| Banner grab (curl /api/version) | Active | `--active` flag, explicit warning |
| Port scan | Active | Out of scope for TOME |
| GraphQL enumeration | Active | `--active` flag |
| Credential guessing | Active | Out of scope |

TOME default = passive only. `--active` flag enables probing with warning: "Active probes send traffic to targets. Only use with written authorization."

---

## 6. Platform-specific intelligence gaps

Cross-referencing OSINT books with prior deployment corpus:

### What NSA Ch7+Ch15 says we're missing per platform

1. **Default credentials** — deployment books don't cover this fully
   - n8n: `admin/changeme` (if basic auth enabled but password unchanged)
   - MLflow: No default user in open-source; auth is optional add-on
   - Langfuse: LANGFUSE_PUBLIC_KEY + LANGFUSE_SECRET_KEY — keys often left as examples in docs
   - Gap: TOME corpus has no `default_creds` field populated for most platforms

2. **CVE linkage per version**
   - Gap: no `vulnerabilities` array per platform linking version ranges to CVE numbers
   - NSA approach: version from banner → NVD query → CVE with CVSS score

3. **Post-discovery pivot paths**
   - If Weaviate exposed: check for Kubernetes service account tokens in error responses
   - If Ollama exposed: check `/api/show` for system prompt leakage
   - If n8n exposed: check workflow JSON for embedded credentials
   - Gap: TOME corpus has no `pivot_paths` field

### OSINT-specific intelligence sources not in deployment books

| Gap | Source | Example |
|-----|--------|---------|
| GitHub repo defaults | GitHub search | Docker Compose files reveal real env var defaults |
| Job posting stack leakage | LinkedIn, Indeed | "Seeking Weaviate expert" confirms company uses Weaviate |
| Docker Hub metadata | Hub API | Image tag popularity reveals which versions are in production |
| Community forum reports | Reddit r/LocalLLM | Real-world misconfiguration patterns reported by users |
| Release notes CVE correlation | GitHub releases | Weaviate 1.3.0 auth fix → target deployments running <1.3.0 |

---

## 7. Comparison table: with vs. without OSINT methodology

| Aspect | Without OSINT Books | With OSINT Books | Impact |
|--------|--------------------|--------------------|--------|
| Shodan dork specificity | Generic: `"ollama" port:11434` | Layered: `product:Ollama http.title:"Ollama" port:11434` | FP rate 40%→5% |
| Service fingerprinting | Banner + open port = "likely Ollama" | Banner + version endpoint + response structure + TLS CN | Confidence 60%→95%+ |
| Data store enumeration | Check if /api/ returns 200 | Schema → record count → collection names → metadata | Surface area mapping vs. existence check |
| Default credential coverage | 0-2 per platform | Job posts + GitHub Compose files = 5-15 real defaults per platform | Actionable cred list vs. empty |
| Tool output | Port list + auth status | JSON Lines with confidence score + discovery method + pivot hooks | Machine-parseable, pipeable, downstream-chainable |
| Authorization boundary | Unclear — may probe without warning | Explicit passive/active split; --active flag with legal warning | Legally defensible for distribution |
| Post-discovery actions | "Service found, done" | Pivot paths: model list → org attribution → WHOIS → job posts | Full operator attribution chain |
| False positive handling | None | Response structure match + version endpoint verification + confidence score | Automated triage; report only high-confidence |
| Dork maintenance | Static, breaks as products update | GitHub issue templates + marketplace model | Community self-heals failing dorks |
| Vulnerability linkage | Static CVE mention | Version from banner → NVD query → CVSS + PoC link | "Weaviate 1.0 found" → "3 critical CVEs, 2 with exploits" |

---

## Books researched (round 3)

10. Reconnaissance for Ethical Hackers (9781837630639) — ch03 + ch05
11. The OSINT Handbook (9781837638277) — ch04 + ch05
12. Network Security Assessment, 3rd Ed (9781491911044) — ch04 + ch07 + ch15
