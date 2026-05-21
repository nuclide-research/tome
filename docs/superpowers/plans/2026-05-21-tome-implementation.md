# TOME Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build TOME — a Go CLI that embeds a 17-platform AI/ML infrastructure corpus and outputs Shodan dorks, aimap probe configs, and passive fingerprint findings.

**Architecture:** Cobra CLI. Platform JSON files at `platforms/*.json` embedded at compile time via `//go:embed` in `main.go`. The `embed.FS` is passed to `internal/corpus` via `Init()`. Passive `tome scan` queries the Shodan API for existing host banner data; `--active` sends HTTP directly to the target with an explicit warning gate.

**Tech Stack:** Go 1.21+, `github.com/spf13/cobra`, stdlib (`encoding/json`, `embed`, `net/http`, `regexp`)

---

## File Map

| File | Responsibility |
|------|---------------|
| `main.go` | Entry point; `//go:embed platforms/*.json`; calls `corpus.Init(fs)` then `cmd.Execute()` |
| `cmd/root.go` | Cobra root; persistent flags `--format`, `--confidence`, `--dork-tier` |
| `cmd/list.go` | `tome list` |
| `cmd/profile.go` | `tome profile <platform>` |
| `cmd/dorks.go` | `tome dorks <platform>` |
| `cmd/probe.go` | `tome probe <platform>` — aimap-compatible JSON |
| `cmd/scan.go` | `tome scan <ip>` — Shodan lookup + passive match + optional active probe |
| `internal/corpus/schema.go` | `Platform`, `Cred`, `Fingerprint`, `ActiveProbe`, `ShodanDorks`, `Finding`, `ProbeConfig` types |
| `internal/corpus/corpus.go` | `Init(embed.FS)`, `LoadPlatform`, `ListPlatforms` |
| `internal/corpus/corpus_test.go` | Corpus loader tests using `testdata/` fixture |
| `internal/fingerprint/passive.go` | `ShodanHost` types, `MatchPassive`, `matchFilter` |
| `internal/fingerprint/active.go` | `ProbeActive`, `extractVersion` |
| `internal/fingerprint/fingerprint_test.go` | Fingerprint tests with httptest mocks |
| `internal/output/output.go` | `FormatProfile`, `FormatList`, `FormatFindings` — table/json/csv |
| `internal/output/output_test.go` | Formatter tests |
| `platforms/*.json` | 17 platform corpus files |
| `.github/workflows/release.yml` | Cross-platform binaries on tag push |

---

### Task 1: Go module + schema types

**Files:**
- Create: `go.mod`
- Create: `internal/corpus/schema.go`
- Create: `internal/corpus/schema_test.go`

- [ ] **Step 1: Initialize module and add Cobra**

```bash
cd /path/to/tome
go mod init github.com/Nicholas-Kloster/tome
go get github.com/spf13/cobra@latest
```

Expected: `go.mod` present with `require github.com/spf13/cobra`.

- [ ] **Step 2: Write the failing schema test**

Create `internal/corpus/schema_test.go`:

```go
package corpus

import (
	"encoding/json"
	"testing"
)

func TestPlatformUnmarshal(t *testing.T) {
	raw := `{
		"platform": "weaviate",
		"display_name": "Weaviate",
		"category": "vector_db",
		"default_ports": [8080, 50051],
		"api_paths": ["/v1/meta"],
		"auth_default": "none",
		"auth_config_env": ["AUTHENTICATION_APIKEY_ENABLED"],
		"default_creds": [],
		"install_tell": "docker run semitechnologies/weaviate:latest",
		"misconfig_patterns": ["GraphQL introspection not disabled"],
		"fingerprint": {
			"passive": ["product:Weaviate"],
			"active_probe": {
				"path": "/v1/meta",
				"method": "GET",
				"response_markers": ["\"version\"", "\"modules\""],
				"false_positive_check": "response must include modules field as array"
			}
		},
		"shodan_dorks": {
			"basic": "port:8080 \"weaviate\"",
			"strict": "product:Weaviate port:8080",
			"version": "product:Weaviate http.html:\"v1/meta\""
		},
		"deployment_tells": ["/v1/meta reveals version"],
		"pivot_paths": ["GET /v1/schema -> class names"],
		"vulnerabilities": [],
		"sources": ["Learning LangChain (9781098167271) ch02"]
	}`

	var p Platform
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.Platform != "weaviate" {
		t.Errorf("platform = %q, want weaviate", p.Platform)
	}
	if len(p.DefaultPorts) != 2 || p.DefaultPorts[0] != 8080 {
		t.Errorf("default_ports = %v, want [8080 50051]", p.DefaultPorts)
	}
	if p.Fingerprint.ActiveProbe.Path != "/v1/meta" {
		t.Errorf("active_probe.path = %q, want /v1/meta", p.Fingerprint.ActiveProbe.Path)
	}
	if p.ShodanDorks.Strict != "product:Weaviate port:8080" {
		t.Errorf("shodan_dorks.strict = %q", p.ShodanDorks.Strict)
	}
}

func TestCredUnmarshal(t *testing.T) {
	raw := `{"user":"admin","pass":"changeme","context":"basic auth"}`
	var c Cred
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if c.User != "admin" || c.Pass != "changeme" {
		t.Errorf("got %+v", c)
	}
}
```

- [ ] **Step 3: Run test to confirm it fails**

```bash
go test ./internal/corpus/ -v -run TestPlatform
```

Expected: `FAIL — undefined: Platform`

- [ ] **Step 4: Write schema.go**

Create `internal/corpus/schema.go`:

```go
package corpus

// Platform is a single AI/ML infrastructure platform profile from the embedded corpus.
type Platform struct {
	Platform          string      `json:"platform"`
	DisplayName       string      `json:"display_name"`
	Category          string      `json:"category"`
	DefaultPorts      []int       `json:"default_ports"`
	APIPaths          []string    `json:"api_paths"`
	AuthDefault       string      `json:"auth_default"`
	AuthConfigEnv     []string    `json:"auth_config_env"`
	DefaultCreds      []Cred      `json:"default_creds"`
	InstallTell       string      `json:"install_tell"`
	MisconfigPatterns []string    `json:"misconfig_patterns"`
	Fingerprint       Fingerprint `json:"fingerprint"`
	ShodanDorks       ShodanDorks `json:"shodan_dorks"`
	DeploymentTells   []string    `json:"deployment_tells"`
	PivotPaths        []string    `json:"pivot_paths"`
	Vulnerabilities   []string    `json:"vulnerabilities"`
	Sources           []string    `json:"sources"`
}

// Cred is a known default credential pair for a platform.
type Cred struct {
	User    string `json:"user"`
	Pass    string `json:"pass"`
	Context string `json:"context"`
}

// Fingerprint holds passive Shodan filter strings and an active HTTP probe spec.
type Fingerprint struct {
	Passive     []string    `json:"passive"`
	ActiveProbe ActiveProbe `json:"active_probe"`
}

// ActiveProbe defines an HTTP check for live target verification (--active only).
type ActiveProbe struct {
	Path               string   `json:"path"`
	Method             string   `json:"method"`
	ResponseMarkers    []string `json:"response_markers"`
	FalsePositiveCheck string   `json:"false_positive_check"`
}

// ShodanDorks holds dork strings at three specificity tiers.
type ShodanDorks struct {
	Basic   string `json:"basic"`
	Strict  string `json:"strict"`
	Version string `json:"version"`
}

// Finding is the output record from tome scan.
type Finding struct {
	Platform        string   `json:"platform"`
	IP              string   `json:"ip"`
	Port            int      `json:"port"`
	DiscoveryMethod string   `json:"discovery_method"`
	AuthRequired    bool     `json:"auth_required"`
	Version         string   `json:"version,omitempty"`
	Verified        bool     `json:"verified"`
	Confidence      float64  `json:"confidence"`
	ActiveProbeUsed bool     `json:"active_probe_used"`
	PivotPaths      []string `json:"pivot_paths,omitempty"`
}

// ProbeConfig is the aimap-compatible output of tome probe.
type ProbeConfig struct {
	Platform            string   `json:"platform"`
	Port                int      `json:"port"`
	ProbePath           string   `json:"probe_path"`
	ResponseMarkers     []string `json:"response_markers"`
	ConfidenceThreshold float64  `json:"confidence_threshold"`
}
```

- [ ] **Step 5: Run test to confirm it passes**

```bash
go test ./internal/corpus/ -v -run TestPlatform
go test ./internal/corpus/ -v -run TestCred
```

Expected: both PASS.

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/corpus/schema.go internal/corpus/schema_test.go
git commit -m "feat: corpus schema types"
```

---

### Task 2: Corpus embed loader

**Files:**
- Create: `internal/corpus/corpus.go`
- Create: `internal/corpus/testdata/test-fixture.json`
- Modify: `internal/corpus/schema_test.go` (add loader tests)

- [ ] **Step 1: Create the testdata fixture**

Create `internal/corpus/testdata/test-fixture.json`:

```json
{
  "platform": "test-fixture",
  "display_name": "Test Fixture",
  "category": "test",
  "default_ports": [9999],
  "api_paths": ["/test"],
  "auth_default": "none",
  "auth_config_env": [],
  "default_creds": [],
  "install_tell": "test only",
  "misconfig_patterns": [],
  "fingerprint": {
    "passive": ["port:9999"],
    "active_probe": {
      "path": "/test",
      "method": "GET",
      "response_markers": ["\"ok\""],
      "false_positive_check": ""
    }
  },
  "shodan_dorks": {
    "basic": "port:9999",
    "strict": "port:9999",
    "version": "port:9999"
  },
  "deployment_tells": [],
  "pivot_paths": [],
  "vulnerabilities": [],
  "sources": []
}
```

- [ ] **Step 2: Write failing corpus loader tests**

Add to `internal/corpus/schema_test.go` (below existing tests):

```go
import (
	"embed"
	"os"
	"testing"
)

//go:embed testdata/*.json
var testFS embed.FS

func TestMain(m *testing.M) {
	Init(testFS)
	os.Exit(m.Run())
}

func TestLoadPlatform(t *testing.T) {
	p, err := LoadPlatform("test-fixture")
	if err != nil {
		t.Fatalf("LoadPlatform: %v", err)
	}
	if p.Platform != "test-fixture" {
		t.Errorf("platform = %q, want test-fixture", p.Platform)
	}
	if len(p.DefaultPorts) != 1 || p.DefaultPorts[0] != 9999 {
		t.Errorf("default_ports = %v, want [9999]", p.DefaultPorts)
	}
}

func TestLoadPlatformMissing(t *testing.T) {
	_, err := LoadPlatform("does-not-exist")
	if err == nil {
		t.Error("expected error for missing platform, got nil")
	}
}

func TestListPlatforms(t *testing.T) {
	platforms, err := ListPlatforms()
	if err != nil {
		t.Fatalf("ListPlatforms: %v", err)
	}
	if len(platforms) == 0 {
		t.Error("expected at least one platform")
	}
	found := false
	for _, p := range platforms {
		if p.Platform == "test-fixture" {
			found = true
		}
	}
	if !found {
		t.Error("test-fixture not found in list")
	}
}
```

- [ ] **Step 3: Run to confirm failure**

```bash
go test ./internal/corpus/ -v -run TestLoad
go test ./internal/corpus/ -v -run TestList
```

Expected: FAIL — `undefined: Init`, `undefined: LoadPlatform`, `undefined: ListPlatforms`

- [ ] **Step 4: Write corpus.go**

Create `internal/corpus/corpus.go`:

```go
package corpus

import (
	"embed"
	"encoding/json"
	"fmt"
	"strings"
)

var fs embed.FS

// Init sets the embedded filesystem. Called once from main with the //go:embed FS.
func Init(embedded embed.FS) {
	fs = embedded
}

// LoadPlatform returns the Platform for the given name (e.g. "weaviate").
// Name is the filename stem — no path, no .json extension.
func LoadPlatform(name string) (Platform, error) {
	// Try both the platforms/ prefix (production) and testdata/ prefix (tests).
	for _, prefix := range []string{"platforms", "testdata"} {
		data, err := fs.ReadFile(prefix + "/" + name + ".json")
		if err == nil {
			var p Platform
			return p, json.Unmarshal(data, &p)
		}
	}
	return Platform{}, fmt.Errorf("unknown platform %q", name)
}

// ListPlatforms returns all platforms in the embedded corpus.
func ListPlatforms() ([]Platform, error) {
	for _, prefix := range []string{"platforms", "testdata"} {
		entries, err := fs.ReadDir(prefix)
		if err != nil {
			continue
		}
		platforms := make([]Platform, 0, len(entries))
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			name := strings.TrimSuffix(e.Name(), ".json")
			p, err := LoadPlatform(name)
			if err != nil {
				continue
			}
			platforms = append(platforms, p)
		}
		return platforms, nil
	}
	return nil, fmt.Errorf("no platform directory found in embedded FS")
}
```

- [ ] **Step 5: Fix the test file — the import block needs to be at the top**

The `schema_test.go` file's imports must be in a single block at the top. Replace the existing import in `schema_test.go` with:

```go
package corpus

import (
	"embed"
	"encoding/json"
	"os"
	"testing"
)

//go:embed testdata/*.json
var testFS embed.FS

func TestMain(m *testing.M) {
	Init(testFS)
	os.Exit(m.Run())
}
```

(Keep all the existing test functions below this block.)

- [ ] **Step 6: Run all corpus tests**

```bash
go test ./internal/corpus/ -v
```

Expected: all PASS — `TestPlatformUnmarshal`, `TestCredUnmarshal`, `TestLoadPlatform`, `TestLoadPlatformMissing`, `TestListPlatforms`.

- [ ] **Step 7: Commit**

```bash
git add internal/corpus/corpus.go internal/corpus/schema_test.go internal/corpus/testdata/
git commit -m "feat: corpus embed loader with Init pattern"
```

---

### Task 3: Platform JSON files — all 17

**Files:**
- Create: `platforms/ollama.json`
- Create: `platforms/vllm.json`
- Create: `platforms/tgi.json`
- Create: `platforms/llamacpp.json`
- Create: `platforms/sglang.json`
- Create: `platforms/rayserve.json`
- Create: `platforms/nvidia-nim.json`
- Create: `platforms/kserve.json`
- Create: `platforms/n8n.json`
- Create: `platforms/langserve.json`
- Create: `platforms/chromadb.json`
- Create: `platforms/weaviate.json`
- Create: `platforms/qdrant.json`
- Create: `platforms/milvus.json`
- Create: `platforms/mlflow.json`
- Create: `platforms/langfuse.json`
- Create: `platforms/langsmith.json`

- [ ] **Step 1: Create platforms/ollama.json**

```json
{
  "platform": "ollama",
  "display_name": "Ollama",
  "category": "inference_serving",
  "default_ports": [11434],
  "api_paths": ["/api/generate", "/api/chat", "/api/tags", "/api/show", "/api/version"],
  "auth_default": "none",
  "auth_config_env": ["OLLAMA_HOST"],
  "default_creds": [],
  "install_tell": "docker run -p 11434:11434 ollama/ollama",
  "misconfig_patterns": [
    "OLLAMA_HOST=0.0.0.0 exposes to all interfaces",
    "No authentication on model API",
    "System prompts exposed via /api/show"
  ],
  "fingerprint": {
    "passive": [
      "product:Ollama",
      "http.title:\"Ollama\"",
      "port:11434"
    ],
    "active_probe": {
      "path": "/api/version",
      "method": "GET",
      "response_markers": ["\"version\""],
      "false_positive_check": "response must be JSON object with version field"
    }
  },
  "shodan_dorks": {
    "basic": "\"ollama\" port:11434",
    "strict": "product:Ollama port:11434",
    "version": "product:Ollama port:11434 http.html:\"version\""
  },
  "deployment_tells": [
    "/api/tags returns full model inventory with sizes",
    "/api/version reveals exact release",
    "OLLAMA_HOST=0.0.0.0 in process environment"
  ],
  "pivot_paths": [
    "GET /api/tags → model inventory → infer org focus from model names",
    "GET /api/show → system prompt leakage (reveals deployment context)",
    "GET /api/version → exact version → CVE matching"
  ],
  "vulnerabilities": [],
  "sources": [
    "Generative AI on Kubernetes (9781098171919) ch01",
    "Hands-On LLM Serving and Optimization (9798341621480) ch08"
  ]
}
```

- [ ] **Step 2: Create platforms/vllm.json**

```json
{
  "platform": "vllm",
  "display_name": "vLLM",
  "category": "inference_serving",
  "default_ports": [8080],
  "api_paths": ["/v1/completions", "/v1/chat/completions", "/v1/models", "/metrics"],
  "auth_default": "none",
  "auth_config_env": ["HF_TOKEN", "HUGGING_FACE_HUB_TOKEN"],
  "default_creds": [],
  "install_tell": "docker run -p 8080:8080 vllm/vllm-openai:latest --model mistralai/Mistral-7B-v0.1",
  "misconfig_patterns": [
    "Binding to 0.0.0.0 without auth proxy",
    "/metrics exposes GPU memory utilization and model stats",
    "No rate limiting — unlimited token generation"
  ],
  "fingerprint": {
    "passive": [
      "http.headers:\"Server: uvicorn\"",
      "port:8080 http.html:\"vllm\"",
      "http.html:\"model_runner\""
    ],
    "active_probe": {
      "path": "/v1/models",
      "method": "GET",
      "response_markers": ["\"object\"", "\"data\""],
      "false_positive_check": "response.object must equal 'list' and data must be array"
    }
  },
  "shodan_dorks": {
    "basic": "\"vllm\" port:8080",
    "strict": "port:8080 http.headers:\"uvicorn\" http.html:\"vllm\"",
    "version": "port:8080 http.html:\"vllm\" http.html:\"version\""
  },
  "deployment_tells": [
    "Server: uvicorn response header",
    "/metrics endpoint exposes GPU stats",
    "Loading model weights log line at startup"
  ],
  "pivot_paths": [
    "GET /v1/models → model list → infer org via model name (org/model-name format)",
    "GET /metrics → gpu_memory_utilization → estimate cluster GPU count",
    "HF_TOKEN in process env → Hugging Face account pivot"
  ],
  "vulnerabilities": [],
  "sources": [
    "Generative AI on Kubernetes (9781098171919) ch01",
    "Generative AI on Kubernetes (9781098171919) ch04"
  ]
}
```

- [ ] **Step 3: Create platforms/tgi.json**

```json
{
  "platform": "tgi",
  "display_name": "Text Generation Inference (TGI)",
  "category": "inference_serving",
  "default_ports": [8080, 3000],
  "api_paths": ["/generate_stream", "/v1/chat/completions", "/health", "/info"],
  "auth_default": "none",
  "auth_config_env": ["HF_TOKEN", "MAX_BATCH_TOTAL_TOKENS", "SM_NUM_GPUS"],
  "default_creds": [],
  "install_tell": "docker run -p 8080:8080 -p 3000:3000 ghcr.io/huggingface/text-generation-inference:latest",
  "misconfig_patterns": [
    "Dual-port exposure: native API on 8080, OpenAI-compat on 3000",
    "No authentication on either port",
    "HF_TOKEN in Kubernetes pod spec"
  ],
  "fingerprint": {
    "passive": [
      "http.html:\"generate_stream\"",
      "port:8080 http.html:\"text-generation\"",
      "\"text-generation-launcher\""
    ],
    "active_probe": {
      "path": "/info",
      "method": "GET",
      "response_markers": ["\"model_id\"", "\"max_concurrent_requests\""],
      "false_positive_check": "response must include model_id as non-empty string"
    }
  },
  "shodan_dorks": {
    "basic": "\"text-generation-launcher\" port:8080",
    "strict": "port:8080 http.html:\"generate_stream\"",
    "version": "port:8080 http.html:\"generate_stream\" http.html:\"model_id\""
  },
  "deployment_tells": [
    "/generate_stream SSE endpoint on port 8080",
    "OpenAI-compatible API on port 3000",
    "Flash Attention backend selection in startup banner"
  ],
  "pivot_paths": [
    "GET /info → model_id → identify Hugging Face model source and owner",
    "Dual-port hit in Shodan = two fingerprint signals per host",
    "MAX_BATCH_TOTAL_TOKENS env → infer GPU VRAM capacity"
  ],
  "vulnerabilities": [],
  "sources": [
    "Generative AI on Kubernetes (9781098171919) ch01"
  ]
}
```

- [ ] **Step 4: Create platforms/llamacpp.json**

```json
{
  "platform": "llamacpp",
  "display_name": "llama.cpp (server mode)",
  "category": "inference_serving",
  "default_ports": [8000],
  "api_paths": ["/v1/completions", "/v1/chat/completions", "/health"],
  "auth_default": "none",
  "auth_config_env": [],
  "default_creds": [],
  "install_tell": "python -m llama_cpp.server --model /path/to/model.gguf --port 8000",
  "misconfig_patterns": [
    "OpenAI-compat API exposed on public interface",
    "GGUF model path reveals filesystem layout",
    "No rate limiting"
  ],
  "fingerprint": {
    "passive": [
      "http.headers:\"Server: llama.cpp\"",
      "port:8000 http.html:\"llama.cpp\"",
      "http.html:\"gguf\""
    ],
    "active_probe": {
      "path": "/health",
      "method": "GET",
      "response_markers": ["\"status\""],
      "false_positive_check": "Server header must contain llama.cpp"
    }
  },
  "shodan_dorks": {
    "basic": "\"llama.cpp\" port:8000",
    "strict": "port:8000 http.headers:\"Server: llama.cpp\"",
    "version": "port:8000 http.headers:\"Server: llama.cpp\" http.html:\"gguf\""
  },
  "deployment_tells": [
    "Server: llama.cpp response header (uniquely identifies)",
    "GGUF model format referenced in /v1/models response",
    "Q4_0/Q5_K/Q8_0 quantization level in startup logs"
  ],
  "pivot_paths": [
    "GET /v1/models → model file path → infer host filesystem layout",
    "Server header version string → exact llama.cpp release → CVE matching",
    "GGUF quantization level → estimate available VRAM"
  ],
  "vulnerabilities": [],
  "sources": [
    "Generative AI on Kubernetes (9781098171919) ch01",
    "Hands-On LLM Serving and Optimization (9798341621480) ch08"
  ]
}
```

- [ ] **Step 5: Create platforms/sglang.json**

```json
{
  "platform": "sglang",
  "display_name": "SGLang",
  "category": "inference_serving",
  "default_ports": [8000],
  "api_paths": ["/v1/completions", "/v1/chat/completions", "/v1/models"],
  "auth_default": "none",
  "auth_config_env": [],
  "default_creds": [],
  "install_tell": "python -m sglang.launch_server --model-path meta-llama/Meta-Llama-3-8B-Instruct --port 8000",
  "misconfig_patterns": [
    "OpenAI-compat API on public interface without auth",
    "RadixAttention state accessible via timing side-channel"
  ],
  "fingerprint": {
    "passive": [
      "port:8000 http.html:\"sglang\"",
      "http.html:\"sglang.launch_server\""
    ],
    "active_probe": {
      "path": "/v1/models",
      "method": "GET",
      "response_markers": ["\"object\"", "\"data\""],
      "false_positive_check": "response must include sglang-specific structured gen endpoints alongside /v1/models"
    }
  },
  "shodan_dorks": {
    "basic": "\"sglang\" port:8000",
    "strict": "port:8000 http.html:\"sglang\"",
    "version": "port:8000 http.html:\"sglang\" http.html:\"version\""
  },
  "deployment_tells": [
    "RadixAttention prefix caching in startup logs",
    "sglang.launch_server process name",
    "Structured generation endpoints alongside OpenAI-compat"
  ],
  "pivot_paths": [
    "GET /v1/models → model name → identify org's model selection",
    "RadixAttention cache timing → infer prior request content",
    "Port 8000 overlap with llama.cpp — verify via Server header"
  ],
  "vulnerabilities": [],
  "sources": [
    "Generative AI on Kubernetes (9781098171919) ch01"
  ]
}
```

- [ ] **Step 6: Create platforms/rayserve.json**

```json
{
  "platform": "rayserve",
  "display_name": "Ray Serve",
  "category": "inference_serving",
  "default_ports": [8000, 8265],
  "api_paths": ["/dashboard", "/api/v0/status"],
  "auth_default": "none",
  "auth_config_env": [],
  "default_creds": [],
  "install_tell": "ray start --head && serve run deployment.py",
  "misconfig_patterns": [
    "Ray dashboard on port 8265 accessible without authentication",
    "Dashboard exposes full cluster topology including all worker IPs",
    "No built-in auth on serving endpoints"
  ],
  "fingerprint": {
    "passive": [
      "port:8265 http.title:\"Ray Dashboard\"",
      "http.html:\"Ray Dashboard\"",
      "port:8265"
    ],
    "active_probe": {
      "path": "/dashboard",
      "method": "GET",
      "response_markers": ["Ray", "Dashboard"],
      "false_positive_check": "response HTML must contain Ray Dashboard title"
    }
  },
  "shodan_dorks": {
    "basic": "port:8265 \"ray\"",
    "strict": "port:8265 http.title:\"Ray Dashboard\"",
    "version": "port:8265 http.title:\"Ray Dashboard\" http.html:\"version\""
  },
  "deployment_tells": [
    "Dashboard at :8265 with no auth — primary signal",
    "RayService CRD present in Kubernetes",
    "Ray cluster head node log lines in banners"
  ],
  "pivot_paths": [
    "GET /api/v0/status → full cluster topology → list all worker node IPs",
    "Worker IPs → expand scan scope to full cluster",
    "Serving deployment names → infer models and application structure"
  ],
  "vulnerabilities": [],
  "sources": [
    "Generative AI on Kubernetes (9781098171919) ch01"
  ]
}
```

- [ ] **Step 7: Create platforms/nvidia-nim.json**

```json
{
  "platform": "nvidia-nim",
  "display_name": "NVIDIA NIM",
  "category": "inference_serving",
  "default_ports": [8000],
  "api_paths": ["/v1/completions", "/v1/chat/completions", "/v1/models"],
  "auth_default": "none",
  "auth_config_env": ["NGC_API_KEY", "NIM_CACHE_PATH"],
  "default_creds": [],
  "install_tell": "docker run -p 8000:8000 nvcr.io/nim/meta/llama3-8b-instruct:latest",
  "misconfig_patterns": [
    "OpenAI-compat container exposes without auth by default",
    "NGC_API_KEY present in container environment",
    "PersistentVolume model cache world-readable in Kubernetes"
  ],
  "fingerprint": {
    "passive": [
      "port:8000 http.html:\"nvidia\"",
      "http.html:\"nvcr.io\"",
      "port:8000 http.html:\"nim\""
    ],
    "active_probe": {
      "path": "/v1/models",
      "method": "GET",
      "response_markers": ["\"object\"", "\"data\""],
      "false_positive_check": "model IDs should follow NVIDIA NIM naming convention (e.g. meta/llama3)"
    }
  },
  "shodan_dorks": {
    "basic": "\"nim\" port:8000",
    "strict": "port:8000 http.html:\"nvidia\" http.html:\"nim\"",
    "version": "port:8000 http.html:\"nvcr.io\""
  },
  "deployment_tells": [
    "NIM container images sourced from nvcr.io registry",
    "PersistentVolume model cache in Kubernetes pod spec",
    "NGC_API_KEY in pod environment"
  ],
  "pivot_paths": [
    "GET /v1/models → NIM model ID → identify NVIDIA catalog offering and version",
    "NGC_API_KEY exposure → NVIDIA cloud registry pivot",
    "nvcr.io image tag → identify exact model family and optimization profile"
  ],
  "vulnerabilities": [],
  "sources": [
    "Generative AI on Kubernetes (9781098171919) ch01"
  ]
}
```

- [ ] **Step 8: Create platforms/kserve.json**

```json
{
  "platform": "kserve",
  "display_name": "KServe",
  "category": "inference_serving",
  "default_ports": [8080],
  "api_paths": ["/v1/models", "/v1/completions", "/health"],
  "auth_default": "none",
  "auth_config_env": [],
  "default_creds": [],
  "install_tell": "kubectl apply -f inferenceservice.yaml",
  "misconfig_patterns": [
    "Kubernetes RBAC not applied to InferenceService endpoints",
    "ServingRuntime CRDs expose model configuration",
    "Inherits runtime auth defaults (vLLM/TGI = none)"
  ],
  "fingerprint": {
    "passive": [
      "http.html:\"InferenceService\"",
      "http.html:\"kserve\""
    ],
    "active_probe": {
      "path": "/v1/models",
      "method": "GET",
      "response_markers": ["\"name\"", "\"ready\""],
      "false_positive_check": "response must include KServe-style model readiness fields"
    }
  },
  "shodan_dorks": {
    "basic": "\"kserve\"",
    "strict": "http.html:\"InferenceService\" http.html:\"kserve\"",
    "version": "http.html:\"kserve\" http.html:\"ServingRuntime\""
  },
  "deployment_tells": [
    "ServingRuntime + InferenceService CRDs in Kubernetes",
    "Kubernetes-native annotations in HTTP response headers",
    "Port inherits from runtime (8080 for vLLM/TGI)"
  ],
  "pivot_paths": [
    "InferenceService metadata → namespace + model name → full K8s context",
    "Kubernetes service account token → cluster pivot if RBAC misconfigured",
    "ServingRuntime spec → identify backing runtime and its own CVE surface"
  ],
  "vulnerabilities": [],
  "sources": [
    "Generative AI on Kubernetes (9781098171919) ch01"
  ]
}
```

- [ ] **Step 9: Create platforms/n8n.json**

```json
{
  "platform": "n8n",
  "display_name": "n8n",
  "category": "orchestration",
  "default_ports": [5678],
  "api_paths": ["/api/v1", "/", "/webhook", "/rest/admin/diagnostics"],
  "auth_default": "basic",
  "auth_config_env": [
    "N8N_BASIC_AUTH_ACTIVE",
    "N8N_BASIC_AUTH_USER",
    "N8N_BASIC_AUTH_PASSWORD",
    "N8N_ENCRYPTION_KEY"
  ],
  "default_creds": [
    {
      "user": "admin",
      "pass": "changeme",
      "context": "basic auth when N8N_BASIC_AUTH_ACTIVE=true with default password"
    }
  ],
  "install_tell": "docker run -p 5678:5678 n8nio/n8n",
  "misconfig_patterns": [
    "N8N_BASIC_AUTH_ACTIVE not set — auth disabled entirely",
    "Credentials stored in workflow JSON in plaintext",
    "Webhook endpoints reachable without authentication",
    "N8N_ENCRYPTION_KEY left at default or in Docker logs"
  ],
  "fingerprint": {
    "passive": [
      "http.title:\"n8n\"",
      "port:5678",
      "port:5678 http.html:\"n8n\""
    ],
    "active_probe": {
      "path": "/",
      "method": "GET",
      "response_markers": ["n8n", "workflow"],
      "false_positive_check": "HTML response must include n8n branding in title or footer"
    }
  },
  "shodan_dorks": {
    "basic": "\"n8n\" port:5678",
    "strict": "http.title:\"n8n\" port:5678",
    "version": "http.title:\"n8n\" port:5678 http.html:\"n8n@\""
  },
  "deployment_tells": [
    "http.title:n8n — highly distinctive",
    "/api/v1 returns workflow list when auth disabled",
    "PostgreSQL or SQLite backend referenced in diagnostics"
  ],
  "pivot_paths": [
    "GET /api/v1/workflows → workflow JSON → extract embedded service credentials",
    "Webhook endpoints → trigger arbitrary workflow execution without auth",
    "GET /rest/admin/diagnostics → stack version info via 401 header leakage"
  ],
  "vulnerabilities": [],
  "sources": [
    "Agentic AI for Offensive Cybersecurity (9781806114474) ch03",
    "AI-Native LLM Security (9781836203759) ch04"
  ]
}
```

- [ ] **Step 10: Create platforms/langserve.json**

```json
{
  "platform": "langserve",
  "display_name": "LangServe",
  "category": "orchestration",
  "default_ports": [8000],
  "api_paths": ["/chain", "/invoke", "/stream", "/docs", "/playground"],
  "auth_default": "none",
  "auth_config_env": [],
  "default_creds": [],
  "install_tell": "pip install langserve && python serve.py",
  "misconfig_patterns": [
    "No input validation on /invoke — prompt injection surface",
    "/playground exposes model behavior analysis without auth",
    "FastAPI /docs exposes full API schema including chain logic"
  ],
  "fingerprint": {
    "passive": [
      "port:8000 http.html:\"/playground\"",
      "port:8000 http.html:\"invoke\"",
      "http.headers:\"Server: uvicorn\""
    ],
    "active_probe": {
      "path": "/docs",
      "method": "GET",
      "response_markers": ["FastAPI", "invoke"],
      "false_positive_check": "OpenAPI spec must include /invoke path"
    }
  },
  "shodan_dorks": {
    "basic": "port:8000 \"/playground\"",
    "strict": "port:8000 http.html:\"/playground\" http.html:\"invoke\"",
    "version": "port:8000 http.html:\"langserve\" http.html:\"/playground\""
  },
  "deployment_tells": [
    "FastAPI /docs endpoint with /invoke path",
    "/playground browser UI for chain interaction",
    "uvicorn Server header — shared with vLLM; verify via /playground presence"
  ],
  "pivot_paths": [
    "GET /docs → full OpenAPI spec → enumerate all chain endpoints and input schemas",
    "POST /invoke → test for prompt injection on chain input",
    "GET /playground → inspect chain behavior, extract system prompt"
  ],
  "vulnerabilities": [],
  "sources": [
    "Learning LangChain (9781098167271) ch09"
  ]
}
```

- [ ] **Step 11: Create platforms/chromadb.json**

```json
{
  "platform": "chromadb",
  "display_name": "ChromaDB",
  "category": "vector_db",
  "default_ports": [8000],
  "api_paths": ["/api/v1", "/api/v1/collections", "/api/v1/query"],
  "auth_default": "none",
  "auth_config_env": ["CHROMA_SERVER_AUTH_CREDENTIALS_FILE"],
  "default_creds": [],
  "install_tell": "docker run -p 8000:8000 ghcr.io/chroma-core/chroma:latest",
  "misconfig_patterns": [
    "No auth in server mode — all collections publicly readable",
    "Collection metadata may contain sensitive data class information",
    "Persistent storage world-readable on host filesystem"
  ],
  "fingerprint": {
    "passive": [
      "port:8000 http.html:\"chromadb\"",
      "http.html:\"/api/v1/collections\""
    ],
    "active_probe": {
      "path": "/api/v1",
      "method": "GET",
      "response_markers": ["nanosecond heartbeat"],
      "false_positive_check": "response must include 'nanosecond heartbeat' field — uniquely identifies ChromaDB"
    }
  },
  "shodan_dorks": {
    "basic": "\"chromadb\" port:8000",
    "strict": "port:8000 http.html:\"/api/v1/collections\"",
    "version": "port:8000 http.html:\"nanosecond heartbeat\""
  },
  "deployment_tells": [
    "/api/v1 heartbeat with 'nanosecond heartbeat' field — uniquely identifies ChromaDB",
    "JSON collection list at /api/v1/collections",
    "Error messages reveal storage backend type"
  ],
  "pivot_paths": [
    "GET /api/v1/collections → collection names → query embeddings without auth",
    "GET /api/v1/collections/<name>/count → record count immediately",
    "Collection metadata → infer data type (medical, financial, personal) and organization"
  ],
  "vulnerabilities": [],
  "sources": [
    "Learning LangChain (9781098167271) ch02",
    "Agentic AI for Offensive Cybersecurity (9781806114474) ch04"
  ]
}
```

- [ ] **Step 12: Create platforms/weaviate.json**

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
    "GraphQL introspection not disabled — schema fully enumerable",
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
      "false_positive_check": "response must include 'modules' field as array — uniquely identifies Weaviate"
    }
  },
  "shodan_dorks": {
    "basic": "port:8080 \"weaviate\"",
    "strict": "product:Weaviate port:8080",
    "version": "product:Weaviate http.html:\"v1/meta\""
  },
  "deployment_tells": [
    "/v1/meta reveals version + all loaded modules",
    "/v1/graphql explorer accessible without auth",
    "gRPC port 50051 open alongside 8080"
  ],
  "pivot_paths": [
    "GET /v1/schema → class definitions → query records via GraphQL without auth",
    "POST /v1/graphql {Get{ClassName{_additional{id}}}} → record count + IDs",
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

- [ ] **Step 13: Create platforms/qdrant.json**

```json
{
  "platform": "qdrant",
  "display_name": "Qdrant",
  "category": "vector_db",
  "default_ports": [6333, 6334],
  "api_paths": [
    "/collections",
    "/points/search",
    "/health",
    "/dashboard",
    "/openapi.json"
  ],
  "auth_default": "api_key",
  "auth_config_env": ["QDRANT_API_KEY", "QDRANT_READ_ONLY_API_KEY"],
  "default_creds": [],
  "install_tell": "docker run -p 6333:6333 -p 6334:6334 qdrant/qdrant",
  "misconfig_patterns": [
    "API key exposed in Docker stdout logs",
    "/dashboard web UI accessible without credentials even when REST API key is configured",
    "Read-write and read-only API keys not distinguished"
  ],
  "fingerprint": {
    "passive": [
      "port:6333 http.html:\"qdrant\"",
      "http.html:\"/dashboard\" qdrant",
      "port:6333"
    ],
    "active_probe": {
      "path": "/health",
      "method": "GET",
      "response_markers": ["\"status\"", "\"result\""],
      "false_positive_check": "response must include Qdrant-specific status structure; probe /dashboard for UI confirmation"
    }
  },
  "shodan_dorks": {
    "basic": "\"qdrant\" port:6333",
    "strict": "port:6333 http.html:\"qdrant\"",
    "version": "port:6333 http.html:\"qdrant\" http.html:\"version\""
  },
  "deployment_tells": [
    "/health returns unauthenticated even with API key configured on REST",
    "/dashboard web UI open in browser at :6333/dashboard",
    "/openapi.json exposes full Qdrant API schema"
  ],
  "pivot_paths": [
    "GET /collections → collection list even with API key on REST (dashboard bypass)",
    "GET /dashboard → full collection browser, vector count, payload fields",
    "GET /openapi.json → enumerate all endpoints including collection management"
  ],
  "vulnerabilities": [],
  "sources": [
    "Learning LangChain (9781098167271) ch02",
    "AI-Native LLM Security (9781836203759) ch04"
  ]
}
```

- [ ] **Step 14: Create platforms/milvus.json**

```json
{
  "platform": "milvus",
  "display_name": "Milvus",
  "category": "vector_db",
  "default_ports": [19530],
  "api_paths": ["/v1/health", "/v1/vector/collections"],
  "auth_default": "none",
  "auth_config_env": ["MILVUS_SECURITY_AUTHORIZATIONENABLED"],
  "default_creds": [],
  "install_tell": "docker run -p 19530:19530 milvusdb/milvus:latest standalone",
  "misconfig_patterns": [
    "No authentication in single-node deployment",
    "gRPC port 19530 exposed without TLS",
    "MILVUS_SECURITY_AUTHORIZATIONENABLED defaults to false"
  ],
  "fingerprint": {
    "passive": [
      "port:19530",
      "port:19530 http.html:\"milvus\""
    ],
    "active_probe": {
      "path": "/v1/health",
      "method": "GET",
      "response_markers": ["\"code\"", "\"data\""],
      "false_positive_check": "response code must be 200 with Milvus health structure; 10-15% FP rate — retry probe 3x"
    }
  },
  "shodan_dorks": {
    "basic": "\"milvus\" port:19530",
    "strict": "port:19530 \"milvus\"",
    "version": "port:19530 http.html:\"milvus\" http.html:\"version\""
  },
  "deployment_tells": [
    "Port 19530 is Milvus-specific — lower FP than port 8000 cluster",
    "Attu web UI often running at port 8000 alongside gRPC on 19530",
    "Error messages reveal Milvus version for CVE matching"
  ],
  "pivot_paths": [
    "GET /v1/vector/collections → list collections → query vectors without auth",
    "Error response bodies reveal exact Milvus version string",
    "Attu UI at :8000 → full vector database browser without credentials"
  ],
  "vulnerabilities": [],
  "sources": [
    "Learning LangChain (9781098167271) ch02"
  ]
}
```

- [ ] **Step 15: Create platforms/mlflow.json**

```json
{
  "platform": "mlflow",
  "display_name": "MLflow Tracking Server",
  "category": "observability",
  "default_ports": [5000],
  "api_paths": [
    "/api/2.0/experiments",
    "/api/2.0/runs",
    "/metrics/",
    "/"
  ],
  "auth_default": "none",
  "auth_config_env": [
    "MLFLOW_TRACKING_USERNAME",
    "MLFLOW_TRACKING_PASSWORD"
  ],
  "default_creds": [],
  "install_tell": "pip install mlflow && mlflow server --host 0.0.0.0 --port 5000",
  "misconfig_patterns": [
    "No authentication in default deployment",
    "Artifact storage world-readable on backing store",
    "Backend store credentials (database URL) exposed in environment"
  ],
  "fingerprint": {
    "passive": [
      "http.title:\"MLflow\"",
      "port:5000 http.html:\"mlflow\""
    ],
    "active_probe": {
      "path": "/api/2.0/experiments",
      "method": "GET",
      "response_markers": ["\"experiments\""],
      "false_positive_check": "response must include experiments array with MLflow experiment structure"
    }
  },
  "shodan_dorks": {
    "basic": "\"mlflow\" port:5000",
    "strict": "http.title:\"MLflow\" port:5000",
    "version": "http.title:\"MLflow\" port:5000 http.html:\"version\""
  },
  "deployment_tells": [
    "http.title:MLflow — highly distinctive at port 5000",
    "/api/2.0/experiments returns full experiment list without auth",
    "/metrics/ path accessible"
  ],
  "pivot_paths": [
    "GET /api/2.0/experiments → experiment names → reveal project structure and team organization",
    "GET /api/2.0/runs → run parameters → model names, hyperparameters, data paths",
    "Artifact store URI in experiment metadata → S3/GCS bucket pivot"
  ],
  "vulnerabilities": [],
  "sources": [
    "LLMOps (9781098154196) ch06",
    "LLMOps (9781098154196) ch08"
  ]
}
```

- [ ] **Step 16: Create platforms/langfuse.json**

```json
{
  "platform": "langfuse",
  "display_name": "Langfuse (self-hosted)",
  "category": "observability",
  "default_ports": [3000],
  "api_paths": ["/api/public", "/api/v1", "/traces", "/sessions"],
  "auth_default": "api_key",
  "auth_config_env": [
    "LANGFUSE_PUBLIC_KEY",
    "LANGFUSE_SECRET_KEY",
    "DATABASE_URL"
  ],
  "default_creds": [],
  "install_tell": "docker run -p 3000:3000 ghcr.io/langfuse/langfuse:latest",
  "misconfig_patterns": [
    "API keys embedded in client-side JavaScript",
    "Traces contain unmasked LLM API credentials passed as context",
    "Self-hosted deployment without SSL — keys transmitted in plaintext",
    "Open signup enabled in self-hosted mode"
  ],
  "fingerprint": {
    "passive": [
      "http.title:\"langfuse\"",
      "port:3000 http.html:\"langfuse\""
    ],
    "active_probe": {
      "path": "/",
      "method": "GET",
      "response_markers": ["Langfuse", "traces"],
      "false_positive_check": "page title must contain Langfuse"
    }
  },
  "shodan_dorks": {
    "basic": "\"langfuse\" port:3000",
    "strict": "http.title:\"langfuse\" port:3000",
    "version": "http.title:\"langfuse\" port:3000 http.html:\"langfuse@\""
  },
  "deployment_tells": [
    "http.title:Langfuse at port 3000",
    "/api/public endpoint present",
    "DATABASE_URL in container environment"
  ],
  "pivot_paths": [
    "Trace endpoint → full conversation history including system prompts without auth",
    "API keys in client-side JS bundle → downstream LLM API access",
    "Self-hosted traces contain unmasked PII and API credentials from traced calls"
  ],
  "vulnerabilities": [],
  "sources": [
    "AI-Native LLM Security (9781836203759) ch04",
    "Learning LangChain (9781098167271) ch10"
  ]
}
```

- [ ] **Step 17: Create platforms/langsmith.json**

```json
{
  "platform": "langsmith",
  "display_name": "LangSmith",
  "category": "observability",
  "default_ports": [1984],
  "api_paths": ["/api/v1", "/runs", "/datasets", "/deployments", "/traces"],
  "auth_default": "api_key",
  "auth_config_env": [
    "LANGCHAIN_API_KEY",
    "LANGCHAIN_TRACING_V2",
    "LANGSMITH_ENDPOINT"
  ],
  "default_creds": [],
  "install_tell": "SaaS primary — self-hosted via Docker Compose on port 1984",
  "misconfig_patterns": [
    "LANGCHAIN_API_KEY committed to source code repositories",
    "Traces contain unmasked PII — full conversation history with user data",
    "Datasets contain reference answers — training data exposure",
    "LANGCHAIN_TRACING_V2=true in production without key rotation"
  ],
  "fingerprint": {
    "passive": [
      "port:1984 http.html:\"langsmith\"",
      "http.html:\"langsmith\""
    ],
    "active_probe": {
      "path": "/api/v1",
      "method": "GET",
      "response_markers": ["langsmith"],
      "false_positive_check": "401 response headers should identify LangSmith API"
    }
  },
  "shodan_dorks": {
    "basic": "\"langsmith\" port:1984",
    "strict": "port:1984 http.html:\"langsmith\"",
    "version": "port:1984 http.html:\"langsmith\" http.html:\"version\""
  },
  "deployment_tells": [
    "LANGCHAIN_API_KEY in environment",
    "Traces contain full conversation history including system prompts",
    "Dataset endpoint contains reference answers"
  ],
  "pivot_paths": [
    "LANGCHAIN_API_KEY in env → direct LangSmith API access to all traces",
    "Trace data → system prompts + user conversations + agent tool calls",
    "Dataset endpoint → model training data + expected outputs"
  ],
  "vulnerabilities": [],
  "sources": [
    "Learning LangChain (9781098167271) ch09",
    "Learning LangChain (9781098167271) ch10"
  ]
}
```

- [ ] **Step 18: Verify all 17 files parse as valid JSON**

```bash
for f in platforms/*.json; do
  python3 -c "import json,sys; json.load(open('$f'))" && echo "OK: $f" || echo "FAIL: $f"
done
```

Expected: `OK: platforms/*.json` for all 17 files.

- [ ] **Step 19: Commit**

```bash
git add platforms/
git commit -m "feat: add 17-platform AI/ML intelligence corpus"
```

---

### Task 4: Output formatters

**Files:**
- Create: `internal/output/output.go`
- Create: `internal/output/output_test.go`

- [ ] **Step 1: Write failing formatter tests**

Create `internal/output/output_test.go`:

```go
package output

import (
	"strings"
	"testing"

	"github.com/Nicholas-Kloster/tome/internal/corpus"
)

var testPlatform = corpus.Platform{
	Platform:    "weaviate",
	DisplayName: "Weaviate",
	Category:    "vector_db",
	DefaultPorts: []int{8080, 50051},
	AuthDefault: "none",
	ShodanDorks: corpus.ShodanDorks{
		Basic:   "port:8080 \"weaviate\"",
		Strict:  "product:Weaviate port:8080",
		Version: "product:Weaviate http.html:\"v1/meta\"",
	},
	MisconfigPatterns: []string{"GraphQL introspection not disabled"},
	PivotPaths:        []string{"GET /v1/objects → record dump"},
	Sources:           []string{"Learning LangChain (9781098167271) ch02"},
}

func TestFormatProfileTable(t *testing.T) {
	out := FormatProfile(testPlatform, "table")
	if !strings.Contains(out, "Weaviate") {
		t.Error("table output missing DisplayName")
	}
	if !strings.Contains(out, "8080") {
		t.Error("table output missing port")
	}
	if !strings.Contains(out, "NONE") {
		t.Error("table output missing auth_default")
	}
	if !strings.Contains(out, "product:Weaviate port:8080") {
		t.Error("table output missing strict dork")
	}
}

func TestFormatProfileJSON(t *testing.T) {
	out := FormatProfile(testPlatform, "json")
	if !strings.Contains(out, `"platform"`) {
		t.Error("json output missing platform field")
	}
	if !strings.Contains(out, `"weaviate"`) {
		t.Error("json output missing platform value")
	}
}

func TestFormatListTable(t *testing.T) {
	out := FormatList([]corpus.Platform{testPlatform}, "table")
	if !strings.Contains(out, "weaviate") {
		t.Error("list table missing platform name")
	}
	if !strings.Contains(out, "vector_db") {
		t.Error("list table missing category")
	}
}

func TestFormatDorks(t *testing.T) {
	if got := FormatDorks(testPlatform, "strict"); got != "product:Weaviate port:8080" {
		t.Errorf("FormatDorks strict = %q", got)
	}
	if got := FormatDorks(testPlatform, "basic"); got != "port:8080 \"weaviate\"" {
		t.Errorf("FormatDorks basic = %q", got)
	}
	if got := FormatDorks(testPlatform, "version"); got != "product:Weaviate http.html:\"v1/meta\"" {
		t.Errorf("FormatDorks version = %q", got)
	}
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test ./internal/output/ -v
```

Expected: FAIL — `undefined: FormatProfile`

- [ ] **Step 3: Write output.go**

Create `internal/output/output.go`:

```go
package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Nicholas-Kloster/tome/internal/corpus"
)

// FormatProfile renders a full platform profile in the requested format.
func FormatProfile(p corpus.Platform, format string) string {
	switch format {
	case "json":
		b, _ := json.MarshalIndent(p, "", "  ")
		return string(b)
	case "csv":
		return profileCSV(p)
	default:
		return profileTable(p)
	}
}

// FormatList renders all platforms as a summary list.
func FormatList(platforms []corpus.Platform, format string) string {
	switch format {
	case "json":
		b, _ := json.MarshalIndent(platforms, "", "  ")
		return string(b)
	case "csv":
		return listCSV(platforms)
	default:
		return listTable(platforms)
	}
}

// FormatFindings renders scan findings in the requested format.
func FormatFindings(findings []corpus.Finding, format string) string {
	if format == "json" {
		var sb strings.Builder
		for _, f := range findings {
			b, _ := json.MarshalIndent(f, "", "  ")
			sb.WriteString(string(b))
			sb.WriteByte('\n')
		}
		return sb.String()
	}
	var sb strings.Builder
	for _, f := range findings {
		sb.WriteString(findingTable(f))
		sb.WriteByte('\n')
	}
	return sb.String()
}

// FormatDorks returns the dork string for the given tier (basic/strict/version).
func FormatDorks(p corpus.Platform, tier string) string {
	switch tier {
	case "basic":
		return p.ShodanDorks.Basic
	case "version":
		return p.ShodanDorks.Version
	default:
		return p.ShodanDorks.Strict
	}
}

// FormatProbeConfig renders a ProbeConfig as JSON (always JSON — machine target).
func FormatProbeConfig(cfg corpus.ProbeConfig) string {
	b, _ := json.MarshalIndent(cfg, "", "  ")
	return string(b)
}

func profileTable(p corpus.Platform) string {
	ports := make([]string, len(p.DefaultPorts))
	for i, port := range p.DefaultPorts {
		ports[i] = fmt.Sprintf("%d", port)
	}
	misconfig := ""
	if len(p.MisconfigPatterns) > 0 {
		misconfig = p.MisconfigPatterns[0]
		if len(p.MisconfigPatterns) > 1 {
			misconfig += fmt.Sprintf(" (+%d more)", len(p.MisconfigPatterns)-1)
		}
	}
	pivot := ""
	if len(p.PivotPaths) > 0 {
		pivot = p.PivotPaths[0]
	}
	return fmt.Sprintf(
		"Platform:        %s\n"+
			"Category:        %s\n"+
			"Default ports:   %s\n"+
			"Auth default:    %s\n"+
			"Shodan (strict): %s\n"+
			"Key misconfig:   %s\n"+
			"Pivot:           %s\n"+
			"Sources:         %s\n",
		p.DisplayName,
		p.Category,
		strings.Join(ports, ", "),
		strings.ToUpper(p.AuthDefault),
		p.ShodanDorks.Strict,
		misconfig,
		pivot,
		strings.Join(p.Sources, "; "),
	)
}

func listTable(platforms []corpus.Platform) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%-20s %-18s %-10s %s\n", "NAME", "CATEGORY", "AUTH", "PORTS"))
	sb.WriteString(strings.Repeat("-", 70) + "\n")
	for _, p := range platforms {
		ports := make([]string, len(p.DefaultPorts))
		for i, port := range p.DefaultPorts {
			ports[i] = fmt.Sprintf("%d", port)
		}
		sb.WriteString(fmt.Sprintf("%-20s %-18s %-10s %s\n",
			p.Platform, p.Category, p.AuthDefault, strings.Join(ports, ", ")))
	}
	return sb.String()
}

func findingTable(f corpus.Finding) string {
	verified := "no"
	if f.Verified {
		verified = "yes"
	}
	return fmt.Sprintf(
		"Platform:   %s\nIP:         %s\nPort:       %d\nConfidence: %.2f\nVerified:   %s\nMethod:     %s\n",
		f.Platform, f.IP, f.Port, f.Confidence, verified, f.DiscoveryMethod,
	)
}

func profileCSV(p corpus.Platform) string {
	ports := make([]string, len(p.DefaultPorts))
	for i, port := range p.DefaultPorts {
		ports[i] = fmt.Sprintf("%d", port)
	}
	var sb strings.Builder
	w := csv.NewWriter(&sb)
	_ = w.Write([]string{"field", "value"})
	_ = w.Write([]string{"platform", p.Platform})
	_ = w.Write([]string{"display_name", p.DisplayName})
	_ = w.Write([]string{"category", p.Category})
	_ = w.Write([]string{"default_ports", strings.Join(ports, ";")})
	_ = w.Write([]string{"auth_default", p.AuthDefault})
	_ = w.Write([]string{"shodan_strict", p.ShodanDorks.Strict})
	w.Flush()
	return sb.String()
}

func listCSV(platforms []corpus.Platform) string {
	var sb strings.Builder
	w := csv.NewWriter(&sb)
	_ = w.Write([]string{"platform", "display_name", "category", "auth_default", "ports", "shodan_strict"})
	for _, p := range platforms {
		ports := make([]string, len(p.DefaultPorts))
		for i, port := range p.DefaultPorts {
			ports[i] = fmt.Sprintf("%d", port)
		}
		_ = w.Write([]string{
			p.Platform, p.DisplayName, p.Category, p.AuthDefault,
			strings.Join(ports, ";"), p.ShodanDorks.Strict,
		})
	}
	w.Flush()
	return sb.String()
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/output/ -v
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/output/
git commit -m "feat: table/json/csv output formatters"
```

---

### Task 5: Root command and main.go

**Files:**
- Create: `main.go`
- Create: `cmd/root.go`

- [ ] **Step 1: Write main.go**

Create `main.go`:

```go
package main

import (
	"embed"

	"github.com/Nicholas-Kloster/tome/cmd"
	"github.com/Nicholas-Kloster/tome/internal/corpus"
)

//go:embed platforms/*.json
var platformFS embed.FS

func main() {
	corpus.Init(platformFS)
	cmd.Execute()
}
```

- [ ] **Step 2: Write cmd/root.go**

Create `cmd/root.go`:

```go
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var (
	formatFlag     string
	confidenceFlag float64
	dorkTierFlag   string
)

var rootCmd = &cobra.Command{
	Use:   "tome",
	Short: "Technical OSINT Mining Engine — AI/ML infrastructure intelligence",
	Long: `TOME embeds a book-derived intelligence corpus for AI/ML infrastructure platforms.
Given a platform name: Shodan dorks, probe configs, default credentials, misconfigs.
Given an IP: passive fingerprinting via Shodan API with optional active verification.`,
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&formatFlag, "format", "f", "", "output format: json|csv|table (default: table for tty, json for pipe)")
	rootCmd.PersistentFlags().Float64Var(&confidenceFlag, "confidence", 0.0, "filter findings below threshold (0.0–1.0)")
	rootCmd.PersistentFlags().StringVar(&dorkTierFlag, "dork-tier", "strict", "dork specificity: basic|strict|version")
}

// resolveFormat returns the active output format, defaulting to json when stdout is piped.
func resolveFormat() string {
	if formatFlag != "" {
		return formatFlag
	}
	fi, err := os.Stdout.Stat()
	if err == nil && (fi.Mode()&os.ModeCharDevice) != 0 {
		return "table"
	}
	return "json"
}
```

- [ ] **Step 3: Build to verify compilation**

```bash
go build ./...
```

Expected: compiles with no errors. No output.

- [ ] **Step 4: Smoke test**

```bash
./tome --help
```

Expected: usage text with `tome` and the three persistent flags listed.

- [ ] **Step 5: Commit**

```bash
git add main.go cmd/root.go
git commit -m "feat: cobra root command and main entry point"
```

---

### Task 6: `tome list`

**Files:**
- Create: `cmd/list.go`

- [ ] **Step 1: Write cmd/list.go**

Create `cmd/list.go`:

```go
package cmd

import (
	"fmt"

	"github.com/Nicholas-Kloster/tome/internal/corpus"
	"github.com/Nicholas-Kloster/tome/internal/output"
	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all known platforms in the corpus",
	RunE:  runList,
}

func init() {
	rootCmd.AddCommand(listCmd)
}

func runList(cmd *cobra.Command, _ []string) error {
	platforms, err := corpus.ListPlatforms()
	if err != nil {
		return err
	}
	fmt.Fprint(cmd.OutOrStdout(), output.FormatList(platforms, resolveFormat()))
	return nil
}
```

- [ ] **Step 2: Build and run**

```bash
go build -o tome . && ./tome list
```

Expected: table with all 17 platforms — NAME, CATEGORY, AUTH, PORTS columns.

- [ ] **Step 3: Test JSON output**

```bash
./tome list --format json | python3 -c "import json,sys; data=json.load(sys.stdin); print(len(data), 'platforms')"
```

Expected: `17 platforms`

- [ ] **Step 4: Commit**

```bash
git add cmd/list.go
git commit -m "feat: tome list command"
```

---

### Task 7: `tome profile`

**Files:**
- Create: `cmd/profile.go`

- [ ] **Step 1: Write cmd/profile.go**

Create `cmd/profile.go`:

```go
package cmd

import (
	"fmt"

	"github.com/Nicholas-Kloster/tome/internal/corpus"
	"github.com/Nicholas-Kloster/tome/internal/output"
	"github.com/spf13/cobra"
)

var profileCmd = &cobra.Command{
	Use:   "profile <platform>",
	Short: "Full OSINT profile for a platform — ports, paths, auth, dorks, misconfigs",
	Args:  cobra.ExactArgs(1),
	RunE:  runProfile,
}

func init() {
	rootCmd.AddCommand(profileCmd)
}

func runProfile(cmd *cobra.Command, args []string) error {
	p, err := corpus.LoadPlatform(args[0])
	if err != nil {
		return err
	}
	fmt.Fprint(cmd.OutOrStdout(), output.FormatProfile(p, resolveFormat()))
	return nil
}
```

- [ ] **Step 2: Build and test**

```bash
go build -o tome . && ./tome profile weaviate
```

Expected:
```
Platform:        Weaviate
Category:        vector_db
Default ports:   8080, 50051
Auth default:    NONE
Shodan (strict): product:Weaviate port:8080
Key misconfig:   GraphQL introspection not disabled (+3 more)
Pivot:           GET /v1/schema → class definitions → query records via GraphQL without auth
Sources:         Learning LangChain (9781098167271) ch02; AI-Native LLM Security (9781836203759) ch04
```

- [ ] **Step 3: Test unknown platform error**

```bash
./tome profile notaplatform
```

Expected: `Error: unknown platform "notaplatform"`

- [ ] **Step 4: Test JSON output**

```bash
./tome profile ollama --format json | python3 -c "import json,sys; p=json.load(sys.stdin); print(p['platform'], p['default_ports'])"
```

Expected: `ollama [11434]`

- [ ] **Step 5: Commit**

```bash
git add cmd/profile.go
git commit -m "feat: tome profile command"
```

---

### Task 8: `tome dorks`

**Files:**
- Create: `cmd/dorks.go`

- [ ] **Step 1: Write cmd/dorks.go**

Create `cmd/dorks.go`:

```go
package cmd

import (
	"fmt"

	"github.com/Nicholas-Kloster/tome/internal/corpus"
	"github.com/Nicholas-Kloster/tome/internal/output"
	"github.com/spf13/cobra"
)

var dorksCmd = &cobra.Command{
	Use:   "dorks <platform>",
	Short: "Shodan dorks for a platform, formatted for paste or JAXEN import",
	Args:  cobra.ExactArgs(1),
	RunE:  runDorks,
}

func init() {
	rootCmd.AddCommand(dorksCmd)
}

func runDorks(cmd *cobra.Command, args []string) error {
	p, err := corpus.LoadPlatform(args[0])
	if err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), output.FormatDorks(p, dorkTierFlag))
	return nil
}
```

- [ ] **Step 2: Build and test all tiers**

```bash
go build -o tome .
./tome dorks weaviate
./tome dorks weaviate --dork-tier basic
./tome dorks weaviate --dork-tier version
```

Expected outputs:
```
product:Weaviate port:8080
port:8080 "weaviate"
product:Weaviate http.html:"v1/meta"
```

- [ ] **Step 3: Test JAXEN pipe compatibility**

```bash
# Simulate piping all strict dorks to a file
for platform in $(./tome list --format json | python3 -c "import json,sys; [print(p['platform']) for p in json.load(sys.stdin)]"); do
  ./tome dorks $platform
done
```

Expected: 17 dork strings, one per line.

- [ ] **Step 4: Commit**

```bash
git add cmd/dorks.go
git commit -m "feat: tome dorks command with tier support"
```

---

### Task 9: `tome probe`

**Files:**
- Create: `cmd/probe.go`

- [ ] **Step 1: Write cmd/probe.go**

Create `cmd/probe.go`:

```go
package cmd

import (
	"fmt"

	"github.com/Nicholas-Kloster/tome/internal/corpus"
	"github.com/Nicholas-Kloster/tome/internal/output"
	"github.com/spf13/cobra"
)

var probeCmd = &cobra.Command{
	Use:   "probe <platform>",
	Short: "aimap-compatible probe config JSON for a platform",
	Args:  cobra.ExactArgs(1),
	RunE:  runProbe,
}

func init() {
	rootCmd.AddCommand(probeCmd)
}

func runProbe(cmd *cobra.Command, args []string) error {
	p, err := corpus.LoadPlatform(args[0])
	if err != nil {
		return err
	}
	port := 0
	if len(p.DefaultPorts) > 0 {
		port = p.DefaultPorts[0]
	}
	cfg := corpus.ProbeConfig{
		Platform:            p.Platform,
		Port:                port,
		ProbePath:           p.Fingerprint.ActiveProbe.Path,
		ResponseMarkers:     p.Fingerprint.ActiveProbe.ResponseMarkers,
		ConfidenceThreshold: 0.90,
	}
	fmt.Fprintln(cmd.OutOrStdout(), output.FormatProbeConfig(cfg))
	return nil
}
```

- [ ] **Step 2: Build and test**

```bash
go build -o tome . && ./tome probe weaviate
```

Expected:
```json
{
  "platform": "weaviate",
  "port": 8080,
  "probe_path": "/v1/meta",
  "response_markers": ["\"version\"", "\"modules\"", "\"hostname\""],
  "confidence_threshold": 0.9
}
```

- [ ] **Step 3: Verify aimap import compatibility**

```bash
./tome probe ollama | python3 -c "
import json, sys
cfg = json.load(sys.stdin)
assert 'platform' in cfg
assert 'port' in cfg
assert 'probe_path' in cfg
assert 'response_markers' in cfg
assert 'confidence_threshold' in cfg
print('aimap schema valid')
"
```

Expected: `aimap schema valid`

- [ ] **Step 4: Commit**

```bash
git add cmd/probe.go
git commit -m "feat: tome probe command — aimap-compatible JSON output"
```

---

### Task 10: Passive fingerprint engine

**Files:**
- Create: `internal/fingerprint/passive.go`
- Create: `internal/fingerprint/fingerprint_test.go`

- [ ] **Step 1: Write failing passive fingerprint tests**

Create `internal/fingerprint/fingerprint_test.go`:

```go
package fingerprint

import (
	"testing"

	"github.com/Nicholas-Kloster/tome/internal/corpus"
)

var weaviatePlatform = corpus.Platform{
	Platform:     "weaviate",
	DefaultPorts: []int{8080, 50051},
	AuthDefault:  "none",
	Fingerprint: corpus.Fingerprint{
		Passive: []string{
			"product:Weaviate",
			"http.html:\"/v1/graphql\"",
			"port:8080",
		},
	},
}

func TestMatchPassiveFullMatch(t *testing.T) {
	host := ShodanHost{
		IPStr: "1.2.3.4",
		Ports: []int{8080, 50051},
		Data: []ShodanData{
			{
				Port:    8080,
				Product: "Weaviate",
				HTTP: ShodanHTTP{
					HTML:  "visit /v1/graphql for the explorer",
					Title: "Weaviate",
				},
			},
		},
	}
	conf := MatchPassive(weaviatePlatform, host)
	if conf != 1.0 {
		t.Errorf("full match confidence = %.2f, want 1.0", conf)
	}
}

func TestMatchPassivePartialMatch(t *testing.T) {
	host := ShodanHost{
		IPStr: "1.2.3.4",
		Ports: []int{8080},
		Data: []ShodanData{
			{Port: 8080, Product: "Weaviate"},
		},
	}
	conf := MatchPassive(weaviatePlatform, host)
	// product:Weaviate and port:8080 match; http.html does not
	if conf < 0.5 || conf >= 1.0 {
		t.Errorf("partial match confidence = %.2f, want ~0.67", conf)
	}
}

func TestMatchPassiveNoMatch(t *testing.T) {
	host := ShodanHost{
		IPStr: "1.2.3.4",
		Ports: []int{3000},
		Data:  []ShodanData{{Port: 3000, Product: "nginx"}},
	}
	conf := MatchPassive(weaviatePlatform, host)
	if conf != 0.0 {
		t.Errorf("no match confidence = %.2f, want 0.0", conf)
	}
}

func TestMatchFilterPort(t *testing.T) {
	host := ShodanHost{Ports: []int{8080, 443}}
	if !matchFilter("port:8080", host) {
		t.Error("port:8080 should match host with port 8080")
	}
	if matchFilter("port:9999", host) {
		t.Error("port:9999 should not match host without that port")
	}
}

func TestMatchFilterProduct(t *testing.T) {
	host := ShodanHost{Data: []ShodanData{{Product: "Weaviate"}}}
	if !matchFilter("product:Weaviate", host) {
		t.Error("product:Weaviate should match")
	}
	if matchFilter("product:ChromaDB", host) {
		t.Error("product:ChromaDB should not match Weaviate host")
	}
}

func TestMatchFilterHTMLCaseInsensitive(t *testing.T) {
	host := ShodanHost{Data: []ShodanData{{HTTP: ShodanHTTP{HTML: "Visit /V1/GRAPHQL for explorer"}}}}
	if !matchFilter("http.html:\"/v1/graphql\"", host) {
		t.Error("html match should be case-insensitive")
	}
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test ./internal/fingerprint/ -v
```

Expected: FAIL — `undefined: ShodanHost`, `undefined: MatchPassive`

- [ ] **Step 3: Write passive.go**

Create `internal/fingerprint/passive.go`:

```go
package fingerprint

import (
	"strconv"
	"strings"

	"github.com/Nicholas-Kloster/tome/internal/corpus"
)

// ShodanHost is the relevant subset of the Shodan host API response.
type ShodanHost struct {
	IPStr string       `json:"ip_str"`
	Ports []int        `json:"ports"`
	Data  []ShodanData `json:"data"`
}

// ShodanData is one service banner entry from the Shodan host response.
type ShodanData struct {
	Port      int        `json:"port"`
	Product   string     `json:"product"`
	Transport string     `json:"transport"`
	Data      string     `json:"data"`
	HTTP      ShodanHTTP `json:"http"`
}

// ShodanHTTP holds parsed HTTP fields from Shodan.
type ShodanHTTP struct {
	HTML    string `json:"html"`
	Title   string `json:"title"`
	Headers string `json:"headers"`
}

// MatchPassive scores how well a Shodan host matches a platform's passive fingerprint.
// Returns confidence in [0.0, 1.0]. Zero if no passive filters are defined.
func MatchPassive(p corpus.Platform, host ShodanHost) float64 {
	if len(p.Fingerprint.Passive) == 0 {
		return 0.0
	}
	matched := 0
	for _, filter := range p.Fingerprint.Passive {
		if matchFilter(filter, host) {
			matched++
		}
	}
	return float64(matched) / float64(len(p.Fingerprint.Passive))
}

// matchFilter parses a Shodan filter string and checks it against the host data.
// Supported fields: product, http.html, http.title, http.headers, port.
// Values are matched case-insensitively; quotes around values are stripped.
func matchFilter(filter string, host ShodanHost) bool {
	field, value, ok := strings.Cut(filter, ":")
	if !ok {
		return hostContains(host, filter)
	}
	value = strings.Trim(value, `"`)
	valueLower := strings.ToLower(value)

	switch field {
	case "port":
		port, err := strconv.Atoi(value)
		if err != nil {
			return false
		}
		for _, p := range host.Ports {
			if p == port {
				return true
			}
		}
		return false

	case "product":
		for _, d := range host.Data {
			if strings.Contains(strings.ToLower(d.Product), valueLower) {
				return true
			}
		}
		return false

	case "http.html":
		for _, d := range host.Data {
			if strings.Contains(strings.ToLower(d.HTTP.HTML), valueLower) {
				return true
			}
		}
		return false

	case "http.title":
		for _, d := range host.Data {
			if strings.Contains(strings.ToLower(d.HTTP.Title), valueLower) {
				return true
			}
		}
		return false

	case "http.headers":
		for _, d := range host.Data {
			if strings.Contains(strings.ToLower(d.HTTP.Headers), valueLower) {
				return true
			}
		}
		return false
	}

	return hostContains(host, valueLower)
}

func hostContains(host ShodanHost, s string) bool {
	s = strings.ToLower(s)
	for _, d := range host.Data {
		if strings.Contains(strings.ToLower(d.Data), s) ||
			strings.Contains(strings.ToLower(d.Product), s) ||
			strings.Contains(strings.ToLower(d.HTTP.HTML), s) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/fingerprint/ -v
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/fingerprint/passive.go internal/fingerprint/fingerprint_test.go
git commit -m "feat: passive Shodan fingerprint engine"
```

---

### Task 11: Active probe

**Files:**
- Create: `internal/fingerprint/active.go`
- Modify: `internal/fingerprint/fingerprint_test.go` (add active probe tests)

- [ ] **Step 1: Write failing active probe tests**

Add to `internal/fingerprint/fingerprint_test.go`:

```go
import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProbeActiveSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"version":"1.3.1","modules":["text2vec-openai"],"hostname":"weaviate-0"}`)
	}))
	defer srv.Close()

	probe := corpus.ActiveProbe{
		Path:            "/v1/meta",
		Method:          "GET",
		ResponseMarkers: []string{"version", "modules", "hostname"},
	}

	verified, version := ProbeActive(srv.Listener.Addr().String(), probe)
	if !verified {
		t.Error("expected verified=true")
	}
	if version != "1.3.1" {
		t.Errorf("version = %q, want 1.3.1", version)
	}
}

func TestProbeActiveMarkerMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"ok"}`)
	}))
	defer srv.Close()

	probe := corpus.ActiveProbe{
		Path:            "/v1/meta",
		Method:          "GET",
		ResponseMarkers: []string{"version", "modules"},
	}

	verified, _ := ProbeActive(srv.Listener.Addr().String(), probe)
	if verified {
		t.Error("expected verified=false when markers missing")
	}
}
```

- [ ] **Step 2: Run to confirm failure**

```bash
go test ./internal/fingerprint/ -v -run TestProbeActive
```

Expected: FAIL — `undefined: ProbeActive`

- [ ] **Step 3: Write active.go**

Create `internal/fingerprint/active.go`:

```go
package fingerprint

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Nicholas-Kloster/tome/internal/corpus"
)

var versionRE = regexp.MustCompile(`"version"\s*:\s*"([^"]+)"`)

// ProbeActive performs an HTTP request to addr+path and checks for response markers.
// addr is host:port (no scheme). Returns (verified, version).
// All markers must be present in the response body to return verified=true.
func ProbeActive(addr string, probe corpus.ActiveProbe) (bool, string) {
	url := fmt.Sprintf("http://%s%s", addr, probe.Path)
	method := probe.Method
	if method == "" {
		method = "GET"
	}

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return false, ""
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, ""
	}
	bodyStr := string(body)

	for _, marker := range probe.ResponseMarkers {
		marker = strings.Trim(marker, `"`)
		if !strings.Contains(bodyStr, marker) {
			return false, ""
		}
	}

	return true, extractVersion(bodyStr)
}

func extractVersion(body string) string {
	m := versionRE.FindStringSubmatch(body)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}
```

- [ ] **Step 4: Run all fingerprint tests**

```bash
go test ./internal/fingerprint/ -v
```

Expected: all PASS including `TestProbeActiveSuccess` and `TestProbeActiveMarkerMissing`.

- [ ] **Step 5: Commit**

```bash
git add internal/fingerprint/active.go internal/fingerprint/fingerprint_test.go
git commit -m "feat: active HTTP probe with version extraction"
```

---

### Task 12: `tome scan`

**Files:**
- Create: `cmd/scan.go`

- [ ] **Step 1: Write cmd/scan.go**

Create `cmd/scan.go`:

```go
package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/Nicholas-Kloster/tome/internal/corpus"
	"github.com/Nicholas-Kloster/tome/internal/fingerprint"
	"github.com/Nicholas-Kloster/tome/internal/output"
	"github.com/spf13/cobra"
)

var activeFlag bool

var scanCmd = &cobra.Command{
	Use:   "scan <ip>",
	Short: "Fingerprint a live target via Shodan lookup (passive) or direct probe (--active)",
	Args:  cobra.ExactArgs(1),
	RunE:  runScan,
}

func init() {
	scanCmd.Flags().BoolVar(&activeFlag, "active", false, "enable active probing (sends traffic to target; requires authorization)")
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	ip := args[0]

	if activeFlag {
		fmt.Fprintln(os.Stderr, "\nWARNING: Active mode sends traffic to the target and may be detected.")
		fmt.Fprintln(os.Stderr, "Only use with explicit written authorization from the target owner.")
		fmt.Fprint(os.Stderr, "Press Enter to continue or Ctrl+C to abort: ")
		bufio.NewReader(os.Stdin).ReadString('\n')
	}

	platforms, err := corpus.ListPlatforms()
	if err != nil {
		return err
	}

	host, err := fetchShodanHost(ip)
	if err != nil {
		return fmt.Errorf("Shodan lookup failed (set SHODAN_API_KEY): %w", err)
	}

	var findings []corpus.Finding
	for _, p := range platforms {
		confidence := fingerprint.MatchPassive(p, host)
		if confidence < confidenceFlag {
			continue
		}
		port := 0
		if len(p.DefaultPorts) > 0 {
			port = p.DefaultPorts[0]
		}

		f := corpus.Finding{
			Platform:        p.Platform,
			IP:              ip,
			Port:            port,
			DiscoveryMethod: "shodan_passive",
			AuthRequired:    p.AuthDefault != "none",
			Verified:        false,
			Confidence:      confidence,
			ActiveProbeUsed: false,
		}
		if confidence > 0 {
			f.PivotPaths = p.PivotPaths
		}

		if activeFlag && confidence > 0 && port > 0 {
			addr := fmt.Sprintf("%s:%d", ip, port)
			verified, version := fingerprint.ProbeActive(addr, p.Fingerprint.ActiveProbe)
			f.Verified = verified
			f.Version = version
			f.ActiveProbeUsed = true
			f.DiscoveryMethod = "shodan_passive+active_probe"
			if verified {
				f.Confidence = 0.95
			}
		}

		if f.Confidence >= confidenceFlag {
			findings = append(findings, f)
		}
	}

	fmt.Fprint(cmd.OutOrStdout(), output.FormatFindings(findings, resolveFormat()))
	return nil
}

func fetchShodanHost(ip string) (fingerprint.ShodanHost, error) {
	key := os.Getenv("SHODAN_API_KEY")
	if key == "" {
		return fingerprint.ShodanHost{}, fmt.Errorf("SHODAN_API_KEY not set")
	}
	resp, err := http.Get(fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", ip, key))
	if err != nil {
		return fingerprint.ShodanHost{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fingerprint.ShodanHost{}, err
	}
	var host fingerprint.ShodanHost
	return host, json.Unmarshal(body, &host)
}
```

- [ ] **Step 2: Build**

```bash
go build -o tome .
```

Expected: compiles cleanly.

- [ ] **Step 3: Test passive scan (requires SHODAN_API_KEY)**

```bash
# Replace with a known Weaviate IP from a prior JAXEN harvest
SHODAN_API_KEY=your_key ./tome scan 203.0.113.42
```

Expected: JSON finding output with `"platform": "weaviate"` and `"confidence": 0.67` or higher.

- [ ] **Step 4: Test missing API key error**

```bash
unset SHODAN_API_KEY && ./tome scan 1.2.3.4
```

Expected: `Error: Shodan lookup failed (set SHODAN_API_KEY): SHODAN_API_KEY not set`

- [ ] **Step 5: Build final binary**

```bash
go build -ldflags="-s -w" -o tome .
```

Expected: stripped binary at `./tome`.

- [ ] **Step 6: Full smoke test — all commands**

```bash
./tome list | head -5
./tome profile ollama
./tome dorks weaviate
./tome dorks n8n --dork-tier basic
./tome probe chromadb
./tome --help
```

Expected: all produce correct output with no errors.

- [ ] **Step 7: Commit**

```bash
git add cmd/scan.go
git commit -m "feat: tome scan — Shodan passive + active probe"
```

---

### Task 13: GitHub Actions release CI

**Files:**
- Create: `.github/workflows/release.yml`

- [ ] **Step 1: Create .github/workflows/release.yml**

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  build:
    name: Build ${{ matrix.goos }}/${{ matrix.goarch }}
    runs-on: ubuntu-latest
    strategy:
      matrix:
        include:
          - goos: linux
            goarch: amd64
          - goos: linux
            goarch: arm64
          - goos: darwin
            goarch: amd64
          - goos: darwin
            goarch: arm64
          - goos: windows
            goarch: amd64

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: '1.21'

      - name: Build
        env:
          GOOS: ${{ matrix.goos }}
          GOARCH: ${{ matrix.goarch }}
          CGO_ENABLED: '0'
        run: |
          EXT=""
          if [ "$GOOS" = "windows" ]; then EXT=".exe"; fi
          go build -ldflags="-s -w" -o "tome-${{ github.ref_name }}-${GOOS}-${GOARCH}${EXT}" .

      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: tome-${{ matrix.goos }}-${{ matrix.goarch }}
          path: tome-${{ github.ref_name }}-*

  release:
    needs: build
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/download-artifact@v4
        with:
          pattern: tome-*
          merge-multiple: true

      - name: Create release
        uses: softprops/action-gh-release@v2
        with:
          files: tome-*
          generate_release_notes: true
```

- [ ] **Step 2: Commit**

```bash
git add .github/
git commit -m "ci: cross-platform release binaries on tag push"
```

- [ ] **Step 3: Tag and push to trigger release**

```bash
git tag v0.1.0
git push origin main --tags
```

Expected: GitHub Actions runs 5 build jobs, produces release at `github.com/Nicholas-Kloster/tome/releases/tag/v0.1.0`.

---

## Self-Review Checklist

**Spec coverage:**
- [x] `tome profile <platform>` → Task 7
- [x] `tome dorks <platform>` with `--dork-tier` → Tasks 8, 5
- [x] `tome probe <platform>` → Task 9
- [x] `tome list` → Task 6
- [x] `tome scan <ip> [--active]` → Tasks 10, 11, 12
- [x] `--format json|csv|table` → Tasks 4, 5
- [x] `--confidence` flag → Tasks 5, 12
- [x] Passive/active split with `--active` warning gate → Task 12
- [x] 17 platform corpus files → Task 3
- [x] Platform corpus schema (all fields) → Tasks 1, 3
- [x] aimap-compatible probe config output → Task 9
- [x] `go install` distribution → Task 13
- [x] Research provenance via `sources` field → Task 3 (all JSON files include sources)

**No gaps found.**

**Type consistency:**
- `corpus.Platform`, `corpus.Cred`, `corpus.Fingerprint`, `corpus.ActiveProbe`, `corpus.ShodanDorks`, `corpus.Finding`, `corpus.ProbeConfig` defined in Task 1, used identically in Tasks 4, 9, 10, 11, 12.
- `fingerprint.ShodanHost`, `fingerprint.ShodanData`, `fingerprint.ShodanHTTP` defined in Task 10, used in Task 12's `fetchShodanHost`.
- `fingerprint.MatchPassive(corpus.Platform, fingerprint.ShodanHost) float64` — signature matches usage in Task 12.
- `fingerprint.ProbeActive(addr string, probe corpus.ActiveProbe) (bool, string)` — signature matches usage in Task 12.
- `output.FormatProfile`, `FormatList`, `FormatFindings`, `FormatDorks`, `FormatProbeConfig` defined in Task 4, imported identically in Tasks 6, 7, 8, 9, 12.
