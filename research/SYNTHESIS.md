# TOME — O'Reilly Research Synthesis
# 8 chapters · 4 books · 530K chars

## Platforms with solid OSINT coverage

### Ollama
- port: 11434
- api_paths: /api/generate, /api/chat, /api/tags, /api/show
- auth_default: none (localhost-only by default)
- auth_config_env: OLLAMA_HOST (controls binding address)
- misconfig: OLLAMA_HOST=0.0.0.0 exposes to all interfaces
- shodan_dorks: "ollama" port:11434, http.title:"Ollama"
- source: GenAI-K8s ch01

### vLLM
- port: 8080
- api_paths: /v1/completions, /v1/chat/completions, /metrics
- auth_default: none
- auth_config_env: HF_TOKEN (optional, for model downloads)
- misconfig: binding to 0.0.0.0 without auth, default gpu_memory_utilization=0.9
- deployment_tells: launch flag --port=8080 --model=/mnt/models, logs "Loading model weights", "model_runner.py" in log output
- shodan_dorks: "vllm" port:8080, "model_runner.py" port:8080
- source: GenAI-K8s ch01 (Example 1-4), ch04 (memory logs)

### TGI (Text Generation Inference)
- ports: 8080 (native API), 3000 (OpenAI-compat)
- api_paths: /generate_stream, /v1/chat/completions
- auth_default: none
- misconfig: dual-port exposure (native + OpenAI format on different ports), no auth on either
- deployment_tells: "text-generation-launcher" process name, Hugging Face DLC images
- shodan_dorks: "text-generation-launcher" port:8080, "generate_stream"
- source: GenAI-K8s ch01 (Example 1-5)

### llama.cpp (server mode)
- port: 8000
- api_paths: /v1/completions, /v1/chat/completions
- auth_default: none
- deployment_tells: GGUF model files, "python -m llama_cpp.server", quantization level in logs (Q4_0, Q5_K, Q8_0)
- source: GenAI-K8s ch01 (Example 1-6), Hands-On LLM Serving ch08

### SGLang
- port: 8000
- api_paths: /v1/completions, /v1/chat/completions (+ native SGLang structured-gen API)
- auth_default: none
- deployment_tells: "python -m sglang.launch_server --model-path", RadixAttention prefix caching
- source: GenAI-K8s ch01 (Example 1-7)

### Ray Serve
- ports: 8000 (serving), 8265 (dashboard — no auth)
- api_paths: custom per deployment
- auth_default: none
- misconfig: Ray dashboard (8265) publicly accessible, no built-in auth
- deployment_tells: RayService CR in K8s, Ray cluster head node logs
- shodan_dorks: port:8265 "Ray Dashboard"
- source: GenAI-K8s ch01 (Examples 1-13/1-14)

### NVIDIA NIM
- port: 8000
- api_paths: /v1/completions, /v1/chat/completions
- auth_default: none
- deployment_tells: pre-optimized container per model family, PersistentVolume model caching
- source: GenAI-K8s ch01 (NVIDIA NIM section)

### KServe
- ports: inherits from runtime (vLLM: 8080, TGI: 8080)
- api_paths: /v1/models, /v1/completions, /health
- auth_default: none (Kubernetes RBAC must be added externally)
- deployment_tells: ServingRuntime + InferenceService CRDs in Kubernetes
- source: GenAI-K8s ch01 (Examples 1-10, 1-11)

## Cross-platform patterns

### Auth-on-default is ABSENT across all open-source inference servers
vLLM, TGI, llama.cpp, SGLang, Ray Serve, KServe — none enforce auth by default.
Auth is always an external add-on (API gateway, nginx, Envoy, Kubernetes RBAC).
This matches and confirms the NuClide auth-on-default thesis.

### OpenAI-compatible API is universal
/v1/chat/completions and /v1/completions are implemented by every major framework.
This means a single probe works across vLLM, TGI, llama.cpp, SGLang, NIM.

### Port range 8000-8080 covers ~90% of open-source serving
Default ports cluster tightly: 8000 (llama.cpp, SGLang, NIM, Ray Serve) and 8080 (vLLM, TGI, KServe).
Ollama is the outlier at 11434.

### Startup logs as fingerprint
vLLM: "Loading model weights", "INFO [model_runner.py", memory calculation lines
TGI: "text-generation-launcher", Flash Attention backend selection messages
Ray Serve: RayService cluster status logs

### Env var exposure vector
HF_TOKEN, HUGGING_FACE_HUB_TOKEN, MAX_BATCH_TOTAL_TOKENS, SM_NUM_GPUS — all appear in
Kubernetes pod specs, CloudWatch logs, and process listings. Sensitive config in plaintext.

## Deployment anti-patterns (from the books)
- Binding to 0.0.0.0 without external auth proxy (all frameworks)
- No rate limiting by default — unlimited token generation
- Ray dashboard (8265) open to internet
- GPU memory utilization at 0.99 on small VRAM → OOM DoS
- ReadWriteMany PVCs for model files (attacker can modify weights)
- KV cache prefix reuse creates timing side-channel across tenants

## Platforms with ZERO O'Reilly coverage (need separate research)
LiteLLM, OpenLLM, BentoML, MLflow (serving), Langfuse, LangSmith, W&B,
ChromaDB, Weaviate, Qdrant, Milvus, pgvector, Open WebUI, LlamaIndex,
n8n, Jupyter/JupyterHub, LocalAI

## Books researched
1. Generative AI on Kubernetes (9781098171919) — ch01 + ch04
2. LLM Engineer's Handbook (9781836200079) — ch10 + ch11
3. LLMOps (9781098154196) — ch06 + ch08
4. Hands-On LLM Serving and Optimization (9798341621480) — ch02 + ch08
