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
	if len(p.Fingerprint.ActiveProbe.ResponseMarkers) != 2 {
		t.Errorf("response_markers len = %d, want 2", len(p.Fingerprint.ActiveProbe.ResponseMarkers))
	}
}

func TestCredUnmarshal(t *testing.T) {
	raw := `{"user":"admin","pass":"changeme","context":"basic auth"}`
	var c Cred
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if c.User != "admin" || c.Pass != "changeme" || c.Context != "basic auth" {
		t.Errorf("got %+v", c)
	}
}
