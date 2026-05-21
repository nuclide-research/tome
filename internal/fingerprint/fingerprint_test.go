package fingerprint

import (
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
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
	const want = 2.0 / 3.0
	if math.Abs(conf-want) > 1e-9 {
		t.Errorf("partial match confidence = %.4f, want %.4f", conf, want)
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

func TestMatchFilterHTMLContent(t *testing.T) {
	matching := ShodanHost{Data: []ShodanData{{HTTP: ShodanHTTP{HTML: "visit /v1/graphql for explorer"}}}}
	nonMatching := ShodanHost{Data: []ShodanData{{HTTP: ShodanHTTP{HTML: "welcome to nginx"}}}}
	if !matchFilter(`http.html:"/v1/graphql"`, matching) {
		t.Error("http.html filter should match host containing /v1/graphql")
	}
	if matchFilter(`http.html:"/v1/graphql"`, nonMatching) {
		t.Error("http.html filter should not match host without /v1/graphql")
	}
}

func TestMatchFilterCompound(t *testing.T) {
	host := ShodanHost{
		Ports: []int{8000},
		Data:  []ShodanData{{HTTP: ShodanHTTP{HTML: "vllm metrics endpoint"}}},
	}
	if !matchFilter(`port:8000 http.html:"vllm"`, host) {
		t.Error("compound filter should match when all terms match")
	}
	hostNoPort := ShodanHost{
		Ports: []int{9999},
		Data:  []ShodanData{{HTTP: ShodanHTTP{HTML: "vllm metrics endpoint"}}},
	}
	if matchFilter(`port:8000 http.html:"vllm"`, hostNoPort) {
		t.Error("compound filter should not match when port term fails")
	}
}

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
