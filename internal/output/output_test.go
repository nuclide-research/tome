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
	if !strings.Contains(out, "none") {
		t.Error("list table missing auth column")
	}
	if !strings.Contains(out, "8080") {
		t.Error("list table missing ports column")
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
	if got := FormatDorks(testPlatform, ""); got != "product:Weaviate port:8080" {
		t.Errorf("FormatDorks default = %q, want strict dork", got)
	}
}
