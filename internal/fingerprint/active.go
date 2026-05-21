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
