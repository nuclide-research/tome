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
// Compound filters (space-separated terms) are AND: all terms must match.
// Values are matched case-insensitively; quotes around values are stripped.
func matchFilter(filter string, host ShodanHost) bool {
	if strings.ContainsRune(filter, ' ') {
		for _, part := range strings.Fields(filter) {
			if !matchFilter(part, host) {
				return false
			}
		}
		return true
	}
	field, value, ok := strings.Cut(filter, ":")
	if !ok {
		return hostContains(host, strings.ToLower(filter))
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
	for _, d := range host.Data {
		if strings.Contains(strings.ToLower(d.Data), s) ||
			strings.Contains(strings.ToLower(d.Product), s) ||
			strings.Contains(strings.ToLower(d.HTTP.HTML), s) {
			return true
		}
	}
	return false
}
