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
