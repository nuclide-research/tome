package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

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
		if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
			return fmt.Errorf("active mode requires interactive confirmation; stdin is not a terminal")
		}
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
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", ip, key))
	if err != nil {
		return fingerprint.ShodanHost{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fingerprint.ShodanHost{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return fingerprint.ShodanHost{}, fmt.Errorf("Shodan API %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var host fingerprint.ShodanHost
	return host, json.Unmarshal(body, &host)
}
