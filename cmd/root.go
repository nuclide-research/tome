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
