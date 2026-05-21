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
