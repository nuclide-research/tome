package cmd

import (
	"fmt"

	"github.com/Nicholas-Kloster/tome/internal/corpus"
	"github.com/Nicholas-Kloster/tome/internal/output"
	"github.com/spf13/cobra"
)

var dorksCmd = &cobra.Command{
	Use:   "dorks <platform>",
	Short: "Shodan dorks for a platform, formatted for paste or JAXEN import",
	Args:  cobra.ExactArgs(1),
	RunE:  runDorks,
}

func init() {
	rootCmd.AddCommand(dorksCmd)
}

func runDorks(cmd *cobra.Command, args []string) error {
	p, err := corpus.LoadPlatform(args[0])
	if err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), output.FormatDorks(p, dorkTierFlag))
	return nil
}
