package cmd

import (
	"fmt"

	"github.com/Nicholas-Kloster/tome/internal/corpus"
	"github.com/Nicholas-Kloster/tome/internal/output"
	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all known platforms in the corpus",
	Args:  cobra.NoArgs,
	RunE:  runList,
}

func init() {
	rootCmd.AddCommand(listCmd)
}

func runList(cmd *cobra.Command, _ []string) error {
	platforms, err := corpus.ListPlatforms()
	if err != nil {
		return err
	}
	fmt.Fprint(cmd.OutOrStdout(), output.FormatList(platforms, resolveFormat()))
	return nil
}
