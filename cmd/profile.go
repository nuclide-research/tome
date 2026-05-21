package cmd

import (
	"fmt"

	"github.com/Nicholas-Kloster/tome/internal/corpus"
	"github.com/Nicholas-Kloster/tome/internal/output"
	"github.com/spf13/cobra"
)

var profileCmd = &cobra.Command{
	Use:   "profile <platform>",
	Short: "Full OSINT profile for a platform — ports, paths, auth, dorks, misconfigs",
	Args:  cobra.ExactArgs(1),
	RunE:  runProfile,
}

func init() {
	rootCmd.AddCommand(profileCmd)
}

func runProfile(cmd *cobra.Command, args []string) error {
	p, err := corpus.LoadPlatform(args[0])
	if err != nil {
		return err
	}
	fmt.Fprint(cmd.OutOrStdout(), output.FormatProfile(p, resolveFormat()))
	return nil
}
