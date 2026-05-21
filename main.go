package main

import (
	"embed"

	"github.com/Nicholas-Kloster/tome/cmd"
	"github.com/Nicholas-Kloster/tome/internal/corpus"
)

//go:embed platforms/*.json
var platformFS embed.FS

func main() {
	corpus.Init(platformFS)
	cmd.Execute()
}
