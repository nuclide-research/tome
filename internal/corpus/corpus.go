package corpus

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var fs embed.FS

// Init sets the embedded filesystem. Called once from main with the //go:embed FS.
func Init(embedded embed.FS) {
	fs = embedded
}

// LoadPlatform returns the Platform for the given name (e.g. "weaviate").
// Name is the filename stem — no path, no .json extension.
func LoadPlatform(name string) (Platform, error) {
	// Try both the platforms/ prefix (production) and testdata/ prefix (tests).
	for _, prefix := range []string{"platforms", "testdata"} {
		data, err := fs.ReadFile(prefix + "/" + name + ".json")
		if err == nil {
			var p Platform
			return p, json.Unmarshal(data, &p)
		}
	}
	return Platform{}, fmt.Errorf("unknown platform %q", name)
}

// ListPlatforms returns all platforms in the embedded corpus.
func ListPlatforms() ([]Platform, error) {
	for _, prefix := range []string{"platforms", "testdata"} {
		entries, err := fs.ReadDir(prefix)
		if err != nil {
			continue
		}
		platforms := make([]Platform, 0, len(entries))
		var errs []error
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			name := strings.TrimSuffix(e.Name(), ".json")
			p, err := LoadPlatform(name)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", name, err))
				continue
			}
			platforms = append(platforms, p)
		}
		return platforms, errors.Join(errs...)
	}
	return nil, fmt.Errorf("no platform directory found in embedded FS")
}
