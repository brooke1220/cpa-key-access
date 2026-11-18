package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The README tells users to add a raw.githubusercontent.com store source. This keeps that address,
// registry.json and the repository recorded in the plugin metadata consistent with each other.
func TestDocumentedStoreSourceListsThisPlugin(t *testing.T) {
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "https://raw.githubusercontent.com/brooke1220/cpa-key-access/main/"
	checked := 0
	for _, field := range strings.Fields(string(readme)) {
		index := strings.Index(field, prefix)
		if index < 0 {
			continue
		}
		path := strings.TrimRight(field[index+len(prefix):], `"',)`)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("documented store source %s is unavailable: %v", path, err)
		}
		var registry struct {
			SchemaVersion int `json:"schema_version"`
			Plugins       []struct {
				ID         string `json:"id"`
				Repository string `json:"repository"`
			} `json:"plugins"`
		}
		if err := json.Unmarshal(raw, &registry); err != nil {
			t.Fatalf("invalid store registry %s: %v", path, err)
		}
		if registry.SchemaVersion != 1 {
			t.Fatalf("store registry %s uses an unsupported schema %d", path, registry.SchemaVersion)
		}
		found := false
		for _, plugin := range registry.Plugins {
			found = found || (plugin.ID == pluginID && plugin.Repository == pluginRepository)
		}
		if !found {
			t.Fatalf("store registry %s does not list %s at %s", path, pluginID, pluginRepository)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("README has no plugin store source")
	}
}
