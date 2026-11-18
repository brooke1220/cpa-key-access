package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

const maxPolicyFileSize = 2 << 20

// pluginConfig is the plugin's block under plugins.configs.key-access.
// The host also injects enabled, priority and store.
type pluginConfig struct {
	Enabled         *bool          `yaml:"enabled,omitempty"`
	Priority        int            `yaml:"priority,omitempty"`
	Store           any            `yaml:"store,omitempty"`
	PolicyFile      string         `yaml:"policy_file,omitempty"`
	Version         int            `yaml:"version,omitempty"`
	UnconfiguredKey string         `yaml:"unconfigured_key,omitempty"`
	Policies        []policyConfig `yaml:"policies,omitempty"`
}

type policyDocument struct {
	Version         int            `json:"version" yaml:"version"`
	UnconfiguredKey string         `json:"unconfigured_key" yaml:"unconfigured_key"`
	Policies        []policyConfig `json:"policies" yaml:"policies"`
}

type policyConfig struct {
	CallerScope   string   `json:"caller_scope" yaml:"caller_scope"`
	Name          string   `json:"name,omitempty" yaml:"name,omitempty"`
	AllowModels   []string `json:"allow_models" yaml:"allow_models"`
	DenyModels    []string `json:"deny_models" yaml:"deny_models"`
	AllowProfiles []string `json:"allow_profiles" yaml:"allow_profiles"`
	DenyProfiles  []string `json:"deny_profiles" yaml:"deny_profiles"`
}

type runtimePolicy struct {
	AllowModels, DenyModels, AllowProfiles, DenyProfiles []string
}

func (p runtimePolicy) hasModelRules() bool   { return len(p.AllowModels)+len(p.DenyModels) > 0 }
func (p runtimePolicy) hasProfileRules() bool { return len(p.AllowProfiles)+len(p.DenyProfiles) > 0 }

// snapshot is the compiled, immutable form of a policy document.
type snapshot struct {
	ByScope          map[string]runtimePolicy
	DenyUnconfigured bool
	BlockAll         bool
}

func failClosedSnapshot() snapshot {
	return snapshot{ByScope: map[string]runtimePolicy{}, BlockAll: true}
}

func compileDocument(doc policyDocument) (snapshot, policyDocument, error) {
	if doc.Version == 0 {
		doc.Version = policySchemaVersion
	}
	if doc.Version != policySchemaVersion {
		return snapshot{}, policyDocument{}, fmt.Errorf("unsupported policy version %d; only version %d is supported", doc.Version, policySchemaVersion)
	}
	doc.UnconfiguredKey = strings.ToLower(strings.TrimSpace(doc.UnconfiguredKey))
	switch doc.UnconfiguredKey {
	case "":
		doc.UnconfiguredKey = "allow"
	case "allow", "deny":
	default:
		return snapshot{}, policyDocument{}, fmt.Errorf("unconfigured_key must be allow or deny")
	}
	if doc.Policies == nil {
		doc.Policies = []policyConfig{}
	}
	snap := snapshot{ByScope: map[string]runtimePolicy{}, DenyUnconfigured: doc.UnconfiguredKey == "deny"}
	for i := range doc.Policies {
		p := &doc.Policies[i]
		p.CallerScope = strings.ToLower(strings.TrimSpace(p.CallerScope))
		p.Name = strings.TrimSpace(p.Name)
		if !validSHA256(p.CallerScope) {
			return snapshot{}, policyDocument{}, fmt.Errorf("policies[%d].caller_scope must be 64 hexadecimal characters", i)
		}
		if _, dup := snap.ByScope[p.CallerScope]; dup {
			return snapshot{}, policyDocument{}, fmt.Errorf("duplicate caller_scope at policies[%d]", i)
		}
		fields := []struct {
			dst  *[]string
			name string
		}{{&p.AllowModels, "allow_models"}, {&p.DenyModels, "deny_models"}, {&p.AllowProfiles, "allow_profiles"}, {&p.DenyProfiles, "deny_profiles"}}
		for _, f := range fields {
			out, err := normalizePatterns(*f.dst, fmt.Sprintf("policies[%d].%s", i, f.name))
			if err != nil {
				return snapshot{}, policyDocument{}, err
			}
			*f.dst = out
		}
		snap.ByScope[p.CallerScope] = runtimePolicy{AllowModels: p.AllowModels, DenyModels: p.DenyModels, AllowProfiles: p.AllowProfiles, DenyProfiles: p.DenyProfiles}
	}
	return snap, doc, nil
}

func normalizePatterns(patterns []string, field string) ([]string, error) {
	seen := make(map[string]struct{}, len(patterns))
	out := make([]string, 0, len(patterns))
	for i, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			return nil, fmt.Errorf("%s[%d] must not be empty", field, i)
		}
		if _, ok := seen[pattern]; ok {
			continue
		}
		seen[pattern] = struct{}{}
		out = append(out, pattern)
	}
	sort.Strings(out)
	return out, nil
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// patternAllows reports whether any of names passes the rules: a deny match on any name
// rejects; an empty allow list accepts; otherwise some name must match an allow pattern.
func patternAllows(allow, deny []string, names ...string) bool {
	for _, pattern := range deny {
		for _, name := range names {
			if wildcardMatch(pattern, name) {
				return false
			}
		}
	}
	if len(allow) == 0 {
		return true
	}
	for _, pattern := range allow {
		for _, name := range names {
			if wildcardMatch(pattern, name) {
				return true
			}
		}
	}
	return false
}

// wildcardMatch supports '*' (any run, including '/') and '?' (one character).
// The '*' case is tested first so a literal '*' in value cannot hide a wildcard.
func wildcardMatch(pattern, value string) bool {
	pr, vr := []rune(pattern), []rune(value)
	p, v, star, mark := 0, 0, -1, 0
	for v < len(vr) {
		switch {
		case p < len(pr) && pr[p] == '*':
			star, mark = p, v
			p++
		case p < len(pr) && (pr[p] == '?' || pr[p] == vr[v]):
			p++
			v++
		case star >= 0:
			mark++
			p, v = star+1, mark
		default:
			return false
		}
	}
	for p < len(pr) && pr[p] == '*' {
		p++
	}
	return p == len(pr)
}

// callerScopeOf derives the scope handle from a raw API key. Used by tests and tooling;
// it must match the host's derivation.
func callerScopeOf(rawKey string) string {
	sum := sha256.Sum256([]byte("cli-proxy-api:caller-scope:v1\x00" + strings.TrimSpace(rawKey)))
	return hex.EncodeToString(sum[:])
}
