package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func scopeMeta(key string) map[string]any {
	return map[string]any{"caller_scope": callerScopeOf(key)}
}

func useDoc(t *testing.T, doc policyDocument) {
	t.Helper()
	snap, _, err := compileDocument(doc)
	if err != nil {
		t.Fatal(err)
	}
	globalState.clear()
	globalState.replace(pluginConfig{}, snap, "test")
	t.Cleanup(globalState.clear)
}

func intercept(t *testing.T, afterAuth bool, req requestInterceptRequest) requestInterceptResponse {
	t.Helper()
	raw, _ := json.Marshal(req)
	out, err := interceptRequest(raw, afterAuth)
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	if err := json.Unmarshal(out, &env); err != nil || !env.OK {
		t.Fatalf("bad envelope: %s", out)
	}
	var resp requestInterceptResponse
	if err := json.Unmarshal(env.Result, &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func pick(t *testing.T, req schedulerPickRequest) (schedulerPickResponse, *envelopeError) {
	t.Helper()
	raw, _ := json.Marshal(req)
	out, err := pickProfile(raw)
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatal(err)
	}
	if !env.OK {
		return schedulerPickResponse{}, env.Error
	}
	var resp schedulerPickResponse
	if err := json.Unmarshal(env.Result, &resp); err != nil {
		t.Fatal(err)
	}
	return resp, nil
}

func TestWildcardMatch(t *testing.T) {
	cases := []struct {
		pattern, value string
		want           bool
	}{
		{"gpt-*", "gpt-5", true},
		{"*", "anything/with/slash", true},
		{"claude-?-x", "claude-4-x", true},
		{"claude-?-x", "claude-44-x", false},
		{"a*b*c", "aXXbYYc", true},
		{"a*b*c", "aXXbYY", false},
		{"*-retired", "codex:abc-retired", true},
		{"gpt-5", "gpt-5-mini", false},
		{"", "", true},
		{"a*", "a*b", true},
	}
	for _, c := range cases {
		if got := wildcardMatch(c.pattern, c.value); got != c.want {
			t.Errorf("wildcardMatch(%q, %q) = %v, want %v", c.pattern, c.value, got, c.want)
		}
	}
}

func TestPatternAllows(t *testing.T) {
	if !patternAllows(nil, nil, "x") {
		t.Error("empty rules must allow")
	}
	if patternAllows([]string{"gpt-*"}, []string{"gpt-5"}, "gpt-5") {
		t.Error("deny must win over allow")
	}
	if !patternAllows([]string{"gpt-*"}, []string{"gpt-5"}, "gpt-4") {
		t.Error("allowed name not denied must pass")
	}
	if patternAllows([]string{"gpt-*"}, nil, "claude-x") {
		t.Error("a non-empty allow list is a whitelist")
	}
	if !patternAllows(nil, []string{"gpt-5"}, "claude-x") {
		t.Error("an empty allow list allows everything not denied")
	}
	if patternAllows(nil, []string{"gpt-5"}, "fast", "gpt-5") {
		t.Error("a deny match on any name must reject")
	}
	if !patternAllows([]string{"gpt-5"}, nil, "fast", "gpt-5") {
		t.Error("an allow match on any name must accept")
	}
}

func TestCompileDocument(t *testing.T) {
	good := callerScopeOf("k")
	if !validSHA256(good) {
		t.Fatal("callerScopeOf must produce 64 hex characters")
	}
	bad := []policyDocument{
		{Policies: []policyConfig{{CallerScope: "short"}}},
		{Policies: []policyConfig{{CallerScope: good}, {CallerScope: good}}},
		{UnconfiguredKey: "maybe"},
		{Version: 9},
		{Policies: []policyConfig{{CallerScope: good, AllowModels: []string{" "}}}},
	}
	for i, doc := range bad {
		if _, _, err := compileDocument(doc); err == nil {
			t.Errorf("document %d must be rejected", i)
		}
	}
	snap, doc, err := compileDocument(policyDocument{Policies: []policyConfig{{CallerScope: strings.ToUpper(good), DenyModels: []string{"b", "a", "a"}}}})
	if err != nil {
		t.Fatal(err)
	}
	p, ok := snap.ByScope[good]
	if !ok || len(p.DenyModels) != 2 || p.DenyModels[0] != "a" {
		t.Errorf("scope must be lower-cased and patterns deduplicated and sorted, got %+v", p)
	}
	if doc.UnconfiguredKey != "allow" || doc.Version != policySchemaVersion {
		t.Errorf("defaults not applied: %+v", doc)
	}
}

func TestStrictYAML(t *testing.T) {
	var doc policyDocument
	if err := decodeStrictYAML([]byte(`version: 1
bogus: true
`), &doc); err == nil {
		t.Error("unknown fields must be rejected")
	}
	if err := decodeStrictYAML([]byte(`version: 1
---
version: 1
`), &doc); err == nil {
		t.Error("multiple documents must be rejected")
	}
	if err := decodeStrictYAML([]byte(`version: 1
unconfigured_key: deny
policies: []
`), &doc); err != nil || doc.UnconfiguredKey != "deny" {
		t.Errorf("valid document rejected: %v %+v", err, doc)
	}
}
