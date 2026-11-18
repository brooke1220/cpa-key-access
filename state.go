package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type stateView struct {
	Config     pluginConfig
	Snapshot   snapshot
	Source     string
	UpdatedAt  time.Time
	HostSchema uint32
	LastError  string
	Revision   uint64
}

type state struct {
	mu       sync.RWMutex
	v        stateView
	hasValid bool
	cursor   map[string]uint64
}

var (
	globalState = state{v: stateView{Snapshot: failClosedSnapshot()}, cursor: map[string]uint64{}}
	mutationMu  sync.Mutex
)

func (s *state) view() stateView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v
}

func (s *state) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.v = stateView{Snapshot: failClosedSnapshot()}
	s.hasValid = false
	s.cursor = map[string]uint64{}
}

func (s *state) replace(cfg pluginConfig, snap snapshot, source string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.v.Config, s.v.Snapshot, s.v.Source = cfg, snap, source
	s.v.UpdatedAt = time.Now().UTC()
	s.v.LastError = ""
	s.v.Revision++
	s.hasValid = true
}

// failOrPreserve records cause and fails closed, unless a valid policy is already active.
func (s *state) failOrPreserve(cfg pluginConfig, schema uint32, cause error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.v.HostSchema = schema
	s.v.LastError = cause.Error()
	if s.hasValid {
		return
	}
	s.v.Config, s.v.Snapshot = cfg, failClosedSnapshot()
	s.v.Source = "fail-closed: " + cause.Error()
	s.v.UpdatedAt = time.Now().UTC()
	s.v.Revision++
}

func (s *state) setHostSchema(schema uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.v.HostSchema = schema
}

func (s *state) recordError(cause error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.v.LastError = cause.Error()
}

// nextIndex returns a round-robin index in [0, n) for the given key.
func (s *state) nextIndex(key string, n int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.cursor[key]
	s.cursor[key] = c + 1
	return int(c % uint64(n))
}

func configure(raw []byte) error {
	mutationMu.Lock()
	defer mutationMu.Unlock()

	var req lifecycleRequest
	if err := decodeJSON(raw, &req); err != nil {
		return err
	}
	cfg := pluginConfig{Version: policySchemaVersion}
	if req.SchemaVersion < minSchemaVersion {
		globalState.failOrPreserve(cfg, req.SchemaVersion, fmt.Errorf("%s requires CPA plugin RPC schema %d or newer", pluginID, minSchemaVersion))
		return nil
	}
	if len(req.ConfigYAML) > 0 {
		if err := decodeStrictYAML(req.ConfigYAML, &cfg); err != nil {
			globalState.failOrPreserve(cfg, req.SchemaVersion, fmt.Errorf("decode plugin config: %w", err))
			return nil
		}
	}
	cfg.PolicyFile = strings.TrimSpace(cfg.PolicyFile)

	doc := policyDocument{Version: cfg.Version, UnconfiguredKey: cfg.UnconfiguredKey, Policies: cfg.Policies}
	source := "inline config"
	if cfg.PolicyFile != "" {
		loaded, err := readPolicyFile(cfg.PolicyFile)
		if err != nil {
			globalState.failOrPreserve(cfg, req.SchemaVersion, err)
			return nil
		}
		doc, source = loaded, cfg.PolicyFile
	}
	snap, sanitized, err := compileDocument(doc)
	if err != nil {
		globalState.failOrPreserve(cfg, req.SchemaVersion, err)
		return nil
	}
	cfg.Version, cfg.UnconfiguredKey, cfg.Policies = sanitized.Version, sanitized.UnconfiguredKey, sanitized.Policies
	globalState.setHostSchema(req.SchemaVersion)
	globalState.replace(cfg, snap, source)
	return nil
}

func readPolicyFile(path string) (policyDocument, error) {
	file, err := os.Open(path)
	if err != nil {
		return policyDocument{}, fmt.Errorf("open policy file %q: %w", path, err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return policyDocument{}, fmt.Errorf("stat policy file %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return policyDocument{}, fmt.Errorf("policy file %q is not a regular file", path)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxPolicyFileSize+1))
	if err != nil {
		return policyDocument{}, fmt.Errorf("read policy file %q: %w", path, err)
	}
	if len(raw) > maxPolicyFileSize {
		return policyDocument{}, fmt.Errorf("policy file %q exceeds %d bytes", path, maxPolicyFileSize)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return policyDocument{}, fmt.Errorf("policy file %q is empty", path)
	}
	var doc policyDocument
	if err := decodeStrictYAML(raw, &doc); err != nil {
		return policyDocument{}, fmt.Errorf("decode policy file %q: %w", path, err)
	}
	return doc, nil
}

func decodeStrictYAML(raw []byte, target any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	return fmt.Errorf("multiple YAML documents are not allowed")
}
