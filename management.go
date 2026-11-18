package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	basePath              = "/v0/management/plugins/" + pluginID
	policiesPath          = basePath + "/policies"
	statusPath            = basePath + "/status"
	reloadPath            = basePath + "/reload"
	initializeStoragePath = basePath + "/initialize-storage"
	settingsResourcePath  = "/v0/resource/plugins/" + pluginID + "/settings"
)

func managementRegistration() managementRegistrationResponse {
	return managementRegistrationResponse{
		Routes: []managementRoute{
			{Method: http.MethodGet, Path: statusPath, Description: "Show key-access status without exposing API keys or caller scopes."},
			{Method: http.MethodGet, Path: policiesPath, Description: "List per-key model and profile policies."},
			{Method: http.MethodPut, Path: policiesPath, Description: "Replace all per-key policies."},
			{Method: http.MethodPost, Path: reloadPath, Description: "Reload policies from policy_file."},
			{Method: http.MethodPost, Path: initializeStoragePath, Description: "Create or validate the default plugin-owned policy file."},
		},
		Resources: []resourceRoute{{
			Path:        "/settings",
			Menu:        "Key Access",
			Description: "Manage per-key model and channel access policies in a browser.",
		}},
	}
}

func handleManagement(raw []byte) ([]byte, error) {
	var req managementRequest
	if err := decodeJSON(raw, &req); err != nil {
		return nil, err
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	path := strings.TrimRight(strings.TrimSpace(req.Path), "/")
	switch {
	case method == http.MethodGet && path == settingsResourcePath:
		return settingsPage()
	case method == http.MethodGet && path == statusPath:
		return managementStatus()
	case method == http.MethodGet && path == policiesPath:
		return managementPolicies()
	case method == http.MethodPut && path == policiesPath:
		return managementReplacePolicies(req.Body, req.Headers.Get("If-Match"))
	case method == http.MethodPost && path == reloadPath:
		return managementReload()
	case method == http.MethodPost && path == initializeStoragePath:
		return managementInitializeStorage(req.Body)
	default:
		return managementJSON(http.StatusNotFound, map[string]any{"error": "management route not found"})
	}
}

func managementStatus() ([]byte, error) {
	v := globalState.view()
	return managementJSON(http.StatusOK, map[string]any{
		"plugin":                  pluginID,
		"version":                 pluginVersion,
		"schema_version":          maxSchemaVersion,
		"host_schema_version":     v.HostSchema,
		"auth_mode":               "cpa_builtin_api_keys",
		"identity_source":         "Metadata.caller_scope",
		"unconfigured_key_action": v.Config.UnconfiguredKey,
		"last_error":              v.LastError,
		"policy_count":            len(v.Snapshot.ByScope),
		"revision":                v.Revision,
		"policy_file":             v.Config.PolicyFile,
		"persistent_updates":      v.Config.PolicyFile != "",
		"source":                  v.Source,
		"updated_at":              formattedTime(v.UpdatedAt),
		"fail_closed":             v.Snapshot.BlockAll,
	})
}

func documentFromConfig(cfg pluginConfig) policyDocument {
	doc := policyDocument{Version: cfg.Version, UnconfiguredKey: cfg.UnconfiguredKey, Policies: make([]policyConfig, len(cfg.Policies))}
	for i, p := range cfg.Policies {
		doc.Policies[i] = policyConfig{
			CallerScope:   p.CallerScope,
			Name:          p.Name,
			AllowModels:   append([]string{}, p.AllowModels...),
			DenyModels:    append([]string{}, p.DenyModels...),
			AllowProfiles: append([]string{}, p.AllowProfiles...),
			DenyProfiles:  append([]string{}, p.DenyProfiles...),
		}
	}
	return doc
}

func managementPolicies() ([]byte, error) {
	v := globalState.view()
	doc := policyDocument{Version: policySchemaVersion, UnconfiguredKey: "allow", Policies: []policyConfig{}}
	if !v.Snapshot.BlockAll {
		doc = documentFromConfig(v.Config)
	}
	return managementJSONWithHeaders(http.StatusOK, map[string]any{
		"policy":     doc,
		"revision":   v.Revision,
		"source":     v.Source,
		"updated_at": formattedTime(v.UpdatedAt),
	}, http.Header{"ETag": []string{etagForRevision(v.Revision)}})
}

func managementReplacePolicies(body []byte, ifMatch string) ([]byte, error) {
	mutationMu.Lock()
	defer mutationMu.Unlock()

	if strings.TrimSpace(ifMatch) != "" {
		expected, err := parseRevisionETag(ifMatch)
		if err != nil {
			return managementJSON(http.StatusBadRequest, map[string]any{"error": err.Error()})
		}
		if current := globalState.view().Revision; expected != current {
			return managementJSON(http.StatusPreconditionFailed, map[string]any{
				"error":            "policy changed since it was loaded; reload before saving",
				"current_revision": current,
			})
		}
	}
	if len(body) == 0 || len(body) > maxPolicyFileSize {
		return managementJSON(http.StatusBadRequest, map[string]any{"error": fmt.Sprintf("policy body must be between 1 and %d bytes", maxPolicyFileSize)})
	}
	var doc policyDocument
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil {
		return managementJSON(http.StatusBadRequest, map[string]any{"error": "invalid policy JSON: " + err.Error()})
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return managementJSON(http.StatusBadRequest, map[string]any{"error": err.Error()})
	}
	snap, sanitized, err := compileDocument(doc)
	if err != nil {
		return managementJSON(http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
	}

	cfg := globalState.view().Config
	if cfg.PolicyFile != "" {
		if err := writePolicyFile(cfg.PolicyFile, sanitized); err != nil {
			return managementJSON(http.StatusInternalServerError, map[string]any{"error": err.Error()})
		}
	}
	cfg.Version, cfg.UnconfiguredKey, cfg.Policies = sanitized.Version, sanitized.UnconfiguredKey, sanitized.Policies
	source := "Management API (memory only)"
	if cfg.PolicyFile != "" {
		source = cfg.PolicyFile
	}
	globalState.replace(cfg, snap, source)
	revision := globalState.view().Revision
	return managementJSONWithHeaders(http.StatusOK, map[string]any{
		"ok":           true,
		"policy_count": len(snap.ByScope),
		"persistent":   cfg.PolicyFile != "",
		"revision":     revision,
		"policy":       sanitized,
	}, http.Header{"ETag": []string{etagForRevision(revision)}})
}

func managementReload() ([]byte, error) {
	mutationMu.Lock()
	defer mutationMu.Unlock()

	cfg := globalState.view().Config
	if cfg.PolicyFile == "" {
		return managementJSON(http.StatusConflict, map[string]any{"error": "policy_file is not configured"})
	}
	doc, err := readPolicyFile(cfg.PolicyFile)
	if err != nil {
		globalState.recordError(err)
		return managementJSON(http.StatusInternalServerError, map[string]any{"error": err.Error()})
	}
	snap, sanitized, err := compileDocument(doc)
	if err != nil {
		globalState.recordError(err)
		return managementJSON(http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
	}
	cfg.Version, cfg.UnconfiguredKey, cfg.Policies = sanitized.Version, sanitized.UnconfiguredKey, sanitized.Policies
	globalState.replace(cfg, snap, cfg.PolicyFile)
	return managementJSON(http.StatusOK, map[string]any{
		"ok": true, "policy_count": len(snap.ByScope), "revision": globalState.view().Revision,
	})
}

// managementInitializeStorage creates <plugins_dir>/key-access/policies.yaml from the
// active inline policy. The plugin cannot learn plugins.dir itself, so the page passes it.
func managementInitializeStorage(body []byte) ([]byte, error) {
	mutationMu.Lock()
	defer mutationMu.Unlock()

	if len(body) == 0 || len(body) > 4096 {
		return managementJSON(http.StatusBadRequest, map[string]any{"error": "plugins_dir request is required"})
	}
	var request struct {
		PluginsDir string `json:"plugins_dir"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return managementJSON(http.StatusBadRequest, map[string]any{"error": "invalid storage initialization body: " + err.Error()})
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return managementJSON(http.StatusBadRequest, map[string]any{"error": err.Error()})
	}
	pluginsDir := strings.TrimSpace(request.PluginsDir)
	if pluginsDir == "" || strings.ContainsRune(pluginsDir, '\x00') {
		return managementJSON(http.StatusBadRequest, map[string]any{"error": "plugins_dir must be a non-empty filesystem path"})
	}
	pluginsDir = filepath.Clean(pluginsDir)
	if !pluginBinaryExists(pluginsDir) {
		return managementJSON(http.StatusUnprocessableEntity, map[string]any{"error": "plugins_dir does not contain the installed " + pluginID + " binary"})
	}
	policyDir := filepath.Join(pluginsDir, pluginID)
	if info, err := os.Lstat(policyDir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return managementJSON(http.StatusConflict, map[string]any{"error": "default policy directory exists but is not a regular directory"})
		}
	} else if !os.IsNotExist(err) {
		return managementJSON(http.StatusInternalServerError, map[string]any{"error": fmt.Sprintf("inspect default policy directory: %v", err)})
	}
	policyPath := filepath.Join(policyDir, "policies.yaml")
	created := false
	info, err := os.Lstat(policyPath)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return managementJSON(http.StatusConflict, map[string]any{"error": "default policy path exists but is not a regular file"})
		}
	case os.IsNotExist(err):
		v := globalState.view()
		if v.Snapshot.BlockAll {
			return managementJSON(http.StatusConflict, map[string]any{"error": "cannot initialize storage while the active policy is fail-closed"})
		}
		_, sanitized, errCompile := compileDocument(documentFromConfig(v.Config))
		if errCompile != nil {
			return managementJSON(http.StatusUnprocessableEntity, map[string]any{"error": errCompile.Error()})
		}
		if errWrite := writePolicyFile(policyPath, sanitized); errWrite != nil {
			return managementJSON(http.StatusInternalServerError, map[string]any{"error": errWrite.Error()})
		}
		created = true
	default:
		return managementJSON(http.StatusInternalServerError, map[string]any{"error": fmt.Sprintf("inspect default policy path: %v", err)})
	}

	doc, err := readPolicyFile(policyPath)
	if err != nil {
		return managementJSON(http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
	}
	if _, _, err := compileDocument(doc); err != nil {
		return managementJSON(http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	return managementJSON(status, map[string]any{"created": created, "policy_file": policyPath, "policy_count": len(doc.Policies)})
}

func pluginBinaryExists(pluginsDir string) bool {
	extension := ".so"
	switch runtime.GOOS {
	case "darwin":
		extension = ".dylib"
	case "windows":
		extension = ".dll"
	}
	for _, dir := range []string{filepath.Join(pluginsDir, runtime.GOOS, runtime.GOARCH), pluginsDir} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry == nil || !entry.Type().IsRegular() {
				continue
			}
			name := entry.Name()
			if !strings.HasSuffix(strings.ToLower(name), extension) {
				continue
			}
			base := name[:len(name)-len(extension)]
			if base == pluginID || (strings.HasPrefix(base, pluginID+"-v") && len(base) > len(pluginID)+2) {
				return true
			}
		}
	}
	return false
}

// writePolicyFile atomically replaces path: same-directory temp file, fsync, rename, then
// fsync of the directory. The file is private to the owner (0600).
func writePolicyFile(path string, doc policyDocument) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("policy_file is not configured")
	}
	raw, err := yaml.Marshal(doc)
	if err != nil {
		return fmt.Errorf("encode policy file: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create policy directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "."+pluginID+"-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary policy file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("secure temporary policy file: %w", err)
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temporary policy file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temporary policy file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary policy file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace policy file: %w", err)
	}
	if runtime.GOOS != "windows" {
		d, err := os.Open(dir)
		if err != nil {
			return fmt.Errorf("open policy directory for sync: %w", err)
		}
		errSync := d.Sync()
		errClose := d.Close()
		if errSync != nil {
			return fmt.Errorf("sync policy directory: %w", errSync)
		}
		if errClose != nil {
			return fmt.Errorf("close policy directory: %w", errClose)
		}
	}
	return nil
}

func managementJSON(status int, value any) ([]byte, error) {
	return managementJSONWithHeaders(status, value, nil)
}

func managementJSONWithHeaders(status int, value any, extra http.Header) ([]byte, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	headers := http.Header{"Content-Type": []string{"application/json; charset=utf-8"}, "Cache-Control": []string{"no-store"}}
	for name, values := range extra {
		for _, v := range values {
			headers.Add(name, v)
		}
	}
	return okEnvelope(managementResponse{StatusCode: status, Headers: headers, Body: body})
}

func etagForRevision(revision uint64) string { return fmt.Sprintf("\"rev-%d\"", revision) }

func parseRevisionETag(value string) (uint64, error) {
	value = strings.TrimPrefix(strings.Trim(strings.TrimSpace(value), "\""), "rev-")
	if value == "" {
		return 0, fmt.Errorf("If-Match must contain a policy revision ETag")
	}
	revision, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid policy revision ETag")
	}
	return revision, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return fmt.Errorf("invalid trailing JSON: %w", err)
	}
	return fmt.Errorf("policy body must contain one JSON object")
}

func formattedTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
