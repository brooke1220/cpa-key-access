package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func call(t *testing.T, fn func() ([]byte, error)) managementResponse {
	t.Helper()
	out, err := fn()
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	if err := json.Unmarshal(out, &env); err != nil || !env.OK {
		t.Fatalf("bad envelope: %s", out)
	}
	var resp managementResponse
	if err := json.Unmarshal(env.Result, &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

// usePolicyFile activates a file-backed policy through the real configure path.
func usePolicyFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state", "policies.yaml")
	if err := writePolicyFile(path, policyDocument{Version: 1, UnconfiguredKey: "allow", Policies: []policyConfig{}}); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(lifecycleRequest{ConfigYAML: []byte("policy_file: " + strconv.Quote(path) + "\n"), SchemaVersion: maxSchemaVersion})
	globalState.clear()
	t.Cleanup(globalState.clear)
	if err := configure(raw); err != nil {
		t.Fatal(err)
	}
	if v := globalState.view(); v.Snapshot.BlockAll {
		t.Fatalf("setup failed closed: %s", v.LastError)
	}
	return path
}

func nonceOf(t *testing.T, r managementResponse) string {
	t.Helper()
	csp := r.Headers.Get("Content-Security-Policy")
	_, rest, ok := strings.Cut(csp, "script-src 'nonce-")
	if !ok {
		t.Fatalf("CSP has no script nonce: %q", csp)
	}
	nonce, _, _ := strings.Cut(rest, "'")
	return nonce
}

func TestSettingsPage(t *testing.T) {
	r := call(t, settingsPage)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("status %d", r.StatusCode)
	}
	body := string(r.Body)
	for _, placeholder := range []string{"{{NONCE}}", "{{CSS}}", "{{JS}}"} {
		if strings.Contains(body, placeholder) {
			t.Errorf("placeholder %s was not replaced", placeholder)
		}
	}
	nonce := nonceOf(t, r)
	if nonce == "" || strings.Count(body, `nonce="`+nonce+`"`) != 2 {
		t.Error("style and script tags must both carry the CSP nonce")
	}
	if strings.Count(body, "</script>") != 1 {
		t.Error("embedded script must not close the script tag early")
	}
	if !strings.Contains(r.Headers.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Error("CSP must default to none")
	}
	if other := nonceOf(t, call(t, settingsPage)); other == nonce {
		t.Error("nonce must change per request")
	}
}

func TestReplacePoliciesETagAndPersistence(t *testing.T) {
	path := usePolicyFile(t)
	etag := call(t, managementPolicies).Headers.Get("ETag")
	if etag == "" {
		t.Fatal("GET policies must return an ETag")
	}
	put := func(body, ifMatch string) managementResponse {
		return call(t, func() ([]byte, error) { return managementReplacePolicies([]byte(body), ifMatch) })
	}
	body := `{"version":1,"unconfigured_key":"deny","policies":[{"caller_scope":"` + callerScopeOf("k1") + `","name":"alice","allow_models":["gpt-*"],"deny_models":[],"allow_profiles":[],"deny_profiles":["codex:*"]}]}`
	if r := put(body, etag); r.StatusCode != http.StatusOK {
		t.Fatalf("save with a fresh ETag: %d %s", r.StatusCode, r.Body)
	}
	if r := put(body, etag); r.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("a stale ETag must return 412, got %d", r.StatusCode)
	}
	doc, err := readPolicyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if doc.UnconfiguredKey != "deny" || len(doc.Policies) != 1 || doc.Policies[0].Name != "alice" {
		t.Fatalf("policy was not persisted: %+v", doc)
	}
	denied := func() bool {
		return intercept(t, false, requestInterceptRequest{RequestedModel: "claude-x", Metadata: scopeMeta("k1")}).Terminate
	}
	if !denied() {
		t.Fatal("the saved policy must take effect immediately")
	}
	if r := put(`{"version":1,"bogus":1}`, ""); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown fields must return 400, got %d", r.StatusCode)
	}
	if r := put(`{"version":1,"policies":[{"caller_scope":"zz"}]}`, ""); r.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("an invalid scope must return 422, got %d", r.StatusCode)
	}
	if !denied() {
		t.Fatal("a rejected save must not change the active policy")
	}
}

func TestInitializeStorage(t *testing.T) {
	useDoc(t, policyDocument{})
	dir := t.TempDir()
	initialize := func() managementResponse {
		body, _ := json.Marshal(map[string]string{"plugins_dir": dir})
		return call(t, func() ([]byte, error) { return managementInitializeStorage(body) })
	}
	if r := initialize(); r.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("a plugins dir without the binary must return 422, got %d", r.StatusCode)
	}
	ext := map[string]string{"darwin": ".dylib", "windows": ".dll"}[runtime.GOOS]
	if ext == "" {
		ext = ".so"
	}
	if err := os.WriteFile(filepath.Join(dir, pluginID+ext), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := initialize(); r.StatusCode != http.StatusCreated {
		t.Fatalf("first initialization must return 201, got %d %s", r.StatusCode, r.Body)
	}
	if _, err := readPolicyFile(filepath.Join(dir, pluginID, "policies.yaml")); err != nil {
		t.Fatalf("initialized policy file must be readable: %v", err)
	}
	if r := initialize(); r.StatusCode != http.StatusOK {
		t.Fatalf("repeat initialization must return 200, got %d", r.StatusCode)
	}
}

func TestWritePolicyFilePrivateAndClean(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.yaml")
	for i := 0; i < 2; i++ {
		if err := writePolicyFile(path, policyDocument{Version: 1, UnconfiguredKey: "allow", Policies: []policyConfig{}}); err != nil {
			t.Fatal(err)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("policy file mode is %v, want 0600", info.Mode().Perm())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("temporary files were left behind: %d entries", len(entries))
	}
}

func TestHandleManagementRouting(t *testing.T) {
	useDoc(t, policyDocument{})
	route := func(method, path string) int {
		raw, _ := json.Marshal(managementRequest{Method: method, Path: path})
		return call(t, func() ([]byte, error) { return handleManagement(raw) }).StatusCode
	}
	for _, path := range []string{settingsResourcePath, statusPath, policiesPath} {
		if got := route(http.MethodGet, path); got != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, got)
		}
	}
	if got := route(http.MethodGet, basePath+"/nope"); got != http.StatusNotFound {
		t.Errorf("unknown path = %d, want 404", got)
	}
	if got := route(http.MethodDelete, policiesPath); got != http.StatusNotFound {
		t.Errorf("unsupported method = %d, want 404", got)
	}
}
