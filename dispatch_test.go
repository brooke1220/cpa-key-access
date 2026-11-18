package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func dispatch(t *testing.T, method string, req any) envelope {
	t.Helper()
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	out, err := handleMethod(method, raw)
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("bad envelope: %s", out)
	}
	return env
}

func registerAt(t *testing.T, hostSchema uint32) registration {
	t.Helper()
	globalState.clear()
	t.Cleanup(globalState.clear)
	env := dispatch(t, methodPluginRegister, lifecycleRequest{SchemaVersion: hostSchema})
	if !env.OK {
		t.Fatalf("register failed: %+v", env.Error)
	}
	var reg registration
	if err := json.Unmarshal(env.Result, &reg); err != nil {
		t.Fatal(err)
	}
	return reg
}

func TestRegistrationCapabilities(t *testing.T) {
	for _, host := range []uint32{7, 10} {
		reg := registerAt(t, host)
		c := reg.Capabilities
		if reg.SchemaVersion != maxSchemaVersion {
			t.Errorf("host %d: schema must be capped at %d, got %d", host, maxSchemaVersion, reg.SchemaVersion)
		}
		if !c.RequestInterceptor || !c.Scheduler || !c.ManagementAPI || !c.OmitBodyBefore || !c.OmitBodyAfter {
			t.Errorf("host %d: every capability must be declared, got %+v", host, c)
		}
	}
	for _, host := range []uint32{2, 3} {
		reg := registerAt(t, host)
		c := reg.Capabilities
		if reg.SchemaVersion != host {
			t.Errorf("host %d: must register at the host schema, got %d", host, reg.SchemaVersion)
		}
		if !c.RequestInterceptor || !c.Scheduler || !c.ManagementAPI {
			t.Errorf("host %d: core capabilities missing, got %+v", host, c)
		}
		if c.OmitBodyBefore || c.OmitBodyAfter {
			t.Errorf("host %d: omit-body needs schema %d, got %+v", host, schemaOmitBody, c)
		}
	}
	// A host that is too old must not get an interceptor (the plugin fails closed instead),
	// but the management API stays so the operator can see why.
	c := registerAt(t, 1).Capabilities
	if c.RequestInterceptor || !c.ManagementAPI {
		t.Errorf("host 1: expected no interceptor but a management API, got %+v", c)
	}
}

func TestDispatchRoutes(t *testing.T) {
	useDoc(t, policyDocument{Policies: []policyConfig{{CallerScope: callerScopeOf("k1"), DenyModels: []string{"gpt-*"}, AllowProfiles: []string{"claude:*"}}}})

	env := dispatch(t, methodManagementRegister, struct{}{})
	var reg managementRegistrationResponse
	if !env.OK || json.Unmarshal(env.Result, &reg) != nil || len(reg.Routes) == 0 || len(reg.Resources) != 1 || reg.Resources[0].Path != "/settings" {
		t.Fatalf("management.register must publish routes and the settings page: %+v %s", env.Error, env.Result)
	}

	env = dispatch(t, methodManagementHandle, managementRequest{Method: http.MethodGet, Path: statusPath})
	var resp managementResponse
	if !env.OK || json.Unmarshal(env.Result, &resp) != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("management.handle must serve the status route: %+v %s", env.Error, env.Result)
	}

	meta := scopeMeta("k1")
	decodeIntercept := func(env envelope) requestInterceptResponse {
		t.Helper()
		var r requestInterceptResponse
		if !env.OK || json.Unmarshal(env.Result, &r) != nil {
			t.Fatalf("bad intercept envelope: %+v %s", env.Error, env.Result)
		}
		return r
	}
	if r := decodeIntercept(dispatch(t, methodRequestInterceptBefore, requestInterceptRequest{RequestedModel: "gpt-5", Metadata: meta})); !r.Terminate || r.StatusCode != http.StatusForbidden {
		t.Fatalf("intercept_before must enforce model rules, got %+v", r)
	}
	after := map[string]any{"caller_scope": callerScopeOf("k1"), "selected_auth_id": "codex:x"}
	if r := decodeIntercept(dispatch(t, methodRequestInterceptAfter, requestInterceptRequest{RequestedModel: "claude-x", Metadata: after})); !r.Terminate {
		t.Fatal("intercept_after must reject a disallowed selected profile")
	}
	after["selected_auth_id"] = "claude:a"
	if r := decodeIntercept(dispatch(t, methodRequestInterceptAfter, requestInterceptRequest{RequestedModel: "claude-x", Metadata: after})); r.Terminate {
		t.Fatal("intercept_after must accept an allowed selected profile")
	}

	env = dispatch(t, methodSchedulerPick, schedulerPickRequest{Provider: "claude", Model: "claude-x", Options: schedulerOptions{Metadata: meta}, Candidates: []schedulerAuthCandidate{{ID: "codex:x", Priority: 1}, {ID: "claude:a", Priority: 1}}})
	var pick schedulerPickResponse
	if !env.OK || json.Unmarshal(env.Result, &pick) != nil || !pick.Handled || pick.AuthID != "claude:a" {
		t.Fatalf("scheduler.pick must choose the allowed candidate: %+v %s", env.Error, env.Result)
	}
}

// TestRegistrationMetadataAcceptedByHost mirrors the host's validPlugin: it drops a plugin whose
// Name, Version, Author or GitHubRepository is blank, and then none of its routes are mounted.
func TestRegistrationMetadataAcceptedByHost(t *testing.T) {
	m := registerAt(t, 7).Metadata
	for name, value := range map[string]string{"Name": m.Name, "Version": m.Version, "Author": m.Author, "GitHubRepository": m.GitHubRepository} {
		if strings.TrimSpace(value) == "" {
			t.Errorf("metadata %s must not be blank: the host rejects the whole plugin", name)
		}
	}
}

func TestDispatchUnknownMethod(t *testing.T) {
	env := dispatch(t, "no.such.method", struct{}{})
	if env.OK || env.Error == nil || env.Error.Code != "unknown_method" {
		t.Fatalf("an unknown method must return unknown_method, got %+v", env)
	}
}
