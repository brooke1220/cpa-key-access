package main

import "testing"

func TestModelRules(t *testing.T) {
	useDoc(t, policyDocument{Policies: []policyConfig{{CallerScope: callerScopeOf("k1"), DenyModels: []string{"gpt-*"}}}})
	meta := scopeMeta("k1")
	if r := intercept(t, false, requestInterceptRequest{RequestedModel: "gpt-5", Metadata: meta}); !r.Terminate || r.StatusCode != 403 {
		t.Fatalf("denied model must terminate with 403, got %+v", r)
	}
	if r := intercept(t, false, requestInterceptRequest{RequestedModel: "fast", Model: "gpt-5", Metadata: meta}); !r.Terminate {
		t.Fatal("an alias must not bypass a deny rule")
	}
	if r := intercept(t, false, requestInterceptRequest{RequestedModel: "claude-x", Metadata: meta}); r.Terminate {
		t.Fatal("an unlisted model must pass when only deny rules exist")
	}
	if r := intercept(t, false, requestInterceptRequest{Metadata: meta}); !r.Terminate {
		t.Fatal("a missing model must fail closed for a key with model rules")
	}
	if r := intercept(t, false, requestInterceptRequest{RequestedModel: "gpt-5", Metadata: scopeMeta("other")}); r.Terminate {
		t.Fatal("keys without a policy must pass by default")
	}
}

func TestUnconfiguredKeyDeny(t *testing.T) {
	useDoc(t, policyDocument{UnconfiguredKey: "deny", Policies: []policyConfig{{CallerScope: callerScopeOf("k1"), AllowModels: []string{"*"}}}})
	if r := intercept(t, false, requestInterceptRequest{RequestedModel: "m", Metadata: scopeMeta("k1")}); r.Terminate {
		t.Fatal("a configured key must pass")
	}
	if r := intercept(t, false, requestInterceptRequest{RequestedModel: "m", Metadata: scopeMeta("other")}); !r.Terminate {
		t.Fatal("an unconfigured key must be denied")
	}
	if r := intercept(t, false, requestInterceptRequest{RequestedModel: "m"}); !r.Terminate {
		t.Fatal("a request without identity must be denied")
	}
}

func TestIdentityMissingFailsClosedWhenPoliciesExist(t *testing.T) {
	useDoc(t, policyDocument{Policies: []policyConfig{{CallerScope: callerScopeOf("k1"), DenyModels: []string{"x"}}}})
	if r := intercept(t, false, requestInterceptRequest{RequestedModel: "m"}); !r.Terminate {
		t.Fatal("missing caller_scope must fail closed while policies exist")
	}
}

func TestFailClosedWhenPolicyUnavailable(t *testing.T) {
	globalState.clear()
	t.Cleanup(globalState.clear)
	if r := intercept(t, false, requestInterceptRequest{RequestedModel: "m", Metadata: scopeMeta("k1")}); !r.Terminate || r.StatusCode != 403 {
		t.Fatalf("an unavailable policy must block, got %+v", r)
	}
	if _, errEnv := pick(t, schedulerPickRequest{Options: schedulerOptions{Metadata: scopeMeta("k1")}}); errEnv == nil || errEnv.HTTPStatus != 403 {
		t.Fatalf("the scheduler must fail closed too, got %+v", errEnv)
	}
}

func TestProfileCheckAfterAuth(t *testing.T) {
	useDoc(t, policyDocument{Policies: []policyConfig{{CallerScope: callerScopeOf("k1"), AllowProfiles: []string{"claude:*"}}}})
	with := func(id string) map[string]any {
		m := scopeMeta("k1")
		if id != "" {
			m["selected_auth_id"] = id
		}
		return m
	}
	if r := intercept(t, false, requestInterceptRequest{RequestedModel: "m", Metadata: with("")}); r.Terminate {
		t.Fatal("the profile check must only run after auth")
	}
	if r := intercept(t, true, requestInterceptRequest{RequestedModel: "m", Metadata: with("claude:a")}); r.Terminate {
		t.Fatal("an allowed profile must pass")
	}
	if r := intercept(t, true, requestInterceptRequest{RequestedModel: "m", Metadata: with("codex:x")}); !r.Terminate {
		t.Fatal("a disallowed profile must be rejected")
	}
	if r := intercept(t, true, requestInterceptRequest{RequestedModel: "m", Metadata: with("")}); !r.Terminate {
		t.Fatal("a missing selected profile must fail closed")
	}
}

func TestPickProfile(t *testing.T) {
	useDoc(t, policyDocument{Policies: []policyConfig{{CallerScope: callerScopeOf("k1"), AllowProfiles: []string{"claude:*"}, DenyProfiles: []string{"claude:low"}}}})
	req := schedulerPickRequest{Provider: "claude", Model: "m", Options: schedulerOptions{Metadata: scopeMeta("k1")}, Candidates: []schedulerAuthCandidate{
		{ID: "claude:b", Priority: 1}, {ID: "claude:a", Priority: 1}, {ID: "codex:x", Priority: 1}, {ID: "claude:low", Priority: 5},
	}}
	for i, want := range []string{"claude:a", "claude:b", "claude:a"} {
		resp, errEnv := pick(t, req)
		if errEnv != nil || !resp.Handled || resp.AuthID != want {
			t.Fatalf("pick %d: got %+v %+v, want %s", i, resp, errEnv, want)
		}
	}
	req.Candidates = []schedulerAuthCandidate{{ID: "codex:x", Priority: 1}}
	if _, errEnv := pick(t, req); errEnv == nil || errEnv.HTTPStatus != 403 {
		t.Fatalf("no allowed candidate must fail with 403, got %+v", errEnv)
	}
}

func TestPickLeavesKeysWithoutProfileRulesToBuiltin(t *testing.T) {
	useDoc(t, policyDocument{Policies: []policyConfig{{CallerScope: callerScopeOf("k1"), DenyModels: []string{"x"}}}})
	req := schedulerPickRequest{Options: schedulerOptions{Metadata: scopeMeta("k1")}, Candidates: []schedulerAuthCandidate{{ID: "claude:a", Priority: 1}}}
	if resp, errEnv := pick(t, req); errEnv != nil || resp.Handled {
		t.Fatalf("expected pass-through to the built-in scheduler, got %+v %+v", resp, errEnv)
	}
	req.Options.Metadata = scopeMeta("unknown")
	if resp, errEnv := pick(t, req); errEnv != nil || resp.Handled {
		t.Fatalf("an unconfigured key must also pass through, got %+v %+v", resp, errEnv)
	}
}
