package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

type access int

const (
	accessOpen   access = iota // no policy applies; pass through
	accessPolicy               // a per-key policy applies
	accessDenied               // reject outright
)

type decision struct {
	policy runtimePolicy
	scope  string
	kind   access
	reason string
}

// resolve decides which policy applies to the caller described by the host metadata.
// It fails closed when the policy is unavailable or the caller identity is missing
// while policies exist.
func resolve(snap snapshot, metadata map[string]any) decision {
	if snap.BlockAll {
		return decision{kind: accessDenied, reason: "access policy is unavailable"}
	}
	scope, hasScope := callerScopeFromMetadata(metadata)
	if !hasScope {
		if len(snap.ByScope) > 0 || snap.DenyUnconfigured {
			return decision{kind: accessDenied, reason: "caller identity is unavailable"}
		}
		return decision{kind: accessOpen}
	}
	if policy, ok := snap.ByScope[scope]; ok {
		return decision{policy: policy, scope: scope, kind: accessPolicy}
	}
	if snap.DenyUnconfigured {
		return decision{scope: scope, kind: accessDenied, reason: "API key has no access policy"}
	}
	return decision{scope: scope, kind: accessOpen}
}

func callerScopeFromMetadata(metadata map[string]any) (string, bool) {
	raw, ok := metadata["caller_scope"].(string)
	if !ok {
		return "", false
	}
	scope := strings.ToLower(strings.TrimSpace(raw))
	return scope, validSHA256(scope)
}

// interceptRequest enforces model rules before auth and, after auth, re-checks the
// model and verifies the selected upstream profile.
func interceptRequest(raw []byte, afterAuth bool) ([]byte, error) {
	var req requestInterceptRequest
	if err := decodeJSON(raw, &req); err != nil {
		return nil, err
	}
	d := resolve(globalState.view().Snapshot, req.Metadata)
	switch d.kind {
	case accessOpen:
		return okEnvelope(requestInterceptResponse{})
	case accessDenied:
		return terminated(http.StatusForbidden, "access_denied", d.reason, nil)
	}
	if d.policy.hasModelRules() {
		models := nonEmpty(req.RequestedModel, req.Model)
		if len(models) == 0 {
			return terminated(http.StatusForbidden, "model_access_denied", "requested model is unavailable for policy evaluation", nil)
		}
		if !patternAllows(d.policy.AllowModels, d.policy.DenyModels, models...) {
			return terminated(http.StatusForbidden, "model_access_denied", "model is not allowed for this API key", map[string]any{"model": models[0]})
		}
	}
	if afterAuth && d.policy.hasProfileRules() {
		id, _ := req.Metadata["selected_auth_id"].(string)
		id = strings.TrimSpace(id)
		if id == "" {
			return terminated(http.StatusForbidden, "profile_access_denied", "selected upstream profile is unavailable for policy evaluation", nil)
		}
		if !patternAllows(d.policy.AllowProfiles, d.policy.DenyProfiles, id) {
			return terminated(http.StatusForbidden, "profile_access_denied", "profile is not allowed for this API key", map[string]any{"profile": id})
		}
	}
	return okEnvelope(requestInterceptResponse{})
}

// pickProfile narrows the host's candidates to the allowed ones, keeps the highest
// priority tier and round-robins inside it. Keys without profile rules are left to
// the built-in scheduler.
func pickProfile(raw []byte) ([]byte, error) {
	var req schedulerPickRequest
	if err := decodeJSON(raw, &req); err != nil {
		return nil, err
	}
	d := resolve(globalState.view().Snapshot, req.Options.Metadata)
	switch d.kind {
	case accessOpen:
		return okEnvelope(schedulerPickResponse{Handled: false})
	case accessDenied:
		return errorEnvelope("access_denied", d.reason, http.StatusForbidden), nil
	}
	if !d.policy.hasProfileRules() {
		return okEnvelope(schedulerPickResponse{Handled: false})
	}
	var eligible []schedulerAuthCandidate
	top := 0
	for _, c := range req.Candidates {
		c.ID = strings.TrimSpace(c.ID)
		if c.ID == "" || !patternAllows(d.policy.AllowProfiles, d.policy.DenyProfiles, c.ID) {
			continue
		}
		if len(eligible) == 0 || c.Priority > top {
			top = c.Priority
		}
		eligible = append(eligible, c)
	}
	var tier []schedulerAuthCandidate
	for _, c := range eligible {
		if c.Priority == top {
			tier = append(tier, c)
		}
	}
	if len(tier) == 0 {
		return errorEnvelope("profile_access_denied", "no allowed upstream profile is available for this API key", http.StatusForbidden), nil
	}
	sort.Slice(tier, func(i, j int) bool { return tier[i].ID < tier[j].ID })
	provider := req.Provider
	if provider == "" {
		provider = strings.Join(req.Providers, ",")
	}
	key := fmt.Sprintf("%s\x00%s\x00%s\x00%d", d.scope, strings.ToLower(provider), req.Model, top)
	return okEnvelope(schedulerPickResponse{AuthID: tier[globalState.nextIndex(key, len(tier))].ID, Handled: true})
}

func nonEmpty(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		dup := false
		for _, seen := range out {
			dup = dup || seen == v
		}
		if !dup {
			out = append(out, v)
		}
	}
	return out
}

func terminated(status int, kind, message string, extra map[string]any) ([]byte, error) {
	details := map[string]any{"type": kind, "message": message}
	for k, v := range extra {
		details[k] = v
	}
	body, err := json.Marshal(map[string]any{"error": details})
	if err != nil {
		return nil, err
	}
	return okEnvelope(requestInterceptResponse{
		Terminate:       true,
		StatusCode:      status,
		ResponseHeaders: http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
		ResponseBody:    body,
	})
}
