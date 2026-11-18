package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

func envelopeOf(t *testing.T, raw []byte) envelope {
	t.Helper()
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("bad envelope %q: %v", raw, err)
	}
	return env
}

func TestSafeHandleFailsClosedOnPanic(t *testing.T) {
	boom := func(string, []byte) ([]byte, error) { panic("boom") }

	raw, rc := safeHandle(boom, methodRequestInterceptAfter, nil)
	env := envelopeOf(t, raw)
	var resp requestInterceptResponse
	if rc != 0 || !env.OK || json.Unmarshal(env.Result, &resp) != nil || !resp.Terminate || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("an interceptor panic must reject the request with 403, got rc=%d %s", rc, raw)
	}

	raw, rc = safeHandle(boom, methodSchedulerPick, nil)
	env = envelopeOf(t, raw)
	if rc != 1 || env.OK || env.Error == nil || env.Error.HTTPStatus != http.StatusForbidden {
		t.Fatalf("a scheduler panic must fail with 403, got rc=%d %s", rc, raw)
	}

	raw, rc = safeHandle(boom, methodManagementHandle, nil)
	env = envelopeOf(t, raw)
	if rc != 1 || env.OK || env.Error == nil || env.Error.Code != "plugin_panic" {
		t.Fatalf("any other panic must report plugin_panic, got rc=%d %s", rc, raw)
	}
}

func TestSafeHandlePassesResultsAndErrors(t *testing.T) {
	want := []byte(`{"ok":true}`)
	raw, rc := safeHandle(func(string, []byte) ([]byte, error) { return want, nil }, methodSchedulerPick, nil)
	if rc != 0 || string(raw) != string(want) {
		t.Fatalf("a normal result must pass through, got rc=%d %s", rc, raw)
	}

	raw, rc = safeHandle(func(string, []byte) ([]byte, error) { return nil, errors.New("nope") }, methodPluginRegister, nil)
	env := envelopeOf(t, raw)
	if rc != 1 || env.OK || env.Error == nil || env.Error.Code != "plugin_error" || env.Error.Message != "nope" {
		t.Fatalf("a handler error must become a plugin_error envelope, got rc=%d %s", rc, raw)
	}
}
