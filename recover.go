package main

import "net/http"

// safeHandle runs handler and turns errors and panics into a response envelope and a C return code.
// A panic that escapes an exported cgo function terminates the whole CPA process, and for the
// access-control hooks it must also fail closed instead of letting the request through.
func safeHandle(handler func(string, []byte) ([]byte, error), method string, request []byte) (raw []byte, rc int) {
	defer func() {
		if recover() != nil {
			raw, rc = panicResponse(method)
		}
	}()
	var err error
	raw, err = handler(method, request)
	if err != nil {
		return errorEnvelope("plugin_error", err.Error(), 0), 1
	}
	return raw, 0
}

// panicResponse answers a call whose handler panicked. Interceptors reject the request and the
// scheduler refuses to pick, both with 403; any other method just reports an error.
func panicResponse(method string) ([]byte, int) {
	const message = "access policy check failed unexpectedly"
	switch method {
	case methodRequestInterceptBefore, methodRequestInterceptAfter:
		if raw, err := terminated(http.StatusForbidden, "plugin_panic", message, nil); err == nil {
			return raw, 0
		}
	case methodSchedulerPick:
		return errorEnvelope("plugin_panic", message, http.StatusForbidden), 1
	}
	return errorEnvelope("plugin_panic", "plugin call failed unexpectedly", 0), 1
}
