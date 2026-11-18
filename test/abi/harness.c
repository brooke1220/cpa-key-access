#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { void *ptr; size_t len; } cliproxy_buffer;
typedef struct { uint32_t abi_version; void *host_ctx; void *call; void *free_buffer; } cliproxy_host_api;
typedef int (*call_fn)(char *, uint8_t *, size_t, cliproxy_buffer *);
typedef void (*free_fn)(void *, size_t);
typedef void (*shutdown_fn)(void);
typedef struct { uint32_t abi_version; call_fn call; free_fn free_buffer; shutdown_fn shutdown; } cliproxy_plugin_api;
typedef int (*init_fn)(cliproxy_host_api *, cliproxy_plugin_api *);

static cliproxy_plugin_api api;
static int failures = 0;

static void check(const char *label, const char *method, const char *req, const char *want, const char *unwanted) {
    cliproxy_buffer out = {0};
    int rc = api.call((char *)method, (uint8_t *)req, strlen(req), &out);
    char *text = out.ptr ? strndup((const char *)out.ptr, out.len) : strdup("");
    int ok = rc == 0 && strstr(text, want) && (!unwanted || !strstr(text, unwanted));
    printf("%s %s\n", ok ? "PASS" : "FAIL", label);
    if (!ok) { printf("  rc=%d want=%s unwanted=%s\n  got=%s\n", rc, want, unwanted ? unwanted : "-", text); failures++; }
    free(text);
    if (out.ptr) api.free_buffer(out.ptr, out.len);
}

int main(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: harness <lib> <scope> <config_b64>\n"); return 2; }
    void *lib = dlopen(argv[1], RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    init_fn init = (init_fn)dlsym(lib, "cliproxy_plugin_init");
    if (!init) { fprintf(stderr, "dlsym: %s\n", dlerror()); return 2; }
    cliproxy_host_api host = {1, NULL, NULL, NULL};
    if (init(&host, &api) != 0 || api.abi_version != 1 || !api.call || !api.free_buffer || !api.shutdown) { fprintf(stderr, "init failed\n"); return 2; }

    char req[4096];
    snprintf(req, sizeof req, "{\"config_yaml\":\"%s\",\"schema_version\":7}", argv[3]);
    check("plugin.register declares management_api", "plugin.register", req, "\"management_api\":true", NULL);
    check("management.register publishes the settings page", "management.register", "{}", "/settings", NULL);
    check("management.handle serves status", "management.handle", "{\"Method\":\"GET\",\"Path\":\"/v0/management/plugins/key-access/status\"}", "\"StatusCode\":200", NULL);
    check("management.handle serves the page", "management.handle", "{\"Method\":\"GET\",\"Path\":\"/v0/resource/plugins/key-access/settings\"}", "\"StatusCode\":200", NULL);

    snprintf(req, sizeof req, "{\"RequestedModel\":\"gpt-5\",\"Metadata\":{\"caller_scope\":\"%s\"}}", argv[2]);
    check("denied model is terminated with 403", "request.intercept_before", req, "\"StatusCode\":403", NULL);
    snprintf(req, sizeof req, "{\"RequestedModel\":\"claude-x\",\"Metadata\":{\"caller_scope\":\"%s\"}}", argv[2]);
    check("allowed model passes", "request.intercept_before", req, "\"ok\":true", "Terminate");
    snprintf(req, sizeof req, "{\"RequestedModel\":\"claude-x\",\"Metadata\":{\"caller_scope\":\"%s\",\"selected_auth_id\":\"codex:x\"}}", argv[2]);
    check("disallowed selected profile is terminated after auth", "request.intercept_after", req, "\"StatusCode\":403", NULL);
    snprintf(req, sizeof req, "{\"Provider\":\"claude\",\"Model\":\"claude-x\",\"Options\":{\"Metadata\":{\"caller_scope\":\"%s\"}},\"Candidates\":[{\"ID\":\"codex:x\",\"Priority\":1},{\"ID\":\"claude:a\",\"Priority\":1}]}", argv[2]);
    check("scheduler picks the allowed profile", "scheduler.pick", req, "\"AuthID\":\"claude:a\"", NULL);
    check("unknown method returns unknown_method", "no.such.method", "{}", "unknown_method", NULL);

    api.shutdown();
    if (failures) { printf("FAILED: %d\n", failures); return 1; }
    printf("ALL PASS\n");
    return 0;
}
