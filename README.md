# key-access

A CLIProxyAPI (CPA) plugin that sets per-API-key allow/deny rules for models and for upstream channels (credential profiles), with one policy and one management page.

Status: v0.1. Unit tests, a dlopen ABI harness, a page smoke test (DOM stub) and an end-to-end test pass. The end-to-end test runs a real CPA host built from source with two fake OpenAI-compatible upstreams, on macOS arm64 only. The settings page has not been opened in a real browser, and the plugin has not been tried against real provider accounts.

## How it works

- API keys stay in CPA's top-level `api-keys`. The plugin identifies a key by the `caller_scope` handle the host derives from it, so it never sees or stores raw keys.
- Each key can have a policy with `allow_models`, `deny_models`, `allow_profiles` and `deny_profiles`. `deny` always wins, a non-empty `allow` is a whitelist, an empty `allow` permits everything that is not denied. `*` matches any run of characters (including `/`), `?` matches one character.
- Models are checked before auth against both the requested model name and the resolved model name, so an alias cannot bypass a deny rule.
- Channels are CPA auth IDs. The scheduler narrows the host's candidates to the allowed ones, keeps the highest priority tier and round-robins inside it. After auth the selected auth ID is checked again and a disallowed one is rejected with 403.
- A key without channel rules is left to CPA's built-in scheduler. A key without any policy is allowed, or denied when `unconfigured_key: deny`.
- Fail closed: if no valid policy could be loaded, or the caller identity is missing while policies exist, requests are rejected with 403. A panic inside the plugin is recovered so it cannot take CPA down: the interceptors reject the request with 403 and the scheduler refuses to pick.

## Limits

- The host consults a single scheduler plugin. Do not enable this plugin together with another scheduler plugin such as key-router or key-account-bind.
- The host only offers the highest priority tier to the scheduler, so an allow rule cannot promote a lower tier.
- There is no profile picker yet: channel rules are typed as auth IDs, one pattern per line.
- Auth ID shapes: `openai-compatibility:<channel>:<12 hex>` was observed in the end-to-end run, so `openai-compatibility:my-channel:*` or `*my-channel*` matches that channel. For other providers the IDs are chosen by CPA; other plugins' docs report that OAuth accounts use the auth file name and API keys look like `claude:apikey:<12 hex>`, but this was not verified here. Check the real ID in CPA before relying on a pattern, and test with a spare key first.
- Needs CPA plugin RPC schema 2 or newer. On schema 7 or newer the request body is not sent to the plugin.

## Install

```sh
make check
make build
make install CPA_DIR=/path/to/CLIProxyAPI
```

Merge `config.example.yaml` into CPA's `config.yaml`, then open Key Access in the management panel and enter the management key.

## Install from the plugin store

This repository is its own plugin store source: `registry.json` at the root lists the plugin, and CPA installs it from the latest GitHub Release of this repository (the repository must stay public).

1. Add the source to CPA's `config.yaml`. The official store stays available.

```yaml
plugins:
  enabled: true
  store-sources:
    - "https://raw.githubusercontent.com/brooke1220/cpa-key-access/main/registry.json"
```

2. Reload CPA, open the plugin store in the management panel, install Key Access, then merge the `key-access` block from `config.example.yaml`.

## Release

Push a tag that is `v` plus a dotted numeric version, for example `v0.1.0`:

```sh
git tag v0.1.0
git push origin v0.1.0
```

`.github/workflows/release.yml` builds linux/amd64, linux/arm64, darwin/arm64 and darwin/amd64, then publishes `key-access_<version>_<goos>_<goarch>.zip` and `checksums.txt` to the GitHub Release. CPA reads the latest release, so a new version does not need a `registry.json` change. `registry.json` must be on `main`, because the raw URL above points at that branch. The release workflow and the store install path have not been run yet. Linux builds need Docker on the CI runner, and the macOS amd64 build is cross-compiled and not ABI-checked.

## Persistence

Without `policy_file`, saves from the page live in memory and are lost on restart. To persist them, click 'Save policies to disk' in the page status bar. It reads `plugins_dir` from the host, creates `<plugins_dir>/key-access/policies.yaml` through `initialize-storage`, and writes `policy_file` into the plugin config through the host's `PATCH /v0/management/plugins/key-access/config`, which also saves CPA's `config.yaml`. In Docker, mount the whole plugins directory writable, because the file is replaced by rename. You can also create a file containing `version: 1` and `policies: []` yourself and set `policy_file` to its path. If `policy_file` is set but missing or invalid, the plugin fails closed. Writes are atomic (temp file, fsync, rename) with mode 0600, and a stale `If-Match` revision is rejected with 412.

## Management API

- `GET /v0/management/plugins/key-access/status`
- `GET|PUT /v0/management/plugins/key-access/policies`
- `POST /v0/management/plugins/key-access/reload`
- `POST /v0/management/plugins/key-access/initialize-storage` with `{plugins_dir}`

The page is served at `/v0/resource/plugins/key-access/settings`. Resource pages are not management-authenticated by the host, so the page asks for the management key and keeps it in memory only.

## Develop

`make check` runs gofmt, vet and the tests with the race detector. `make build` writes the c-shared library to `dist/`. `test/abi/harness.c` loads that library with dlopen and drives it through the C ABI.
