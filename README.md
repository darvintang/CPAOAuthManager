# 凭证管理

统一管理凭证优先级、调度权重与并发上限，支持批量保存、满额切换和实时用量查看。

The plugin uses the official CLIProxyAPI dynamic-library plugin ABI and request
lifecycle hooks. It limits upstream calls per selected CPA account, returns
structured local capacity errors before provider I/O, and provides an
authenticated Management Center view of account usage.

## Features

- Per-account hard in-flight concurrency limits, with individual overrides editable in the plugin UI.
- Local authority for a single CPA process.
- Optional Redis authority for multiple CPA processes sharing the same account
  pool.
- Cache-aware warm/general capacity handling.
- Stable selected-auth identity and failover-safe lease lifecycle.
- Bounded admission wait; no unbounded internal request queue.
- Fail-closed behavior when the configured authority is unavailable or a lease
  cannot be renewed safely.
- Authenticated Management Center usage view with explicit unavailable-auth
  filtering.
- An **All available accounts** summary calculated only from displayed rows.
- No credential JSON, provider token, password, authority key, or Management key
  is returned by the plugin API or rendered in the usage table.

## Compatibility

- Host: CLIProxyAPI/CPA with the native plugin ABI and request-lifecycle support.
- Plugin ID: `cpa-oauth-manager`.
- Current release: `v0.0.2`.
- Published binary targets: **Linux amd64/arm64, macOS amd64/arm64, Windows amd64**.

Release archives use the platform-native dynamic library name: `.so` on Linux,
`.dylib` on macOS, and `.dll` on Windows.

## Configuration

Enable the global plugin system and configure the plugin in the normal
CLIProxyAPI configuration:

```yaml
plugins:
  enabled: true
  dir: plugins
  configs:
    cpa-oauth-manager:
      enabled: true
      admission-enforcing: true
      priority: 100
      max_concurrency: 2
      warm_reserved_slots: 0 # 0 selects the recommended formula
      wait_timeout: 50ms
      authority: local
      redis_prefix: cpa:concurrency
      # Required when authority is redis:
      # redis_addr: 127.0.0.1:6379
      # redis_password: example-value
      # redis_db: 0
```

`max_concurrency` must be at least one. For a hard limit `C`, the recommended
warm reservation is `W=0` for `C<=1`; otherwise it is
`min(C-1, max(1, ceil(0.20*C)))`. General capacity is `G=C-W`.

Set `authority: local` for one CPA process. Use `authority: redis` only when
all participating CPA processes point at the same Redis authority and use a
consistent `redis_prefix`. Keep Redis credentials in the service secret
configuration; never commit them to this repository.

`admission-enforcing: true` is intentional. It makes plugin loading,
registration, incompatible host schemas, callback failures, and authority
failures terminate the request with the typed local 503 error instead of
silently bypassing the configured hard limit.

## Admission and failover behavior

The plugin reserves a lease during scheduler selection, before CPA starts the
upstream request. It tries remaining eligible credentials if another request
takes the final slot. After-auth admission reuses that lease without double counting.
Repeated post-auth callbacks for the same request are idempotent. When CPA
retries or fails over to another account, the previous lease is released before
the new lease is acquired, so leases do not stack across accounts.

`request.complete` releases the final lease for successful requests, provider
failures, stream termination, cancellation, timeout, client disconnect,
rejection, and plugin errors. Admission waits at most `wait_timeout`.

A local capacity rejection is returned before executor/provider I/O:

```http
HTTP/1.1 503 Service Unavailable
Retry-After: 1
Content-Type: application/json
```

```json
{
  "error": {
    "type": "account_concurrency_limit",
    "code": "account_concurrency_limit",
    "message": "account concurrency limit reached",
    "retryable": true
  }
}
```

Authority failures use the separate
`account_concurrency_authority_unavailable` code. They are not provider 429
responses and should not be treated as provider health or breaker failures.

Redis leases use bounded expiry and heartbeat renewal. Uncertain authority
operations fail closed; the plugin does not assume that a lost lease was safely
released.

## Management observability

The usage view reads the authenticated CPA route:

```text
/v0/management/plugins/cpa-oauth-manager/usage
```

It uses CPA's stock `host.auth.list` callback as the account index and filters an
entry only when explicit metadata marks it disabled, unavailable,
unauthorized, authentication-failed, or inside a future retry window. Account
names and filenames are not used as availability heuristics, so an available
account whose name contains `401` remains visible.

The view displays idle available accounts as `0 / limit` and `0 / reserved`.
The editable table lists all credentials with their status, priority, scheduling
weight, concurrency limit and active requests. Summary metrics cover available
credentials only.

The **All available accounts** summary sums only the rows shown in that table.
Filtered or unavailable accounts do not contribute to the totals.

The page follows the Management Center language (简体中文、繁體中文、English、Русский)
and theme. Background refresh preserves the current rows and in-progress edits.
The table includes enabled, disabled and temporarily unavailable credentials.
Edit priority, scheduling weight and concurrency limits locally, then click Save all
changes. Priority and weight use the host credential field API; concurrency limits
use plugin configuration. Failed saves keep pending edits for retry; the host does
not provide a transaction across credential files and plugin configuration.
The plugin persists opaque
credential IDs under `credential_limits` and uses those limits for admission,
scheduling, and summary totals. `max_concurrency` remains the fallback for
credentials without an override.

The UI reuses the Management Center's saved login on the same origin, including
its encoded storage and legacy Management key format. Enable “Remember password”
when signing in to the Management Center. Automatically read keys are used only
in authentication headers and are never copied into the plugin's password field
or storage. The password field is hidden when authentication is available and shown only
when credentials are missing or rejected.
The plugin does not request or store provider credentials.

## Install the published release

Download the assets from the public GitHub Release:

<https://github.com/darvintang/cpa-oauth-manager/releases/tag/v0.0.2>

The release contains all CPA Plugin Store required targets:

```text
cpa-oauth-manager_0.0.2_linux_amd64.zip
cpa-oauth-manager_0.0.2_linux_arm64.zip
cpa-oauth-manager_0.0.2_darwin_amd64.zip
cpa-oauth-manager_0.0.2_darwin_arm64.zip
cpa-oauth-manager_0.0.2_windows_amd64.zip
registry.json
checksums.txt
```

Verify the archive before installation:

```bash
sha256sum --check checksums.txt
unzip -t cpa-oauth-manager_0.0.2_linux_amd64.zip
```

Each archive contains exactly one root-level dynamic library named for its
platform: `cpa-oauth-manager.so`, `cpa-oauth-manager.dylib`, or
`cpa-oauth-manager.dll`.

For manual installation, place the versioned library under the CLIProxyAPI
plugin directory for the target platform:

```text
plugins/linux/amd64/cpa-oauth-manager-v0.0.2.so
```

Restart or reload CLIProxyAPI according to its normal plugin lifecycle after
installation. The official CLIProxyAPI plugin store can install the same
release after the registry entry is accepted.

## Build and release provenance

The CLIProxyAPI SDK is a public, versioned module dependency pinned in
`go.mod`, with its checksums committed in `go.sum`. The project does not use a
local SDK checkout or a `replace` directive.

To run the same checks and a native target build used by release `v0.0.2`:

```bash
go mod tidy
git diff --exit-code -- go.mod go.sum
GOOS=linux GOARCH=amd64 scripts/build-release.sh 0.0.2
(cd dist && sha256sum --check checksums.txt)
```

The tag-triggered GitHub Actions workflow performs these checks from a clean
checkout, builds the five required native CGO targets on matching GitHub-hosted
runners, packages one root-level dynamic library per ZIP, generates one combined
`checksums.txt`, uploads the result as workflow evidence, and publishes the
assets to the matching GitHub Release. See [`RELEASE.md`](RELEASE.md) for the complete
process. The plugin does not require a CLIProxyAPI source modification.

## Official plugin store

This repository is prepared for submission to the official CLIProxyAPI plugin
registry:

<https://github.com/router-for-me/CLIProxyAPI-Plugins-Store>

The official store maintains registry metadata only. Plugin binaries,
`checksums.txt`, and release notes remain in this repository. Store inclusion is
controlled by the upstream registry review and should not be assumed until the
corresponding registry pull request is merged.

## Security and trust

Native plugins run in-process with CLIProxyAPI and must be treated as trusted
code. Review the source and release checksum before installation. Do not commit
provider credentials, Redis passwords, Management keys, cookies, or API tokens
to this repository or to a release asset.

## License

MIT. See the repository license notice for the applicable terms.

Higher-priority credentials are preferred while they have capacity; lower tiers
are eligible when the higher tiers are full. Zero weight excludes a credential
from automatic selection. Explicit caller pinning still preserves identity.
The current host may wrap an all-full scheduler rejection as HTTP 503 with
`internal_server_error`; automatic failover happens before that response.
