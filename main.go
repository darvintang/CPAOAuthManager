package main

/*
#include <stdint.h>
#include <stdlib.h>
typedef struct { void* ptr; size_t len; } cliproxy_buffer;
typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);
typedef struct { uint32_t abi_version; void* host_ctx; cliproxy_host_call_fn call; cliproxy_host_free_fn free_buffer; } cliproxy_host_api;
typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);
typedef struct { uint32_t abi_version; cliproxy_plugin_call_fn call; cliproxy_plugin_free_fn free_buffer; cliproxy_plugin_shutdown_fn shutdown; } cliproxy_plugin_api;
extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);

static const cliproxy_host_api* stored_host;
static void store_host_api(const cliproxy_host_api* host) { stored_host = host; }
static void clear_host_api(void) { stored_host = NULL; }
static int call_host_api(const char* method, const uint8_t* request, size_t request_len, cliproxy_buffer* response) {
	if (stored_host == NULL || stored_host->call == NULL) return 1;
	return stored_host->call(stored_host->host_ctx, method, request, request_len, response);
}
static void free_host_buffer(void* ptr, size_t len) {
	if (stored_host != NULL && stored_host->free_buffer != NULL && ptr != NULL) stored_host->free_buffer(ptr, len);
}
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"gopkg.in/yaml.v3"
)

// Keep cpa-oauth-manager consistent across routing, registry metadata and release filenames; localize the display name separately.
const pluginID = "cpa-oauth-manager"
const requestReservationHeader = "X-Cpa-Concurrency-Request"

// authorityCallTimeout bounds release/renew/snapshot calls that are not
// already covered by the request admission wait timeout.  A lost authority
// must never leave a callback blocked forever.
const authorityCallTimeout = 2 * time.Second

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *envelopeError  `json:"error,omitempty"`
}
type envelopeError struct {
	Code       string `json:"code"`
	Class      string `json:"class,omitempty"`
	Message    string `json:"message"`
	Retryable  bool   `json:"retryable,omitempty"`
	HTTPStatus int    `json:"http_status,omitempty"`
	RetryAfter int    `json:"retry_after,omitempty"`
}
type lifecycleRequest struct {
	ConfigYAML    []byte `json:"config_yaml"`
	SchemaVersion uint32 `json:"schema_version"`
}

type quiesceRequest struct {
	DeadlineUnixNano int64 `json:"deadline_unix_nano,omitempty"`
}
type registration struct {
	SchemaVersion uint32                   `json:"schema_version"`
	Metadata      pluginapi.Metadata       `json:"metadata"`
	Capabilities  registrationCapabilities `json:"capabilities"`
}
type registrationCapabilities struct {
	SchedulerAcrossPriorities           bool `json:"scheduler_across_priorities"`
	Scheduler                           bool `json:"scheduler"`
	RequestInterceptor                  bool `json:"request_interceptor"`
	RequestInterceptorEnforcesAdmission bool `json:"request_interceptor_enforces_admission"`
	RequestLifecyclePlugin              bool `json:"request_lifecycle_plugin"`
	ManagementAPI                       bool `json:"management_api"`
}

type managementRegistrationPayload struct {
	Routes    []pluginapi.ManagementRoute `json:"routes,omitempty"`
	Resources []pluginapi.ResourceRoute   `json:"resources,omitempty"`
}

type concurrencySnapshot struct {
	ConfiguredLimit   int                `json:"-"`
	WarmReserved      int                `json:"-"`
	InFlight          int                `json:"-"`
	WarmInFlight      int                `json:"-"`
	GeneralInFlight   int                `json:"-"`
	GeneralCapacity   int                `json:"-"`
	AvailableCapacity int                `json:"-"`
	Authority         string             `json:"authority"`
	AuthorityState    string             `json:"authority_state"`
	CapacityState     string             `json:"-"`
	AccountsInUse     int                `json:"-"`
	Empty             bool               `json:"-"`
	LastRefresh       time.Time          `json:"last_refresh"`
	Stale             bool               `json:"stale"`
	Error             string             `json:"error,omitempty"`
	Accounts          []AccountUsage     `json:"accounts,omitempty"`
	Summary           concurrencySummary `json:"summary,omitempty"`
}

type concurrencySummary struct {
	Label        string           `json:"label"`
	Total        totalUsageMetric `json:"total"`
	WarmReserved warmUsageMetric  `json:"warm_reserved"`
}

type totalUsageMetric struct {
	InFlight int `json:"in_flight"`
	Limit    int `json:"limit"`
}

type warmUsageMetric struct {
	InFlight int `json:"in_flight"`
	Reserved int `json:"reserved"`
}

const (
	managementUsagePath = "/plugins/cpa-oauth-manager/usage"
	managementUIPath    = "/ui"
)

type managementHandler struct{}

type hostAuthListResponse struct {
	Files []pluginapi.HostAuthFileEntry `json:"files"`
}

type hostAuthListCallResult struct {
	raw  []byte
	code int
}

type hostAuthListCallState struct {
	mu            sync.Mutex
	inFlight      bool
	activeWorkers int
	done          chan struct{}
	retiring      bool
}

var (
	hostAuthCallState hostAuthListCallState
	hostAuthInvoker   = invokeHostAuthList
	hostAuthTimeout   = authorityCallTimeout
)

// invokeHostAuthList performs the stock callback and copies only its bounded
// response bytes before returning. The caller runs it in a worker so a host
// callback that never returns cannot hold a management request open forever.
func invokeHostAuthList() hostAuthListCallResult {
	method := C.CString(pluginabi.MethodHostAuthList)
	defer C.free(unsafe.Pointer(method))
	payload := []byte(`{}`)
	payloadPtr := C.CBytes(payload)
	if payloadPtr == nil {
		return hostAuthListCallResult{code: -1}
	}
	defer C.free(payloadPtr)
	var response C.cliproxy_buffer
	callCode := C.call_host_api(method, (*C.uint8_t)(payloadPtr), C.size_t(len(payload)), &response)
	if response.ptr == nil || response.len == 0 {
		return hostAuthListCallResult{code: int(callCode)}
	}
	defer C.free_host_buffer(response.ptr, response.len)
	return hostAuthListCallResult{raw: C.GoBytes(response.ptr, C.int(response.len)), code: int(callCode)}
}

// hostAuthMetadata uses CPA's stock host.auth.list callback. The callback only
// exposes redacted auth metadata (ID/name/email); credential JSON is never
// requested, retained, or included in management responses.
func hostAuthMetadata() (map[string]pluginapi.HostAuthFileEntry, error) {
	hostAuthCallState.mu.Lock()
	if hostAuthCallState.inFlight || hostAuthCallState.retiring {
		hostAuthCallState.mu.Unlock()
		return nil, errors.New("host auth list callback still pending")
	}
	hostAuthCallState.inFlight = true
	hostAuthCallState.activeWorkers++
	workerDone := make(chan struct{})
	hostAuthCallState.done = workerDone
	hostAuthCallState.mu.Unlock()

	done := make(chan hostAuthListCallResult, 1)
	go func() {
		hostAuthCallState.mu.Lock()
		if hostAuthCallState.retiring {
			hostAuthCallState.inFlight = false
			hostAuthCallState.activeWorkers--
			if hostAuthCallState.done == workerDone {
				hostAuthCallState.done = nil
			}
			close(workerDone)
			hostAuthCallState.mu.Unlock()
			done <- hostAuthListCallResult{code: -1}
			return
		}
		invoker := hostAuthInvoker
		hostAuthCallState.mu.Unlock()

		result := invoker()
		hostAuthCallState.mu.Lock()
		hostAuthCallState.inFlight = false
		hostAuthCallState.activeWorkers--
		if hostAuthCallState.done == workerDone {
			hostAuthCallState.done = nil
		}
		close(workerDone)
		hostAuthCallState.mu.Unlock()
		done <- result
	}()
	var result hostAuthListCallResult
	select {
	case result = <-done:
	case <-time.After(hostAuthTimeout):
		return nil, errors.New("host auth list callback timed out")
	}
	if result.code != 0 {
		return nil, fmt.Errorf("host auth list callback failed (code=%d)", result.code)
	}
	if len(result.raw) == 0 {
		return nil, errors.New("host auth list unavailable")
	}
	var env envelope
	if err := json.Unmarshal(result.raw, &env); err != nil {
		return nil, fmt.Errorf("decode host auth list response: %w", err)
	}
	if !env.OK {
		if env.Error != nil {
			return nil, fmt.Errorf("host auth list: %s", env.Error.Message)
		}
		return nil, errors.New("host auth list failed")
	}
	var listed hostAuthListResponse
	if err := json.Unmarshal(env.Result, &listed); err != nil {
		return nil, fmt.Errorf("decode host auth metadata: %w", err)
	}
	if len(listed.Files) == 0 {
		return nil, errors.New("host auth list returned no entries")
	}
	byKey := make(map[string]pluginapi.HostAuthFileEntry, len(listed.Files))
	for _, entry := range listed.Files {
		if authEntryUnavailable(entry) {
			continue
		}
		id := canonicalAuthID(entry.ID)
		if id == "" {
			// CPA's stock disk fallback has no runtime ID; its Name is the
			// auth JSON filename and is the stable identity in that mode.
			id = canonicalAuthID(entry.Name)
		}
		if id == "" {
			return nil, errors.New("host auth list returned malformed entry")
		}
		byKey[accountKey("cpa", id)] = entry
	}
	return byKey, nil
}

// authEntryUnavailable is intentionally based only on explicit host status
// metadata. Names, IDs, labels, paths, and credential contents are never
// consulted when deciding whether an account can be displayed.
func authEntryUnavailable(entry pluginapi.HostAuthFileEntry) bool {
	if entry.Disabled || entry.Unavailable {
		return true
	}
	if !entry.NextRetryAfter.IsZero() && entry.NextRetryAfter.After(time.Now()) {
		return true
	}
	status := strings.ToLower(strings.TrimSpace(entry.Status))
	message := strings.ToLower(strings.TrimSpace(entry.StatusMessage))
	for _, value := range []string{status, message} {
		if explicitUnavailableStatus(value) {
			return true
		}
	}
	return false
}

func explicitUnavailableStatus(value string) bool {
	if value == "" {
		return false
	}
	// Status messages are structured metadata supplied by the host. Match
	// authentication failures and explicit unusable states, including HTTP 401,
	// without applying any heuristic to account names or filenames.
	for _, token := range []string{"disabled", "unavailable", "unauthorized", "unauthorised", "unauthenticated", "authentication failed", "authentication failure", "authentication_failure", "authentication_error", "authentication_required", "auth failed", "auth_failure", "auth_error", "auth_required", "invalid credential", "invalid_credentials", "login required", "login_required", "not ready", "not_ready", "unusable", "cannot use", "cannot_use", "no credentials", "missing credential", "reauth", "relogin", "re-login", "reauthorize", "re-authorize", "forbidden", "rate limited", "rate_limited", "quota exhausted", "quota_exhausted", "suspended", "revoked", "401", "403", "429"} {
		if strings.Contains(value, token) {
			return true
		}
	}
	for _, token := range []string{"error", "failed", "failure", "cooldown", "cooling", "blocked", "expired", "revoked", "degraded"} {
		if value == token || strings.HasPrefix(value, token+" ") || strings.HasPrefix(value, token+":") || strings.HasPrefix(value, token+"_") || strings.HasPrefix(value, token+"-") {
			return true
		}
	}
	return false
}

// retireHostAuthWorker fences new host callbacks and joins the sole callback
// worker. The management timeout remains bounded; lifecycle transitions wait
// for a timed-out callback before CPA can release the host API or unload us.
func retireHostAuthWorker() {
	hostAuthCallState.mu.Lock()
	hostAuthCallState.retiring = true
	workerDone := hostAuthCallState.done
	hostAuthCallState.mu.Unlock()
	if workerDone != nil {
		<-workerDone
	}
}

func resumeHostAuthWorker() {
	hostAuthCallState.mu.Lock()
	hostAuthCallState.retiring = false
	hostAuthCallState.mu.Unlock()
}

func accountLabel(key string, metadata map[string]pluginapi.HostAuthFileEntry) string {
	entry, ok := metadata[key]
	if ok {
		if email := strings.TrimSpace(entry.Email); email != "" {
			return email
		}
		if name := strings.TrimSpace(entry.Name); name != "" {
			return name
		}
	}
	return "Account"
}

func managementRegistrationResponse() managementRegistrationPayload {
	return managementRegistrationPayload{
		Routes:    []pluginapi.ManagementRoute{{Method: http.MethodGet, Path: managementUsagePath}},
		Resources: []pluginapi.ResourceRoute{{Path: managementUIPath, Menu: "凭证管理", Description: "按凭证限制并发请求，支持缓存亲和、共享并发控制和实时用量查看。"}},
	}
}

func (managementHandler) HandleManagement(ctx context.Context, req pluginapi.ManagementRequest) (pluginapi.ManagementResponse, error) {
	if req.Path == managementUIPath || strings.HasSuffix(req.Path, managementUIPath) {
		return pluginapi.ManagementResponse{StatusCode: http.StatusOK, Headers: http.Header{"Content-Type": []string{"text/html; charset=utf-8"}, "Cache-Control": []string{"no-store"}}, Body: []byte(managementHTMLAuthenticated)}, nil
	}
	if req.Method != http.MethodGet {
		return pluginapi.ManagementResponse{StatusCode: http.StatusMethodNotAllowed, Headers: http.Header{"Allow": []string{http.MethodGet}, "Content-Type": []string{"application/json"}}, Body: []byte(`{"error":"method_not_allowed"}`)}, nil
	}
	snapshot := readConcurrencySnapshot(ctx)
	body, err := json.Marshal(snapshot)
	if err != nil {
		return pluginapi.ManagementResponse{}, err
	}
	return pluginapi.ManagementResponse{StatusCode: http.StatusOK, Headers: http.Header{"Content-Type": []string{"application/json"}, "Cache-Control": []string{"no-store"}}, Body: body}, nil
}

func readConcurrencySnapshot(ctx context.Context) concurrencySnapshot {
	state.gate.RLock()
	defer state.gate.RUnlock()
	state.mu.Lock()
	cfg, authority, uncertain, stopping := state.cfg, state.authority, state.uncertain, state.stopping
	state.mu.Unlock()
	s := concurrencySnapshot{ConfiguredLimit: cfg.MaxConcurrency, WarmReserved: cfg.WarmReservedSlots, GeneralCapacity: maxInt(0, cfg.MaxConcurrency-cfg.WarmReservedSlots), Authority: cfg.Authority, AuthorityState: "available", CapacityState: "available", LastRefresh: time.Now().UTC()}
	if stopping || uncertain || authority == nil {
		s.AuthorityState = "unavailable"
		s.CapacityState = "unavailable"
		s.Stale = true
		s.Error = "concurrency authority unavailable"
		return s
	}
	if _, ok := authority.(*redisAuthority); ok {
		s.AuthorityState = "connected"
	}
	if local, ok := authority.(*localAuthority); ok {
		u, accounts, err := local.AggregateSnapshot(ctx, cfg.MaxConcurrency, cfg.WarmReservedSlots)
		if err != nil {
			s.AuthorityState, s.Stale, s.Error = "unavailable", true, "concurrency authority unavailable"
			return s
		}
		s.InFlight, s.WarmInFlight, s.AccountsInUse = u.InFlight, u.WarmFlight, accounts
	}
	// The stock host listing is the sole available-account index for every
	// authority. It must succeed before any account can be rendered as
	// available; authority usage is then read independently for each listed key.
	metadata, metadataErr := hostAuthMetadata()
	if metadataErr != nil {
		s.Stale = true
		s.Error = "account list unavailable"
	} else {
		accounts, usage, usageErr := availableAccountSnapshots(ctx, authority, metadata, cfg)
		if usageErr != nil {
			s.Stale = true
			s.Error = "concurrency authority unavailable"
			s.AuthorityState = "unavailable"
			s.CapacityState = "unavailable"
		} else {
			s.Accounts = accounts
			s.InFlight, s.WarmInFlight, s.AccountsInUse = usage.InFlight, usage.WarmFlight, countActiveAccounts(accounts)
			s.Summary = summaryFromAccounts(accounts)
		}
	}
	if !s.Stale {
		s.GeneralInFlight = maxInt(0, s.InFlight-s.WarmInFlight)
		s.Empty = s.InFlight == 0
		if s.Empty {
			s.CapacityState = "empty"
		}
	}
	return s
}

func summaryFromAccounts(accounts []AccountUsage) concurrencySummary {
	summary := concurrencySummary{Label: "All available accounts"}
	for _, account := range accounts {
		summary.Total.InFlight += account.InFlight
		summary.Total.Limit += account.Limit
		summary.WarmReserved.InFlight += account.WarmFlight
		summary.WarmReserved.Reserved += account.Reserved
	}
	return summary
}

// availableAccountSnapshots reads usage only for accounts successfully returned
// by the host listing. A failed authority read is not converted to zero usage.
func availableAccountSnapshots(ctx context.Context, authority Authority, metadata map[string]pluginapi.HostAuthFileEntry, cfg pluginConfig) ([]AccountUsage, Usage, error) {
	ctx, cancel := ensureAuthorityContext(ctx)
	defer cancel()
	keys := make([]string, 0, len(metadata))
	for key := range metadata {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	accounts := make([]AccountUsage, 0, len(keys))
	var total Usage
	total.Limit, total.Reserved = cfg.MaxConcurrency, cfg.WarmReservedSlots
	for _, key := range keys {
		limit, reserved := cfg.limitsFor(key)
		u, err := authority.Snapshot(ctx, key, limit, reserved)
		if err != nil {
			return nil, Usage{}, err
		}
		accounts = append(accounts, AccountUsage{Key: key, ConfigID: key, Label: accountLabel(key, metadata), Limit: limit, Reserved: reserved, InFlight: u.InFlight, WarmFlight: u.WarmFlight})
		total.InFlight += u.InFlight
		total.WarmFlight += u.WarmFlight
	}
	return accounts, total, nil
}

func countActiveAccounts(accounts []AccountUsage) int {
	count := 0
	for _, account := range accounts {
		if account.InFlight > 0 {
			count++
		}
	}
	return count
}

// managementHTMLAuthenticated reuses the same-origin Management Center login.
// Show manual credentials only when automatic authentication is unavailable or rejected.
// Host credentials stay in host storage and are sent only in authentication headers;
// the password input and manual fallback storage never receive the host key.
const managementHTMLAuthenticated = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Credential Manager</title>
<style>
:root{color-scheme:light;--bg:#fff;--panel:#fff;--alt:#f5f5f5;--text:#242424;--muted:#737373;--line:#e5e5e5;--brand:#424242;--success:#10b981}
:root[data-theme="white"]{--bg:#fff;--panel:#fff;--alt:#f5f5f5;--text:#242424;--muted:#737373;--line:#e5e5e5;--brand:#424242}
:root[data-theme="dark"]{color-scheme:dark;--bg:#151412;--panel:#1d1b18;--alt:#262320;--text:#f6f4f1;--muted:#c9c3bb;--line:#3a3530;--brand:#8b8680}
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:var(--bg);color:var(--text);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;-webkit-font-smoothing:antialiased}
.shell{width:min(1280px,calc(100% - 48px));margin:0 auto;padding:32px 0 48px}header{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:20px}h1{margin:0 0 6px;font-size:clamp(24px,2.4vw,28px);line-height:1.25;letter-spacing:-.025em}h2{margin:0;font-size:15px;font-weight:650}p{margin:0;color:var(--muted)}.subtitle{font-size:13px}.auth{font-size:12px;color:var(--muted);margin-top:10px}.toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center}.cards{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-bottom:16px}.card,.panel,.settings{background:var(--panel);border:1px solid var(--line);border-radius:12px;box-shadow:0 1px 2px #0000000a}.card{padding:18px}.card dt{font-size:12px;color:var(--muted)}.card dd{margin:10px 0 0;font-size:clamp(22px,2.2vw,28px);font-weight:700;line-height:1.2;font-variant-numeric:tabular-nums}.cards{padding:0}dl{margin:0}.panel{overflow:hidden}.panel-head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:16px;border-bottom:1px solid var(--line)}.panel-head span{font-size:12px;color:var(--muted)}.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse}th,td{padding:14px 16px;border-bottom:1px solid var(--line);text-align:right;font-variant-numeric:tabular-nums}th{font-size:12px;color:var(--muted);background:var(--alt);font-weight:600}th:first-child,td:first-child{text-align:left}td:first-child{overflow-wrap:anywhere;min-width:160px;font-weight:600}tbody tr:last-child td{border:0}tbody tr:hover{background:var(--alt)}.empty td{text-align:center;font-weight:400;color:var(--muted);padding:40px 16px}.status{font-size:12px;color:var(--muted);border-left:3px solid var(--success);padding:4px 12px;margin:0 0 18px}.settings{margin-top:16px;padding:14px 16px}.settings summary{cursor:pointer;font-weight:600}.settings form{display:flex;flex-wrap:wrap;align-items:end;gap:8px;margin-top:16px}.settings label{display:flex;flex:1 1 240px;flex-direction:column;gap:6px;font-size:12px;color:var(--muted)}button,input,select{border:1px solid var(--line);border-radius:8px;background:var(--panel);color:var(--text);min-height:36px;padding:7px 12px;font:inherit}button{cursor:pointer;font-weight:600}button:hover{background:var(--alt)}button.primary{background:var(--brand);border-color:var(--brand);color:#fff;white-space:nowrap}button:disabled{opacity:.55;cursor:wait}button:focus-visible,input:focus-visible,summary:focus-visible{outline:2px solid var(--success);outline-offset:3px}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
.config-status:not(:empty){padding:12px 16px;border-bottom:1px solid var(--line)}#accounts input{width:92px}#accounts td small{display:block;color:var(--muted);font-size:11px;font-weight:400}#accounts tr.dirty{background:var(--alt)}.limit-form{display:flex;align-items:center;flex-wrap:wrap;gap:12px}.limit-form label{display:flex;flex-direction:column;gap:3px;flex:1 1 240px;font-weight:600}.limit-form small{font-weight:400;color:var(--muted)}#concurrency-limit{width:100px}#credential-select{max-width:100%;flex:1 1 200px;min-width:0}#config-status:not(:empty){margin-top:10px;font-size:12px}
.column-label{display:inline-flex;align-items:center;gap:5px;white-space:nowrap}.info-button{display:inline-flex;align-items:center;justify-content:center;min-height:26px;width:26px;padding:3px;border:0;background:transparent;color:var(--muted);border-radius:50%}.info-button:hover{color:var(--text);background:var(--line)}.help-popover{position:fixed;inset:auto;margin:0;width:min(330px,calc(100vw - 32px));padding:16px;border:1px solid var(--line);border-radius:12px;background:var(--panel);color:var(--text);box-shadow:0 8px 28px #0002}.help-popover p{margin-top:8px;font-size:13px;line-height:1.7}table{min-width:880px}th,td:not(:first-child){white-space:nowrap}.card{min-width:0}
@media(max-width:640px){.shell{width:calc(100% - 28px);padding:20px 0 32px}header{flex-direction:column}.cards{grid-template-columns:1fr}.card{padding:14px}.panel-head{align-items:flex-start;flex-direction:column}th,td{padding:12px}.settings button{flex:1}h1{font-size:24px}}
</style></head><body><main class="shell">
<header><div><h1 data-i18n="Credential Manager">Credential Manager</h1><p class="subtitle" data-i18n="Per-credential concurrency and cache reservations">Per-credential concurrency and cache reservations</p><p id="key-status" class="auth" role="status" aria-live="polite"></p></div><div class="toolbar"><button id="refresh" class="primary" type="button" data-i18n="Refresh now">Refresh now</button></div></header>
<div id="state" class="status" role="status" aria-live="polite" data-i18n="Loading live usage...">Loading live usage...</div>
<dl class="cards"><div class="card"><dt data-i18n="All credentials">All credentials</dt><dd id="summary-count">--</dd></div><div class="card"><dt data-i18n="Total (in-flight / limit)">Total (in-flight / limit)</dt><dd id="summary-total">--</dd></div><div class="card"><dt data-i18n="Warm reserved (in-flight / reserved)">Warm reserved (in-flight / reserved)</dt><dd id="summary-warm">--</dd></div></dl>
<section class="panel"><div class="panel-head"><h2 data-i18n="All credentials">All credentials</h2><div class="toolbar"><span id="updated" aria-live="polite"></span><button id="save-all" class="primary" type="button" disabled data-i18n="Save all changes">Save all changes</button></div></div><p id="config-status" class="config-status" role="status" aria-live="polite"></p><div class="table-wrap"><table><caption class="sr-only" data-i18n="All credentials">All credentials</caption><thead><tr><th scope="col" data-i18n="Account">Account</th><th scope="col" data-i18n="Status">Status</th><th scope="col"><span class="column-label"><span data-i18n="Priority">Priority</span><button type="button" class="info-button" popovertarget="priority-help" data-i18n-aria="Priority details" aria-label="Priority details"><svg viewBox="0 0 20 20" width="16" height="16" aria-hidden="true"><circle cx="10" cy="10" r="7.25" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M10 9v5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/><circle cx="10" cy="6" r="1" fill="currentColor"/></svg></button></span></th><th scope="col"><span class="column-label"><span data-i18n="Scheduling weight">Scheduling weight</span><button type="button" class="info-button" popovertarget="weight-help" data-i18n-aria="Scheduling weight details" aria-label="Scheduling weight details"><svg viewBox="0 0 20 20" width="16" height="16" aria-hidden="true"><circle cx="10" cy="10" r="7.25" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M10 9v5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/><circle cx="10" cy="6" r="1" fill="currentColor"/></svg></button></span></th><th scope="col" data-i18n="Concurrency limit">Concurrency limit</th><th scope="col" data-i18n="Active requests">Active requests</th></tr></thead><tbody id="accounts"></tbody></table></div></section>
<details id="settings" class="settings" hidden><summary id="settings-title" data-i18n="Settings">Settings</summary><form id="settings-form"><label for="management-key"><span data-i18n="CPA Management key">CPA Management key</span><input id="management-key" name="management-key" type="password" autocomplete="off" spellcheck="false"></label><button id="save-key" type="submit" data-i18n="Save key">Save key</button><button id="clear-key" type="button" data-i18n="Clear saved key">Clear saved key</button></form></details>
<div id="priority-help" class="help-popover" popover><h2 data-i18n="Priority">Priority</h2><p data-i18n="Priority explanation"></p></div><div id="weight-help" class="help-popover" popover><h2 data-i18n="Scheduling weight">Scheduling weight</h2><p data-i18n="Weight explanation"></p></div>
</main>
<script>(function(){
const api='/v0/management/plugins/cpa-oauth-manager/usage',storageKey='cpa-oauth-manager.management-key';
const state=document.getElementById('state'),accounts=document.getElementById('accounts'),updated=document.getElementById('updated'),summaryTotal=document.getElementById('summary-total'),summaryWarm=document.getElementById('summary-warm'),keyInput=document.getElementById('management-key'),keyStatus=document.getElementById('key-status');
// Follow CPAMC persisted language; preserve English API identifiers and credential values.
const messages={
  "zh-CN": {
    "Credential Manager": "凭证管理",
    "Settings": "设置",
    "CPA Management key": "CPA 管理密码",
    "Save key": "保存密码",
    "Clear saved key": "清除已存密码",
    "Refresh now": "立即刷新",
    "All available accounts": "所有可用凭证",
    "Total (in-flight / limit)": "总并发（使用中 / 上限）",
    "Warm reserved (in-flight / reserved)": "缓存预留（使用中 / 预留）",
    "Available CPA accounts": "可用 CPA 凭证",
    "Account": "凭证",
    "Loading live usage...": "正在加载实时用量…",
    "Management key required. Save a key in Settings to load live usage.": "未读取到管理密码。请在管理中心登录时勾选“记住密码”，或在设置中填写。",
    "Management authentication required.": "管理认证失败，请重新登录管理中心或更新密码。",
    "Unable to load live usage.": "无法加载实时用量。",
    "Using Management Center authentication.": "已自动使用管理中心登录凭据。",
    "Enter a Management key.": "请输入管理密码。",
    "Unable to save the Management key in this browser.": "无法在此浏览器中保存管理密码。",
    "Management key saved for this browser.": "已在此浏览器中保存管理密码。",
    "Unable to clear the saved Management key.": "无法清除已保存的管理密码。",
    "Saved Management key cleared.": "已清除手动保存的管理密码。",
    "Authority: ": "并发控制状态：",
    "Last refresh ": "上次刷新：",
    "available": "可用",
    "unavailable": "不可用",
    "connected": "已连接",
    "unknown": "未知",
    "stale": "数据已过期",
    "concurrency authority unavailable": "并发控制服务不可用",
    "account list unavailable": "无法获取凭证列表",
    "Per-credential concurrency and cache reservations": "管理所有凭证的优先级、调度权重与并发上限",
    "No available credentials": "暂无可用凭证",
    "Concurrency limit per credential": "每个凭证的并发上限",
    "Choose a credential and set its own limit": "选择凭证，单独设置并发上限",
    "Save": "保存",
    "Enter an integer greater than zero.": "请输入大于 0 的整数。",
    "Saving...": "正在保存…",
    "Concurrency limit saved.": "并发上限已保存。",
    "Unable to load concurrency settings.": "无法加载并发设置。",
    "Unable to save concurrency settings.": "无法保存并发设置，请重试。",
    "Save all changes": "保存全部修改",
    "All credentials": "所有凭证",
    "Priority": "优先级",
    "Scheduling weight": "调度权重",
    "Concurrency limit": "并发上限",
    "Active requests": "当前并发",
    "Status": "状态",
    "Enabled": "已启用",
    "Disabled": "已停用",
    "Unavailable": "暂不可用",
    "Unsaved changes": "有未保存的修改",
    "All changes saved.": "全部修改已保存。",
    "Some changes could not be saved. Pending edits are retained; retry Save.": "部分修改保存失败，未成功的修改已保留，请重试保存。",
    "Enter valid integers: priority, weight ≤1000000, concurrency 1–1000000.": "请输入有效整数：优先级、权重 ≤1000000、并发上限 1–1000000。",
    "Credentials changed elsewhere. Refresh before saving.": "凭证已在其他页面修改，请刷新后再保存。",
    "Priority explanation": "仅支持整数，数值越大优先级越高。本页面会阻止非法值保存。高优先级凭证达到并发上限后，插件会尝试较低优先级的可用凭证。",
    "Weight explanation": "默认值为 1；小于或等于 0 时不参与加权调度；最大值为 1,000,000。CLIProxyAPI 原生调度需开启“加权轮询”才按权重分配。本插件接管选凭证时，会在同一优先级且有空余并发的候选中按权重选择；会话亲和可能优先复用已有凭证。",
    "Priority details": "优先级说明",
    "Scheduling weight details": "调度权重说明"
  },
  "zh-TW": {
    "Credential Manager": "憑證管理",
    "Settings": "設定",
    "CPA Management key": "CPA 管理密碼",
    "Save key": "儲存密碼",
    "Clear saved key": "清除已存密碼",
    "Refresh now": "立即重新整理",
    "All available accounts": "所有可用憑證",
    "Total (in-flight / limit)": "總並行（使用中 / 上限）",
    "Warm reserved (in-flight / reserved)": "快取預留（使用中 / 預留）",
    "Available CPA accounts": "可用 CPA 憑證",
    "Account": "憑證",
    "Loading live usage...": "正在載入即時用量…",
    "Management key required. Save a key in Settings to load live usage.": "未讀取到管理密碼。請在管理中心登入時勾選「記住密碼」，或在設定中填寫。",
    "Management authentication required.": "管理驗證失敗，請重新登入管理中心或更新密碼。",
    "Unable to load live usage.": "無法載入即時用量。",
    "Using Management Center authentication.": "已自動使用管理中心登入憑據。",
    "Enter a Management key.": "請輸入管理密碼。",
    "Unable to save the Management key in this browser.": "無法在此瀏覽器中儲存管理密碼。",
    "Management key saved for this browser.": "已在此瀏覽器中儲存管理密碼。",
    "Unable to clear the saved Management key.": "無法清除已儲存的管理密碼。",
    "Saved Management key cleared.": "已清除手動儲存的管理密碼。",
    "Authority: ": "並行控制狀態：",
    "Last refresh ": "上次重新整理：",
    "available": "可用",
    "unavailable": "無法使用",
    "connected": "已連線",
    "unknown": "未知",
    "stale": "資料已過期",
    "concurrency authority unavailable": "並行控制服務無法使用",
    "account list unavailable": "無法取得憑證清單",
    "Per-credential concurrency and cache reservations": "管理所有憑證的優先順序、排程權重與並行上限",
    "No available credentials": "暫無可用憑證",
    "Concurrency limit per credential": "每個憑證的並行上限",
    "Choose a credential and set its own limit": "選擇憑證，單獨設定並行上限",
    "Save": "儲存",
    "Enter an integer greater than zero.": "請輸入大於 0 的整數。",
    "Saving...": "正在儲存…",
    "Concurrency limit saved.": "並行上限已儲存。",
    "Unable to load concurrency settings.": "無法載入並行設定。",
    "Unable to save concurrency settings.": "無法儲存並行設定，請重試。",
    "Save all changes": "儲存全部修改",
    "All credentials": "所有憑證",
    "Priority": "優先順序",
    "Scheduling weight": "排程權重",
    "Concurrency limit": "並行上限",
    "Active requests": "目前並行數",
    "Status": "狀態",
    "Enabled": "已啟用",
    "Disabled": "已停用",
    "Unavailable": "暫時無法使用",
    "Unsaved changes": "有未儲存的修改",
    "All changes saved.": "全部修改已儲存。",
    "Some changes could not be saved. Pending edits are retained; retry Save.": "部分修改儲存失敗，未成功的修改已保留，請重試儲存。",
    "Enter valid integers: priority, weight ≤1000000, concurrency 1–1000000.": "請輸入有效整數：優先順序、權重 ≤1000000、並行上限 1–1000000。",
    "Credentials changed elsewhere. Refresh before saving.": "憑證已在其他頁面修改，請重新整理後再儲存。",
    "Priority explanation": "僅支援整數，數值越大優先順序越高。本頁面會阻止無效值儲存。高優先順序憑證達到並行上限後，外掛會嘗試較低優先順序的可用憑證。",
    "Weight explanation": "預設值為 1；小於或等於 0 時不參與加權排程；最大值為 1,000,000。CLIProxyAPI 原生排程需啟用「加權輪詢」。此外掛接管選擇時，會在相同優先順序且有剩餘容量的候選中按權重選擇；工作階段親和可能優先重用既有憑證。",
    "Priority details": "優先順序說明",
    "Scheduling weight details": "排程權重說明"
  },
  "ru": {
    "Credential Manager": "Управление учётными данными",
    "Settings": "Настройки",
    "CPA Management key": "Ключ управления CPA",
    "Save key": "Сохранить ключ",
    "Clear saved key": "Удалить сохранённый ключ",
    "Refresh now": "Обновить",
    "All available accounts": "Все доступные учётные данные",
    "Total (in-flight / limit)": "Всего (активные / лимит)",
    "Warm reserved (in-flight / reserved)": "Резерв кэша (активные / резерв)",
    "Available CPA accounts": "Доступные учётные данные CPA",
    "Account": "Учётные данные",
    "Loading live usage...": "Загрузка текущего использования…",
    "Management key required. Save a key in Settings to load live usage.": "Ключ не найден. Войдите в центр управления с опцией сохранения пароля или укажите ключ в настройках.",
    "Management authentication required.": "Ошибка авторизации. Войдите заново или обновите ключ.",
    "Unable to load live usage.": "Не удалось загрузить данные.",
    "Using Management Center authentication.": "Используются учётные данные центра управления.",
    "Enter a Management key.": "Введите ключ управления.",
    "Unable to save the Management key in this browser.": "Не удалось сохранить ключ в браузере.",
    "Management key saved for this browser.": "Ключ сохранён в браузере.",
    "Unable to clear the saved Management key.": "Не удалось удалить сохранённый ключ.",
    "Saved Management key cleared.": "Вручную сохранённый ключ удалён.",
    "Authority: ": "Состояние: ",
    "Last refresh ": "Обновлено: ",
    "available": "доступно",
    "unavailable": "недоступно",
    "connected": "подключено",
    "unknown": "неизвестно",
    "stale": "данные устарели",
    "concurrency authority unavailable": "Сервис ограничения параллельных запросов недоступен",
    "account list unavailable": "Список учётных данных недоступен",
    "Per-credential concurrency and cache reservations": "Приоритет, вес и лимит для каждой записи",
    "No available credentials": "Нет доступных учётных данных",
    "Concurrency limit per credential": "Лимит запросов на учётные данные",
    "Choose a credential and set its own limit": "Выберите запись и задайте её лимит",
    "Save": "Сохранить",
    "Enter an integer greater than zero.": "Введите целое число больше нуля.",
    "Saving...": "Сохранение…",
    "Concurrency limit saved.": "Лимит сохранён.",
    "Unable to load concurrency settings.": "Не удалось загрузить настройки.",
    "Unable to save concurrency settings.": "Не удалось сохранить настройки. Повторите попытку.",
    "Save all changes": "Сохранить все изменения",
    "All credentials": "Все учётные данные",
    "Priority": "Приоритет",
    "Scheduling weight": "Вес планирования",
    "Concurrency limit": "Лимит запросов",
    "Active requests": "Активные запросы",
    "Status": "Состояние",
    "Enabled": "Включено",
    "Disabled": "Отключено",
    "Unavailable": "Недоступно",
    "Unsaved changes": "Есть несохранённые изменения",
    "All changes saved.": "Все изменения сохранены.",
    "Some changes could not be saved. Pending edits are retained; retry Save.": "Часть изменений не сохранена. Несохранённые правки сохранены в форме; повторите попытку.",
    "Enter valid integers: priority, weight ≤1000000, concurrency 1–1000000.": "Введите целые числа: приоритет, вес ≤1000000, лимит 1–1000000.",
    "Credentials changed elsewhere. Refresh before saving.": "Учётные данные изменены в другом окне. Обновите страницу перед сохранением.",
    "Priority explanation": "Только целые числа: большее значение означает более высокий приоритет. Неверные значения не сохраняются. При исчерпании лимита верхнего уровня плагин выбирает доступные записи с меньшим приоритетом.",
    "Weight explanation": "По умолчанию 1; значения не выше 0 исключают взвешенный выбор; максимум 1 000 000. Штатному CLIProxyAPI нужен режим взвешенного round-robin. При выборе через плагин веса применяются к доступным записям одного приоритета; привязка сессии может предпочесть текущую запись.",
    "Priority details": "О приоритете",
    "Scheduling weight details": "О весе планирования"
  },
  "en": {
    "Priority explanation": "Integers only; larger values have higher priority. This page blocks invalid values from being saved. When higher-priority credentials reach their concurrency limits, the plugin tries available lower-priority credentials.",
    "Weight explanation": "Default: 1. Values at or below zero are excluded from weighted selection. Maximum: 1,000,000. Native CLIProxyAPI scheduling requires weighted round-robin to use weights. When this plugin controls selection, it uses weights among same-priority candidates with capacity; session affinity may reuse an existing credential first."
  }
};
let language='en',appliedLanguage='';
function t(value){return messages[language]?.[value]||value}
function applyTheme(){
  const saved=readHostValue('cli-proxy-theme');
  const theme=saved?.state?.theme||saved?.theme||'auto';
  const resolved=theme==='auto'?(window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light'):theme;
  if(document.documentElement.dataset.theme!==resolved){document.documentElement.dataset.theme=resolved}
}
function applyLanguage(){
  let selected;
  try{const saved=readHostValue('cli-proxy-language');selected=saved?.state?.language||saved?.language||saved}catch(_){}
  selected=selected||navigator.language||'en';
  language=/^zh-(TW|HK|MO|Hant)/i.test(selected)?'zh-TW':/^zh/i.test(selected)?'zh-CN':/^ru/i.test(selected)?'ru':'en';
  if(appliedLanguage===language){return}
  appliedLanguage=language;
  document.documentElement.lang=language;
  document.title=t('Credential Manager');
  document.querySelectorAll('[data-i18n]').forEach(el=>{el.textContent=t(el.dataset.i18n)});
  document.querySelectorAll('[data-i18n-aria]').forEach(el=>{el.setAttribute('aria-label',t(el.dataset.i18nAria))});
}
function setText(element,value){value=String(value);if(element.textContent!==value){element.textContent=value}}
function setMessage(element,message){element.dataset.i18n=message;setText(element,t(message))}
const esc=v=>String(v??'').replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;'}[c]));
function readHostValue(name){
  try{
    let value=localStorage.getItem(name);
    if(!value){return null}
    // Match CPAMC secure-storage v1, including its origin and user-agent binding.
    if(value.startsWith('enc::v1::')){
      const mask=new TextEncoder().encode('cli-proxy-api-webui::secure-storage|'+location.host+'|'+navigator.userAgent);
      const bytes=Uint8Array.from(atob(value.slice(9)),c=>c.charCodeAt(0));
      for(let i=0;i<bytes.length;i++){bytes[i]^=mask[i%mask.length]}
      value=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
    }
    try{return JSON.parse(value)}catch(_){return value}
  }catch(_){return null}
}
function readHostKey(){
  try{
    const auth=readHostValue('cli-proxy-auth')?.state;
    // Never send a saved credential for a different backend to this plugin server.
    const backend=auth?.apiBase||readHostValue('apiBase')||readHostValue('apiUrl');
    if(backend&&new URL(backend).origin!==location.origin){return ''}
    if(typeof auth?.managementKey==='string'&&auth.managementKey.trim()){return auth.managementKey.trim()}
    const legacy=readHostValue('managementKey');
    return typeof legacy==='string'?legacy.trim():'';
  }catch(_){return ''}
}
function readManualKey(){try{return localStorage.getItem(storageKey)||''}catch(_){return ''}}
let rejectedHostKey='';
function readKey(){const host=readHostKey();return(host!==rejectedHostKey?host:'')||readManualKey()}
function writeKey(value){try{localStorage.setItem(storageKey,value);return true}catch(_){return false}}
function removeKey(){try{localStorage.removeItem(storageKey);return true}catch(_){return false}}
// Stage table edits locally. Only the explicit save action writes host credential fields.
const saveAll=document.getElementById('save-all'),configStatus=document.getElementById('config-status');
let configBusy=false,currentAccounts=[],drafts=new Map(),tableSignature='';
// Native popovers provide outside-click and Escape dismissal with accessible buttons.
document.querySelectorAll('[popovertarget]').forEach(button=>{button.addEventListener('click',()=>{const panel=document.getElementById(button.getAttribute('popovertarget'));const rect=button.getBoundingClientRect();const width=Math.min(330,window.innerWidth-32);panel.style.left=Math.max(16,Math.min(rect.right-width,window.innerWidth-width-16))+'px';panel.style.top=Math.max(16,Math.min(rect.bottom+8,window.innerHeight-280))+'px'})});
async function getConfig(authKey){
  let url='/v0/management/config/plugins/configs/cpa-oauth-manager';
  const options={cache:'no-store',headers:{'X-Management-Key':authKey}};
  let response=await fetch(url,options);
  if(response.status===404){url='/v0/management/plugins/cpa-oauth-manager/config';response=await fetch(url,options)}
  if(!response.ok){throw new Error('config')}
  const config=await response.json();
  if(!config||typeof config!=='object'||Array.isArray(config)){throw new Error('config')}
  return {url,config};
}
async function listCredentials(authKey){
  const response=await fetch('/v0/management/auth-files',{cache:'no-store',headers:{'X-Management-Key':authKey}});
  if(!response.ok){throw new Error('credentials')}
  const result=await response.json();
  if(!Array.isArray(result.files)){throw new Error('credentials')}
  return Promise.all(result.files.map(async file=>{
    const id=String(file.id||file.name||'').trim();
    const hash=await crypto.subtle.digest('SHA-256',new TextEncoder().encode('cpa\x00'+id));
    return {config_id:Array.from(new Uint8Array(hash),b=>b.toString(16).padStart(2,'0')).join(''),name:file.name||id,label:file.email||file.label||file.name||id,provider:file.provider||file.type||'',priority:Number(file.priority??0),weight:Number(file.weight??1),disabled:!!file.disabled,unavailable:!!file.unavailable,runtimeOnly:!!file.runtime_only};
  }));
}
function stageEdit(event){
  const input=event.target,field=input.dataset.field,key=input.dataset.key;
  if(!['priority','weight','limit'].includes(field)||configBusy){return}
  const account=currentAccounts.find(a=>a.config_id===key);
  if(!account){return}
  const draft=drafts.get(key)||{...account,changes:{}};
  if(input.value!==''&&Number(input.value)===account[field]){delete draft.changes[field]}
  else{draft.changes[field]=input.value}
  if(Object.keys(draft.changes).length){drafts.set(key,draft)}else{drafts.delete(key)}
  saveAll.disabled=!drafts.size;
  setMessage(configStatus,drafts.size?'Unsaved changes':'');
}
accounts.addEventListener('input',stageEdit);
async function saveChanges(){
  if(configBusy||!drafts.size){return}
  for(const draft of drafts.values()){
    for(const [field,value] of Object.entries(draft.changes)){
      const number=Number(value);
      if(value===''||!Number.isSafeInteger(number)||(field==='weight'&&number>1000000)||(field==='limit'&&(number<1||number>1000000))){setMessage(configStatus,'Enter valid integers: priority, weight ≤1000000, concurrency 1–1000000.');return}
    }
  }
  const authKey=readKey();
  if(!authKey){setMessage(configStatus,'Management authentication required.');return}
  configBusy=true;saveAll.disabled=true;setMessage(configStatus,'Saving...');
  accounts.querySelectorAll('input').forEach(input=>{input.disabled=true});
  try{
    const {url,config}=await getConfig(authKey),latest=await listCredentials(authKey);
    // Check all targets before writing, so stale drafts cannot overwrite external edits.
    for(const [key,draft] of drafts){
      const fresh=latest.find(a=>a.config_id===key);
      if(!fresh){throw new Error('conflict')}
      for(const field of Object.keys(draft.changes)){
        const value=field==='limit'?(config.credential_limits?.[key]??config.max_concurrency??2):fresh[field];
        if(value!==draft[field]){throw new Error('conflict')}
      }
    }
    for(const [key,draft] of drafts){
      const patch={name:draft.name};
      for(const field of ['priority','weight']){if(field in draft.changes){patch[field]=Number(draft.changes[field])}}
      if(Object.keys(patch).length>1){
        if(readKey()!==authKey){throw new Error('auth')}
        const response=await fetch('/v0/management/auth-files/fields',{method:'PATCH',headers:{'X-Management-Key':authKey,'Content-Type':'application/json'},body:JSON.stringify(patch)});
        if(!response.ok){throw new Error('save')}
        for(const field of ['priority','weight']){if(field in patch){draft[field]=patch[field];delete draft.changes[field]}}
      }
    }
    const limits={...config.credential_limits};let changed=false;
    for(const [key,draft] of drafts){if('limit' in draft.changes){limits[key]=Number(draft.changes.limit);changed=true}}
    if(changed){
      if(readKey()!==authKey){throw new Error('auth')}
      const response=await fetch(url,{method:'PUT',headers:{'X-Management-Key':authKey,'Content-Type':'application/json'},body:JSON.stringify({...config,credential_limits:limits})});
      if(!response.ok){throw new Error('save')}
      for(const [key,draft] of drafts){if('limit' in draft.changes){draft.limit=limits[key];delete draft.changes.limit}}
    }
    drafts.clear();setMessage(configStatus,'All changes saved.');
  }catch(error){
    for(const [key,draft] of drafts){if(!Object.keys(draft.changes).length){drafts.delete(key)}}
    setMessage(configStatus,error.message==='conflict'?'Credentials changed elsewhere. Refresh before saving.':'Some changes could not be saved. Pending edits are retained; retry Save.');
  }finally{
    configBusy=false;saveAll.disabled=!drafts.size;
    accounts.querySelectorAll('input').forEach(input=>{input.disabled=false});
    load();
  }
}
saveAll.onclick=saveChanges;
function clearUsage(){tableSignature='';accounts.innerHTML='';document.getElementById('summary-count').textContent='--';summaryTotal.textContent='--';summaryWarm.textContent='--';updated.textContent=''}
function render(d,list,config){
  const usage=new Map((d.accounts||[]).map(a=>[a.config_id,a]));
  currentAccounts=list.map(a=>({...a,limit:config.credential_limits?.[a.config_id]??config.max_concurrency??2,in_flight:usage.get(a.config_id)?.in_flight}));
  setText(document.getElementById('summary-count'),list.length);
  const summary=d.summary||{},total=summary.total||{},warm=summary.warm_reserved||{};
  setText(summaryTotal,(total.in_flight??0)+' / '+(total.limit??0));setText(summaryWarm,(warm.in_flight??0)+' / '+(warm.reserved??0));
  // Leave input nodes untouched during editing; refresh resumes once changes are saved.
  const signature=JSON.stringify([language,currentAccounts.map(({in_flight,...a})=>a)]);
  if(signature!==tableSignature&&!drafts.size&&!configBusy&&!accounts.contains(document.activeElement)){
    const rows=currentAccounts.map(a=>{
      const input=(field,min,max)=>'<input type="number" step="1" '+(min!==null?'min="'+min+'" ':'')+(max!==null?'max="'+max+'" ':'')+'data-field="'+field+'" data-key="'+a.config_id+'" value="'+a[field]+'" aria-label="'+esc(t(field==='priority'?'Priority':field==='weight'?'Scheduling weight':'Concurrency limit')+' '+a.label)+'"'+(a.runtimeOnly&&field!=='limit'?' disabled':'')+'>';
      return '<tr><td>'+esc(a.label)+'<small>'+esc(a.provider+' · '+a.name)+'</small></td><td>'+esc(t(a.disabled?'Disabled':a.unavailable?'Unavailable':'Enabled'))+'</td><td>'+input('priority',null,null)+'</td><td>'+input('weight',null,1000000)+'</td><td>'+input('limit',1,1000000)+'</td><td data-live="'+a.config_id+'">'+(a.in_flight??'—')+'</td></tr>';
    }).join('')||'<tr class="empty"><td colspan="6">'+esc(t('No available credentials'))+'</td></tr>';
    if(accounts.innerHTML!==rows){accounts.innerHTML=rows}
    tableSignature=signature;
  }
  accounts.querySelectorAll('[data-live]').forEach(cell=>{setText(cell,usage.get(cell.dataset.live)?.in_flight??'—')});
  let msg=t('Authority: ')+t(d.authority_state||'unknown');if(d.stale){msg+='; '+t('stale')}if(d.error){msg+='; '+t(d.error)}
  delete state.dataset.i18n;setText(state,msg);setText(updated,d.last_refresh?t('Last refresh ')+new Date(d.last_refresh).toLocaleTimeString(language):'');
}
// Poll silently after the first snapshot and never overlap requests or rebuild unchanged rows.
let refreshing=false,hasUsage=false;
async function load(){
  if(refreshing||configBusy){return}
  refreshing=true;
  try{
    applyLanguage();applyTheme();
    if(readHostKey()&&readKey()===readHostKey()){setMessage(keyStatus,'Using Management Center authentication.')}
    const authKey=readKey();const settings=document.getElementById('settings');
    settings.hidden=!!authKey;settings.open=!authKey;
    if(!authKey){setMessage(state,'Management key required. Save a key in Settings to load live usage.');clearUsage();hasUsage=false;return}
    if(!hasUsage){setMessage(state,'Loading live usage...')}
    const r=await fetch(api,{method:'GET',credentials:'same-origin',cache:'no-store',headers:{'X-Management-Key':authKey}});
    if(authKey!==readKey()){clearUsage();hasUsage=false;return}
    if(!r.ok){
      if(r.status===401||r.status===403){if(authKey===readHostKey()){rejectedHostKey=authKey}settings.hidden=false;settings.open=true;setMessage(state,'Management authentication required.');clearUsage();hasUsage=false}
      else{setMessage(state,'Unable to load live usage.')}
      return;
    }
    const [data,list,settingsConfig]=await Promise.all([r.json(),listCredentials(authKey),getConfig(authKey)]);
    render(data,list,settingsConfig.config);hasUsage=true;
  }catch(_){setMessage(state,'Unable to load live usage.')}
  finally{refreshing=false}
}
document.getElementById('settings').open=!readHostKey()&&!readManualKey();keyInput.value=readManualKey();if(readHostKey()&&readKey()===readHostKey()){setMessage(keyStatus,'Using Management Center authentication.')}document.getElementById('settings-form').addEventListener('submit',function(event){event.preventDefault();const value=keyInput.value.trim();if(!value){setMessage(keyStatus,'Enter a Management key.');return}if(!writeKey(value)){setMessage(keyStatus,'Unable to save the Management key in this browser.');return}keyInput.value=value;setMessage(keyStatus,'Management key saved for this browser.');load()});document.getElementById('clear-key').addEventListener('click',function(){if(!removeKey()){setMessage(keyStatus,'Unable to clear the saved Management key.');return}keyInput.value='';setMessage(keyStatus,'Saved Management key cleared.');load()});document.getElementById('refresh').onclick=load;window.addEventListener('storage',function(event){if(event.key==='cli-proxy-language'||event.key==='cli-proxy-theme'||event.key==='cli-proxy-auth'||event.key==='managementKey'||event.key===null){load()}});load();setInterval(load,5000)})()</script></body></html>`

type managementRPCRequest struct {
	pluginapi.ManagementRequest
}

func handleManagement(raw []byte) ([]byte, error) {
	var req managementRPCRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	resp, err := (managementHandler{}).HandleManagement(context.Background(), req.ManagementRequest)
	if err != nil {
		return nil, err
	}
	return okEnvelope(resp)
}

type pluginConfig struct {
	CredentialLimits  map[string]int `yaml:"credential_limits"`
	Enabled           bool           `yaml:"enabled"`
	MaxConcurrency    int            `yaml:"max_concurrency"`
	WarmReservedSlots int            `yaml:"warm_reserved_slots"`
	WaitTimeout       time.Duration  `yaml:"wait_timeout"`
	Authority         string         `yaml:"authority"`
	RedisPrefix       string         `yaml:"redis_prefix"`
	RedisAddr         string         `yaml:"redis_addr"`
	RedisPassword     string         `yaml:"redis_password"`
	RedisDB           int            `yaml:"redis_db"`
}

// Use opaque credential hashes consistently for admission, scheduling and management.
func (cfg pluginConfig) limitsFor(key string) (int, int) {
	limit, reserved := cfg.MaxConcurrency, cfg.WarmReservedSlots
	if override, ok := cfg.CredentialLimits[key]; ok {
		limit = override
		reserved = minInt(limit-1, maxInt(1, (limit+4)/5))
	}
	return limit, minInt(reserved, limit-1)
}

type pluginState struct {
	mu          sync.Mutex
	gate        sync.RWMutex // serializes shutdown/reconfigure against callbacks
	cfg         pluginConfig
	authority   Authority
	leases      map[string]Lease
	bound       map[string]string
	requests    map[string]*requestLifecycle
	stopping    bool
	uncertain   bool
	reloadFence bool
}

type requestLifecycle struct {
	mu        sync.Mutex
	terminal  bool
	fenced    bool // lease renewal failed; do not admit another request
	completed bool
	lease     Lease
	bound     string
	stopBeat  chan struct{}
}

// postAuthInterceptRequest is the wire shape used by the post-auth
// interception callback.  The stock CPA host identifies the selected auth in
// Metadata["selected_auth_id"]; AuthID is retained here only as an optional
// compatibility field for host variants that added that convenience field.
// Keeping this shape local means the plugin also builds against the stock SDK,
// where RequestInterceptRequest has no AuthID member.
type postAuthInterceptRequest struct {
	RequestID string          `json:"RequestID"`
	AuthID    json.RawMessage `json:"AuthID"`
	Headers   http.Header     `json:"Headers"`
	Body      []byte          `json:"Body"`
	Metadata  map[string]any  `json:"Metadata"`
}

var localAuthorityShared = newLocalAuthority()
var state = pluginState{cfg: defaultConfig(), authority: localAuthorityShared, leases: make(map[string]Lease), bound: make(map[string]string), requests: make(map[string]*requestLifecycle)}

func defaultConfig() pluginConfig {
	return pluginConfig{Enabled: true, MaxConcurrency: defaultLimit, WarmReservedSlots: 0, WaitTimeout: defaultWait, Authority: "local", RedisPrefix: "cpa:concurrency"}
}

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if plugin == nil {
		return 1
	}
	state.gate.Lock()
	defer state.gate.Unlock()
	retireHostAuthWorker()
	C.store_host_api(host)
	resumeHostAuthWorker()
	plugin.abi_version = C.uint32_t(pluginabi.ABIVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		writeResponse(response, errorEnvelope("invalid_method", "method is required"))
		return 1
	}
	var raw []byte
	if request != nil && requestLen > 0 {
		raw = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	out, err := handleMethod(C.GoString(method), raw)
	if err != nil {
		var admission *AdmissionError
		if errors.As(err, &admission) {
			writeResponse(response, typedErrorEnvelope(admission.Code, admission.Message, admission.Retryable(), admission.StatusCode(), admission.RetryAfter))
		} else {
			writeResponse(response, errorEnvelope("plugin_error", err.Error()))
		}
		return 1
	}
	writeResponse(response, out)
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, _ C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {
	state.gate.Lock()
	defer state.gate.Unlock()
	retireHostAuthWorker()
	defer C.clear_host_api()
	state.mu.Lock()
	leases := make([]Lease, 0, len(state.leases))
	for _, lease := range state.leases {
		leases = append(leases, lease)
	}
	authority := state.authority
	state.stopping = true
	if len(leases) > 0 {
		state.uncertain = true
		state.reloadFence = true
	}
	requests := make([]*requestLifecycle, 0, len(state.requests))
	for _, rs := range state.requests {
		requests = append(requests, rs)
	}
	state.mu.Unlock()
	for _, rs := range requests {
		rs.mu.Lock()
		if rs.stopBeat != nil {
			close(rs.stopBeat)
			rs.stopBeat = nil
		}
		rs.mu.Unlock()
	}
	for _, lease := range leases {
		if authority != nil {
			ctx, cancel := boundedAuthorityContext()
			_ = authority.Release(ctx, lease)
			cancel()
		}
	}
	// Authority release above is the single ownership transition. Keep request
	// records so late completion callbacks can clear the reload fence, but do
	// not ask the authority to release the same token a second time.
	for _, rs := range requests {
		rs.mu.Lock()
		rs.lease = Lease{}
		rs.bound = ""
		rs.mu.Unlock()
	}
}

func handleMethod(method string, raw []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		if err := configure(raw); err != nil {
			return nil, err
		}
		return okEnvelope(pluginRegistration())
	case pluginabi.MethodPluginQuiesce:
		if err := quiesce(raw); err != nil {
			return nil, err
		}
		return okEnvelope(struct{}{})
	case pluginabi.MethodSchedulerPick:
		return schedulerPick(raw)
	case pluginabi.MethodRequestInterceptBefore:
		return interceptBefore(raw)
	case pluginabi.MethodRequestInterceptAfter:
		return interceptAfter(raw)
	case pluginabi.MethodRequestComplete:
		return complete(raw)
	case pluginabi.MethodManagementRegister:
		return okEnvelope(managementRegistrationResponse())
	case pluginabi.MethodManagementHandle:
		return handleManagement(raw)
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

// quiesce fences new admission on this instance and waits for every lease it
// owns to complete. It intentionally does not take state.gate: completion
// callbacks must remain able to drain existing leases while new callbacks see
// state.stopping and fail closed. A timeout leaves the instance fenced and
// authoritative; the host must not replace it.
func quiesce(raw []byte) error {
	deadline := time.Now().Add(authorityCallTimeout)
	if len(raw) > 0 {
		var req quiesceRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return err
		}
		if req.DeadlineUnixNano > 0 {
			deadline = time.Unix(0, req.DeadlineUnixNano)
		}
	}
	state.mu.Lock()
	state.stopping = true
	if len(state.leases) > 0 {
		state.reloadFence = true
	}
	state.mu.Unlock()
	for {
		state.mu.Lock()
		remaining := len(state.leases)
		state.mu.Unlock()
		if remaining == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			state.mu.Lock()
			state.reloadFence = true
			state.mu.Unlock()
			return context.DeadlineExceeded
		}
		time.Sleep(defaultPollInterval)
	}
}

func configure(raw []byte) error {
	state.gate.Lock()
	defer state.gate.Unlock()
	retireHostAuthWorker()
	defer resumeHostAuthWorker()
	var req lifecycleRequest
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &req); err != nil {
			return err
		}
	}
	if req.SchemaVersion != 0 && req.SchemaVersion < 2 {
		return fmt.Errorf("CPA schema version 2 or newer is required")
	}
	cfg := defaultConfig()
	if len(req.ConfigYAML) > 0 {
		if err := yaml.Unmarshal(req.ConfigYAML, &cfg); err != nil {
			return err
		}
	}
	if cfg.MaxConcurrency < 1 {
		return fmt.Errorf("max_concurrency must be greater than zero")
	}
	for key, limit := range cfg.CredentialLimits {
		if len(key) != 64 || strings.Trim(key, "0123456789abcdef") != "" || limit < 1 || limit > 1000000 {
			return fmt.Errorf("credential_limits requires credential hashes and limits between 1 and 1000000")
		}
	}
	if cfg.WarmReservedSlots < 0 {
		return fmt.Errorf("warm_reserved_slots must not be negative")
	}
	if cfg.MaxConcurrency <= 1 {
		cfg.WarmReservedSlots = 0
	} else if cfg.WarmReservedSlots == 0 {
		cfg.WarmReservedSlots = minInt(cfg.MaxConcurrency-1, maxInt(1, (cfg.MaxConcurrency+4)/5))
	}
	if cfg.WarmReservedSlots >= cfg.MaxConcurrency {
		cfg.WarmReservedSlots = cfg.MaxConcurrency - 1
	}
	if cfg.WaitTimeout < 0 {
		return fmt.Errorf("wait_timeout must not be negative")
	}
	if cfg.WaitTimeout == 0 {
		cfg.WaitTimeout = defaultWait
	}
	cfg.Authority = strings.ToLower(strings.TrimSpace(cfg.Authority))
	if cfg.Authority == "" {
		cfg.Authority = "local"
	}
	if cfg.Authority != "local" && cfg.Authority != "redis" {
		return fmt.Errorf("authority must be local or redis")
	}
	if cfg.Authority == "redis" && strings.TrimSpace(cfg.RedisAddr) == "" {
		return fmt.Errorf("redis_addr is required when authority is redis")
	}
	state.mu.Lock()
	state.stopping = false
	// Do not clear an uncertainty while leases remain.  In particular, a
	// renewal failure may have left a running request without a fenced lease;
	// admitting new work before that request completes would permit oversell.
	if len(state.leases) == 0 {
		state.uncertain = false
	}
	if len(state.leases) > 0 && state.cfg.Authority != "" && state.cfg.Authority != cfg.Authority {
		state.mu.Unlock()
		return fmt.Errorf("cannot change concurrency authority while requests are in flight")
	}
	previousAuthority := state.cfg.Authority
	materialRedisChange := previousAuthority == "redis" && cfg.Authority == "redis" &&
		(state.cfg.RedisAddr != cfg.RedisAddr || state.cfg.RedisPassword != cfg.RedisPassword || state.cfg.RedisDB != cfg.RedisDB || state.cfg.RedisPrefix != cfg.RedisPrefix)
	if materialRedisChange && len(state.leases) > 0 {
		state.mu.Unlock()
		return fmt.Errorf("cannot change Redis authority configuration while requests are in flight")
	}
	state.cfg = cfg
	if cfg.Authority == "local" {
		if previousAuthority != "local" || state.authority == nil {
			state.authority = localAuthorityShared
		}
	} else if previousAuthority != "redis" || state.authority == nil || materialRedisChange {
		state.authority = newRedisAuthority(redisNetClient{addr: cfg.RedisAddr, password: cfg.RedisPassword, db: cfg.RedisDB}, cfg.RedisPrefix)
	}
	state.mu.Unlock()
	return nil
}

// Registration author identifies the maintainer of this published plugin.
func pluginRegistration() registration {
	return registration{SchemaVersion: pluginabi.SchemaVersion, Metadata: pluginapi.Metadata{Name: "凭证管理", Version: "0.0.2", Author: "darvintang", GitHubRepository: "https://github.com/darvintang/cpa-oauth-manager", ConfigFields: []pluginapi.ConfigField{
		{Name: "credential_limits", Type: pluginapi.ConfigFieldTypeObject, Description: "Per-credential concurrency limits, keyed by opaque credential IDs from the management UI."},
		{Name: "max_concurrency", Type: pluginapi.ConfigFieldTypeInteger, Description: "Hard per-account in-flight limit."},
		{Name: "warm_reserved_slots", Type: pluginapi.ConfigFieldTypeInteger, Description: "Reserved slots for verified warm/strict affinity."},
		{Name: "wait_timeout", Type: pluginapi.ConfigFieldTypeString, Description: "Bounded admission wait (Go duration, for example 50ms)."},
		{Name: "authority", Type: pluginapi.ConfigFieldTypeEnum, EnumValues: []string{"local", "redis"}, Description: "Lease authority; Redis requires redis_addr."},
		{Name: "redis_prefix", Type: pluginapi.ConfigFieldTypeString, Description: "Redis key prefix; account identities are hashed."},
		{Name: "redis_addr", Type: pluginapi.ConfigFieldTypeString, Description: "Redis address when authority is redis."},
		{Name: "redis_password", Type: pluginapi.ConfigFieldTypeString, Description: "Redis password when authority is redis."},
		{Name: "redis_db", Type: pluginapi.ConfigFieldTypeInteger, Description: "Redis database number."},
	}}, Capabilities: registrationCapabilities{Scheduler: true, SchedulerAcrossPriorities: true, RequestInterceptor: true, RequestInterceptorEnforcesAdmission: true, RequestLifecyclePlugin: true, ManagementAPI: true}}
}

func schedulerPick(raw []byte) ([]byte, error) {
	state.gate.RLock()
	defer state.gate.RUnlock()
	var req pluginapi.SchedulerPickRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	state.mu.Lock()
	cfg, authority, stopping, uncertain := state.cfg, state.authority, state.stopping, state.uncertain
	state.mu.Unlock()
	if !cfg.Enabled {
		return okEnvelope(pluginapi.SchedulerPickResponse{Handled: false})
	}
	if authority == nil || stopping || uncertain {
		return nil, &AdmissionError{Code: "account_concurrency_authority_unavailable", HTTPStatus: http.StatusServiceUnavailable, RetryAfter: defaultRetryAfter, Message: "concurrency authority unavailable", Authority: true}
	}
	ids := make([]string, 0, len(req.Candidates))
	seen := make(map[string]struct{}, len(req.Candidates))
	// Host priority and weight are authoritative; exclude zero-weight credentials.
	weights := make(map[string]int)
	for _, c := range req.Candidates {
		weight := 1
		if raw := strings.TrimSpace(c.Attributes["weight"]); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed > 1000000 {
				return nil, fmt.Errorf("invalid credential scheduling weight")
			}
			weight = maxInt(0, parsed)
		}
		weights[canonicalAuthID(c.ID)] = weight
	}
	priorities := make(map[string]int)
	for _, c := range req.Candidates {
		priorities[canonicalAuthID(c.ID)] = c.Priority
	}
	for _, c := range req.Candidates {
		if id := canonicalAuthID(c.ID); id != "" && weights[id] > 0 {
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil, &AdmissionError{Code: "account_concurrency_limit", HTTPStatus: http.StatusServiceUnavailable, RetryAfter: defaultRetryAfter, Message: "no protected account is available"}
	}
	hint, strict, warm := affinityHint(req.Options.Metadata)
	if strict && hint != "" {
		// Explicit caller pinning cannot switch identity; ordinary affinity may fail over.
		for _, id := range ids {
			if id == hint {
				ids = []string{id}
				break
			}
		}
	}

	if warm {
		ids = preferHint(ids, hint)
	}
	requestID := http.Header(req.Options.Headers).Get(requestReservationHeader)
	state.mu.Lock()
	rs := state.requests[requestID]
	state.mu.Unlock()
	if rs != nil {
		rs.mu.Lock()
		defer rs.mu.Unlock()
		if rs.terminal || rs.fenced {
			return nil, ErrAuthorityUnavailable
		}
		// Release the prior attempt before selecting another credential for this request.
		if rs.lease.Token != "" {
			ctx, cancel := boundedAuthorityContext()
			err := authority.Release(ctx, rs.lease)
			cancel()
			if err != nil {
				return nil, authorityError(err)
			}
			stopHeartbeat(rs)
			state.mu.Lock()
			delete(state.leases, requestID)
			delete(state.bound, requestID)
			state.mu.Unlock()
			rs.lease, rs.bound = Lease{}, ""
		}
	}
	class := classCold
	if warm {
		class = classWarm
	}
	for len(ids) > 0 {
		ctx, cancel := boundedAuthorityContext()
		selected, err := chooseCandidate(ctx, authority, ids, cfg, class, weights, priorities)
		cancel()
		if err != nil {
			return nil, authorityError(err)
		}
		if rs == nil {
			return okEnvelope(pluginapi.SchedulerPickResponse{Handled: true, AuthID: selected})
		}
		selectedClass := class
		if warm && hint != "" && hint != selected {
			selectedClass = classCold
		}
		limit, reserved := cfg.limitsFor(accountKey("cpa", selected))
		ctx, cancel = context.WithTimeout(context.Background(), cfg.WaitTimeout)
		lease, err := authority.Acquire(ctx, accountKey("cpa", selected), limit, reserved, selectedClass)
		cancel()
		if err == nil {
			state.mu.Lock()
			state.leases[requestID] = lease
			state.bound[requestID] = selected
			state.mu.Unlock()
			rs.lease, rs.bound = lease, selected
			startHeartbeat(rs, authority, lease)
			return okEnvelope(pluginapi.SchedulerPickResponse{Handled: true, AuthID: selected})
		}
		var capacity *AdmissionError
		if !errors.Is(err, context.DeadlineExceeded) && !(errors.As(err, &capacity) && capacity.Code == "account_concurrency_limit") {
			return nil, authorityError(err)
		}
		// A competing request took the final slot; try the remaining credentials now.
		for i, id := range ids {
			if id == selected {
				ids = append(ids[:i], ids[i+1:]...)
				break
			}
		}
	}
	return nil, &AdmissionError{Code: "account_concurrency_limit", HTTPStatus: http.StatusServiceUnavailable, RetryAfter: defaultRetryAfter, Message: "all eligible credentials are at their concurrency limit"}
}

func authorityError(err error) error {
	if err == nil {
		return nil
	}
	var ae *AdmissionError
	if errors.As(err, &ae) {
		return err
	}
	markAuthorityUncertain()
	return &AdmissionError{Code: "account_concurrency_authority_unavailable", HTTPStatus: http.StatusServiceUnavailable, RetryAfter: defaultRetryAfter, Message: "concurrency authority unavailable", Authority: true}
}

func interceptBefore(raw []byte) ([]byte, error) {
	var req pluginapi.RequestInterceptRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	state.gate.RLock()
	defer state.gate.RUnlock()
	state.mu.Lock()
	if state.cfg.Enabled && req.RequestID != "" {
		if state.requests[req.RequestID] == nil {
			state.requests[req.RequestID] = &requestLifecycle{}
		}
		// Overwrite untrusted client input with the host lifecycle identity.
		if req.Headers == nil {
			req.Headers = make(http.Header)
		}
		req.Headers.Set(requestReservationHeader, req.RequestID)
	}
	state.mu.Unlock()
	return okEnvelope(pluginapi.RequestInterceptResponse{Headers: req.Headers, Body: req.Body})
}

func interceptAfter(raw []byte) ([]byte, error) {
	var req postAuthInterceptRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	req.Headers.Del(requestReservationHeader)
	req.RequestID = strings.TrimSpace(req.RequestID)
	if req.RequestID == "" {
		return admissionResponse(&AdmissionError{Code: "invalid_request_id", HTTPStatus: http.StatusBadRequest, Message: "request_id is required"})
	}
	state.gate.RLock()
	defer state.gate.RUnlock()
	state.mu.Lock()
	cfg, authority := state.cfg, state.authority
	if state.stopping || state.uncertain {
		state.mu.Unlock()
		return admissionResponse(&AdmissionError{Code: "account_concurrency_authority_unavailable", HTTPStatus: http.StatusServiceUnavailable, RetryAfter: defaultRetryAfter, Message: "concurrency authority unavailable", Authority: true})
	}
	state.mu.Unlock()
	if !cfg.Enabled {
		return okEnvelope(pluginapi.RequestInterceptResponse{Headers: req.Headers, Body: req.Body, ClearHeaders: []string{requestReservationHeader}})
	}
	authID, identityErr := selectedAccountID(req.Metadata, req.AuthID)
	if identityErr != nil {
		return admissionResponse(identityErr)
	}

	state.mu.Lock()
	rs := state.requests[req.RequestID]
	if rs == nil {
		rs = &requestLifecycle{}
		state.requests[req.RequestID] = rs
	}
	state.mu.Unlock()
	class := classCold
	hint, _, warm := affinityHint(req.Metadata)
	// A verified binding reserves warm capacity only while executing on the
	// bound original auth. Retries/failovers selected onto another auth are
	// cold and must use general capacity.
	if warm && hint != "" && hint != authID {
		warm = false
	}
	if warm {
		class = classWarm
	}
	key := accountKey("cpa", authID)
	if authority == nil {
		return admissionResponse(&AdmissionError{Code: "account_concurrency_authority_unavailable", HTTPStatus: http.StatusServiceUnavailable, RetryAfter: defaultRetryAfter, Message: "concurrency authority unavailable", Authority: true})
	}
	ctx := context.Background()
	if cfg.WaitTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.WaitTimeout)
		defer cancel()
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.fenced {
		return admissionResponse(&AdmissionError{Code: "account_concurrency_authority_unavailable", HTTPStatus: http.StatusServiceUnavailable, RetryAfter: defaultRetryAfter, Message: "concurrency authority unavailable", Authority: true})
	}
	if rs.terminal {
		return okEnvelope(pluginapi.RequestInterceptResponse{Headers: req.Headers, Body: req.Body, ClearHeaders: []string{requestReservationHeader}})
	}
	old, bound := rs.lease, rs.bound
	if bound == authID && old.Token != "" {
		return okEnvelope(pluginapi.RequestInterceptResponse{Headers: req.Headers, Body: req.Body, ClearHeaders: []string{requestReservationHeader}})
	}
	if old.Token != "" {
		ctxRelease, cancelRelease := boundedAuthorityContext()
		errRelease := authority.Release(ctxRelease, old)
		cancelRelease()
		if errRelease != nil {
			markAuthorityUncertain()
			return admissionResponse(&AdmissionError{Code: "account_concurrency_authority_unavailable", HTTPStatus: http.StatusServiceUnavailable, RetryAfter: defaultRetryAfter, Message: "concurrency authority unavailable", Authority: true})
		}
		state.mu.Lock()
		delete(state.leases, req.RequestID)
		delete(state.bound, req.RequestID)
		state.mu.Unlock()
		rs.lease = Lease{}
		rs.bound = ""
		stopHeartbeat(rs)
	}
	limit, reserved := cfg.limitsFor(key)
	lease, err := authority.Acquire(ctx, key, limit, reserved, class)
	if err != nil {
		var capacity *AdmissionError
		isCapacity := errors.As(err, &capacity) && capacity.Code == "account_concurrency_limit"
		if !isCapacity && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
			markAuthorityUncertain()
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			err = &AdmissionError{Code: "account_concurrency_limit", HTTPStatus: http.StatusServiceUnavailable, RetryAfter: defaultRetryAfter, Message: "account concurrency limit reached"}
		}
		var ae *AdmissionError
		if !errors.As(err, &ae) {
			ae = &AdmissionError{Code: "account_concurrency_authority_unavailable", HTTPStatus: http.StatusServiceUnavailable, RetryAfter: defaultRetryAfter, Message: "concurrency authority unavailable", Authority: true}
		}
		return admissionResponse(ae)
	}
	state.mu.Lock()
	state.leases[req.RequestID] = lease
	state.bound[req.RequestID] = authID
	state.mu.Unlock()
	rs.lease, rs.bound = lease, authID
	startHeartbeat(rs, authority, lease)
	return okEnvelope(pluginapi.RequestInterceptResponse{Headers: req.Headers, Body: req.Body, ClearHeaders: []string{requestReservationHeader}})
}

func complete(raw []byte) ([]byte, error) {
	var req pluginapi.RequestCompletion
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	req.RequestID = strings.TrimSpace(req.RequestID)
	if req.RequestID == "" {
		return okEnvelope(struct{}{})
	}
	state.gate.RLock()
	defer state.gate.RUnlock()
	state.mu.Lock()
	rs := state.requests[req.RequestID]
	if rs == nil {
		rs = &requestLifecycle{}
		state.requests[req.RequestID] = rs
	}
	state.mu.Unlock()
	rs.mu.Lock()
	if rs.completed {
		rs.mu.Unlock()
		return okEnvelope(struct{}{})
	}
	rs.terminal = true
	rs.completed = true
	lease := rs.lease
	ok := lease.Token != ""
	stopHeartbeat(rs)
	state.mu.Lock()
	authority := state.authority
	state.mu.Unlock()
	// Keep the lease visible to quiesce until its authority release succeeds.
	// Otherwise quiesce could report a safe drain while a slow or failed Redis
	// release still leaves the retiring instance authoritative.
	if ok && authority != nil {
		ctx, cancel := boundedAuthorityContext()
		err := authority.Release(ctx, lease)
		cancel()
		if err != nil {
			markAuthorityUncertain()
			rs.fenced = true
			rs.mu.Unlock()
			return okEnvelope(struct{}{})
		}
	}
	rs.lease = Lease{}
	rs.bound = ""
	state.mu.Lock()
	delete(state.leases, req.RequestID)
	delete(state.bound, req.RequestID)
	if len(state.leases) == 0 && state.reloadFence {
		state.uncertain = false
		state.reloadFence = false
	}
	state.mu.Unlock()
	rs.mu.Unlock()
	return okEnvelope(struct{}{})
}

func markAuthorityUncertain() {
	state.mu.Lock()
	state.uncertain = true
	state.mu.Unlock()
}

func startHeartbeat(rs *requestLifecycle, authority Authority, lease Lease) {
	startHeartbeatWithInterval(rs, authority, lease, leaseRenewInterval)
}

func startHeartbeatWithInterval(rs *requestLifecycle, authority Authority, lease Lease, interval time.Duration) {
	if authority == nil || lease.Token == "" {
		return
	}
	stopHeartbeat(rs)
	stop := make(chan struct{})
	rs.stopBeat = stop
	go func() {
		if interval <= 0 {
			interval = leaseRenewInterval
		}
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				rs.mu.Lock()
				if rs.terminal || rs.lease.Token != lease.Token {
					rs.mu.Unlock()
					return
				}
				ctx, cancel := boundedAuthorityContext()
				err := authority.Renew(ctx, lease)
				cancel()
				if err != nil {
					// Best-effort distributed fencing. Redis authorities persist this
					// marker so another instance cannot acquire the account after the
					// lease expires. If the partition also prevents Fence, the Redis
					// acquire script fences on observing expiry.
					if fencer, ok := authority.(interface {
						Fence(context.Context, Lease) error
					}); ok {
						ctxFence, cancelFence := boundedAuthorityContext()
						_ = fencer.Fence(ctxFence, lease)
						cancelFence()
					}
					rs.terminal = true
					rs.fenced = true
					// Renewal uncertainty fences this request and fails closed for all
					// future admissions. Reconfigure cannot clear uncertainty while the
					// lease remains in state.leases. Publish it before exposing rs.fenced.
					markAuthorityUncertain()
					rs.mu.Unlock()
					return
				}
				rs.mu.Unlock()
			case <-stop:
				return
			}
		}
	}()
}

func stopHeartbeat(rs *requestLifecycle) {
	if rs.stopBeat != nil {
		close(rs.stopBeat)
		rs.stopBeat = nil
	}
}

func admissionResponse(err *AdmissionError) ([]byte, error) {
	if err == nil {
		err = &AdmissionError{Code: "account_concurrency_authority_unavailable", HTTPStatus: http.StatusServiceUnavailable, RetryAfter: defaultRetryAfter, Message: "concurrency authority unavailable", Authority: true}
	}
	body, _ := json.Marshal(map[string]any{"error": map[string]any{"type": err.Code, "code": err.Code, "message": err.Message, "retryable": err.Retryable()}})
	status := err.HTTPStatus
	if status == 0 {
		status = http.StatusServiceUnavailable
	}
	headers := http.Header{"Content-Type": []string{"application/json"}}
	if err.RetryAfter > 0 {
		headers.Set("Retry-After", strconv.Itoa(err.RetryAfter))
	}
	return okEnvelope(pluginapi.RequestInterceptResponse{Terminate: true, StatusCode: status, ResponseHeaders: headers, ResponseBody: body})
}

func boundedAuthorityContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), authorityCallTimeout)
}

// Account IDs are canonicalized by trimming surrounding whitespace only.
// Case and all interior characters remain significant; distinct IDs therefore
// cannot silently alias except for this documented whitespace normalization.
func canonicalAuthID(id string) string { return strings.TrimSpace(id) }

func selectedAccountID(metadata map[string]any, explicitRaw json.RawMessage) (string, *AdmissionError) {
	explicit := ""
	if len(explicitRaw) > 0 {
		var value *string
		if err := json.Unmarshal(explicitRaw, &value); err != nil {
			return "", missingAccountIdentityError()
		}
		if value != nil {
			explicit = canonicalAuthID(*value)
		}
	}

	selectedValue, selectedPresent := metadata["selected_auth_id"]
	if selectedPresent {
		selected, ok := selectedValue.(string)
		if !ok {
			return "", missingAccountIdentityError()
		}
		selected = canonicalAuthID(selected)
		if selected == "" {
			return "", missingAccountIdentityError()
		}
		if explicit != "" && explicit != selected {
			return "", contradictoryAccountIdentityError()
		}
		return selected, nil
	}
	if explicit != "" {
		return explicit, nil
	}
	return "", missingAccountIdentityError()
}

func missingAccountIdentityError() *AdmissionError {
	return &AdmissionError{Code: "account_concurrency_identity_unavailable", HTTPStatus: http.StatusServiceUnavailable, RetryAfter: defaultRetryAfter, Message: "selected account identity unavailable", Authority: true}
}

func contradictoryAccountIdentityError() *AdmissionError {
	return &AdmissionError{Code: "account_concurrency_identity_conflict", HTTPStatus: http.StatusServiceUnavailable, RetryAfter: defaultRetryAfter, Message: "selected account identity is contradictory", Authority: true}
}

func affinityHint(metadata map[string]any) (hint string, strict, warm bool) {
	if metadata == nil {
		return
	}
	// Explicit pins/session bindings are warm/strict. selected_auth_id is only
	// scheduler selection state and is deliberately never sufficient for warm
	// classification (CPA publishes it on every retry).
	explicit := false
	for _, key := range []string{"pinned_auth_id", "session_auth_id", "affinity_auth_id"} {
		if v, ok := metadata[key].(string); ok && canonicalAuthID(v) != "" {
			hint = canonicalAuthID(v)
			strict, warm = true, true
			explicit = true
			break
		}
	}
	if hint == "" {
		if v, ok := metadata["selected_auth_id"].(string); ok {
			hint = canonicalAuthID(v)
		}
	}
	if !explicit {
		if v, ok := metadata["cache_auth_id"].(string); ok && canonicalAuthID(v) != "" {
			if verified, _ := metadata["cache_verified"].(bool); verified {
				hint = canonicalAuthID(v)
				warm, strict = true, true
			}
		}
	}
	return
}
func preferHint(ids []string, hint string) []string {
	if hint == "" {
		return ids
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if id == hint {
			out = append(out, id)
		}
	}
	for _, id := range ids {
		if id != hint {
			out = append(out, id)
		}
	}
	return out
}
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func okEnvelope(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{OK: true, Result: raw})
}
func errorEnvelope(code, msg string) []byte {
	return typedErrorEnvelope(code, msg, true, http.StatusServiceUnavailable)
}

func typedErrorEnvelope(code, msg string, retryable bool, status int, retryAfter ...int) []byte {
	value := 0
	if len(retryAfter) > 0 {
		value = retryAfter[0]
	}
	raw, _ := json.Marshal(envelope{OK: false, Error: &envelopeError{Code: code, Class: code, Message: msg, Retryable: retryable, HTTPStatus: status, RetryAfter: value}})
	return raw
}
func writeResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	ptr := C.CBytes(raw)
	if ptr == nil {
		return
	}
	response.ptr = ptr
	response.len = C.size_t(len(raw))
}
