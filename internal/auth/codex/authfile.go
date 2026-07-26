// Package codex provides authentication and token management functionality for
// OpenAI's Codex AI services. This file implements parsing and normalisation of
// the auth.json credential file written by the official Codex CLI, so an
// already-authenticated workstation credential can be imported directly instead
// of running the OAuth or device-code flow again.
//
// The Codex CLI nests its OAuth material under a "tokens" object and records the
// selected authentication mode alongside it, whereas CLIProxyAPI persists a flat
// credential document (see CodexTokenStorage). ParseAuthFile bridges the two
// shapes and rejects payloads that cannot be served by the codex provider.
package codex

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// AuthFileClockSkew is the tolerance applied when comparing a token expiry
// against the local clock. Codex writes expiry timestamps derived from OpenAI's
// servers, so a small amount of drift must not reject a usable credential.
const AuthFileClockSkew = 2 * time.Minute

// Authentication modes recorded by the Codex CLI in auth.json.
const (
	// AuthModeChatGPT marks a credential backed by a ChatGPT subscription. This
	// is the only mode the codex provider can serve from an imported file.
	AuthModeChatGPT = "chatgpt"
	// AuthModeAPIKey marks a credential that carries a plain OpenAI API key.
	AuthModeAPIKey = "apikey"
)

// Sentinel errors returned by ParseAuthFile. Callers may match on these with
// errors.Is to distinguish a malformed file from an unsupported one.
var (
	// ErrAuthFileEmpty indicates the payload contained no JSON object.
	ErrAuthFileEmpty = errors.New("codex auth file: empty payload")
	// ErrAuthFileMalformed indicates the payload was not a JSON object.
	ErrAuthFileMalformed = errors.New("codex auth file: expected a JSON object")
	// ErrAuthFileUnsupportedMode indicates auth_mode is set to something other
	// than chatgpt, which the codex OAuth provider cannot serve.
	ErrAuthFileUnsupportedMode = errors.New("codex auth file: unsupported auth_mode")
	// ErrAuthFileNoAccessToken indicates no OAuth access token could be located.
	ErrAuthFileNoAccessToken = errors.New("codex auth file: missing access token")
	// ErrAuthFileExpired indicates the access token expired before import.
	ErrAuthFileExpired = errors.New("codex auth file: access token expired")
	// ErrAuthFileNotRenewable indicates the credential carries neither a refresh
	// token nor a determinable expiry, so its validity cannot be established.
	ErrAuthFileNotRenewable = errors.New("codex auth file: credential cannot be renewed or validated")
	// ErrAuthFileNoAccount indicates an account-export payload contained no
	// usable account entry.
	ErrAuthFileNoAccount = errors.New("codex auth file: no account entry found")
)

// AuthFileImport is the normalised result of parsing a Codex auth.json payload.
// Storage is ready to be persisted through the auth store; the remaining fields
// carry derived information used to name the credential file and to surface
// non-fatal findings to the operator.
type AuthFileImport struct {
	// Storage holds the flattened credential document.
	Storage *CodexTokenStorage
	// PlanType is the ChatGPT plan claimed by the token, when present.
	PlanType string
	// AccountIDHash is a short digest of the ChatGPT account ID, used to keep
	// credential filenames distinct for accounts sharing an email and plan.
	AccountIDHash string
	// ExpiresAt is the parsed access-token expiry, zero when unknown.
	ExpiresAt time.Time
	// Warnings lists non-fatal findings the caller should report.
	Warnings []string
}

// ParseAuthFile parses a Codex CLI auth.json payload and normalises it into the
// credential document used by the codex provider. It validates the
// authentication mode, resolves the OAuth material from either the nested
// "tokens" object or the legacy flat layout, enriches missing identity fields
// from the ID and access token claims, and rejects credentials that are already
// expired or that can neither be refreshed nor validated.
//
// Parameters:
//   - data: the raw auth.json contents
//
// Returns:
//   - *AuthFileImport: the normalised credential and any non-fatal warnings
//   - error: a sentinel error (possibly wrapped) describing why import failed
func ParseAuthFile(data []byte) (*AuthFileImport, error) {
	return parseAuthFileAt(data, time.Now())
}

// codexAuthFileMarkers are keys whose presence signals a Codex/ChatGPT OAuth
// credential regardless of whether the payload is a native CLI auth.json or an
// account-export document.
var codexAuthFileMarkers = []string{
	"chatgpt_account_id", "chatgptAccountId",
	"chatgpt_user_id", "chatgptUserId",
	"auth_mode", "authMode",
	"OPENAI_API_KEY",
}

// LooksLikeCodexAuthFile reports whether a raw JSON payload is a Codex CLI
// auth.json or an account-export document carrying Codex credentials, and is not
// already a flattened codex auth file (type == "codex").
//
// It is deliberately conservative: it returns false for anything that already
// declares a provider type or that shows no Codex-specific markers, so uploads
// for other providers are never rewritten.
func LooksLikeCodexAuthFile(data []byte) bool {
	var root map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if err := decoder.Decode(&root); err != nil || len(root) == 0 {
		return false
	}

	// Already a flattened auth file: let the normal load path handle it. A codex
	// type is served as-is; any other declared type belongs to another provider.
	if declared, ok := root["type"].(string); ok && strings.TrimSpace(declared) != "" {
		return false
	}

	candidate := root
	if accounts, ok := root["accounts"].([]any); ok {
		account, found := firstAuthFileObject(accounts)
		if !found {
			return false
		}
		candidate = account
		if creds, okCreds := account["credentials"].(map[string]any); okCreds {
			candidate = creds
		}
	}

	// A nested tokens object is the strongest native-CLI signal.
	if _, ok := candidate["tokens"].(map[string]any); ok {
		return true
	}
	for _, marker := range codexAuthFileMarkers {
		if _, ok := candidate[marker]; ok {
			return true
		}
	}
	// An access_token alongside a ChatGPT-style id_token also qualifies.
	if _, ok := candidate["access_token"]; ok {
		if _, okID := candidate["id_token"]; okID {
			return true
		}
	}
	return false
}

// NormalizeAuthFileJSON converts a Codex CLI auth.json or account-export payload
// into the flattened credential document served by the codex provider, returning
// the marshalled JSON. It is the shared normalisation used by both the CLI import
// command and the management upload path, so a credential imported either way is
// byte-compatible with one produced by the OAuth login flow.
//
// The returned document preserves the identity and routing fields the source
// carried (client_id, chatgpt_user_id, organization_id, token_type,
// model_mapping) so the credential behaves identically to a native login.
func NormalizeAuthFileJSON(data []byte) ([]byte, *AuthFileImport, error) {
	imported, err := ParseAuthFile(data)
	if err != nil {
		return nil, nil, err
	}

	doc := imported.Storage.toDocument()

	// Carry across optional fields that ParseAuthFile does not model but that a
	// native codex file and the executor benefit from.
	if raw := extractSourceCredentials(data); raw != nil {
		for _, key := range []string{"client_id", "chatgpt_user_id", "organization_id", "token_type", "model_mapping"} {
			if _, present := doc[key]; present {
				continue
			}
			if value, ok := raw[key]; ok && value != nil {
				doc[key] = value
			}
		}
	}
	if imported.PlanType != "" {
		doc["plan_type"] = imported.PlanType
	}

	out, errMarshal := json.MarshalIndent(doc, "", "  ")
	if errMarshal != nil {
		return nil, nil, fmt.Errorf("codex auth file: marshal normalised document: %w", errMarshal)
	}
	return out, imported, nil
}

// extractSourceCredentials returns the credentials object from either the flat
// root or accounts[0].credentials, for carrying across optional passthrough
// fields. It returns nil when no object can be located.
func extractSourceCredentials(data []byte) map[string]any {
	var root map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if err := decoder.Decode(&root); err != nil {
		return nil
	}
	if accounts, ok := root["accounts"].([]any); ok {
		if account, found := firstAuthFileObject(accounts); found {
			if creds, okCreds := account["credentials"].(map[string]any); okCreds {
				return creds
			}
			return account
		}
		return nil
	}
	return root
}

// parseAuthFileAt is the clock-injectable core of ParseAuthFile.
func parseAuthFileAt(data []byte, now time.Time) (*AuthFileImport, error) {
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, ErrAuthFileEmpty
	}

	decoder := json.NewDecoder(strings.NewReader(string(data)))
	// Preserve integral precision so second/millisecond epochs survive the round trip.
	decoder.UseNumber()
	var root map[string]any
	if err := decoder.Decode(&root); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAuthFileMalformed, err)
	}
	if len(root) == 0 {
		return nil, ErrAuthFileEmpty
	}

	// Accept both the native Codex CLI auth.json layout and the account-export
	// layout written by sub2api-style gateways ({"accounts":[{"credentials":...}]}).
	// unwrapAuthFileRoot flattens the latter onto a single working object so the
	// path-based extraction below stays layout-agnostic.
	root, err := unwrapAuthFileRoot(root)
	if err != nil {
		return nil, err
	}

	result := &AuthFileImport{Storage: &CodexTokenStorage{Type: "codex"}}

	if err := checkAuthFileMode(root); err != nil {
		return nil, err
	}

	storage := result.Storage
	storage.AccessToken = authFileString(root,
		[]string{"tokens", "access_token"},
		[]string{"tokens", "accessToken"},
		[]string{"access_token"},
		[]string{"accessToken"},
	)
	storage.RefreshToken = authFileString(root,
		[]string{"tokens", "refresh_token"},
		[]string{"tokens", "refreshToken"},
		[]string{"refresh_token"},
		[]string{"refreshToken"},
	)
	storage.IDToken = authFileString(root,
		[]string{"tokens", "id_token"},
		[]string{"tokens", "idToken"},
		[]string{"id_token"},
		[]string{"idToken"},
	)
	storage.AccountID = authFileString(root,
		[]string{"tokens", "account_id"},
		[]string{"tokens", "accountId"},
		[]string{"account_id"},
		[]string{"accountId"},
		[]string{"chatgpt_account_id"},
	)
	storage.Email = authFileString(root,
		[]string{"email"},
		[]string{"tokens", "email"},
	)

	if storage.AccessToken == "" {
		// A file holding only OPENAI_API_KEY is a valid Codex credential but not
		// an OAuth one; point the operator at the configuration path instead.
		if authFileString(root, []string{"OPENAI_API_KEY"}, []string{"openai_api_key"}) != "" {
			return nil, fmt.Errorf("%w: file carries only OPENAI_API_KEY; configure it under codex-api-key in config.yaml instead", ErrAuthFileNoAccessToken)
		}
		return nil, ErrAuthFileNoAccessToken
	}

	// Explicit expiry wins over anything derived from the token claims.
	expiresAt, hasExpiry := authFileTime(root,
		[]string{"tokens", "expires_at"},
		[]string{"tokens", "expiresAt"},
		[]string{"expires_at"},
		[]string{"expiresAt"},
		[]string{"expired"},
	)

	// The ID token carries richer identity claims; consult it first so the
	// access token only fills in what is still missing.
	result.enrichFromToken(storage.IDToken)
	claimExpiry, claimOK := result.enrichFromToken(storage.AccessToken)
	if !hasExpiry && claimOK {
		expiresAt, hasExpiry = claimExpiry, true
	}

	if hasExpiry {
		if expiresAt.Add(AuthFileClockSkew).Before(now) {
			return nil, fmt.Errorf("%w at %s", ErrAuthFileExpired, expiresAt.UTC().Format(time.RFC3339))
		}
		result.ExpiresAt = expiresAt.UTC()
		storage.Expire = expiresAt.UTC().Format(time.RFC3339)
	} else {
		result.Warnings = append(result.Warnings, "access token expiry could not be determined; the credential will only be validated on first use")
	}

	if storage.RefreshToken == "" {
		if !hasExpiry {
			// Without either signal the credential is indistinguishable from a
			// dud, and the refresh loop has nothing to act on. Fail loudly
			// rather than registering a credential that silently never works.
			return nil, ErrAuthFileNotRenewable
		}
		result.Warnings = append(result.Warnings, fmt.Sprintf("no refresh token present; the credential stops working after %s and must be re-imported", storage.Expire))
	}

	storage.LastRefresh = authFileString(root, []string{"last_refresh"}, []string{"lastRefresh"})
	if storage.LastRefresh == "" {
		storage.LastRefresh = now.UTC().Format(time.RFC3339)
	}

	if storage.Email == "" {
		result.Warnings = append(result.Warnings, "no account email found; the credential filename falls back to the account identifier")
	}

	return result, nil
}

// unwrapAuthFileRoot normalises the two supported payload layouts onto a single
// working object.
//
// The native Codex CLI writes its fields at the top level (optionally nested
// under "tokens"), which is returned unchanged. Account-export gateways instead
// wrap one or more accounts under an "accounts" array, each carrying its OAuth
// material inside a "credentials" object and its plan/email at the account
// level. For that shape the first account is selected and its credentials are
// merged with the surviving account-level fields so the downstream path lookups
// resolve regardless of origin.
//
// Only the first account is imported: each credential lands in its own auth
// file, so multi-account exports are handled by importing the file per account
// rather than fanning out here.
func unwrapAuthFileRoot(root map[string]any) (map[string]any, error) {
	rawAccounts, ok := root["accounts"]
	if !ok {
		return root, nil
	}

	accounts, ok := rawAccounts.([]any)
	if !ok || len(accounts) == 0 {
		return nil, ErrAuthFileNoAccount
	}

	account, ok := firstAuthFileObject(accounts)
	if !ok {
		return nil, ErrAuthFileNoAccount
	}

	credentials, ok := account["credentials"].(map[string]any)
	if !ok {
		// Some exports flatten credentials onto the account object itself.
		credentials = account
	}

	// Start from the credentials object and layer on account-level fields that
	// the credentials block does not already provide (email, plan_type, name).
	merged := make(map[string]any, len(credentials)+4)
	for key, value := range credentials {
		merged[key] = value
	}
	for _, key := range []string{"email", "plan_type", "planType", "name", "auth_mode", "authMode"} {
		if _, exists := merged[key]; exists {
			continue
		}
		if value, present := account[key]; present {
			merged[key] = value
		}
	}

	// A placeholder expires_at of 0 (or an empty string) must not be treated as
	// a real expiry; drop it so the parser falls back to the token claims.
	if isZeroAuthFileExpiry(merged["expires_at"]) {
		delete(merged, "expires_at")
	}
	if isZeroAuthFileExpiry(merged["expiresAt"]) {
		delete(merged, "expiresAt")
	}

	return merged, nil
}

// firstAuthFileObject returns the first element of the slice that is a JSON
// object.
func firstAuthFileObject(values []any) (map[string]any, bool) {
	for _, value := range values {
		if obj, ok := value.(map[string]any); ok && len(obj) > 0 {
			return obj, true
		}
	}
	return nil, false
}

// isZeroAuthFileExpiry reports whether an expiry value is a placeholder that
// should be ignored (numeric zero, or an empty/zero string).
func isZeroAuthFileExpiry(value any) bool {
	switch typed := value.(type) {
	case nil:
		return true
	case json.Number:
		if n, err := typed.Int64(); err == nil {
			return n <= 0
		}
		if f, err := typed.Float64(); err == nil {
			return f <= 0
		}
	case float64:
		return typed <= 0
	case int:
		return typed <= 0
	case string:
		trimmed := strings.TrimSpace(typed)
		return trimmed == "" || trimmed == "0"
	}
	return false
}

// checkAuthFileMode rejects auth.json payloads whose recorded authentication
// mode cannot be served by the codex OAuth provider.
func checkAuthFileMode(root map[string]any) error {
	mode := authFileString(root,
		[]string{"auth_mode"},
		[]string{"authMode"},
		[]string{"OPENAI_AUTH_MODE"},
	)
	if mode == "" || strings.EqualFold(mode, AuthModeChatGPT) {
		return nil
	}
	if strings.EqualFold(mode, AuthModeAPIKey) {
		return fmt.Errorf("%w %q: configure the key under codex-api-key in config.yaml instead", ErrAuthFileUnsupportedMode, mode)
	}
	return fmt.Errorf("%w %q: only %q is supported", ErrAuthFileUnsupportedMode, mode, AuthModeChatGPT)
}

// enrichFromToken fills identity fields that the raw document left empty using
// the claims embedded in the supplied JWT. Tokens that are absent or not
// parseable are skipped silently; callers decide whether that is fatal.
//
// Returns the claimed expiry and whether one was present.
func (r *AuthFileImport) enrichFromToken(token string) (time.Time, bool) {
	if strings.TrimSpace(token) == "" {
		return time.Time{}, false
	}
	claims, err := ParseJWTToken(token)
	if err != nil || claims == nil {
		return time.Time{}, false
	}

	if r.Storage.Email == "" {
		r.Storage.Email = strings.TrimSpace(claims.Email)
	}
	if r.Storage.AccountID == "" {
		r.Storage.AccountID = strings.TrimSpace(claims.CodexAuthInfo.ChatgptAccountID)
	}
	if r.PlanType == "" {
		r.PlanType = strings.TrimSpace(claims.CodexAuthInfo.ChatgptPlanType)
	}
	if r.AccountIDHash == "" {
		if accountID := strings.TrimSpace(claims.CodexAuthInfo.ChatgptAccountID); accountID != "" {
			r.AccountIDHash = HashAccountID(accountID)
		}
	}

	if claims.Exp <= 0 {
		return time.Time{}, false
	}
	return time.Unix(int64(claims.Exp), 0).UTC(), true
}

// authFileString returns the first non-empty string found at any of the supplied
// key paths. Codex has shipped several spellings of the same field over time, so
// each candidate path is tried in order of preference.
func authFileString(root map[string]any, paths ...[]string) string {
	for _, path := range paths {
		value, ok := authFileLookup(root, path)
		if !ok {
			continue
		}
		if str := authFileStringify(value); str != "" {
			return str
		}
	}
	return ""
}

// authFileTime returns the first parseable timestamp found at any of the
// supplied key paths.
func authFileTime(root map[string]any, paths ...[]string) (time.Time, bool) {
	for _, path := range paths {
		value, ok := authFileLookup(root, path)
		if !ok {
			continue
		}
		if ts, parsed := authFileParseTime(value); parsed {
			return ts, true
		}
	}
	return time.Time{}, false
}

// authFileLookup walks a nested key path and reports whether a value exists.
func authFileLookup(root map[string]any, path []string) (any, bool) {
	var current any = root
	for _, key := range path {
		obj, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		value, ok := obj[key]
		if !ok {
			return nil, false
		}
		current = value
	}
	return current, true
}

// authFileStringify renders scalar JSON values as trimmed strings. Numeric
// account identifiers are rendered without scientific notation.
func authFileStringify(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case json.Number:
		return strings.TrimSpace(typed.String())
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(typed)
	default:
		return ""
	}
}

// authFileParseTime accepts RFC3339 strings, numeric strings and JSON numbers,
// treating bare numbers as Unix epochs in either seconds or milliseconds.
func authFileParseTime(value any) (time.Time, bool) {
	switch typed := value.(type) {
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return time.Time{}, false
		}
		if ts, err := time.Parse(time.RFC3339Nano, trimmed); err == nil {
			return ts.UTC(), true
		}
		if epoch, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
			return authFileEpoch(epoch)
		}
	case json.Number:
		if epoch, err := typed.Int64(); err == nil {
			return authFileEpoch(epoch)
		}
		if seconds, err := typed.Float64(); err == nil {
			return authFileEpoch(int64(seconds))
		}
	case float64:
		return authFileEpoch(int64(typed))
	}
	return time.Time{}, false
}

// authFileEpoch converts a Unix timestamp to a time, auto-detecting whether the
// value carries millisecond precision.
func authFileEpoch(value int64) (time.Time, bool) {
	if value <= 0 {
		return time.Time{}, false
	}
	if value > 1_000_000_000_000 {
		return time.UnixMilli(value).UTC(), true
	}
	return time.Unix(value, 0).UTC(), true
}
