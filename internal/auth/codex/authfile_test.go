package codex

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// makeTestJWT builds an unsigned JWT whose payload carries the supplied claims.
// Only the payload segment is meaningful; ParseJWTToken does not verify
// signatures, so the header and signature are placeholders.
func makeTestJWT(t *testing.T, exp time.Time, email, accountID, planType string) string {
	t.Helper()

	payload := map[string]any{
		"email": email,
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id": accountID,
			"chatgpt_plan_type":  planType,
			"chatgpt_user_id":    "user-" + accountID,
		},
	}
	if !exp.IsZero() {
		payload["exp"] = exp.Unix()
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	segment := base64.RawURLEncoding.EncodeToString(raw)
	return "header." + segment + ".signature"
}

// codexAuthFileJSON renders a Codex CLI style auth.json with the nested tokens object.
func codexAuthFileJSON(t *testing.T, authMode, accessToken, refreshToken, idToken, accountID, lastRefresh string) []byte {
	t.Helper()

	doc := map[string]any{
		"tokens": map[string]any{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
			"id_token":      idToken,
			"account_id":    accountID,
		},
	}
	if authMode != "" {
		doc["auth_mode"] = authMode
	}
	if lastRefresh != "" {
		doc["last_refresh"] = lastRefresh
	}

	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal auth file: %v", err)
	}
	return raw
}

func TestParseAuthFileValid(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(2 * time.Hour)
	accessToken := makeTestJWT(t, expiry, "user@example.com", "acct-123", "plus")
	idToken := makeTestJWT(t, expiry, "user@example.com", "acct-123", "plus")

	data := codexAuthFileJSON(t, AuthModeChatGPT, accessToken, "refresh-abc", idToken, "acct-123", "2026-07-26T10:00:00Z")

	got, err := parseAuthFileAt(data, now)
	if err != nil {
		t.Fatalf("parseAuthFileAt() unexpected error: %v", err)
	}

	if got.Storage.AccessToken != accessToken {
		t.Errorf("AccessToken = %q, want the token from tokens.access_token", got.Storage.AccessToken)
	}
	if got.Storage.RefreshToken != "refresh-abc" {
		t.Errorf("RefreshToken = %q, want refresh-abc", got.Storage.RefreshToken)
	}
	if got.Storage.AccountID != "acct-123" {
		t.Errorf("AccountID = %q, want acct-123", got.Storage.AccountID)
	}
	if got.Storage.Email != "user@example.com" {
		t.Errorf("Email = %q, want user@example.com", got.Storage.Email)
	}
	if got.Storage.Type != "codex" {
		t.Errorf("Type = %q, want codex", got.Storage.Type)
	}
	if got.Storage.LastRefresh != "2026-07-26T10:00:00Z" {
		t.Errorf("LastRefresh = %q, want the value from the file", got.Storage.LastRefresh)
	}
	if got.PlanType != "plus" {
		t.Errorf("PlanType = %q, want plus", got.PlanType)
	}
	if got.AccountIDHash != HashAccountID("acct-123") {
		t.Errorf("AccountIDHash = %q, want the digest of the account id", got.AccountIDHash)
	}
	if !got.ExpiresAt.Equal(expiry) {
		t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, expiry)
	}
	if got.Storage.Expire != expiry.Format(time.RFC3339) {
		t.Errorf("Expire = %q, want %q", got.Storage.Expire, expiry.Format(time.RFC3339))
	}
	if len(got.Warnings) != 0 {
		t.Errorf("Warnings = %v, want none for a complete file", got.Warnings)
	}
}

func TestParseAuthFileFlatLayout(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(time.Hour)
	accessToken := makeTestJWT(t, expiry, "flat@example.com", "acct-flat", "pro")

	// Legacy shape: OAuth material sits at the top level rather than under tokens.
	data := []byte(fmt.Sprintf(`{"access_token":%q,"refresh_token":"r-flat","account_id":"acct-flat"}`, accessToken))

	got, err := parseAuthFileAt(data, now)
	if err != nil {
		t.Fatalf("parseAuthFileAt() unexpected error: %v", err)
	}
	if got.Storage.AccessToken != accessToken {
		t.Errorf("AccessToken not resolved from the flat layout")
	}
	if got.Storage.Email != "flat@example.com" {
		t.Errorf("Email = %q, want the claim from the access token", got.Storage.Email)
	}
	if got.Storage.LastRefresh == "" {
		t.Error("LastRefresh should default to the current time when absent")
	}
}

func TestParseAuthFileExpiredToken(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(-time.Hour)
	accessToken := makeTestJWT(t, expiry, "user@example.com", "acct-123", "plus")

	data := codexAuthFileJSON(t, AuthModeChatGPT, accessToken, "refresh-abc", "", "acct-123", "")

	_, err := parseAuthFileAt(data, now)
	if !errors.Is(err, ErrAuthFileExpired) {
		t.Fatalf("parseAuthFileAt() error = %v, want ErrAuthFileExpired", err)
	}
}

func TestParseAuthFileWithinClockSkew(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	// Expired a minute ago, which is inside the tolerated skew window.
	expiry := now.Add(-time.Minute)
	accessToken := makeTestJWT(t, expiry, "user@example.com", "acct-123", "plus")

	data := codexAuthFileJSON(t, AuthModeChatGPT, accessToken, "refresh-abc", "", "acct-123", "")

	if _, err := parseAuthFileAt(data, now); err != nil {
		t.Fatalf("parseAuthFileAt() rejected a credential inside the skew window: %v", err)
	}
}

func TestParseAuthFileMissingRefreshTokenWarns(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(3 * time.Hour)
	accessToken := makeTestJWT(t, expiry, "user@example.com", "acct-123", "plus")

	data := codexAuthFileJSON(t, AuthModeChatGPT, accessToken, "", "", "acct-123", "")

	got, err := parseAuthFileAt(data, now)
	if err != nil {
		t.Fatalf("parseAuthFileAt() unexpected error: %v", err)
	}
	if got.Storage.RefreshToken != "" {
		t.Errorf("RefreshToken = %q, want empty", got.Storage.RefreshToken)
	}
	if len(got.Warnings) == 0 {
		t.Fatal("expected a warning about the missing refresh token")
	}
	if !strings.Contains(strings.Join(got.Warnings, " "), "refresh token") {
		t.Errorf("Warnings = %v, want one mentioning the refresh token", got.Warnings)
	}
}

func TestParseAuthFileNotRenewable(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)

	// Opaque access token: no refresh token and no expiry can be derived.
	data := []byte(`{"tokens":{"access_token":"opaque-token"}}`)

	_, err := parseAuthFileAt(data, now)
	if !errors.Is(err, ErrAuthFileNotRenewable) {
		t.Fatalf("parseAuthFileAt() error = %v, want ErrAuthFileNotRenewable", err)
	}
}

func TestParseAuthFileMissingAccessToken(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		data string
	}{
		{name: "empty tokens object", data: `{"tokens":{}}`},
		{name: "refresh token only", data: `{"tokens":{"refresh_token":"r-only"}}`},
		{name: "api key only", data: `{"OPENAI_API_KEY":"sk-test","tokens":{}}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseAuthFileAt([]byte(tc.data), now)
			if !errors.Is(err, ErrAuthFileNoAccessToken) {
				t.Fatalf("parseAuthFileAt() error = %v, want ErrAuthFileNoAccessToken", err)
			}
		})
	}
}

func TestParseAuthFileUnsupportedAuthMode(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	accessToken := makeTestJWT(t, now.Add(time.Hour), "user@example.com", "acct-123", "plus")

	for _, mode := range []string{AuthModeAPIKey, "agentIdentity", "personal_access_token"} {
		t.Run(mode, func(t *testing.T) {
			data := codexAuthFileJSON(t, mode, accessToken, "refresh-abc", "", "acct-123", "")
			_, err := parseAuthFileAt(data, now)
			if !errors.Is(err, ErrAuthFileUnsupportedMode) {
				t.Fatalf("parseAuthFileAt() error = %v, want ErrAuthFileUnsupportedMode", err)
			}
		})
	}
}

func TestParseAuthFileAcceptsChatGPTModeCaseInsensitively(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	accessToken := makeTestJWT(t, now.Add(time.Hour), "user@example.com", "acct-123", "plus")

	data := codexAuthFileJSON(t, "ChatGPT", accessToken, "refresh-abc", "", "acct-123", "")
	if _, err := parseAuthFileAt(data, now); err != nil {
		t.Fatalf("parseAuthFileAt() rejected a chatgpt credential: %v", err)
	}
}

func TestParseAuthFileMalformed(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		data string
		want error
	}{
		{name: "blank", data: "   ", want: ErrAuthFileEmpty},
		{name: "empty object", data: `{}`, want: ErrAuthFileEmpty},
		{name: "array", data: `[]`, want: ErrAuthFileMalformed},
		{name: "truncated", data: `{"tokens":`, want: ErrAuthFileMalformed},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseAuthFileAt([]byte(tc.data), now)
			if !errors.Is(err, tc.want) {
				t.Fatalf("parseAuthFileAt() error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestParseAuthFileExplicitExpiryWins(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	claimExpiry := now.Add(10 * time.Hour)
	accessToken := makeTestJWT(t, claimExpiry, "user@example.com", "acct-123", "plus")

	// The document states an earlier expiry than the token claims; the explicit
	// field is authoritative so the refresh loop acts on the conservative value.
	explicit := now.Add(time.Hour).UTC()
	data := []byte(fmt.Sprintf(
		`{"tokens":{"access_token":%q,"refresh_token":"r","expires_at":%q}}`,
		accessToken, explicit.Format(time.RFC3339),
	))

	got, err := parseAuthFileAt(data, now)
	if err != nil {
		t.Fatalf("parseAuthFileAt() unexpected error: %v", err)
	}
	if !got.ExpiresAt.Equal(explicit) {
		t.Errorf("ExpiresAt = %v, want the explicit field %v", got.ExpiresAt, explicit)
	}
}

func TestParseAuthFileNumericEpochExpiry(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(time.Hour).UTC()

	tests := []struct {
		name string
		data string
	}{
		{name: "seconds", data: fmt.Sprintf(`{"tokens":{"access_token":"opaque","refresh_token":"r","expires_at":%d}}`, expiry.Unix())},
		{name: "milliseconds", data: fmt.Sprintf(`{"tokens":{"access_token":"opaque","refresh_token":"r","expires_at":%d}}`, expiry.UnixMilli())},
		{name: "numeric string", data: fmt.Sprintf(`{"tokens":{"access_token":"opaque","refresh_token":"r","expires_at":"%d"}}`, expiry.Unix())},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseAuthFileAt([]byte(tc.data), now)
			if err != nil {
				t.Fatalf("parseAuthFileAt() unexpected error: %v", err)
			}
			if !got.ExpiresAt.Equal(expiry) {
				t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, expiry)
			}
		})
	}
}

// accountExportJSON renders the account-export layout used by sub2api-style
// gateways: OAuth material nested under accounts[].credentials, with a
// placeholder expires_at of 0.
func accountExportJSON(t *testing.T, accessToken, refreshToken, idToken, accountID, email, plan string) []byte {
	t.Helper()

	doc := map[string]any{
		"accounts": []any{
			map[string]any{
				"name":      "acct-name",
				"plan_type": plan,
				"platform":  "openai",
				"type":      "oauth",
				"credentials": map[string]any{
					"access_token":       accessToken,
					"refresh_token":      refreshToken,
					"id_token":           idToken,
					"chatgpt_account_id": accountID,
					"email":              email,
					"expires_at":         0,
					"token_type":         "Bearer",
				},
			},
		},
		"exported_at": "2026-07-24T13:39:58Z",
		"proxies":     []any{},
	}

	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal account export: %v", err)
	}
	return raw
}

func TestParseAuthFileAccountExportLayout(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	expiry := now.Add(6 * time.Hour)
	accessToken := makeTestJWT(t, expiry, "export@example.com", "acct-export", "team")
	idToken := makeTestJWT(t, expiry, "export@example.com", "acct-export", "team")

	data := accountExportJSON(t, accessToken, "rt-export", idToken, "acct-export", "export@example.com", "team")

	got, err := parseAuthFileAt(data, now)
	if err != nil {
		t.Fatalf("parseAuthFileAt() unexpected error: %v", err)
	}
	if got.Storage.AccessToken != accessToken {
		t.Errorf("AccessToken not resolved from accounts[].credentials")
	}
	if got.Storage.RefreshToken != "rt-export" {
		t.Errorf("RefreshToken = %q, want rt-export", got.Storage.RefreshToken)
	}
	if got.Storage.AccountID != "acct-export" {
		t.Errorf("AccountID = %q, want acct-export", got.Storage.AccountID)
	}
	if got.Storage.Email != "export@example.com" {
		t.Errorf("Email = %q, want export@example.com", got.Storage.Email)
	}
	if got.PlanType != "team" {
		t.Errorf("PlanType = %q, want team", got.PlanType)
	}
	// The placeholder expires_at of 0 must be ignored in favour of the JWT claim.
	if !got.ExpiresAt.Equal(expiry) {
		t.Errorf("ExpiresAt = %v, want the JWT claim %v (placeholder expires_at must be ignored)", got.ExpiresAt, expiry)
	}
}

func TestParseAuthFileAccountExportZeroExpiryNotExpired(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	// Token is valid; only the file-level expires_at is the placeholder 0.
	expiry := now.Add(time.Hour)
	accessToken := makeTestJWT(t, expiry, "z@example.com", "acct-z", "plus")

	data := accountExportJSON(t, accessToken, "rt", "", "acct-z", "z@example.com", "plus")

	got, err := parseAuthFileAt(data, now)
	if err != nil {
		t.Fatalf("parseAuthFileAt() rejected a valid credential because of the placeholder expiry: %v", err)
	}
	if !got.ExpiresAt.Equal(expiry) {
		t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, expiry)
	}
}

func TestParseAuthFileEmptyAccounts(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		data string
	}{
		{name: "empty array", data: `{"accounts":[]}`},
		{name: "null entry", data: `{"accounts":[null]}`},
		{name: "non-object entry", data: `{"accounts":["nope"]}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseAuthFileAt([]byte(tc.data), now)
			if !errors.Is(err, ErrAuthFileNoAccount) {
				t.Fatalf("parseAuthFileAt() error = %v, want ErrAuthFileNoAccount", err)
			}
		})
	}
}

func TestParseAuthFileAccountExportUnsupportedMode(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	accessToken := makeTestJWT(t, now.Add(time.Hour), "e@x.com", "a", "plus")

	// auth_mode lives at the account level in this layout; it must still be honoured.
	doc := map[string]any{
		"accounts": []any{
			map[string]any{
				"auth_mode": "apikey",
				"credentials": map[string]any{
					"access_token": accessToken,
				},
			},
		},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if _, err := parseAuthFileAt(raw, now); !errors.Is(err, ErrAuthFileUnsupportedMode) {
		t.Fatalf("parseAuthFileAt() error = %v, want ErrAuthFileUnsupportedMode", err)
	}
}

func TestLooksLikeCodexAuthFile(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	accessToken := makeTestJWT(t, now.Add(time.Hour), "e@x.com", "acct", "plus")
	idToken := makeTestJWT(t, now.Add(time.Hour), "e@x.com", "acct", "plus")

	tests := []struct {
		name string
		data string
		want bool
	}{
		{name: "native tokens object", data: `{"auth_mode":"chatgpt","tokens":{"access_token":"x"}}`, want: true},
		{name: "account export", data: string(accountExportJSON(t, accessToken, "rt", idToken, "acct", "e@x.com", "team")), want: true},
		{name: "access plus id token", data: `{"access_token":"a","id_token":"b"}`, want: true},
		{name: "chatgpt account marker", data: `{"access_token":"a","chatgpt_account_id":"acct"}`, want: true},
		{name: "api key only", data: `{"OPENAI_API_KEY":"sk"}`, want: true},
		{name: "already flat codex", data: `{"type":"codex","access_token":"a"}`, want: false},
		{name: "other provider", data: `{"type":"gemini","access_token":"a"}`, want: false},
		{name: "vertex service account", data: `{"project_id":"p","client_email":"e","private_key":"k"}`, want: false},
		{name: "garbage", data: `not json`, want: false},
		{name: "empty object", data: `{}`, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := LooksLikeCodexAuthFile([]byte(tc.data)); got != tc.want {
				t.Fatalf("LooksLikeCodexAuthFile() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNormalizeAuthFileJSON(t *testing.T) {
	now := time.Now()
	expiry := now.Add(4 * time.Hour)
	accessToken := makeTestJWT(t, expiry, "norm@example.com", "acct-norm", "team")
	idToken := makeTestJWT(t, expiry, "norm@example.com", "acct-norm", "team")

	// Account-export shape carrying passthrough fields the parser does not model.
	doc := map[string]any{
		"accounts": []any{
			map[string]any{
				"plan_type": "team",
				"credentials": map[string]any{
					"access_token":       accessToken,
					"refresh_token":      "rt-norm",
					"id_token":           idToken,
					"chatgpt_account_id": "acct-norm",
					"chatgpt_user_id":    "user-norm",
					"client_id":          "app_client_norm",
					"organization_id":    "org-norm",
					"token_type":         "Bearer",
					"email":              "norm@example.com",
					"expires_at":         0,
					"model_mapping":      map[string]any{"gpt-5.5": "gpt-5.5"},
				},
			},
		},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	out, imported, err := NormalizeAuthFileJSON(raw)
	if err != nil {
		t.Fatalf("NormalizeAuthFileJSON() error: %v", err)
	}

	var flat map[string]any
	if err := json.Unmarshal(out, &flat); err != nil {
		t.Fatalf("normalised output is not valid JSON: %v", err)
	}

	// Fields the button and executor depend on must be present at the top level.
	if flat["type"] != "codex" {
		t.Errorf("type = %v, want codex", flat["type"])
	}
	if flat["id_token"] != idToken {
		t.Error("id_token missing from flat document (button would not render)")
	}
	if flat["access_token"] != accessToken {
		t.Error("access_token missing from flat document")
	}
	if flat["refresh_token"] != "rt-norm" {
		t.Errorf("refresh_token = %v, want rt-norm", flat["refresh_token"])
	}
	if flat["account_id"] != "acct-norm" {
		t.Errorf("account_id = %v, want acct-norm", flat["account_id"])
	}
	// Passthrough fields carried across from the source.
	if flat["client_id"] != "app_client_norm" {
		t.Errorf("client_id = %v, want app_client_norm", flat["client_id"])
	}
	if flat["organization_id"] != "org-norm" {
		t.Errorf("organization_id = %v, want org-norm", flat["organization_id"])
	}
	if flat["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", flat["token_type"])
	}
	if _, ok := flat["model_mapping"]; !ok {
		t.Error("model_mapping should be carried across")
	}
	// The placeholder expires_at of 0 must not survive as a real expiry; the
	// flat document records the JWT-derived expiry under "expired".
	if _, ok := flat["expires_at"]; ok {
		t.Error("placeholder expires_at must not be carried into the flat document")
	}
	if strings.TrimSpace(imported.Storage.Expire) == "" {
		t.Error("expected a resolved expiry from the JWT claim")
	}
}

func TestNormalizeAuthFileJSONRejectsExpired(t *testing.T) {
	now := time.Now()
	accessToken := makeTestJWT(t, now.Add(-2*time.Hour), "e@x.com", "acct", "plus")
	data := codexAuthFileJSON(t, AuthModeChatGPT, accessToken, "rt", "", "acct", "")

	if _, _, err := NormalizeAuthFileJSON(data); !errors.Is(err, ErrAuthFileExpired) {
		t.Fatalf("NormalizeAuthFileJSON() error = %v, want ErrAuthFileExpired", err)
	}
}

func TestHashAccountID(t *testing.T) {
	if got := HashAccountID(""); got != "" {
		t.Errorf("HashAccountID(\"\") = %q, want empty", got)
	}
	if got := HashAccountID("  "); got != "" {
		t.Errorf("HashAccountID(blank) = %q, want empty", got)
	}
	got := HashAccountID("acct-123")
	if len(got) != accountIDHashLength {
		t.Errorf("HashAccountID length = %d, want %d", len(got), accountIDHashLength)
	}
	if got != HashAccountID(" acct-123 ") {
		t.Error("HashAccountID should ignore surrounding whitespace")
	}
}
