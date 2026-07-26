package management

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

// makeCodexJWT builds an unsigned JWT carrying the ChatGPT auth claims the
// management UI reads to render the plan details and quota-refresh action.
func makeCodexJWT(t *testing.T, exp time.Time, email, accountID, plan string) string {
	t.Helper()
	payload := map[string]any{
		"email": email,
		"exp":   exp.Unix(),
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id":                accountID,
			"chatgpt_plan_type":                 plan,
			"chatgpt_subscription_active_start": "2026-07-24T13:04:57+00:00",
			"chatgpt_subscription_active_until": "2026-08-24T13:04:57+00:00",
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	return "hdr." + base64.RawURLEncoding.EncodeToString(raw) + ".sig"
}

// TestUploadedCodexAccountExportClassifiesAsCodex verifies the fix for the
// missing quota-refresh button: an uploaded account-export payload is normalised
// into a flat codex document, so buildAuthFromFileData classifies it as the
// codex provider with a JWT that the UI can read for the refresh action.
func TestUploadedCodexAccountExportClassifiesAsCodex(t *testing.T) {
	now := time.Now()
	expiry := now.Add(6 * time.Hour)
	accessToken := makeCodexJWT(t, expiry, "user@example.com", "acct-1", "team")
	idToken := makeCodexJWT(t, expiry, "user@example.com", "acct-1", "team")

	// Account-export layout (as written by sub2api-style gateways).
	export := map[string]any{
		"accounts": []any{
			map[string]any{
				"plan_type": "team",
				"type":      "oauth",
				"platform":  "openai",
				"credentials": map[string]any{
					"access_token":       accessToken,
					"refresh_token":      "rt-1",
					"id_token":           idToken,
					"chatgpt_account_id": "acct-1",
					"email":              "user@example.com",
					"expires_at":         0,
				},
			},
		},
	}
	raw, err := json.Marshal(export)
	if err != nil {
		t.Fatalf("marshal export: %v", err)
	}

	if !codex.LooksLikeCodexAuthFile(raw) {
		t.Fatal("payload not detected as a codex auth file")
	}
	normalized, _, err := codex.NormalizeAuthFileJSON(raw)
	if err != nil {
		t.Fatalf("normalise: %v", err)
	}

	h := &Handler{cfg: &config.Config{AuthDir: t.TempDir()}}
	auth, err := h.buildAuthFromFileData(h.cfg.AuthDir+"/codex-user@example.com-team.json", normalized)
	if err != nil {
		t.Fatalf("buildAuthFromFileData: %v", err)
	}

	if auth.Provider != "codex" {
		t.Fatalf("provider = %q, want codex (button hangs off codex classification)", auth.Provider)
	}
	if _, ok := auth.Metadata["id_token"].(string); !ok {
		t.Fatal("id_token missing from metadata; quota-refresh button would not render")
	}

	claims := extractCodexIDTokenClaims(auth)
	if claims == nil {
		t.Fatal("extractCodexIDTokenClaims returned nil; button data absent")
	}
	if claims["plan_type"] != "team" {
		t.Errorf("plan_type = %v, want team", claims["plan_type"])
	}
	if claims["chatgpt_account_id"] != "acct-1" {
		t.Errorf("chatgpt_account_id = %v, want acct-1", claims["chatgpt_account_id"])
	}
}

// TestUploadedNonCodexFileUntouched confirms the normaliser leaves other
// providers' auth files alone.
func TestUploadedNonCodexFileUntouched(t *testing.T) {
	for _, payload := range []string{
		`{"type":"gemini","access_token":"a"}`,
		`{"project_id":"p","client_email":"e","private_key":"k"}`,
		`{"type":"codex","access_token":"a","id_token":"b"}`,
	} {
		if codex.LooksLikeCodexAuthFile([]byte(payload)) {
			t.Errorf("payload should not be rewritten: %s", payload)
		}
	}
}
