package synthesizer

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

// codexTestJWT builds an unsigned JWT carrying the ChatGPT plan claims the
// synthesizer reads to derive plan_type.
func codexTestJWT(t *testing.T, exp time.Time, plan string) string {
	t.Helper()
	payload := map[string]any{
		"email": "user@example.com",
		"exp":   exp.Unix(),
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id": "acct-1",
			"chatgpt_plan_type":  plan,
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	return "hdr." + base64.RawURLEncoding.EncodeToString(raw) + ".sig"
}

func newSynthCtx(dir string) *SynthesisContext {
	return &SynthesisContext{
		Config:      &config.Config{AuthDir: dir},
		AuthDir:     dir,
		Now:         time.Now(),
		IDGenerator: NewStableIDGenerator(),
	}
}

// TestSynthesizeCodexAccountExport verifies that an account-export payload
// (nested accounts[].credentials, no top-level type) is normalised at load time
// so it is recognised as the codex provider with plan_type derived from the JWT.
// This is the fix for both the missing model list and the missing quota-refresh
// button, and it works regardless of how the file reached the auth directory.
func TestSynthesizeCodexAccountExport(t *testing.T) {
	exp := time.Now().Add(6 * time.Hour)
	idToken := codexTestJWT(t, exp, "team")
	accessToken := codexTestJWT(t, exp, "team")

	export := map[string]any{
		"accounts": []any{
			map[string]any{
				"plan_type": "team",
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
	data, err := json.Marshal(export)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	auths := SynthesizeAuthFile(newSynthCtx(t.TempDir()), "/tmp/164.json", data)
	if len(auths) == 0 {
		t.Fatal("no auth synthesized from account-export file")
	}
	a := auths[0]
	if a.Provider != "codex" {
		t.Errorf("provider = %q, want codex", a.Provider)
	}
	if got := a.Attributes["plan_type"]; got != "team" {
		t.Errorf("plan_type = %q, want team (wrong tier selects wrong models)", got)
	}
	if _, ok := a.Metadata["id_token"].(string); !ok {
		t.Error("id_token missing from metadata; quota-refresh button would not render")
	}
}

// TestSynthesizeNativeCodexUnchanged confirms an already-flat codex file still
// synthesizes normally (the normalization is a no-op for it).
func TestSynthesizeNativeCodexUnchanged(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	flat := map[string]any{
		"type":          "codex",
		"access_token":  codexTestJWT(t, exp, "plus"),
		"id_token":      codexTestJWT(t, exp, "plus"),
		"refresh_token": "rt",
		"account_id":    "acct-1",
		"email":         "user@example.com",
	}
	data, err := json.Marshal(flat)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	auths := SynthesizeAuthFile(newSynthCtx(t.TempDir()), "/tmp/codex-user.json", data)
	if len(auths) == 0 {
		t.Fatal("no auth synthesized from flat codex file")
	}
	if auths[0].Provider != "codex" {
		t.Errorf("provider = %q, want codex", auths[0].Provider)
	}
	if got := auths[0].Attributes["plan_type"]; got != "plus" {
		t.Errorf("plan_type = %q, want plus", got)
	}
}
