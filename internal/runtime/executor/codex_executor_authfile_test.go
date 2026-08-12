package executor

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	codexauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestCodexExecutorPrepareRequestUsesNormalizedAuthFileToken(t *testing.T) {
	raw := []byte(`{"type":"sub2api-data","accounts":[{"platform":"openai","credentials":{"access_token":"oauth-access-token","chatgpt_account_id":"acct-test","expires_at":4102444800}}]}`)
	normalized, _, err := codexauth.NormalizeAuthFileJSON(raw)
	if err != nil {
		t.Fatalf("NormalizeAuthFileJSON() error: %v", err)
	}

	var metadata map[string]any
	if err := json.Unmarshal(normalized, &metadata); err != nil {
		t.Fatalf("normalized auth file is not JSON: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://chatgpt.com/backend-api/wham/usage", nil)
	auth := &cliproxyauth.Auth{Metadata: metadata}
	if err := (&CodexExecutor{}).PrepareRequest(req, auth); err != nil {
		t.Fatalf("PrepareRequest() error: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer oauth-access-token" {
		t.Fatalf("Authorization = %q, want normalized access token", got)
	}
}
