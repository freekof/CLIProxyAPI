// Package cmd contains CLI helpers. This file implements importing an existing
// Codex CLI auth.json into the auth store as a "codex" credential, so a
// workstation that already completed the Codex login can be adopted without
// running the OAuth or device-code flow again.
package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v7/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// defaultCodexAuthFile is the location the Codex CLI writes its credential to,
// relative to the user's home directory.
var defaultCodexAuthFile = filepath.Join(".codex", "auth.json")

// DoCodexImport imports a Codex CLI auth.json and persists it as a "codex"
// provider credential. When authPath is empty the default Codex CLI location is
// used. The credential is normalised into the same flat document produced by the
// OAuth login flow, so the executor and refresh loop treat it identically.
//
// Parameters:
//   - cfg: The application configuration
//   - authPath: Path to the Codex auth.json, or empty to use the default
func DoCodexImport(cfg *config.Config, authPath string) {
	if cfg == nil {
		cfg = &config.Config{}
	}
	if resolved, errResolve := util.ResolveAuthDir(cfg.AuthDir); errResolve == nil {
		cfg.AuthDir = resolved
	}

	resolvedPath, errResolve := resolveCodexAuthFilePath(authPath)
	if errResolve != nil {
		log.Errorf("codex-import: %v", errResolve)
		return
	}

	data, errRead := os.ReadFile(resolvedPath)
	if errRead != nil {
		log.Errorf("codex-import: read file failed: %v", errRead)
		return
	}

	imported, errParse := codex.ParseAuthFile(data)
	if errParse != nil {
		log.Errorf("codex-import: %v", errParse)
		return
	}
	for _, warning := range imported.Warnings {
		log.Warnf("codex-import: %s", warning)
	}

	storage := imported.Storage
	nameSeed := storage.Email
	if strings.TrimSpace(nameSeed) == "" {
		// CredentialFileName expects a stable identifier; fall back to the
		// account ID so a credential without an email claim still lands on a
		// deterministic path instead of "codex--plan.json".
		nameSeed = storage.AccountID
	}
	if strings.TrimSpace(nameSeed) == "" {
		log.Errorf("codex-import: auth file has neither an account email nor an account id")
		return
	}

	fileName := codex.CredentialFileName(nameSeed, imported.PlanType, imported.AccountIDHash, true)
	metadata := map[string]any{
		"email": storage.Email,
	}
	record := &coreauth.Auth{
		ID:       fileName,
		Provider: "codex",
		FileName: fileName,
		Storage:  storage,
		Metadata: metadata,
		Attributes: map[string]string{
			"plan_type": imported.PlanType,
		},
	}

	store := sdkAuth.GetTokenStore()
	if setter, ok := store.(interface{ SetBaseDir(string) }); ok {
		setter.SetBaseDir(cfg.AuthDir)
	}
	savedPath, errSave := store.Save(context.Background(), record)
	if errSave != nil {
		log.Errorf("codex-import: save credential failed: %v", errSave)
		return
	}

	fmt.Printf("Codex credentials imported from %s\n", resolvedPath)
	if savedPath != "" {
		fmt.Printf("Authentication saved to %s\n", savedPath)
	}
	if !imported.ExpiresAt.IsZero() {
		fmt.Printf("Access token expires at %s\n", imported.ExpiresAt.Format("2006-01-02 15:04:05 MST"))
	}
}

// resolveCodexAuthFilePath expands the supplied path, falling back to the
// default Codex CLI credential location when none was provided.
func resolveCodexAuthFilePath(authPath string) (string, error) {
	trimmed := strings.TrimSpace(authPath)
	if trimmed == "" {
		home, errHome := os.UserHomeDir()
		if errHome != nil {
			return "", fmt.Errorf("cannot locate home directory to find the default auth file: %w", errHome)
		}
		return filepath.Join(home, defaultCodexAuthFile), nil
	}

	// A bare directory is a common slip; accept it and append the filename.
	if info, errStat := os.Stat(trimmed); errStat == nil && info.IsDir() {
		return filepath.Join(trimmed, "auth.json"), nil
	}
	return trimmed, nil
}
