package codex

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"
)

// accountIDHashLength is the number of hex characters retained from the account
// ID digest when building credential filenames.
const accountIDHashLength = 8

// HashAccountID returns the short digest of a ChatGPT account ID used to keep
// credential filenames distinct for accounts that share an email and plan type.
// It returns an empty string for a blank account ID.
func HashAccountID(accountID string) string {
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(accountID))
	return hex.EncodeToString(digest[:])[:accountIDHashLength]
}

// CredentialFileName returns the filename used to persist Codex OAuth credentials.
// The account hash is included when available to keep accounts with the same email
// and plan distinct. The legacy email-based format remains the fallback.
func CredentialFileName(email, planType, hashAccountID string, includeProviderPrefix bool) string {
	email = strings.TrimSpace(email)
	plan := normalizePlanTypeForFilename(planType)
	hashAccountID = strings.TrimSpace(hashAccountID)

	prefix := ""
	if includeProviderPrefix {
		prefix = "codex"
	}

	if hashAccountID != "" {
		if plan == "" {
			return fmt.Sprintf("%s-%s-%s.json", prefix, hashAccountID, email)
		}
		return fmt.Sprintf("%s-%s-%s-%s.json", prefix, hashAccountID, email, plan)
	}
	if plan == "" {
		return fmt.Sprintf("%s-%s.json", prefix, email)
	}
	return fmt.Sprintf("%s-%s-%s.json", prefix, email, plan)
}

func normalizePlanTypeForFilename(planType string) string {
	planType = strings.TrimSpace(planType)
	if planType == "" {
		return ""
	}

	parts := strings.FieldsFunc(planType, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	if len(parts) == 0 {
		return ""
	}

	for i, part := range parts {
		parts[i] = strings.ToLower(strings.TrimSpace(part))
	}
	return strings.Join(parts, "-")
}
