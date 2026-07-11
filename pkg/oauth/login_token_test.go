// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package oauth

import (
	"bytes"
	"strings"
	"testing"
)

// TestLoginTemplateVaultTokenMethod verifies the login page offers the "Vault
// token (paste)" method as the default, exposes a vault_token field, and includes
// the method-toggle script that swaps the token field for username/password.
func TestLoginTemplateVaultTokenMethod(t *testing.T) {
	var buf bytes.Buffer
	if err := loginTemplate.Execute(&buf, loginPageData{
		AuthState:   "state",
		VaultAddr:   "https://vault.example.com",
		OIDCEnabled: true,
		BasePath:    "/mcps/vault-mcp",
	}); err != nil {
		t.Fatalf("execute template: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		`<option value="token" selected>`, // token is the default method
		`id="tokenFields"`,
		`name="vault_token"`,
		`id="userpassFields" style="display:none"`, // username/password hidden by default
		`getElementById('method')`,                 // toggle script present
	} {
		if !strings.Contains(out, want) {
			t.Errorf("login page missing %q", want)
		}
	}
}
