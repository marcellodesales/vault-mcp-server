// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package oauth

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestIsPublicMCPRequest verifies discovery methods are allowed pre-auth, tool
// execution is not, and the request body is restored for the downstream handler.
func TestIsPublicMCPRequest(t *testing.T) {
	cases := []struct {
		method string
		public bool
	}{
		{"tools/list", true},
		{"initialize", true},
		{"ping", true},
		{"tools/call", false},
		{"resources/read", false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			body := `{"jsonrpc":"2.0","id":1,"method":"` + tc.method + `","params":{}}`
			req := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
			if got := isPublicMCPRequest(req); got != tc.public {
				t.Errorf("isPublicMCPRequest(%q) = %v, want %v", tc.method, got, tc.public)
			}
			// Body must be restored for the downstream MCP handler.
			restored, _ := io.ReadAll(req.Body)
			if string(restored) != body {
				t.Errorf("body not restored: got %q", string(restored))
			}
		})
	}

	// A GET (SSE stream) is never treated as a public discovery POST.
	if isPublicMCPRequest(httptest.NewRequest("GET", "/mcp", nil)) {
		t.Error("GET must not be treated as a public MCP request")
	}
}
