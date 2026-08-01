// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 Ozy-666 (https://dnsdoh.art)

package rules

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFindRegexpShortcutAST_Pathological confirms the AST extractor terminates
// with bounded work and never panics on malformed or adversarial patterns.
// regexp/syntax itself rejects oversized or too-deeply-nested input with an
// error, which the extractor turns into an empty shortcut.
func TestFindRegexpShortcutAST_Pathological(t *testing.T) {
	t.Parallel()

	patterns := []string{
		"/" + strings.Repeat("(a", 5000) + strings.Repeat(")", 5000) + "/",
		"/(?:" + strings.Repeat("a|", 20000) + "a)/",
		"/a{1000}{1000}{1000}/",
		"/" + strings.Repeat("a", 200000) + "/",
		"/(?P<x>(?P<y>(?P<z>a+)+)+)+/",
		"/[/", "/(/", "/*/", "//", "/", "",
		"/^https?:\\/\\/(?!x)evil/",
		"/\\x{10FFFF}+abc/",
	}

	for i, p := range patterns {
		t.Run(fmt.Sprintf("p%d_len%d", i, len(p)), func(t *testing.T) {
			t.Parallel()

			// The assertion is simply that this returns without panicking or
			// hanging; the value is logged for inspection.
			assert.NotPanics(t, func() {
				s := findRegexpShortcutAST(p)
				t.Logf("shortcut=%q", s)
			})
		})
	}
}

// TestFindRegexpShortcutAST_Allocs documents the allocation cost of the AST
// extractor.  It runs only at filter-load time (never on the query hot path),
// so the cost is one-time per rule; this guards against accidental blow-ups.
func TestFindRegexpShortcutAST_Allocs(t *testing.T) {
	const pattern = `/^ad[0-9]?-tracker[a-z]*\.doubleclick\.net$/`

	require.Equal(t, ".doubleclick.net", findRegexpShortcutAST(pattern))

	avg := testing.AllocsPerRun(100, func() {
		_ = findRegexpShortcutAST(pattern)
	})
	t.Logf("allocs/op (load-time only): %.0f", avg)

	// A typical rule parse should be well under this; the bound only catches
	// runaway regressions, not normal parser allocation.
	assert.Less(t, avg, 200.0)
}
