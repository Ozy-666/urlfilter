package urlfilter

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/internal/uftest"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/require"
)

// curatedRegexRules exercises the AST-vs-legacy difference directly: optional
// groups, alternations, '+' repetitions and anchors that the legacy extractor
// bails on but the AST extractor indexes.  Hosts that match these must be
// returned identically by both engines.
const curatedRegexRules = `/^ad[0-9]?-bad\.example$/
/(?:tracker|spy)\.evil/
/(badword)+\.net/
/^https?:\/\/cdn[0-9]?\.junk\.org/
/[0-9]{8}\.nolit/
||plain.example^
@@||allow.example^
`

// matchTextFor builds a NetworkEngine from text with the given shortcut
// extractor active and returns host→matched-rule-text (empty when no match) for
// every host.  Build and all matches happen inside the toggle scope so the
// indexed shortcut and the cache-parsed rule always agree.
func matchTextFor(tb testing.TB, text string, useAST bool, hosts []string) (out map[string]string) {
	tb.Helper()

	prev := rules.SetASTShortcutForTesting(useAST)
	defer rules.SetASTShortcutForTesting(prev)

	rl := filterlist.NewBytes(&filterlist.BytesConfig{
		RulesText:      []byte(text),
		ID:             1,
		IgnoreCosmetic: true,
	})
	st, err := filterlist.NewRuleStorage([]filterlist.Interface{rl})
	require.NoError(tb, err)
	defer func() { _ = st.Close() }()

	e := NewNetworkEngine(st)

	out = make(map[string]string, len(hosts))
	for _, h := range hosts {
		// Honor the engine contract: hostnames reach the urlfilter engine
		// already lowercased (AGH's matchHost does strings.ToLower).  Both
		// indexes store lowercased shortcuts, so a non-lowercased host is
		// out of contract for legacy and AST alike.
		rule, ok := e.Match(rules.NewRequestForHostname(strings.ToLower(h)))
		if ok && rule != nil {
			out[h] = rule.Text()
		} else {
			out[h] = ""
		}
	}

	return out
}

// readFileOrSkip returns the file contents or skips the test if absent.
func readFileOrSkip(tb testing.TB, path string) (data []byte) {
	tb.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		tb.Skipf("test data %s unavailable: %v", path, err)
	}

	return data
}

var blockHostRE = regexp.MustCompile(`^\|\|([a-z0-9.-]+)\^$`)

// blocklistHosts extracts hostnames from "||host^" rules in text, capped at
// maxN, and adds mutations that stress the shortcut index and regexp rules.
func blocklistHosts(text string, maxN int) (hosts []string) {
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	n := 0
	for sc.Scan() && n < maxN {
		m := blockHostRE.FindStringSubmatch(strings.TrimSpace(sc.Text()))
		if m == nil {
			continue
		}

		h := m[1]
		hosts = append(hosts,
			h,
			"www."+h,
			"sub-"+fmt.Sprintf("%d", n)+"."+h,
			strings.ToUpper(h),
		)
		n++
	}

	return hosts
}

// TestEquivalence_RealLists runs the equivalence harness over the real AdGuard
// filter lists plus procedurally generated hosts: the AST engine must return a
// byte-identical match decision to the legacy engine for every host.
func TestEquivalence_RealLists(t *testing.T) {
	sdn := readFileOrSkip(t, "testdata/adguard_sdn_filter.txt")
	base := readFileOrSkip(t, "testdata/adguard_base_filter.txt")

	text := string(sdn) + "\n" + string(base) + "\n" + curatedRegexRules

	// Hosts: request corpus + procedural blocklist-derived + curated matches.
	hosts := uftest.RequestHostnames(t)
	hosts = append(hosts, blocklistHosts(string(sdn), 1500)...)
	hosts = append(hosts, blocklistHosts(string(base), 1500)...)
	hosts = append(hosts,
		"ad-bad.example", "ad7-bad.example", "AD7-BAD.EXAMPLE",
		"x.tracker.evil", "spy.evil.org", "badword.net", "badwordbadword.net",
		"cdn.junk.org", "cdn3.junk.org", "https://cdn.junk.org",
		"12345678.nolit", "plain.example", "allow.example", "clean.example.com",
	)

	t.Logf("rules ≈ %d KiB, hosts = %d", len(text)/1024, len(hosts))

	legacy := matchTextFor(t, text, false, hosts)
	ast := matchTextFor(t, text, true, hosts)

	diverged := 0
	for _, h := range hosts {
		if legacy[h] != ast[h] {
			diverged++
			if diverged <= 20 {
				t.Errorf("DIVERGENCE host=%q legacy=%q ast=%q", h, legacy[h], ast[h])
			}
		}
	}
	if diverged == 0 {
		t.Logf("OK: %d hosts, 0 divergences (AST ≡ legacy)", len(hosts))
	}
}

// FuzzShortcutEquivalence fuzzes arbitrary hostnames against a small curated
// rule set: the AST and legacy engines must always agree.
func FuzzShortcutEquivalence(f *testing.F) {
	for _, s := range []string{
		"ad-bad.example", "ad7-bad.example", "x.tracker.evil", "spy.evil.org",
		"badword.net", "cdn3.junk.org", "12345678.nolit", "plain.example",
		"allow.example", "clean.example.com", "", "a", "....", "AD-BAD.EXAMPLE",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, host string) {
		legacy := matchTextFor(t, curatedRegexRules, false, []string{host})
		ast := matchTextFor(t, curatedRegexRules, true, []string{host})
		if legacy[host] != ast[host] {
			t.Fatalf("divergence host=%q legacy=%q ast=%q", host, legacy[host], ast[host])
		}
	})
}

// BenchmarkAST_RegexFlood measures the cache-miss flood worst case: N
// host-level regexp rules that each contain a '?' (so legacy leaves them all in
// noIndex → O(N) scan) but share a ≥5 mandatory literal (so AST indexes them →
// a random host that lacks the literal never evaluates any of them → O(1)).
func BenchmarkAST_RegexFlood(b *testing.B) {
	req := rules.NewRequestForHostname("random-clean-host-12345.org")

	for _, n := range []int{100, 1000} {
		var text strings.Builder
		for i := range n {
			fmt.Fprintf(&text, "/^evil%d[0-9]?-tracker\\.example\\.com$/\n", i)
		}

		for _, mode := range []struct {
			name string
			ast  bool
		}{{"legacy", false}, {"ast", true}} {
			b.Run(fmt.Sprintf("%s/n=%d", mode.name, n), func(b *testing.B) {
				prev := rules.SetASTShortcutForTesting(mode.ast)
				defer rules.SetASTShortcutForTesting(prev)

				rl := filterlist.NewBytes(&filterlist.BytesConfig{
					RulesText:      []byte(text.String()),
					ID:             1,
					IgnoreCosmetic: true,
				})
				st, err := filterlist.NewRuleStorage([]filterlist.Interface{rl})
				require.NoError(b, err)
				defer func() { _ = st.Close() }()

				e := NewNetworkEngine(st)
				_, _ = e.Match(req) // warm caches under the active toggle

				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					_, _ = e.Match(req)
				}
			})
		}
	}
}
