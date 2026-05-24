# urlfilter (Edge Fork for AdGuardHome)

This is a performance-optimized fork of the original [AdguardTeam/urlfilter](https://github.com/AdguardTeam/urlfilter).

## Purpose

Maintained specifically for the [AdGuardHome-edge](https://github.com/Ozy-666/AdGuardHome-edge-spec) project. All changes target
the DNS filtering hot path and are benchmarked on the production host before
deployment.

## Versioning

The fork is based on upstream stable releases and extended with edge commits on
the `urlfilter-edge` branch.

| Tag | Upstream base | Notes |
|---|---|---|
| `v0.23.2-edge.1` | `v0.23.2` | Base anchor — no changes yet |

**Branch `urlfilter-edge` commits on top of `v0.23.2-edge.1`** (in order):

| Commit | Description |
|---|---|
| `1335417` | AST-based required-literal shortcut extraction for regexp rules (closes the host-level regexp `noIndex` O(N) cache-miss vector) |

The fork module path remains `github.com/AdguardTeam/urlfilter` (unchanged from
upstream) so it integrates via a `go.mod replace` directive in the host repo:

```
replace github.com/AdguardTeam/urlfilter => ../urlfilter
```

Builds must be run from the AdGuardHome-Edge repo root with this fork checked
out at `../urlfilter`.

## AST shortcut extraction (regexp rules)

`findRegexpShortcut` parses each regexp rule with `regexp/syntax` and extracts the
longest **guaranteed-required contiguous literal**, replacing the legacy extractor
that bailed on any `?` and returned the longest special-char-free run. This moves
host-level regexp rules such as `/^ad[0-9]?-tracker\.com$/` out of the unindexed
`noIndex` bucket and into the shortcut index, so a unique-subdomain flood no longer
forces `matchPattern` on every cache miss (O(N) → O(1)).

The walk is deliberately conservative — optional, alternated, repeated-zero and
otherwise non-mandatory subexpressions contribute nothing — so it can only ever
*under*-extract; it never claims a literal that is not guaranteed, which would cause
the shortcut index to drop real matches. The legacy extractor is retained behind
`SetASTShortcutForTesting` for the equivalence harness.

**Why not the alternation gate?** A merged-regexp alternation gate was prototyped and
**rejected by benchmark** — it was ~14× *slower* than the linear scan, because
anchored regexps reject a non-matching host in O(1) individually while the union
automaton loses that per-branch early-exit. Empty-literal regexps cannot be prefiltered
by any literal structure, so AST indexing (which removes the literal-bearing ones from
the scan entirely) is the correct defense. Full analysis: AdGuardHome-Edge
`PERF-BACKLOG.md` §10.

### Bluehat verification (2026-05-25)
- **Equivalence harness:** AST vs legacy engine over the real SDN+base lists +
  `requests.json` + procedural blocklist hosts — **0 divergences / 39,983 hosts**.
- **Fuzz:** 130k executions, 0 divergences.
- **Pathological/malformed regexps:** no panic, bounded work, ~29 allocs (load-time
  only; `regexp/syntax` rejects oversized input).
- **Flood benchmark** (N `?`-regexps, random host): **111 µs → 449 ns at N=1000
  (248×), flat in N, 0 query-path allocs.**
