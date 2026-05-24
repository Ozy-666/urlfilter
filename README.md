# urlfilter (Edge Fork for AdGuardHome)

This is a performance-optimized fork of the original [AdguardTeam/urlfilter](https://github.com/AdguardTeam/urlfilter).

## Purpose

Maintained specifically for the `AdGuardHome-Edge` project. All changes target
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
| *(no code changes — see note below)* | |

The fork module path remains `github.com/AdguardTeam/urlfilter` (unchanged from
upstream) so it integrates via a `go.mod replace` directive in the host repo:

```
replace github.com/AdguardTeam/urlfilter => ../urlfilter
```

Builds must be run from the AdGuardHome-Edge repo root with this fork checked
out at `../urlfilter`.

## Investigated and shelved

A `noIndex` regex-scan optimization (Bloom filter gate + merged-regex alternation)
was evaluated on 2026-05-24 and **shelved** — it is not warranted for the AdGuard DNS
filtering workload.

Measured against the real AdGuard SDN (DNS) filter, only **5 rules** land in
`NetworkEngine.noIndex`, all clean 5-char literal shortcuts with **zero regex**. The
per-request `noIndex` scan is already negligible and is fully short-circuited by the
host engine's copy-on-write match cache. A Bloom filter cannot gate the only expensive
case (empty-shortcut regex rules, which always reach `matchPattern` by design), and
those rules are non-host-level anyway, so they never reach the DNS engine. Full analysis
is recorded in the AdGuardHome-Edge `PERF-BACKLOG.md`, Section 10.
