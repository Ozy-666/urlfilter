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
| *(none yet — Priority 4 and 5 pending)* | |

The fork module path remains `github.com/AdguardTeam/urlfilter` (unchanged from
upstream) so it integrates via a `go.mod replace` directive in the host repo:

```
replace github.com/AdguardTeam/urlfilter => ../urlfilter
```

Builds must be run from the AdGuardHome-Edge repo root with this fork checked
out at `../urlfilter`.
