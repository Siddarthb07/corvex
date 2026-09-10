# Draft action schemas (NOT installed)

*Updated: 2026-09-07*

Destructive verbs are documented here for contain design review only.

**Do not import from the installable `corvex` package.**

Reserved verbs: `IsolateHost`, `KillPid`, `AddFirewallRule`.

Required fields before any live executor: `impact_class`, `dry_run`, `idempotency_key`, `expiry`, `policy_version`.
