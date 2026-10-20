# Community records

This directory is empty. Community records start when the license of the records is decided and
`vsym verify` exists.

One OSV document per advisory, at `records/<OSV ecosystem>/<record id>.json`, as
`records/npm/VSYM-2026-0001.json`.

Upstream records are not stored here. The builder makes them from the upstream databases, and they
exist only in the bundle.

Every file here passes `vsym verify`. See [docs/spec/verification.md](../docs/spec/verification.md).
