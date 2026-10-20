---
name: verify-record
description: Use when vsym verify fails on a record, when CI rejects a record pull request, or when
  someone asks why a record does not pass. The skill reads the failed check and fixes the record. It
  never weakens a check to make a record pass.
---

# Fix a record that fails verify

`vsym candidates`, `vsym derive` and `vsym verify` are planned. Until they exist, this workflow
cannot run. Say so, and stop.

Each failure names a check id from [docs/spec/verification.md](../../../docs/spec/verification.md).
Find the id and apply its fix.

| Id | Fix |
| --- | --- |
| V0 | Correct the field that the message names. Compare with `docs/spec/examples/`. |
| V1 | A symbol that resolves at one end of the range and not the other means the range must split into two `affected` entries. A fix site that does not resolve at all means that `fix`, `ranges` or `package` is wrong, or the notation is wrong. Correct those. Never move a fix site to `excluded` to make it pass, and never rename it. |
| V2 | The fix site is not a changed function. Remove it, or choose the right fix in `fix`. |
| V3 | Run `vsym derive` again. Never edit `entry_symbols` by hand. |
| V4 | Correct `aliases` or `ranges` from the advisory in OSV. |
| V5 | Write the symbol in the notation of its language. |
| V6 | Point `fix` at the source repository of the package and at the commits that the advisory names. With no named commit, use `release-diff` with exactly the last affected and the first fixed version. |
| A1 | Add an account for each changed function that `vsym candidates` lists. Remove an account for a function that is not on the list. |
| A2 | Keep one account per function. |
| A3 | Set `proof: tool` for a proved reason. If the tool cannot prove the reason, the reason is wrong. Choose `fix-site`, or a judged reason with a `note`. |
| A4 | Add a `note` that says why the change does not touch the vulnerable behavior. |
| A5 | Make `fix_sites` equal to the changed functions with `account: fix-site`. |

## Rules

- Do not change a check, a test or the spec to make a record pass. A wrong check is a separate pull
  request with its own test.
- When a check looks wrong, say so, and stop.
