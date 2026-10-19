---
name: verify-record
description: Use when vsym verify fails on a record, when CI rejects a record pull request, or when
  someone asks why a record does not pass. The skill reads the failed check and fixes the record. It
  never weakens a check to make a record pass.
---

# Fix a record that fails verify

Each failure names a check id from [docs/spec/verification.md](../../../docs/spec/verification.md).
Find the id and apply its fix.

| Id | Fix |
| --- | --- |
| V0 | Correct the field that the message names. Compare with `docs/spec/examples/`. |
| V1 | The symbol does not exist at an affected version. Check the notation and the package version. Remove a symbol that does not exist. Never rename it to make it pass. |
| V2 | The fix site is not a changed function. Remove it, or choose the right fix in `fix`. |
| V3 | Run `vsym derive` again. Never edit `entry_symbols` by hand. |
| V4 | Correct `aliases` or `ranges` from the advisory in OSV. |
| V5 | Write the symbol in the notation of its language. |
| A1 | Add an account for each changed function that `vsym candidates` lists. Remove an account for a function that is not on the list. |
| A2 | Keep one account per function. |
| A3 | Set `proof: tool` for `test`, `comment-only` and `added`. If the tool cannot prove the reason, the reason is wrong. Choose another. |
| A4 | Add a `note` that says why the change does not touch the vulnerable behavior. |
| A5 | Make `fix_sites` equal to the changed functions with `account: fix-site`. |

## Rules

- Do not change a check, a test or the spec to make a record pass. A wrong check is a separate pull
  request with its own test.
- When a check looks wrong, say so, and stop.
