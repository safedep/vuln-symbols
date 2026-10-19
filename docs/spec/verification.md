# Verification

Status: draft. Each rule in this file gets a test that fails without the rule.

`vsym verify` checks a record with no model and no judgment. CI runs it on every pull request that
adds or changes a record. The same record and the same package artifacts give the same result.

## What verification proves, and what it does not

Verification proves three things:

1. Each symbol in the record is real. It exists in the package code at an affected version.
2. Each fix site is linked to the fix. The fix changed it.
3. Every function that the fix changed has an account.

Verification does not prove that a judged exclusion is right. A function can change in a fix and
still hold the vulnerable code, while a contributor or a model calls it a refactor. A reviewer reads
each judged exclusion. The accounting rule keeps that list short and visible.

The dangerous mistake is a missing fix site, because a consumer can then say "not called" about code
that is called. The trust rules at the end of this file limit what a record can claim until people
have reviewed it.

## Inputs

- The record.
- The advisory from OSV, by each id in `aliases`.
- The package artifacts from the registry: the last affected version and the first fixed version of
  each range, or the versions around the fix commits. The tool fetches each artifact by version and
  checks it against the hash that the registry publishes: the Go checksum database, the crates.io
  index checksum, the npm `integrity` field, the PyPI `sha256` digest. An artifact with no matching
  hash fails verification.
- For `fix.kind: commit`, the fix commits from `fix.repo`.

Advisory text, commit messages, diffs and package code are untrusted input. Verification parses
them. It never runs them.

## The changed-function list

The tool computes the list of changed functions. A person or a model never adds to it.

- With `fix.kind: commit`, the tool parses each file that the commits change, before and after the
  commits, and compares each function by its parsed code.
- With `fix.kind: release-diff`, the tool compares the package code of the `from` and `to` versions.
- Formatting and comments do not count as a change of code. A function whose only change is in
  comments is still listed, and its exclusion reason `comment-only` is proved by the tool.

## The checks

| Id | Check | Fails when |
| --- | --- | --- |
| V0 | Schema | The record is not a valid OSV document, or the extension breaks a rule of [record.md](record.md). |
| V1 | Real symbols | A fix site or an entry symbol does not resolve to a definition in the package code at an affected version. |
| V2 | Linked to the fix | A fix site is not on the changed-function list. |
| V3 | Derived entry symbols | The entry symbols that the tool derives from the package call graph differ from `entry_symbols`. The tool also sets `complete`. |
| V4 | Advisory match | An id in `aliases` does not exist in OSV, the package is not affected by that advisory, or a range of the record is not inside a range of the advisory. |
| V5 | Notation | A symbol does not follow the notation of its language in [record.md](record.md). |

## The accounting rule

| Id | Rule | Fails when |
| --- | --- | --- |
| A1 | Complete account | A changed function has no entry in `changed_functions`, or an entry names a function that is not on the list. |
| A2 | One account each | A function has more than one entry. |
| A3 | Proved reasons | An exclusion with the reason `test`, `comment-only` or `added` has `proof: judgment`, or the tool cannot prove it. `test`: the file is a test file of its language. `comment-only`: the parsed code is the same. `added`: the function does not exist in the affected code. |
| A4 | Judged reasons | An exclusion with `proof: judgment` has no `note`. |
| A5 | Consistent fix sites | `fix_sites` differs from the changed functions whose `account` is `fix-site`. |

`propose` writes proved exclusions with no model. A model sorts only what is left. So a model can
make one kind of mistake: a wrong account for a changed function. A wrong fix site is still linked
to the fix and still real. A wrong exclusion is a judged exclusion with a note, and a reviewer reads
it.

## Entry symbols

The tool derives the entry symbols from the call graph of the package at the last affected version.

- An entry symbol is an exported symbol from which the package call graph reaches a fix site.
- An exported method of an exported type counts, so a call through an interface counts.
- When the derivation hits a call that it cannot resolve on a path that can reach a fix site,
  `complete` is false and the record is `broad`.

A fix site can be internal. A consumer that has the package code in its own call graph can target the
fix sites. A consumer that has only the project code targets the entry symbols.

## The trust rules

These rules say what a consumer may conclude from a record. The record states its facts. The
consumer applies the rules.

| Id | Rule |
| --- | --- |
| T1 | Any record that passes verification may support "the project calls the vulnerable code". |
| T2 | A record may support "the project does not call the vulnerable code" only when its coverage is `exact` and its review state is `verified`. |
| T3 | `verified` means two maintainers approved the record, or the record is an upstream record. |
| T4 | A `broad` record never supports "does not call". |

## Later levels

A record can carry a stronger proof later: a test that calls an entry symbol, fails on the affected
version and passes on the fixed version. It is costly, so it is optional and not part of the MVP.
