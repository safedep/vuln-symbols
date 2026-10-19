# Verification

Status: draft. Each rule in this file gets a test that fails without the rule.

`vsym verify` checks a record with no model and no judgment. CI runs it on every pull request that
adds or changes a record.

## What verification proves, and what it does not

Verification proves four things:

1. The fix that the record reads is the fix of the advisory. It comes from the source repository of
   the package and sits between the affected and the fixed versions.
2. Each symbol in the record is real. It exists in the package code at an affected version.
3. Each fix site is linked to the fix. The fix changed it.
4. Every function that the fix changed has an account.

Verification does not prove that a judged exclusion is right. A function can change in a fix and
still hold the vulnerable code, while a contributor or a model calls it a refactor. A reviewer reads
each judged exclusion. The accounting rule keeps that list short and visible.

The dangerous mistake is a missing fix site, because a consumer can then say "not called" about code
that is called. The trust rules at the end of this file limit what a record can claim until people
have reviewed it.

## Determinism

The same record, the same package artifacts, the same fix commits and the same advisory give the same
result. Two inputs come from live services:

- V4 reads the advisory from OSV. The record stores the `modified` time of each advisory that it
  read. Verification fails when the advisory changed after that time, and the contributor runs
  `vsym candidates` again.
- V6 reads the fix commits from `fix.repo`. A commit id fixes its content, so a commit that exists
  gives the same diff on every run.

## Inputs

- The record.
- The advisory from OSV, by each id in `aliases`.
- The package artifacts from the registry. For each `affected` entry, the tool fetches the last
  affected version and the first fixed version of its range. The tool checks each artifact against
  the hash that the registry publishes: the Go checksum database, the crates.io index checksum, the
  npm `integrity` field, the PyPI `sha256` digest. An artifact with no matching hash fails
  verification.
- For `fix.kind: commit`, the fix commits from `fix.repo`.

Advisory text, commit messages, diffs and package code are untrusted input. Verification parses
them. It never runs them.

## One range, one fix

Each `affected` entry has exactly one range and one `fix`. An advisory with a 1.x backport and a 2.x
fix gives two `affected` entries, each with its own fix and its own account.

- The **affected code** of an entry is the artifact of the last affected version of its range.
- The **fixed code** of an entry is the artifact of the first fixed version of its range.

## The changed-function list

The tool computes the list of changed functions. A person or a model never adds to it.

- A function is identified by its symbol, not by its file. A function that moves to another file is
  one function.
- A function is changed when its parsed code differs between the two sides, when it exists before and
  not after (removed), or when it exists after and not before (added). A rename is one removed and one
  added function.
- With `fix.kind: commit`, the two sides are the files that the commits change, before and after the
  commits.
- With `fix.kind: release-diff`, the two sides are the affected code and the fixed code.
- Formatting and comments do not count as a change of code. A function whose only change is in
  comments is still listed, and the tool proves its exclusion reason `comment-only`.
- The list holds only functions inside the artifact of the `affected` entry. A commit can change
  files of other packages in the same repository. The tool lists those functions with the reason
  `outside-package`, which it proves. When such a file belongs to another published package that the
  advisory names, the record needs an `affected` entry for that package.

## The checks

| Id | Check | Fails when |
| --- | --- | --- |
| V0 | Schema | The record is not a valid OSV document, or the extension breaks a rule of [record.md](record.md). |
| V1 | Real symbols | A fix site or an entry symbol does not resolve to a definition in the affected code. A removed function resolves in the affected code too. |
| V2 | Linked to the fix | A fix site is not on the changed-function list. |
| V3 | Derived entry symbols | The entry symbols that the tool derives differ from `entry_symbols`. The tool also sets `complete`. |
| V4 | Advisory match | An id in `aliases` does not exist in OSV. The package is not affected by that advisory. A range of the record is not inside a range of the advisory. The advisory changed after the `modified` time that the record stores. |
| V5 | Notation | A symbol does not follow the notation of its language in [record.md](record.md). |
| V6 | The fix of the advisory | See the rules below. |

V6 has these rules:

- `fix.repo` is the source repository of the package. The tool reads it from a `FIX` or `PACKAGE`
  reference of the advisory, or from the source URL that the registry publishes for the package. For
  Go, the module path names the repository. A fork fails.
- With `fix.kind: commit`, each commit is an ancestor of the first fixed version. No commit is an
  ancestor of the last affected version.
- With `fix.kind: release-diff`, `from` is the last affected version and `to` is the first fixed
  version of the range.

## The accounting rule

| Id | Rule | Fails when |
| --- | --- | --- |
| A1 | Complete account | A changed function has no entry in `changed_functions`. An entry names a function that is not on the list. |
| A2 | One account each | A function has more than one entry. |
| A3 | Proved reasons | An exclusion with a proved reason has `proof: judgment`, or the tool cannot prove it. The proved reasons are in the next table. |
| A4 | Judged reasons | An exclusion with `proof: judgment` has no `note`. |
| A5 | Consistent fix sites | `fix_sites` differs from the changed functions whose `account` is `fix-site`. |

The tool proves these reasons:

| Reason | The tool proves it when |
| --- | --- |
| `test` | The file is a test file of its language. |
| `comment-only` | The parsed code is the same on both sides. |
| `added` | The function does not exist in the affected code. |
| `outside-package` | The file is not in the artifact of the `affected` entry. |
| `generated` | The file carries the generated-code marker of its language, as the Go line `// Code generated … DO NOT EDIT.` |

`propose` writes proved exclusions with no model. A model sorts only what is left. So a model can
make one kind of mistake: a wrong account for a changed function. A wrong fix site is still linked
to the fix and still real. A wrong exclusion is a judged exclusion with a note, and a reviewer reads
it.

## Entry symbols

The tool derives the entry symbols from the call graph of the affected code.

- An entry symbol is an exported symbol from which the package call graph reaches a fix site. Reach
  includes the symbol itself, so an exported fix site is its own entry symbol.
- An exported method of an exported type counts, so a call through an interface counts.
- Code that runs when a program imports the package counts as an entry symbol, because every
  importer runs it with no call. In Go, this is `init` and the initializers of package-level
  variables, written `<import path>.init`.
- `complete` is false when the derivation hits any call that it cannot resolve, or a call through an
  interface or a function value whose candidate set holds a fix site. The tool cannot know where an
  unresolved call goes, so it cannot rule out a path to a fix site.

A fix site can be internal. A consumer that has the package code in its own call graph can target the
fix sites. A consumer that has only the project code targets the entry symbols.

## The trust rules

These rules say what a consumer may conclude from a record. The record states its facts. The
consumer applies the rules.

| Id | Rule |
| --- | --- |
| T1 | Any record that passes verification may support "the project calls the vulnerable code". |
| T2 | A record may support "the project does not call the vulnerable code" only when its coverage is `exact` and its review state is `verified`. A `broad` record never supports it. |
| T3 | `verified` means two maintainers approved the record, or the record is an upstream record. |

## Known limits

- **Compiled npm packages.** Many npm packages publish compiled code in `dist/`. The fix commits
  change the source tree, while V1 reads the artifact, so a fix site from the source does not resolve.
  Until the JavaScript notation solves this, such a record uses `fix.kind: release-diff`.

## Later levels

A record can carry a stronger proof later: a test that calls an entry symbol, fails on the affected
version and passes on the fixed version. It is costly, so it is optional and not part of the MVP.
