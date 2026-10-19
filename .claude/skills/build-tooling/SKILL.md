---
name: build-tooling
description: Use when you add or change code in cmd/, internal/ or symbols/, when you implement a
  check of the verification spec, or when you add support for a new language or ecosystem. The
  skill keeps each check deterministic and tested.
---

# Build or change the tooling

## Before you write code

1. Read [AGENTS.md](../../../AGENTS.md), the rules that keep a record safe.
2. Read the section of `docs/spec/` that the change implements. If the spec does not say what the
   code must do, change the spec first, in the same pull request.
3. Search this repository, `safedep/code` and `safedep/dry` for the part you need. Use what exists.

## Rules

- `verify`, `derive` and `build` never call a model, and never depend on the clock, the order of a
  map or the network beyond hashed artifact fetches. Run each twice in a test and compare the bytes.
- One check of the spec, one test that fails without it. Name the test after the check id, as
  `TestV2_FixSiteNotChanged`.
- Fetch an artifact only through the one fetch package, which checks the registry hash.
- Parse code only through `safedep/code`. Do not import a tree-sitter grammar.
- Package identity only through `dry/api/pb`.
- Never import `github.com/safedep/vet`.

## A new language

1. Add its symbol notation to the notation table in `docs/spec/record.md`, with examples.
2. Add the map from the notation to the definitions that `safedep/code` finds.
3. Add the test-file rule of the language for the proved reason `test`.
4. Add synthetic fixtures for each check of the verification spec.
