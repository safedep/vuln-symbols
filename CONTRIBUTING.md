# Contributing

The repository is private before the first alpha release. Until the license of the community records
is decided, it takes no contribution from outside SafeDep.

## Developer Certificate of Origin

Each commit carries a `Signed-off-by` line, as the [Developer Certificate of
Origin](https://developercertificate.org/) asks. `git commit -s` adds it. The line says that you have
the right to submit the change under its license.

- Code is under Apache-2.0.
- A record is under the license that its `database_specific.license` names.
- Until the record license is decided, only SafeDep staff add records.

## A record

1. Read [docs/spec/record.md](docs/spec/record.md) and
   [docs/spec/verification.md](docs/spec/verification.md).
2. Draft the record with the `propose-record` workflow in `.claude/skills/`. You can use your own LLM
   for the step that sorts changed functions. Nothing else needs a model.
3. Run `vsym verify` before you open the pull request. CI runs it again.
4. In the pull request, name the advisory, the fix and each judged exclusion.

## Code

1. Read [AGENTS.md](AGENTS.md).
2. Run `go vet ./...` and `go test ./... -count=1` before you push.
3. Each check of the verification spec has a test that fails without it.
