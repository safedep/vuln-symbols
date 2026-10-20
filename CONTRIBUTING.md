# Contributing

Issues and code changes are welcome. Community records are not open yet, because their license is not
decided and the tools that verify them do not exist yet.

## Developer Certificate of Origin

Each commit carries a `Signed-off-by` line, as the [Developer Certificate of
Origin](https://developercertificate.org/) asks. `git commit -s` adds it. The line says that you have
the right to submit the change under its license.

- Code is under Apache-2.0.
- A record is under the license that its `database_specific.license` names.

## Code

1. Read [AGENTS.md](AGENTS.md). It holds the rules that keep a record safe, for people and agents.
2. A change to a rule in `docs/spec/` and the code that enforces it go in the same pull request.
3. Run `gofmt -l .`, `go vet ./...` and `go test ./... -count=1` before you push. CI runs them again.
4. A bug fix needs a test that fails without the fix.
5. Test fixtures are synthetic. Do not copy a real advisory, package or secret into a fixture.

## A record

This workflow starts when `vsym candidates`, `vsym derive` and `vsym verify` exist. Until then, only
SafeDep maintainers add records.

1. Read [docs/spec/record.md](docs/spec/record.md) and
   [docs/spec/verification.md](docs/spec/verification.md).
2. Draft the record with the `propose-record` workflow in `.claude/skills/`. You can use your own LLM
   for the step that sorts changed functions. Nothing else needs a model.
3. Run `vsym verify` before you open the pull request. CI runs it again.
4. In the pull request, name the advisory, the fix and each judged exclusion.

## Security

Do not report a security problem in an issue. See [SECURITY.md](SECURITY.md).
