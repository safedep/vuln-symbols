# Security Policy

Report a vulnerability to `security@safedep.io`. Do not open a public issue. SafeDep's
[organization-wide security policy](https://github.com/safedep/.github/blob/main/SECURITY.md) gives
the disclosure process.

In this project, these are security problems:

- A way to make the `symbols` SDK accept a bundle that the build workflow did not sign, an older
  bundle than its cache, or records that do not match the signed manifest.
- A weakness in the build workflow that lets a person or a pull request change the signed bundle.
- A record with a missing fix site or a wrong `exact` coverage. A tool can then say "not called" for
  vulnerable code.

A missing or wrong symbol in an upstream record comes from the upstream database. Report it to the
[Go vulnerability database](https://go.dev/s/vulndb-report-feedback) or to
[RustSec](https://github.com/rustsec/advisory-db), and tell us too.
