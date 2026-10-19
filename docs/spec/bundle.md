# The bundle

Status: draft. The format changes freely until the first alpha release.

The bundle is how a consumer gets the records. The build workflow makes it every day, signs it, and
publishes it. The `symbols` package of this repository fetches, verifies, caches and matches it. A
consumer uses the package and does not read the host itself.

## Files

| File | Holds |
| --- | --- |
| `bundles/<sha256>.jsonl.gz` | Every record, one compact JSON document per line, sorted by `id`. The name is the SHA-256 of the file. |
| `manifest.json` | The manifest of the newest bundle. |
| `manifest.sigstore.json` | The Sigstore signature of the manifest. |
| `manifests/<sha256>.json` | The manifest of each bundle, by the SHA-256 of the bundle. |
| `manifests/<sha256>.sigstore.json` | Its signature. |

The public host is `https://vuln-data.safedep.io/v1/`. A bundle and the manifest of a bundle never
change after the workflow writes them. Only `manifest.json` and its signature change.

The same exports give the same bundle bytes. The gzip header holds no name and no time.

## Manifest

| Field | Meaning |
| --- | --- |
| `format` | The version of the bundle format and of the `vuln_symbols` extension. It is 1. |
| `as_of` | The newest `modified` time of a record. A client rejects a manifest older than its cached one. |
| `records` | The number of records. |
| `bundle.path` | `bundles/<sha256>.jsonl.gz`. A client rejects any other path. |
| `bundle.size`, `bundle.sha256` | The size and the SHA-256 of the bundle file. |
| `bundle.content_sha256` | The SHA-256 of the uncompressed JSON lines. |
| `sources[]` | Each upstream database: name, OSV ecosystem, export URL and its SHA-256, newest `modified` time, record count, license and attribution text. |

The signature covers the manifest bytes, and the manifest holds the hashes of the bundle. So one
signature covers the bundle.

## Signature

The build workflow signs the manifest with a keyless Sigstore certificate from its GitHub OIDC token.
A client accepts a signature only with these values:

- issuer `https://token.actions.githubusercontent.com`
- identity `https://github.com/safedep/vuln-symbols/.github/workflows/build.yml@refs/heads/main`
- a certificate timestamp, a transparency log entry and a time from the log or from a timestamp
  authority

A rename of the workflow file or of the branch breaks every client.

## Client rules

- A client asks the host at most once per day. It sends the ETag of its last manifest, and a 304
  answer costs no download.
- A client stores a bundle only after it checks the signature, the size, both hashes and the record
  count. It writes the bundle first and the manifest last.
- A client keeps its cached bundle when a check fails, when the host is down, and when the host
  offers a manifest older than the cached one.
- A client can pin a bundle by its SHA-256. It then reads `manifests/<sha256>.json`.
- A client can read a local directory with the layout of the host, and it checks the signature
  there too.
- A record of the bundle matches a package version by any id of the alias set, by the ecosystem and
  the folded name of `dry/api/pb`, and by the OSV order of the range. A version that the ecosystem
  cannot order matches, because a missed match would hide the symbols of a known advisory.

## Versions

A change that an older client can read adds fields to `v1/`. A change that an older client cannot
read goes to `v2/`, and the workflow keeps `v1/` while clients of `v1/` are in use.
