# The bundle

Status: draft. The format changes freely until the first stable release.

The bundle is how a consumer gets the records. The build workflow makes it every day, signs it, and
publishes it. The `symbols` package of this repository fetches, verifies, caches and matches it. A
consumer uses the package and does not read the host itself.

## Files

| File | Holds |
| --- | --- |
| `bundles/<sha256>.jsonl.gz` | Every record, one compact JSON document per line, sorted by `id`. The name is the SHA-256 of the file. |
| `manifest.json` | The manifest of the newest bundle. A client reads only the bundle hash from it. |
| `manifest.sigstore.json` | Its signature. A client reads it only for a bundle that comes back. See the client rules. |
| `manifests/<sha256>.json` | The manifest of each bundle, by the SHA-256 of the bundle. |
| `manifests/<sha256>.sigstore.json` | Its signature. A client trusts only this signed pair. |

The public host is `https://vuln-data.safedep.io/v1/`. A bundle and the signed pair of its manifest
never change after the workflow writes them. When a later build gives the same bundle hash, the host
keeps the first pair. Only `manifest.json` and its signature change.

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
  answer costs no download. A client with no cached bundle asks at once.
- A client reads the bundle hash from `manifest.json`, and then reads and checks the signed pair of
  that hash. It stores a bundle only after it checks the signature, the size, both hashes and the
  record count. It writes the bundle first and the manifest last, each with a sync and a rename.
- The signing time decides the order of two bundles. It is the time that the transparency log or a
  timestamp authority proves. A client keeps its cached bundle when a check fails, when the host is
  down, and when the host offers a bundle signed before the cached one.
- A bundle can come back after a newer one, as when upstream removes a record and restores it. The
  host keeps the first signed pair of that bundle, so the pair is older than the cache. The client
  then checks `manifest.sigstore.json` against `manifest.json`. It takes the bundle when that
  signature is valid, names the same bundle, and is newer than the cache.
- A client with a lost or damaged cached bundle fetches it again at once.
- A client gives the signing time of its bundle to its consumer. A consumer warns when it is old,
  because a host that serves an old bundle looks the same as a database with no new advisories.
- A client can pin a bundle by its SHA-256. It then reads only the signed pair of that hash.
- A client can read a local directory with the layout of the host, and it checks the signature
  there too. With no network it needs a Sigstore trusted root file, because TUF can need the network.
- The cache directory is trusted. A client checks the signature before it writes the cache, and
  reads the cache back with a hash check and no network. A process that can write the cache can
  change the records, as it can change any other cache of the consumer. The client creates the
  directory for its user only.
- A record of the bundle matches a package version by any id of the alias set, by the ecosystem and
  the folded name of `dry/api/pb`, and by the OSV order of the range. A version that is not valid in
  its ecosystem matches, because a missed match would hide the symbols of a known advisory. For Go
  and crates.io a valid version is semver.

## Versions

A change that an older client can read adds fields to `v1/`. A change that an older client cannot
read goes to `v2/`, and the workflow keeps `v1/` while clients of `v1/` are in use.
