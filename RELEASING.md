# Releasing

Pushing a `v*` tag runs `.github/workflows/release.yml`, which publishes
the Rust crates to crates.io and the `pragmatic-runtime` wheels (Linux
x86_64/aarch64, macOS universal2, Windows x86_64, plus sdist) to PyPI, and
builds the Pragmatic Server container image.

Pragmatic Server (`crates/pragmatic-server`) and its anchoring library
(`crates/pragmatic-anchor`) are commercial software under the Business
Source License 1.1 and are never published to crates.io: both have
`publish = false` and `license = "BUSL-1.1"`, the release job checks both
before it publishes anything, and `cargo publish` excludes them by name as
well. The server ships as a container image and binaries.

## One-time setup

Both registries need an account owner to authorize this repository once.

**PyPI (trusted publishing, no token):**

1. Sign in at pypi.org and open *Your account → Publishing → Add a new
   pending publisher*.
2. PyPI project name `pragmatic-runtime`, owner `pragmaticco`, repository
   `pragmatic`, workflow `release.yml`, environment `pypi`.
3. In the GitHub repository settings, create an environment named `pypi`
   (optionally with required reviewers, so a release needs a click).

**crates.io (API token):**

1. Sign in at crates.io with the GitHub account that should own the
   crates, then *Account Settings → API Tokens → New Token* with the
   `publish-new` and `publish-update` scopes.
2. Add it as the repository secret `CARGO_REGISTRY_TOKEN`.

After the first release, crates.io trusted publishing can replace the
token (crate settings → Trusted Publishing).

**Container registry (optional):** the `container` job builds the server
image for every `v*` tag and smoke-tests it (read-only root filesystem,
unprivileged user, OpenSSL and the pinned TSA anchors present). It pushes
the image only when all three repository secrets are set; otherwise it
says so and stops after the build:

| secret | value |
|---|---|
| `CONTAINER_REGISTRY_IMAGE` | the image name without a tag, for example `ghcr.io/pragmaticco/pragmatic-server`; the part before the first `/` is the registry logged in to |
| `CONTAINER_REGISTRY_USERNAME` | the registry user (for GHCR, the account or bot that owns the package) |
| `CONTAINER_REGISTRY_TOKEN` | a token that may push to that image (for GHCR, a personal access token with `write:packages`) |

The image is tagged with the version (`v0.6.0` pushes `:0.6.0`); nothing
is pushed from a branch or a pull request.

## Cutting a release

1. Bump `version` in the root `Cargo.toml` (`[workspace.package]`) and
   every pin on a workspace crate (`version = "X.Y.Z", path = "../..."` in
   `crates/*/Cargo.toml`). The Python package takes its version from Cargo.
   Pragmatic Server announces the oldest SDK it accepts as `min_sdk` in
   `/v1/info` (`crates/pragmatic-server/src/server.rs`); raise it when the
   server's API changes in a way older SDKs cannot follow.
2. Move the `Unreleased` notes in `CHANGELOG.md` under the new version.
3. Check locally:
   ```sh
   cargo test --workspace
   cargo publish --workspace --dry-run --exclude pragmatic-server --exclude pragmatic-anchor
   docker build -t pragmatic-server:X.Y.Z .
   ```
4. Commit, then tag and push:
   ```sh
   git tag vX.Y.Z && git push origin main vX.Y.Z
   ```

A failed release can be re-run from the Actions tab once the cause is
fixed. The PyPI step skips files that already exist; crates.io rejects a
version that is already published, so if only some crates went out,
publish the rest by hand with `cargo publish -p <crate>`.
