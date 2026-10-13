# Releasing

Pushing a `v*` tag runs `.github/workflows/release.yml`, which publishes
the Rust crates to crates.io and the `pragmatic-runtime` wheels (Linux
x86_64/aarch64, macOS universal2, Windows x86_64, plus sdist) to PyPI.

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

## Cutting a release

1. Bump `version` in the root `Cargo.toml` (`[workspace.package]`) and the
   `pragmatic-macros` version pin in `crates/pragmatic/Cargo.toml`.
2. Move the `Unreleased` notes in `CHANGELOG.md` under the new version.
3. Check locally:
   ```sh
   cargo test --workspace
   cargo publish --workspace --dry-run
   ```
4. Commit, then tag and push:
   ```sh
   git tag vX.Y.Z && git push origin main vX.Y.Z
   ```

A failed release can be re-run from the Actions tab once the cause is
fixed. The PyPI step skips files that already exist; crates.io rejects a
version that is already published, so if only some crates went out,
publish the rest by hand with `cargo publish -p <crate>`.
