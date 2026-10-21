# Releasing

Surfski uses [Semantic Versioning](https://semver.org). The version lives in exactly one place:
`version` in `pyproject.toml`. The package, `surfski --version`, the MCP server info and the
`surfski_build_info` metric all read it from there.

## Steps

1. **Bump the version.** On a branch, set `version = "X.Y.Z"` in `pyproject.toml` and run `uv lock`
   so `uv.lock` records it.
2. **Move the changelog.** In `CHANGELOG.md`, rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD`
   (today's date), add a fresh empty `## [Unreleased]` above it, and check the entries read well as
   release notes. Check it renders: `python3 scripts/changelog_section.py X.Y.Z`.
3. **Open a PR** ("Release vX.Y.Z"), let CI pass, and merge it into `main`.
4. **Tag `main`:**
   ```bash
   git switch main && git pull
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push origin vX.Y.Z
   ```
   The tag must be exactly `v` + the `pyproject.toml` version. Pre-releases use a suffix in both,
   e.g. `version = "0.2.0-rc.1"` and tag `v0.2.0-rc.1`; they are published as GitHub pre-releases. Note that Python normalizes such versions in package metadata (`0.2.0-rc.1` becomes `0.2.0rc1`), so `surfski --version` prints the normalized form.
5. **The release workflow** (`.github/workflows/release.yml`) then:
   - fails at once if the tag doesn't match the `pyproject.toml` version or the changelog has no
     section for it;
   - runs the full CI;
   - builds and pushes `ghcr.io/rayhu/surfski:vX.Y.Z`, `:X.Y` and `:latest` (not `latest` for
     pre-releases) for amd64 and arm64;
   - creates the GitHub Release `vX.Y.Z` with the changelog section as its notes.
6. **Verify:** the Actions run is green, the image pulls
   (`docker pull ghcr.io/rayhu/surfski:vX.Y.Z` and `docker run --rm ghcr.io/rayhu/surfski:vX.Y.Z
   surfski --version`), and the Release page shows the notes.
7. **First release only:** GHCR packages start private. In GitHub → your profile → Packages →
   `surfski` → Package settings, set visibility to **Public** and link it to the repository.

## If something goes wrong

- **Tag/version mismatch:** delete the tag (`git push --delete origin vX.Y.Z && git tag -d vX.Y.Z`),
  fix `pyproject.toml` through a PR, and tag again.
- **Image built but the Release step failed:** re-run the failed job from the Actions page; the
  image push is idempotent for the same tag.
- Never move a published tag; cut a new patch version instead.
