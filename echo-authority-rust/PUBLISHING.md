# Publishing Echo Authority

Both crates use the manual `Publish to crates.io` workflow in
`yestoshiaikamoto-wq/echo-authority`. A push or pull request runs CI. A manual
run defaults to verification. Publishing requires an explicit selection of
`publish` on the `main` branch.

## Configure the trusted publisher

Before enabling this release path, the repository and crate owners must approve
and apply the following settings.

1. In GitHub **Settings → Environments**, create `crates-io`. Set deployment
   branches and tags to **Selected branches and tags**, add the **Branch**
   rule `main`, and leave the tag list empty.
2. On crates.io, open **Settings → Trusted Publishing** for each existing crate,
   `echo-authority-core` and `echo-authority-wasm`. Add a GitHub publisher to
   each using these exact values.

   | Field | Value |
   | --- | --- |
   | Repository owner | `yestoshiaikamoto-wq` |
   | Repository | `echo-authority` |
   | Workflow filename | `publish.yml` |
   | Environment | `crates-io` |

3. Review both entries against the workflow and check the GitHub environment's
   branch rule. The release job exchanges its GitHub OIDC identity for a
   short-lived credential using the Rust project's auth action.

## Validate without uploading

From a clean checkout of the revision under review, install the
`wasm32-unknown-unknown` target for stable Rust and run the same checks as CI
from the repository root. These commands need no registry credential.

```sh
cargo test --locked --manifest-path echo-authority-rust/Cargo.toml --all-targets
cargo check --locked --manifest-path echo-authority-wasm/Cargo.toml --target wasm32-unknown-unknown
(
  set -eu
  vectors=$(mktemp)
  trap 'rm -f "$vectors"' EXIT
  cargo run --locked --quiet --manifest-path echo-authority-rust/Cargo.toml --bin dump-vectors > "$vectors"
  printf '%s  %s\n' 'f4c7b4eaed25a206774a2e1ee760c6cff2e0c6ed5414529acfffa2be2ca39844' "$vectors" | sha256sum --check
)
```

For packaging, run `cargo package --list --locked --manifest-path PATH`
once for each manifest above. This lists the files that would ship.

After merge, a separately authorized manual run with `publish` unchecked
can exercise the release workflow's verification path. Expect successful CI
and a **skipped publish job**. This path never requests an OIDC token. A green
result verifies the code and gates. Registry acceptance is established on an
authorized release.

## Release an approved revision

1. Review the commit on `main`, the package versions in both manifests, their
   lockfiles, and the version of core required by WASM. Confirm both intended
   versions are available to publish. Each crate version can be uploaded once.
2. When the release is authorized, select **Actions → Publish to crates.io →
   Run workflow**, choose `main`, and select `publish`. The workflow verifies
   the dispatched commit, then publishes core, waits for the index, and publishes
   WASM for `wasm32-unknown-unknown`.
3. Confirm both versions on crates.io. If an upload fails partway through, check
   which versions reached the registry before deciding on recovery.
4. After the first successful trusted release of both crates, the owners may
   separately approve **Trusted Publishing Only** on each crate. That setting
   disables traditional API-token publishing for the crate. Review any legacy
   secret or token separately before retiring it.

[crates.io Trusted Publishing](https://crates.io/docs/trusted-publishing)
