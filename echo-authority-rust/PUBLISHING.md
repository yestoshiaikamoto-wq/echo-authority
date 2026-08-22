# Publishing the Echo Authority reference implementation

Everything is prepared. These are the only steps that require **your** accounts — a GitHub
repository and a crates.io login. Nothing here can be done from inside v0; run it locally
after you download the project.

## 0. Repository URL — DONE

Both `Cargo.toml` files now point at the real repo:

```
repository = "https://github.com/yestoshiaikamoto-wq/echo-authority"
homepage   = "https://moneymusk.space/protocol"
```

Nothing to change. Create the GitHub repo with the matching name — **`echo-authority`**,
owner `yestoshiaikamoto-wq` — so the manifests and the repo agree.

Suggested repo description:

> A human-rooted authority protocol for autonomous systems. No authority, no privileged
> action. Reference implementation in Rust — 22/22 conformance vectors.

Create it **empty**: no README, no .gitignore, no license from the dropdown. The crates
already carry their own `README.md`, `LICENSE-MIT`, and `LICENSE-APACHE`, and an
auto-generated file would collide on your first push.

## 1. Push to the public GitHub repo

Push **only the two crate folders** — not the whole Money Musk website. This repo is the
reference implementation of the protocol, so it should contain nothing a reviewer has to
wade past. Build a clean folder first:

```
echo-authority/                  <- rename echo-authority-repo/ to this
├── README.md                    <- already inside echo-authority-repo/
├── echo-authority-rust/         <- copy in from the v0 project
└── echo-authority-wasm/         <- copy in from the v0 project
```

After downloading the project ZIP from v0: rename the `echo-authority-repo` folder to
`echo-authority` (it already holds the repo's front-page `README.md`), copy the two crate
directories into it, then from inside it:

```sh
git init
git add .
git commit -m "Echo Authority Protocol — Rust reference implementation (Draft 0.1)"
git branch -M main
git remote add origin https://github.com/yestoshiaikamoto-wq/echo-authority.git
git push -u origin main
```

Each crate carries its own `.gitignore` with `/target`, so build artifacts can never be
committed regardless of where the crates sit. Confirm with `git status` before committing:
you should see roughly 17 files and **no** `target/` anywhere. If you see thousands, a `target/`
folder came along — delete it and re-check.

## 2. Dry-run the package (no account needed — do this first)

```sh
cd echo-authority-rust
cargo publish --dry-run          # verifies metadata, builds, and packs the tarball
cargo package --list             # shows exactly which files would be uploaded
```

Fix any warning it prints. A clean dry-run means the real publish will succeed.

## 3. Log in and publish — order matters

`echo-authority-wasm` depends on `echo-authority-core`, so **core must be published first**;
crates.io will not accept a crate whose path-dependency isn't already registered.

```sh
cargo login                      # paste the token from https://crates.io/settings/tokens

cd echo-authority-rust
cargo publish                    # publishes echo-authority-core 0.1.0

# wait ~30s for the index to update, then:
cd ../echo-authority-wasm
cargo publish                    # publishes echo-authority-wasm 0.1.0
```

That's it. Both crates are now installable with `cargo add echo-authority-core` and the docs
render automatically at `https://docs.rs/echo-authority-core`.

## 4. Cutting future versions

- Bump `version` in the crate's `Cargo.toml` (semver: breaking = `0.2.0`, additive = `0.1.1`).
- If `core` changes, bump the `version = "..."` pin in `echo-authority-wasm`'s dependency too.
- `cargo publish` is irreversible per version — you can `yank` a bad release but never re-upload
  the same number. Dry-run first, always.

## What's already done for you

- `description`, `license = "MIT OR Apache-2.0"`, `LICENSE-MIT` + `LICENSE-APACHE` in both crates
- `keywords`, `categories`, `readme`, `authors`, `rust-version`, `repository`, `homepage`
- `exclude = ["target/"]` so build artifacts never ship
- `echo-authority-wasm`'s core dependency carries both a `path` (local) and a `version` (crates.io)
- `cargo test` → 22/22 green · `cargo build --release` clean · wasm build verified in-browser
