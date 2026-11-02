# Toolchain evidence and development setup

| Artifact | Rust stamp | LLVM linker stamp | Clang stamp | Unwind entries |
| --- | --- | --- | --- | ---: |
| Node #94 | 1.94.1, e408947bf, 2026-03-25 | LLD 21.1.8 | 21.1.0-rc2 | 121299 |
| Node #115 | 1.95.0, 59807616e, 2026-04-14 | LLD 22.1.2 | 22.1.0-rc2 | 135313 |

Source: preserved binary inventories; `make reproduce` regenerates them.
Unwind entry counts are a proxy for function counts, not a complete function census.

The root rust-toolchain.toml retains Rust 1.94.1 for existing historical components.
Setup also installs Rust 1.95.0. New #115 build work should explicitly select
`cargo +1.95.0 ...`; preserve each existing component's evidenced compiler. Neither command currently builds a node: manifests, dependency lock,
private forks, exact build flags and recovered logic are incomplete.

The .devcontainer uses Linux/amd64 on Ubuntu 24.04 and installs both Rust
versions, Python, GPG, ripgrep and distribution LLVM/binutils. Its distribution
LLVM is for inspection, not asserted to match either target linker. On Apple
Silicon the container needs amd64 emulation. Host-native macOS rustc is useful
for development but cannot establish Linux binary equivalence.

Exact LLD/clang versions above are recorded requirements for a later matched
build image. Merely matching the Rust release is insufficient for byte identity.
