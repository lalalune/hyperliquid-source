# Toolchain evidence and development setup

| Artifact | Rust stamp | LLVM linker stamp | Clang stamp | Unwind entries |
| --- | --- | --- | --- | ---: |
| Node #115 | 1.95.0, 59807616e, 2026-04-14 | LLD 22.1.2 | 22.1.0-rc2 | 135313 |

Source: preserved binary inventories; `make reproduce` regenerates them.
Unwind entry counts are a proxy for function counts, not a complete function census.

The root rust-toolchain.toml selects Rust 1.95.0 for node #115 development.
Some retained #115 proof runners explicitly use research Rust 1.94.1 to reproduce
their existing independently compiled experiments. Setup installs both. Those
research builds do not establish the original compiler flags or whole-node identity.

The .devcontainer uses Linux/amd64 on Ubuntu 24.04 and installs both Rust
versions, Python, GPG, ripgrep and distribution LLVM/binutils. Its distribution
LLVM is for inspection, not asserted to match either target linker. On Apple
Silicon the container needs amd64 emulation. Host-native macOS rustc is useful
for development but cannot establish Linux binary equivalence.

Exact LLD/clang versions above are recorded requirements for a later matched
build image. Merely matching the Rust release is insufficient for byte identity.
