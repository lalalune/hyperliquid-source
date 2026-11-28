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

### Replaying the ThinLTO Debug formatter comparisons

The storage/ABCI, consensus/staking and Stream E2 Debug packet verifiers build
their Rust reference programs with Rust 1.95.0 for `x86_64-unknown-linux-gnu`.
They read saved post-ThinLTO code-generation objects from a **successful whole
program link**. An object-only build produces different machine code. Neither
the reference executable nor the captured node runs during these comparisons.

On Linux x86-64 the default system linker is sufficient. On another host,
install the Linux target with `rustup target add --toolchain 1.95.0
x86_64-unknown-linux-gnu` and set
`CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER` to a working Linux x86-64 GNU
linker driver with a compatible sysroot. A wrapper that runs
`zig cc -target x86_64-linux-gnu "$@"` was tested with Zig 0.14.1 on arm64
macOS. After `make fde-index`, each existing packet supports
`python3 verify.py --self-test` from its own directory.
