# Node94 kind-5 reader contract

This dependency-free, `no_std`, safe Rust component implements the observed
byte/cursor/fixed-eight-charge contract of node94 FDEs `0x466dad0`,
`0x466be70` and `0x466dac0`. It is independently authored from their authenticated
instructions. It does not copy the unlicensed inferred reference source.

The input cursor and `Outcome` are a new interface. They do not recover a
target Rust layout, calling convention or source type for the opaque kind5
byte. The output adapter writes only the observed fields of the packet's
24-byte window; it preserves inactive bytes. The 40-byte state window and
synthetic pointer base are confined to the test adapter.

The reader accepts immediate tags through250 and tagged2/4/8-byte payloads,
including nonminimal payloads. Every nonzero endian byte swaps payload order.
A truncated payload consumes its marker only. The wrapper always uses little
endian. It charges8 only for raw selector1, checks overflow before storing the
charge, and checks the limit afterward. An invalid marker advances the cursor
on its short-input fallback but not on its remaining>8 fast path.

Run the full target-grounded check from the repository root:

```sh
python3 tools/kind5_reader_rust.py --controls --output work/kind5-rust-new
```

Use an existing GNU objdump on PATH and LLVM objdump through `LLVM_OBJDUMP`.
The runner authenticates node94, creates a non-executable owned snapshot,
repeats both native decodes and the finite instruction evaluator, and checks
that all28,992 expected output/state rows equal the original retained packet.
It passes that freshly produced ledger to Rust debug and release tests. No
expected output comes from the Rust implementation.

The command uses only an existing Cargo/rustc, offline locked builds, and no
external dependencies. It checks formatting, Clippy, two clean release archive
builds and compiling Rust-source corruption controls. An existing output
directory is refused to preserve evidence. Its generated ledger, build trees
and logs belong under ignored `work/`.

The runner removes its own successful compiler caches between mutations to
bound disk use. It retains the two actual release archives, mutant sources,
all command logs and the comparison record in that output directory. A failed
unexpected command leaves its build tree available for diagnosis.

`cargo test --manifest-path src/node94-kind5-reader/Cargo.toml --offline
--locked` runs six focused tests and explicitly ignores the authenticated
corpus until its required export is available. The runner sets
`NODE94_KIND5_VECTORS` and uses `--include-ignored`; all seven tests must pass.
It compares every24 output bytes and40 state bytes for every fixture.

This component declares Rust1.88 as its host build minimum. It is not the
missing whole-node manifest or exact Linux build provenance. The root pinned
rebuild toolchains are unchanged. See the evidence packet under
`research/work-items/RE-005-kind5-reader-94/` for actual host/tool versions,
results and remaining gaps. No captured node execution, network, chain action,
runtime-equivalence claim or component gate is included.
