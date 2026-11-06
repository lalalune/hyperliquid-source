# Node #115 u32 reader Rust reconstruction

Base commit 05bc2de303c05525b71e7e257426e741bc66a390 contains the static
reader evidence from #2412. It has no standalone compiled Rust implementation
for these two wrappers. This packet adds one with a borrowed remaining slice
and separate raw mode, limit and charged count.

The checker authenticates the full Node #115 capture and verifies the two
wrapper unwind extents at 0x2cd79c0 and 0x5821150, the shared slow path at
0x5822490, their text digests, the slow and constructor relocation slots and
the static dispatch tables. The expected rows were frozen before writing the
Rust implementation. They cover every marker at lengths one through nine,
empty input, nonminimal values, charge overflow, exceeded limits, invalid
markers, shortfalls and consumed-byte differences between fast and slow paths.

Run with Rust 1.94.1, its x86_64-unknown-linux-gnu target and Capstone:

    cargo check --offline --locked --target x86_64-unknown-linux-gnu --manifest-path src/node115-u32-varint/Cargo.toml
    python tools/u32_reader115_rust.py
    python tests/test_u32_reader115_rust.py

The checker compiles the probe without jump tables because the initial object
contained a PC-relative relocation into its own read-only data. The scoped
interpreter adds the signed JLE predicate required by this probe and rejects
external relocations, helper calls and external data reads. All eight input
alignments matched across 18,600 frozen rows. Six separately compiled private
mutants changed the mode test, charge amount, limit rollback, short-path
threshold, decoded value and invalid marker field. Each differed from a
frozen row. Their first divergent rows are retained in mutant-witnesses.json.

The verifier interprets only the independently compiled object. The captured
node is read as data. The synthetic seven-word probe does not expose the
original Rust ABI or claim the original nominal types or full codec behavior.
There is no byte identity or module gate credit.
