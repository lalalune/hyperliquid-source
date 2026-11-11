# Node #115 execution-row comparison dependencies

Partial HL115-024, pinned to node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Prior [#2096](https://github.com/lalalune/hyperliquid-source/pull/2096) establishes execution selection and leaves its comparators unresolved. Open [#4945](https://github.com/lalalune/hyperliquid-source/pull/4945) models the 32-byte selector while explicitly leaving the suffix comparator opaque. This contribution closes selected logical comparator behavior without copying that selector or asserting row economic meaning.

## Two comparison paths

On the 32-byte selection loop, the first u64 is compared unsigned. Only equality calls `0x23316c0` with the two row+8 descriptors. That helper constructs two iterators and hands them to `0x243b7a0`; the iterator path compares 20-byte key values via `memcmp`, proceeding after equality, with exhaustion resolving prefixes. The logical result is lexicographic comparison of the sequences in native visitation order. The caller keeps its current row only on a positive result, so equality chooses the later candidate. #4945 owns that selector relation; the companion code exports the missing key-sequence comparator and includes a small test witness of the prior tie convention, not a second selector implementation.

The 64-byte selection loop calls `0x26a7880`. It compares the first u64 unsigned. When equal it compares the nested descriptor at +8 via `0x2e35350` / `0x26c1f40`: keys are 20 bytes, and equal keys lead to unsigned comparison of their associated u64 values. The flat path has 32-byte rows (key bytes 0..20, ignored bytes 20..24, value 24..32). Only when those map sequences compare equal does `0x26a7880` compare the trailing key sequences through `0x2387b20`, again using 20-byte `memcmp` and prefix exhaustion. The caller's signed result test keeps the current row when positive and otherwise selects the candidate.

The Rust source takes logical ordered sequences. Valid descriptor layout, iterator visitation order, lifetime, allocation and native tree/ring operations are explicit premises. It does not decode or dereference process pointers, prove arbitrary physical tree invariants, reconstruct publication, or identify domain-level row names. These are selected static/source relations, not whole-component or executed-native equivalence claims.

## Validation

`python3 research/work-items/RE-008-node115-execution-order/verify.py` authenticates the target and checks eight selected windows, original instruction bytes and operands, the `memcmp` import, and 26 rejected instruction corruptions. No captured instruction executes or is emulated. `cargo test --manifest-path src/node115-execution-order/Cargo.toml` tests empty/prefix cases, every key byte, unsigned full-width value, padding, nested branch precedence and a separate pairwise reference across ordered slices. Test the release profile with `--release`.
