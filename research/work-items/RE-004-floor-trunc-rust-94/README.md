# RE-004: independently reconstruct floor and truncation with explicit DAZ

- Component: foundation; bounded RE-004 arithmetic reconstruction.
- Target: node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
- Reference pin: can1357/hl `999556f6e0a474b8312db96ec3149e1c44e97c23`;
  its inferred implementation was not read or copied for this work.
- Included: complete 85-byte truncation and 148-byte floor bodies, FDE/CIE
  records, branch closure, -1 constant, two relocation slots, independent
  Rust returned-bit APIs, mathematical proof and native boundary controls.
- Excluded: original ABI, upper XMM lanes, MXCSR flags/traps, incoming caller
  behavior, original source/build provenance and compiled target-byte identity.

The prior `RE-006-twap-slice-94` packet includes floor as an evaluator edge.
This packet adds an independent Rust implementation and qualifies its denormal
operand condition. It does not reuse or execute that packet's instruction
evaluator. The truncation leaf has its own complete extent and slot. The two
contracts share fractional clearing, while floor's negative-small path has a
distinct floating comparison; `PROOF.md` derives that distinction.

`trunc_bits` preserves every NaN and signed-zero bit pattern. `floor_bits`
accepts an explicit DAZ argument: with DAZ set, a negative subnormal returns
unchanged input bits. With DAZ clear and the denormal exception masked, it
returns -1. A generic host `floor()` call would conceal this target condition.
The boolean is a new value-API parameter, not a recovered target argument.

## Reproduce

From the repository root, with pinned submodules/LFS inputs materialized:

```sh
PATH="/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH" \
  LLVM_OBJDUMP=/usr/bin/objdump make doctor verify catalogue-check reproduce
python3 -B research/work-items/RE-004-floor-trunc-rust-94/verify_static.py
python3 -B research/work-items/RE-004-floor-trunc-rust-94/verify_rust.py \
  --rustc /opt/homebrew/opt/rustup/bin/rustc --out work/floor-trunc-review
```

The compiler must resolve to rustc 1.94.1. Native validation uses
`aarch64-apple-darwin`, edition 2024, opt0 and opt3, codegen-units=1,
panic=abort, overflow-checks=yes, warnings denied, and a remapped source root.
It builds and runs only newly authored Rust. Each client receives only 9-byte
input records (u64 LE bits plus DAZ byte) and returns two u64 LE words; it
cannot read the expected-output fixture. Both malformed framing and DAZ bytes
outside 0/1 are rejected before any output. There are no downloads or runtime
dependencies. Build directories must be new.

Raw disassembly was produced with GNU objdump 2.47 (`-d --insn-width=16`)
and `/usr/bin/objdump` (Apple LLVM 17), with start/stop values from `static.json`.
The preserved `.gnu.txt` and `.llvm.txt` files include their exact raw output.
`commands.json` records every native command; `<repo>` is the sole path label
substitution. `streams.json.gz` retains original stdout/stderr bytes as base64
with their hashes in `result.json`. Input and expected fixtures have separate
deterministic gzip archives. Decompression restores their original hashes.

## Observed results

All 66,132 frozen rows match at opt0 and opt3 and in both repeated builds.
Both Rust unit tests pass at each optimization. Repeated native libraries,
clients and output streams are raw-byte-identical at each level, without
normalization. Six compiled wrong implementations are rejected: ignoring DAZ
(7 rows), flushing its returned subnormal (7), truncating negative fractions
(828), incrementing integral negatives (312), losing truncation's signed zero
(16,336), and returning early at exponent 1074 (18).

Seven altered target structures are rejected independently below the full-file
digest admission: both bodies, both FDE extents, both slot addends and the -1
constant. The complete target digest remains mandatory in the ordinary path.
The corpus is a static rational oracle, not captured execution output.

Repository checks and the shared running legacy test suite are reported in
`VALIDATION.md`; no hosted CI result is presumed. No progress gate or byte-window
counter is changed. The next unresolved question is which caller establishes
MXCSR.DAZ and the denormal exception mask before using the floor slot.
