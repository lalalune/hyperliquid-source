# RE-004: node94 indexed table offset with output aliases

The existing `foundation-byte-indexed-table-offset-94` packet left Rust
unimplemented and parameterized the table's post-store value. This adds a real
safe byte-image implementation of complete node94 `[0x54ccfb0,0x54cd009)`.
It preserves the optional selector store before the table load, including
partial output/table aliases and output aliases with already-read state fields.
The [proof](PROOF.md) covers all admitted images and each instruction path.

Target node94 is 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`;
base is `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`, reference gitlink
`999556f6e0a474b8312db96ec3149e1c44e97c23`. New Rust/prose are independently
authored under the root MIT license; no unlicensed inferred implementation was
read or copied. Captured bytes/disassembly retain the artifact's rights.

## Behavior and admission

The full low32 index selects a state byte and table word. Null object or zero
presence makes the selector zero, but still permits the output store and still
loads the table. A nonnull output receives the selector as four little-endian
bytes. The return is the wrapping sum of the input base, the **post-store**
unsigned table word and 224 times the selector. For coincident output/table,
that word becomes the selector; base 10 and selector 7 return 1585 even if the
old table word is 0xfedcba98.

The linked table base 0x5799cc0 is in writable NOBITS `.bss`, with unknown
runtime contents/length. The API's explicit runtime `table_base` must equal
the actual LEA result after load bias. No file byte or guessed zero base is
substituted. The checked single-image domain preserves all data overlaps
within ordinary nonwrapping mapped memory and unchanged code/return state.
Bounds errors preserve the entire image as additional safe policy; native
faults, partial fault writes, concurrent/MMIO effects, control-state aliases
and pointer ABI are outside the claim. The computed result need not point
inside the image because the original does not dereference it.

## Static evidence

The leaf has 89 bytes/24 instructions and SHA-256
`aa17e5804e7498bdc538b462ce80b85803e892e24c394a2de3da74f9f90c2ba8`.
Complete caller evidence comprises:

| Caller FDE | Bytes | Instructions | Incoming site |
|---|---:|---:|---|
| `0x5554b50..0x5555bcc` | 4,220 | 927 | `0x55557a3` |
| `0x5555bd0..0x555661f` | 2,639 | 579 | `0x5556447` |
| `0x5557510..0x5557617` | 263 | 71 | `0x555755c` |

GNU, LLVM and Capstone agree on all bytes/boundaries. Six separately printed
LLVM LOCK prefixes are grouped with checked F0 bytes and adjacent addresses;
raw exports are retained without text normalization. Full FDE/CIE records,
seven padding bytes, RIP-relative table address and NOBITS/PT_LOAD coverage
are bound. Whole-text E8 scanning confirms the three aligned sites. All 80,300
RELA records are checked for entry naming/protected-code writes, with none
found. Caller purpose, indirect-reference completeness and table extent are
unclaimed. Thirteen downstream corruption controls reject field/index/scale,
store/load width, LEA, padding, FDE/CIE and each caller-edge mutation.

## Frozen oracle and native qualification

Before Rust existed, the oracle froze 5,525 cases using immutable per-byte
output overlays and a base256 sum over the resulting table bytes. It performs
no sequential target stores, decoded-instruction evaluation or Rust execution.
There are 5,328 successful image operations and 197 new refusals (3 image-range,
54 state, 75 output and 65 table bounds). All 256 selector values, seven partial/
exact table overlaps, high index bits, state aliases and boundary images are
covered. Finite fixtures corroborate the all-input proof, not a complete census.

All four native builds/runs (opt0/opt3, each repeated) match 22,100 rows:
21,312 successful operations and 788 safe-refusal observations. Three unit tests
run per optimization. Repeated rlib, client and stdout hashes match within each
profile. The input-only client receives a 370-byte record and emits a 329-byte
result containing tag, full return word and every one of 320 backing bytes,
including unchanged bytes beyond the actual image slice. No output mask is used.

All 14 wrong implementations compile, exit normally and differ observably.
Examples restricted to successful observations: loading the table before the
store changes 3,848 cases, sign-extending the table changes 1,795, and using a
two-byte output store changes 4,564. Moving the store before failed admission
changes 25 refusal images; those are safe-contract controls, not target return
evidence. `native/mutation-domains.json` separates changed successful results,
false refusals of admitted inputs and differences in new refusal behavior.

The initial qualification stopped when the signed-entry mutant triggered a
compiler warning for redundant parentheses under `-D warnings`. Only that
mutation expression changed; the Rust library/oracle remained unchanged. A
fresh complete run then passed. The failed compilation is not counted as a
detected semantic mutant. `native/initial-diagnostic.json.gz` preserves all 74
initial raw streams and command records; `native/streams.json.gz` preserves
all 126 qualified streams with lossless payloads/hashes. Final commands/results
bind source, actual compiler/linker binaries, artifacts and first witnesses.
Two comparator controls detect a changed row and a missing output byte.

An independent reviewer regenerated and directly recomputed all 5,525 cases,
confirmed all seven overlaps, 960 successful high-index cases and 13 null-object
successes, and reran static verification under `-O`. Source hash at review is
`0e5ccd13400101a6eb7dd58f7eed5d7f47bb7fc0648cc609989e501292f2fe63`.
No blocking issue or source change resulted.

## Reproduce and limits

From repository root after materializing pinned artifacts:

```sh
export PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH
export LLVM_OBJDUMP=/usr/bin/objdump
python3 -O -B research/work-items/RE-004-table-offset-alias-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-table-offset-alias-rust-94/verify_rust.py \
  --out work/table-offset-review \
  --rustc /Users/shinjun/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin/rustc
python3 -B -m unittest tests.test_foundation_byte_indexed_table_offset -v
rustfmt +1.94.1 --check --edition 2024 src/node94-table-offset-alias/*.rs
make doctor verify catalogue-check reproduce
(cd research/work-items/RE-004-table-offset-alias-rust-94 && shasum -a256 -c MANIFEST.sha256)
```

`--out` must be fresh. The qualified host is macOS ARM64, Python 3.14.3,
rustc 1.94.1 commit `e408947bfd200af42db322daf0fadfe7e26d3bd1`, LLVM 21.1.8;
actual compiler SHA-256 is
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`.
Static tools are GNU binutils 2.47.20260726, Apple LLVM 17 and Capstone 5.0.7.
Exact compiler/export pins intentionally require these recorded versions;
other-host evidence must be separately labeled. Native validation ran under
Python `-O` with explicit guards. Seven focused predecessor tests, rustfmt,
repository checks and manifest pass, with raw check logs retained.

The shared full legacy sweep remains incomplete and is not claimed as this
packet's result. No captured binary execution, instruction emulation, original
compiled-byte identity, whole-node equivalence or gate advancement is claimed.
Only this packet and `src/node94-table-offset-alias/` change; pins, imports,
catalogues and prior evidence remain intact.
