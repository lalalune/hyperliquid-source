# RE-004: reconstruct node94 unwindless population count

This implements the previously static-only node94 population-count helper in
independent safe `no_std` Rust, and closes its complete u32 field-caller value
path. The leaf has no FDE; qualification explicitly uses full overlap checks,
bracketing records, padding and instruction-aligned callers. No FDE size is
invented and no original compiler or intrinsic name is inferred.

- Component: foundation; bounded RE-001 boundary qualification and RE-004 arithmetic.
- Target: node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
- Reference gitlink: `999556f6e0a474b8312db96ec3149e1c44e97c23`, unchanged;
  no unlicensed inferred implementation was read or copied.
- Prior grounding: [static packet](../foundation-unwindless-popcount-94/README.md).
  Its call-site constants are reused as expected addresses, then freshly
  authenticated against the target. Its numeric model does not generate these
  expectations or compare the new Rust.
- New [Rust library](../../../src/node94-popcount/lib.rs) and [full proof](PROOF.md).

## Complete static qualification

The main body is `[0x5660010,0x5660072)`, 98 bytes and 27 instructions, SHA-256
`09027f7508488f9fabf097f96e8db1d2e2740cf931ae88d008e04df4a8ab2916`.
All 121,299 decoded FDE intervals are checked: none overlaps it. The nearest
lower FDE ends at `0x5660004`, and the next begins at `0x5660080`. Their raw
FDE/CIE records and the 12 leading/14 trailing INT3 bytes are retained.

Fresh GNU, LLVM and Capstone decodes agree on every main-body instruction
boundary. The main body has no call, branch or explicit memory operand; all
masks and shift counts are immediate bytes. The complete field caller at
`[0x4f9eb90,0x4f9eba5)` is 21 bytes and six instructions, with SHA-256
`50fbc6d1c10dbce2d2c037c275f0c4a7ea279770e14258aaa632c2607f71f50b`.
All three decoders agree there too. Its dword read at object offset `0x40`
zero-extends into RDI before the selected call and preserves the returned RAX.

The whole-text E8-pattern scan retains exactly 25 candidates, each confirmed
at an instruction start in a freshly decoded complete caller FDE:

| Caller FDE | Bytes / instructions | Selected calls |
| --- | --- | ---: |
| `0x4f9eb90..0x4f9eba5` | 21 / 6 | 1 |
| `0x4fb3040..0x4fb3ff9` | 4,025 / 793 | 1 |
| `0x5363490..0x5363ba2` | 1,810 / 423 | 3 |
| `0x54cd010..0x54cd781` | 1,905 / 446 | 1 |
| `0x54cd790..0x54cde02` | 1,650 / 393 | 1 |
| `0x5525500..0x55261af` | 3,247 / 798 | 18 |

Complete caller hashes, FDE/CIE records and exact call bytes are retained in
[static.json](static.json). This is not a register-indirect/tail-call census or
proof of wider caller semantics. A scan of all 80,300 RELA records finds no
entry-naming or protected-code relocation for the main body/field adapter.
No bytes or operands are normalized.

Thirteen in-memory structural corruptions are rejected below whole-target
digest admission: pair mask, final fold, leading/trailing padding, an expanded
neighbor FDE overlapping the body, CIE encoding, one call edge in each of six
callers, and the adapter's field-load width. The captured altered bytes are
only parsed, never executed.

## Full-domain behavior and independent oracle

The target computes pair counts without borrowing, nibble counts without
carrying, and byte counts bounded by eight. Three 32-bit folds preserve the
sum of all eight byte counts, bounded by 64. The final seven-bit mask retains
that result. The proof accounts for every lane and truncation, including why
the source's two checked u64 additions cannot overflow. The field adapter
counts an unsigned dword's bits; sign extension would be wrong.

[oracle.py](oracle.py) counts literal one digits in textual binary forms,
independently of the source's mask/subtract/fold construction. It and the
fixtures were frozen before Rust existed; [frozen.json](frozen.json) records
source and decompressed-stream hashes. The 136,258 distinct u64 inputs include
all 65,536 lower-16-bit patterns and their full-width complements, all byte
patterns in every byte lane and their complements, every result 0..64,
field results 0..32, and 2,048 digest-derived varied inputs. Each row checks
the main result and the u32 caller projection separately.

The algebraic proof covers the full domain. The finite corpus is not an
exhaustive enumeration of all u64 values or a target execution differential.

## Native checks and reproducibility

Actual rustc 1.94.1 is version/commit and executable-hash pinned; commit is
`e408947bfd200af42db322daf0fadfe7e26d3bd1`. The selected `/usr/bin/cc` linker
is explicit, with hash/version recorded. Host is macOS arm64; Python 3.14.3,
Capstone 5.0.7, GNU objdump 2.47.20260726 and Apple LLVM objdump 17.0.0 provide
static/build tooling. No original toolchain or target-code equivalence follows.

Opt0 and opt3 each run twice: 545,032 input-row comparisons, each containing
two output values, with zero mismatches. Repeated libraries, clients and output
hashes agree within each optimization. Both unit tests pass per optimization,
and partial client input is rejected before producing output.

| Compiled wrong variant | Differing rows / 136,258 |
| --- | ---: |
| Change the pair mask's low bit | 68,125 |
| Add instead of subtract pair contributions | 129,010 |
| Wrong nibble shift | 122,800 |
| Omit high 32-bit contribution | 70,196 |
| Wrong middle fold shift | 70,212 |
| Wrong final fold shift | 135,237 |
| Keep only six result bits | 1 |
| Sign-extend the field input | 68,137 |

Two comparator controls detect a changed row and reject a missing byte. Exact
commands, source/compiler/fixture identities, first wrong-variant witnesses and
raw hashes are retained in [result.json](result.json) and [commands.json](commands.json).
[streams.json.gz](streams.json.gz) preserves all 90 original stdout/stderr
streams losslessly as content-addressed base64 payloads. No expected outputs
are passed to the newly compiled client.

A separate reviewer found no blocker after checking the complete instruction
sequence, lane proof and field adapter. The reviewer independently reran static
qualification and regenerated all 136,258 frozen oracle rows; no extra native
matrix run is claimed.

Six legacy focused tests and local `make doctor verify catalogue-check reproduce`
pass. The shared full repository sweep remains pending; no complete full-suite,
hosted-CI or target/Linux build success is claimed. Imports, pins, progress
gates and byte-window counts are unchanged.

## Reproduction and limits

From the repository root with pinned artifacts materialized:

```sh
export PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH
export LLVM_OBJDUMP=/usr/bin/objdump
python3 -O -B research/work-items/RE-004-popcount-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-popcount-rust-94/verify_rust.py \
  --out work/popcount-review \
  --rustc "$(rustup which --toolchain 1.94.1 rustc)"
python3 -B -m unittest tests.test_foundation_unwindless_popcount -v
rustfmt +1.94.1 --check src/node94-popcount/lib.rs src/node94-popcount/input_only_driver.rs
make doctor verify catalogue-check reproduce
```

The native verifier requires a fresh output directory and the recorded actual
compiler. The library needs no package downloads or root Cargo workspace.
Its APIs project raw values; they do not expose the original pointer/stack
ABI, invalid-memory faults, concurrent field reads, register/flag/timing
identity or unwind behavior. Wider caller purposes, source provenance and
compiled-byte identity remain unresolved. No captured code or instruction
emulator ran. The next bounded question is what the remaining callers count
and whether they consume the whole result or a predicate of it.
