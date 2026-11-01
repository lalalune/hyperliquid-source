# RE-004 — node94 decimal-u64 parser state and raw RAX

This packet independently reconstructs the complete parser
`[0x54307c0,0x5430857)` in dependency-free `no_std` Rust. Beyond ordinary decimal
accumulation, it resolves two details absent from the prior Python model:
nondigit termination uses a **signed wrapping u32 digit count**, and SETG AL
preserves the high EAX bits from a sign-extended stopping byte. The new API
reports raw RAX, consumed/remaining lengths, output value and output-store
presence. The [prior packet](../foundation-decimal-index-replace-94/README.md)
is preserved. Its decimal-index formatting wrapper is not reconstructed here.

## Target and complete static closure

Target node #94: 91,774,280-byte Linux x86-64 ELF; full SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Source base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. Addresses are ELF VAs.
The leaf is 151 bytes / 48 instructions, body SHA-256
`1361c480a3939ad2c6d2c04bf97d46fae7d79adbe2fa24552ad4fd4bc8bed42d`, with
FDE `.eh_frame+0x2badc0`. Nine following INT3 bytes are excluded. Every branch
remains inside the complete body; there are no callees or external constant
tables. The decimal threshold and digit bound are immediate operands.

Ten direct E8 sites are qualified inside six full, separately hash-bound caller
bodies. These bounds and actual FDE/CIE bytes are in `static-lock.json`, whose
hash is pinned in the frozen oracle:

| Caller range | Direct sites | Instructions |
| --- | --- | ---: |
| `[0x514b390,0x514b486)` | `0x514b3d4` | 61 |
| `[0x514cc10,0x514ccf9)` | `0x514cc4e` | 60 |
| `[0x514dce0,0x514ddf1)` | `0x514dd13` | 73 |
| `[0x514eb90,0x514ed1b)` | `0x514ebcf` | 100 |
| `[0x5154250,0x515442d)` | `0x5154289` | 103 |
| `[0x529eb60,0x529f342)` | `0x529ec1f`, `0x529ecd0`, `0x529ee36`, `0x529eea8`, `0x529f127` | 443 |

A complete 70,370,352-byte `.text` E8 scan returns exactly these ten sites.
80,300 RELA records contain no addend naming the parser. Every listed caller
later tests AL; several first save EAX. This is evidence of low-byte
consumption, not a complete caller/type reconstruction. Indirect references,
caller effects and the wrapper's formatting/string callees remain excluded.

## Domain and findings

The safe value input is an explicit count of leading ASCII zero bytes followed
by an immutable tail byte slice, plus the initial output value. Ordinary byte
strings use count zero. The compressed representation permits actual native
Rust tests at 2^31/2^32 digit-count boundaries without allocating or traversing
gigabytes. It does not claim the expanded string was physically constructed
or read by captured code. The [proof](../../../src/node94-decimal-u64-parser/PROOF.md)
establishes equivalence to that exact logical concatenation.

For target correspondence, the logical sequence must be stable/readable, its
native pointer plus total length nonwrapping, and state/output cells valid
and disjoint from input and one another. Native faults, concurrent mutation,
state/input/output aliases and original pointer ABI are excluded. Consumed
and remaining lengths represent cursor effects. `LengthOverflow` is a new API
refusal for a logical concatenation exceeding u64, not target numeric overflow.

The retained instructions establish:

- The low-byte digit gate accepts exactly ASCII `0..9`, including exclusion of
  every high-bit byte. A digit is accepted iff `10*value+digit <= u64::MAX`.
- Numeric overflow returns RAX=0, leaves the failing digit unconsumed and does
  not write the output; previously accepted digits remain consumed.
- A nondigit writes the accumulated value, leaves that byte unconsumed, and
  sets AL according to signed `(consumed_digits mod 2^32)>0`.
- That path's RAX is `0x00000000ffffff00 | AL` for a high-bit stopping byte,
  otherwise AL. Raw RAX is therefore not a Boolean. For example an immediate
  `0x80` yields raw `0xffffff00`, while AL is zero.
- Empty input writes zero and returns zero. EOF after digits writes the value
  and sets EAX=1, bypassing the signed count test. A prefix of 2^31 zeros
  followed by `A` has RAX=0, whereas the same zeros ending at EOF have RAX=1.

The library uses the proven zero-prefix transition, then a guarded decimal
multiply-add loop with explicit wrapping u32 count. All projected store and
cursor effects are preserved; flags and unrelated scratch registers are not
claimed. No alias refinement is implied by this immutable-input API.

## Pre-Rust oracle and native observations

Oracle freeze: `2026-11-01T20:51:56.459357+00:00`, before any new Rust source
existed. Unchanged oracle SHA-256:
`a5b8eff97cc0f3accf313eaee5daad6e02501895619fdae6cf9144a44398b98b`.
It identifies the ASCII digit prefix, removes insignificant zeroes, and uses
significant-string length and lexical comparison with
`18446744073709551615` to locate the first overflowing digit. It converts only
admitted strings of at most 20 significant digits to integers. It does not use
the Rust multiply-add/threshold recurrence or invoke the prior decoded model.

The 101,346 frozen cases include every two-byte string, all 256 single bytes
with count boundaries, values around UINT64_MAX, overflow/store-preservation
cases, exact/beyond-u64 concatenation lengths and seeded mixed strings.
32,231 cases use compressed nonempty zero prefixes; 889 have the new logical
length refusal. Of the admitted outcomes, 16,904 omit the output store and
42,255 retain nonzero high RAX bits. These are sampled observations backed by
the all-input proof, not whole-node coverage.

Installed rustc 1.94.1 (`e408947bfd200af42db322daf0fadfe7e26d3bd1`, LLVM 21.1.8)
builds the new library and input-only client at opt0 and opt3 twice each.
Edition 2021, warnings denied, overflow checks, `panic=abort`, one codegen unit
and zero debug info are explicit. The native process receives only compressed
input scalars, tail bytes and prior output values; expectations stay outside.
All four runs have **zero mismatches across 101,346 cases each**. Same-opt
library, executable and stdout hashes repeat exactly.

Fourteen separately compiled wrong sources all produce actual mismatches on
admitted parser outcomes, rather than only on the new length refusal:

| Wrong behavior | Mismatching cases |
| --- | ---: |
| Unsigned nonzero digit count | 5,948 |
| Any consumed digit implies true | 6,570 |
| Discard stopping-byte high bits | 42,255 |
| Sign-extend into full 64-bit RAX | 42,255 |
| Exclude digit 9 | 25,601 |
| Reject final digit 5 at limit | 120 |
| Accept final digit 6 at limit | 120 |
| Change output on overflow | 16,904 |
| Claim an output store on overflow | 16,904 |
| Consume the overflowing digit | 16,904 |
| Multiply by radix 9 | 21,841 |
| Ignore zero-prefix digit count | 6,015 |
| Truncate zero-prefix consumption | 8,517 |
| Use signed count for EOF status | 1,281 |

Mutation source changes, binary/output hashes and first mismatches are in
`observed/results.json`; concrete admitted-input witnesses are in
`selected-admitted-controls.json`. Twenty-nine downstream static corruption
controls reject body/count/gate/state/return/FDE/CIE/padding, ten caller edges,
and a naming relocation while skipping only the full-file SHA admission.
A deliberately corrupted expectation causes exactly one comparison mismatch.
No captured instruction or emulator is executed.

## Reproduction and retained records

```sh
python3 -B -O research/work-items/RE-004-node94-decimal-u64-parser-rust/validate.py \
  --output work/node94-decimal-u64-parser/recheck
python3 -B -O research/work-items/RE-004-node94-decimal-u64-parser-rust/verify_recorded.py
python3 -m unittest discover -s tests -p test_foundation_decimal_index_replace.py -v
/opt/homebrew/opt/rustup/bin/rustfmt +1.94.1 --edition 2021 --check \
  src/node94-decimal-u64-parser/lib.rs src/node94-decimal-u64-parser/input_only_driver.rs
PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH \
  make doctor verify catalogue-check reproduce
shasum -a 256 -c research/work-items/RE-004-node94-decimal-u64-parser-rust/MANIFEST.sha256
```

Observed host: macOS 27.0.1 arm64; Python 3.14.3, Capstone 5.0.7 and GNU objdump
2.47.20260726. Validators were run with Python `-O`; all evidence gates use
explicit exceptions. Focused legacy tests passed **21/21**, including their
existing parser/wrapper model tests, which do not establish the new long-count
or raw-RAX findings. Rustfmt, doctor, verify, catalogue-check and reproduce
passed. No new full repository sweep, hosted CI, Docker build or target-byte
match is claimed.

`raw-streams.json.gz` losslessly retains 126 stdout/stderr streams from 18 native
runs and compiler/disassembler commands. Labels, exact bytes and hashes are
retained together; commands/results remain readable. GNU disassembly views
remove trailing whitespace only; exact bytes remain in the archive. Whole-ELF
GNU frame stdout is explicitly excerpted to the selected CIEs/seven FDEs,
not claimed fully retained. The stored-record verifier checks streams, source
bindings, comparisons, readable exports and selected witnesses. Repository
logs redact only root/home paths and retain original/retained hashes. The
manifest binds all new files except itself.

`overlap-inventory.json.gz` retains the initial and final live PR/issue/recent
merge inventories and base source/evidence/catalogue searches. No overlap was
found. Root's separate modular cursor arithmetic and the reserved record/state
work are excluded. Existing imported evidence, pins, progress gates,
catalogues and byte-window accounting are unchanged.

New code/docs are independently authored under repository MIT. No unlicensed
inferred implementation was read or copied. Provider/client: OpenAI / Codex;
exact model identifier is not exposed in this session. This bounded value
projection does not establish a node build, original ABI, arbitrary aliases,
complete callers, or a completed component gate. Parent owns publication.
