# RE-004: two field-derived stores with full register/image effects

Target: node94, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Source base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
Only `src/node94-field-walk-pair` and this packet are added. This is bounded
RE-004/foundation reconstruction; imported pins, progress and full-scope
acceptance gates remain unchanged.

## Complete relation

The first complete entry, `[0x514ab20,0x514ab4a)`, follows the qword at
RDI+0x788 and its field +0x30 to Q, subtracts the qwords Q+0xb20 minus Q+0xb18
modulo64, arithmetic-shifts the signed result by four and stores eight bytes
through RSI. Full RAX is 1 and RDX retains Q. The second complete entry,
`[0x514ab50,0x514ab64)`, reads exactly four bytes at incoming RDX+0x1438,
sign-extends to 64 bits and stores eight bytes through RSI. It returns full
RAX=1 while preserving RDX; RDI is never read by this member.

The grouped safe `no_std` component covers all 62 bytes/14 instructions.
The predecessor `foundation-field-walk-shift-94` established only the first
leaf and left the adjacent second leaf unclaimed. No source type, original
component census or inferred library implementation is asserted or copied.
[PROOF.md](PROOF.md) derives the full-u64 wrapping/signed-shift equation,
full-u32 sign extension, all-read-before-store relation and complete RAX/RDX.

The new numeric-image API admits arbitrary partial/exact data aliases under
stable ordinary-memory and normal-control premises. Every field addition
wraps before its width-specific range check. All required reads and the full
destination are checked before any write; new safe refusals leave every byte
unchanged. The library has no 128-byte cap: that size is only the synthetic
client record format. Numeric addresses never become Rust pointers. Faults,
MMIO, races, code/control aliases, flags, machine ABI, original compiled-byte
identity and whole-node behavior are outside the projection.

## Full static closure

Both complete actual bodies, unique FDE/CIE records, neighboring FDE extents
and separate 12/6/12 bytes of INT3 padding are bound. GNU, Apple LLVM and
Capstone agree on all instruction boundaries and bytes without normalization.
Each entry has a single final RET, no branch/helper and no RIP-relative data.
All 80,300 RELA records are scanned: no record names either entry and no
partial write overlaps the protected bodies/padding. Full .text E8/E9 scans
find no direct candidates. This is not a complete indirect-reference census
or a claim about source ownership/reachability. All 36 structural corruption
controls reject independently of the initial full-target hash check.

## Frozen expectations and retained corrections

The original 46,654 images and expectations were frozen before Rust existed:
32,607 ShiftedDifference and 9,963 SignedField cases are admitted, with 4,084
new API refusals. The oracle reads an immutable numeric-address dictionary,
uses a centered residue and exact floor division for the shifted difference,
and weights a signed top byte for the four-byte field. Rust instead uses
checked slice reads, casts/shifts and a final little-endian copy. The oracle
never imports Rust and neither side executes/emulates captured instructions.

Coverage includes value bits and signed/wrapping boundaries, all 16 residues,
signed32 endpoints, every byte offset of the chain destination, overlapping
read/store fields, high/wrapped addresses and exact read/store limits. The
input-only client receives member, image and address metadata; it receives
neither expected outputs nor target instructions. Every output byte is
compared, including unchanged inactive image bytes.

Two qualification corrections are retained, not replaced by a clean-only
history. Initial control preflight compiled 22 variants, then stopped because
a return-expression mutation anchor also matched a unit assertion. A native
attempt stopped at the same selector guard before any native execution.
Only two mutation anchors changed; `initial-selector.json.gz` retains the
validator, sources, streams and exact retry diagnostic.

The first actual native matrix then exposed a surviving `ignore_image_overflow`
control. The two original whole-image-overflow cases also lost selected fields
through wrapping, so later read-span refusals masked deletion of the global
check. `initial-native/` preserves all 101 commands/202 streams, the exact
validator and failure result. No correct-source mismatch occurred.

Two separately labeled **post-freeze** admission inputs now describe 128 bytes
at base 2^64-64, with every reached read/output wholly below 2^64. These isolate
the overflowing image description. Their expected refusals come from the
unchanged pre-Rust algebraic oracle. `post-freeze-admission.json` binds the
primary freeze, unchanged source/oracle and exact supplementary input/output
bytes. The original oracle and frozen streams remain unchanged; these two
cases are never claimed to predate Rust.

## Completed native qualification

The final fresh matrix passes all 46,656 cases per opt0/opt3 build and repeat:
186,624 exact output records, including 170,280 admitted value/image results
and 16,344 safe refusals. This comprises the original 46,654 pre-Rust cases
plus the two explicit post-freeze admission cases, per build. The combined
stream hashes and separate provenance appear in `native-result.json`.

All 30 wrong implementations were actually compiled and run at both levels:
60 effective controls. Forty-two runs have admitted-value/image witnesses;
18 detect admission errors. These cover incorrect fields/address wrapping,
subtraction order/width/overflow, logical versus arithmetic shifts, truncating
division, signed-field width/extension/byte order, unused-object reads, RAX/RDX,
store width/order, premature aliased writes and image/span boundaries. The
previously surviving global-overflow control now detects exactly the two
supplemental cases at each level. Three unit tests per profile, malformed
input and changed/missing-output controls also pass. Same-option repeated
library/client artifacts are byte-identical in four comparisons, without
normalization. No additional failure occurred in this final matrix.

All 206 final commands and 412 original stdout/stderr streams are retained in
`native-commands.json` and `native-streams.json.gz`. The separate checks add
18 streams; the failed matrix retains its 202 streams. Archives use
content-addressed base64 payloads, gzip level1 and mtime0. All stream hashes,
command references, original freeze, supplemental inputs, source bindings,
30 preflight control sources and retained failure archives were verified;
`archive-audit.json` records the result. `mutant-preflight.json.gz` contains
the final 30 successful metadata compilations and exact generated sources.
The manifest binds all evidence and source while excluding itself and caches.
Only newly authored Rust executed natively; captured code/emulation and
original compiled-byte identity remain unclaimed.

## Reproduction and repository checks

```sh
python3 -O -B research/work-items/RE-004-field-walk-pair-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-field-walk-pair-rust-94/verify_rust.py \
  --rustc /Users/shinjun/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin/rustc \
  --out work/field-walk-pair-replay
```

Use a fresh output directory. The exact compiler is rustc 1.94.1, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, executable SHA-256
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`.
The recipe pins aarch64-apple-darwin, edition2021, denied warnings, one codegen
unit, overflow checks, opt0/opt3 and `/usr/bin/cc`. No dependency installation
or invented workspace/lockfile is needed. Python3.14.3, Capstone5.0.7,
GNU2.47.20260726 and AppleLLVM17.0.0 supplied validation tools.

Doctor, verify, catalogue-check, reproduce, the legacy foundation packet
check, all 15 focused predecessor/FDE/GNU-tool tests and rustfmt passed.
Exact commands and all 18 raw streams are retained in checks records.
The separate shared baseline at the stated source base attempted 971 files /
15,462 reported tests / 69 skips. Original exit2 was solely three Errno28
disk-full errors; the 20 affected tests passed isolated retries. This is not
a successful full-sweep rerun, a suite on this head, skipped Linux qualification
or hosted CI success.

Fresh pre-implementation checks covered 175 open PRs, zero open issues,
100 recent merged PRs and current tracked source without an address/topic
match; `overlap.json` records hashes, scope and reservations. Attribution:
OpenAI / Codex client; exact model identifier unavailable.
