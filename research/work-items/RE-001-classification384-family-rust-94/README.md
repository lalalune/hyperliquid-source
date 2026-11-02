# RE-001: complete node94 six-word classification pair

This packet reconstructs a bounded arithmetic protocol in independent safe
`no_std` Rust. One body combines original parity with a full-width doubled-value
comparison; the other selects those two bits independently from low/high blocks
according to whether each block is zero. Both retain their full auxiliary
register observations. These bodies were not implemented on the base revision;
no component gate or whole-node claim changes.

## Target and complete closure

- Node94 `artifacts/node/94/hl-node`, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base/source revision: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
  Reference gitlink `999556f6e0a474b8312db96ec3149e1c44e97c23` is unchanged.
- RE-001 bounded numeric reconstruction; coordinates are linked ELF VAs.
- Source: [node94-classification384-family](../../../src/node94-classification384-family/README.md).
  `lib.rs` SHA-256:
  `8c9300d1360ad7ac67d3dfcebb9072d8e067808815aee81aed8d2ffbb8cf4693`.

| Complete body | Linked ELF interval | Bytes | Instructions |
| --- | --- | ---: | ---: |
| Single | `[0x56573a0,0x5657402)` | 98 | 28 |
| Pair | `[0x5657420,0x5657531)` | 273 | 79 |
| Total | Two complete FDEs | 371 | 107 |

[Static records](static/records.json) bind the whole target, exact raw FDE/CIE
records, all bytes and the matching GNU/LLVM instruction partitions. The complete
121,299-FDE / 3-CIE inventory gives one unique exact FDE per body and shared CIE
`0xce1518`. The 30/15-byte following alignment regions and next FDE `0x5657540`
are separately bound; that next SIMD-selection function is outside this scope.

The full .text E8/E9 scans find zero candidates targeting any byte of either
selected interval. All 80,300 RELA records contain no naming addend within those
intervals and no overlapping code writer. Thus there are no direct caller
contexts for this packet. Both bodies contain no calls or out-of-body branches,
RIP-relative constant/table/import reads or unknown helpers. Data consists of
supplied operand spans and Pair's private saved-register/scratch control stack.
This closes the selected computation, not complete indirect reachability or
runtime frequency. No inference is drawn from objdump's synthetic symbol label.

[Scope selection](scope-selection.json) records full-body hashes and exact .text
occurrences for the scouted candidates. These two full bodies each occur once.
The implemented u128 division and correction-add/doubling variants were excluded.
This exact-byte check is not an exhaustive semantic-equivalence census.

## Relation and domain

[PROOF.md](PROOF.md) derives every selected register for all unsigned 384-bit
operands, with no reduced-value, nonzero or odd-correction premise. Single's tag
is `parity(A)+2*[2A>=C]`, using the full 385-bit doubling. The six raw difference
words remain `(2A-C) mod 2^384` regardless of the comparison. RDI retains original
parity. Pair's parity comes from low unless low is zero; its comparison comes
from high unless high is zero. RDI retains the high tag, R8 the full low-word OR
union, and R9/R10/R11/RCX/RDX the five upper low-difference limbs. Both blocks
zero with C=0 returns tag 2. No library or cryptographic identity is asserted.

Eight final GP observations are returned exactly, with no normalization. RSI is
unchanged. Pair restores incoming RBX/RBP; those and other unchanged entry values
are explicitly outside the selected tuple. No guessed restored values or extra
claimed difference registers are returned. Native flags, control-stack/ABI,
CET, timing and fault ordering are not represented.

The pure value APIs cover the entire arithmetic domain. Checked read-only image
adapters require all input48/input96 and correction48 bytes even when a block is
zero. Stable ordinary little-endian data may alias at any byte offset; the image
is nonwrapping and may end exactly at 2^64. Pair's repeated correction reads are
represented by one stable snapshot because the target writes only its disjoint
private control stack. Native saved-register/scratch/return storage must be valid
and separate from supplied data. Faults, MMIO, volatile effects, concurrency and
arbitrary wrapped pointer layouts are excluded. Invalid slice spans return None,
an additional safe API policy; immutable slices cannot be changed.

## Frozen expectations and qualification

The independent [oracle](oracle.py) uses `A>=ceil(C/2)` for the comparison,
whole-integer modulo arithmetic for differences, quotient/remainder for words,
and bit-column existence for the OR union. Pair chooses first/last nonzero
whole values directly. It does not import Rust, mirror the limb borrow chain,
or interpret target instructions.

The final [freeze](fixtures/freeze.json) predates all Rust source:
`2026-11-01T23:20:07.090601+00:00`. Its 13,457 cases comprise 7,550 pure Single,
3,830 pure Pair, 1,038 Single images and 1,039 Pair images. Across each build,
13,212 are admitted values and 245 are safe refusals. Coverage includes every
384-bit power position, odd/even threshold neighbors, equality, all doubling
carry/borrow cases, zero-block combinations, full-width raw limbs/unions,
955 overlapping and 877 disjoint image cases, exact-end admission, wrapping
images and mandatory-span failures. No post-Rust supplement was added.

- Raw inputs SHA-256:
  `d7ae0b74e169aadc593638842a9724a074544b088fcf970ab7948c60a226dc58`.
- Raw expected outputs SHA-256:
  `1d71e12c199d243e4e2b792d61d925615b04c8f2d556c7de9a098347a1719883`.
- Oracle SHA-256:
  `4b5913f930fb71752ffaaea5d95111f343e61c7bbb39870a6317a546d9346d8e`.

Before any Rust, an unreachable generated conditional expression in one fixture
constructor was removed. [Both pre-Rust records](pre-rust-oracle-cleanup/) and the
original oracle text are retained. Raw/compressed input and expectation hashes
are identical across that cleanup; only oracle text/hash and freeze time changed.

Rust 1.94.1 on macOS arm64 produced four input-only correct builds: opt0 and
opt3, each repeated. All 13,457 × 4 = 53,828 full-register/status outputs match
exactly (52,848 admitted observations and 980 refusals). Same-option library and
client hashes repeat identically. All 37 compiled mutant programs exit normally
and differ, including doubling carries, borrow propagation, equality, comparison
bit, parity, each raw output position, zero selection, OR union, endianness,
swapped blocks, exact image bounds and skipped zero-input correction reads.
All 119 structural corruptions reject: every selected instruction, both FDEs,
CIE, both gaps, extra E8/E9/RELA references, overlapping unrelated FDE, adjacent
FDE and whole-target SHA. Five comparator controls and two archive controls also
reject. All 41 native stdout streams are retained without normalization.

[Final commands](native/commands.json), [result](native/result.json) and
[log](native/qualification.log) retain the actual outcomes. The input-only native
client receives no expectations. Exact stdout is stored in
[native/raw-streams.json.gz](native/raw-streams.json.gz), a deterministic lossless
shared-line archive retaining each stream's original label, order, newline bytes,
byte count and SHA-256. Storage deduplication is not comparison normalization.
The checker reconstructs and hashes every original stream.

[An initial static-control failure](initial-static-control-failure/) is retained:
the relocation corruption still named old out-of-scope address `0x5656981`, so it
correctly did not overlap this packet's code. Qualification stopped before any
native compilation or output. Only that control's destination was corrected to
`0x56573a1`, followed by a fresh complete replay. The target verifier, Rust source,
oracle and fixtures were unchanged. [Mutation preflight](mutant-preflight.json)
records all 37 metadata builds; it is separate from actual native mutation runs.

## Reproduction and repository checks

From the repository root with pinned inputs materialized:

```sh
python3 -O research/work-items/RE-001-classification384-family-rust-94/verify.py --out work/classification384-family-replay
python3 -O research/work-items/RE-001-classification384-family-rust-94/verify.py --check-archive
cargo +1.94.1 check --locked --offline --manifest-path src/node94-classification384-family/Cargo.toml --all-targets
cargo +1.94.1 fmt --manifest-path src/node94-classification384-family/Cargo.toml -- --check
```

[Check commands](checks/commands.json) and raw logs record 22 focused ELF/FDE
parser tests, Cargo, rustfmt, doctor, verify, catalogue-check and reproduce, all
passing. GNU binutils and rustup were placed on PATH for global checks.
[Tool versions](checks/tool-versions.json) retain actual versions and pin state.
The library has no third-party dependencies or node integration.

The separate shared base sweep covered 971 files / 15,462 reported tests / 69 skips.
Its original aggregate exit 2 came only from three disk-full errors; all 20
affected tests passed isolated retries. This is not a clean aggregate rerun or
full-suite qualification on this head. No captured code, instruction emulator,
Linux target differential, container, hosted CI, whole-node equivalence or
completion gate is claimed. New source and evidence are the only changes.

[Overlap records](overlap/summary.json) retain initial 204 and final 208 open PRs,
zero open issues and 100 recent merges at each check, plus the empty main-source
address search. No matching claim was found; active worker reservations were
excluded. Imported evidence, pins and progress are untouched.

New implementation and documentation are independently authored under MIT by
신준. Captured artifacts retain their existing rights and provenance. No
unlicensed inferred implementation was read or copied. Provider OpenAI; client
Codex; exact model identifier unavailable and not invented. Independent replay
of this bounded packet remains the review step; broader node gates stay open.
