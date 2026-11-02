# RE-007: selected custom-table leverage-increase decision

## Bounded question and source

Project the caller's custom-table, active-position, matching-table,
nondecreasing-leverage gate into the genuine existing margin-risk component.
`check_custom_leverage_increase` uses one resolved `MarginTable` for both the
first-tier maximum and `position_leverage_cap`. **EnterCommit is not action
success**: it denotes the branch to native `0x3709cfa`, before mutation helpers.

- Target: node94 Linux x86-64, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source integration base: draft #1460 head
  `709baa5d2b5d568984bae21646b9c677bf154ad1`; all changed compiler inputs are frozen.
- Caller FDE: `[0x37098a0,0x370a3c1)`, 2,849 bytes / 600 instructions.
  Coordinates are ELF virtual addresses. No normalization or captured execution.
- Credit `RE-004-update-leverage-path-94` for the original caller gate and row
  update observations. Credit #1460's static lookup and independently authored
  hash/selector/tier-cap work. This adds the selected caller decision composition,
  not new ownership or coverage of those established helpers. No inferred
  unlicensed reference implementation was copied.

## Native coupling, widths and decision order

The complete static proof and pre-Rust native freeze are in
[pre-source/NATIVE.md](pre-source/NATIVE.md) and
[pre-source/NATIVE-FREEZE.json](pre-source/NATIVE-FREEZE.json). The complete caller
GNU/LLVM exports are reused from the credited tier-cap packet; both cover the
same 600 native instruction byte partitions. The freeze binds full FDE/CIE/LSDA,
unwind-header/body identities, 131 syntactic CFG blocks, 33 calls and 15 coordinate
windows. Calls have ordinary-return edges; no exception or generic helper
behavior is invented. Coordinate checks authenticate byte identity, not executed
semantic CFG proof.

| Fact | Native evidence |
|---|---|
| Metadata table id is u32; unsigned id at least 50 selects the custom registry | `0x370997d..998a` |
| Custom registry root/height at D+0x38/+0x40; equality yields a 56-byte record in R15 | `0x3709a47..9ad6` |
| That same R15 supplies the first-tier maximum and the cap argument | `0x3709ae8..9b88`, `0x3709ef6` |
| Requested leverage is a full u32 | `0x37098b1`, `0x3709b8c`, `0x3709f02` |
| Position mode is compared as DWORD==0, including nonzero words such as 256 | `0x3709cad..9cba` |
| Cap receives signed size from position+0x10 and raw unsigned price from D+0x68 +96×local+0x20 | `0x3709ca3`, `0x3709ebb..9ef9` |
| Cap AL is zero-extended to u32; requested<=cap includes equality | `0x3709eff..9f06` |
| Cap rejection initializes only u16 tag 0x50 and u32 cap at status+4 | `0x3709f11`, `0x3709f16` |
| Matching table and requested>=old u32 leverage jump to the commit entry | `0x370a083..a090` → `0x3709cfa` |

The selected decision order is:

1. Canonical cross requested with unsupported kind byte: tag `0x44`.
2. Requested level above the same table's **first-tier** maximum: tag `0x43`.
3. `(mode_word == 0) != cross`: tag `0x45`.
4. Requested level above the actual position-size cap: tag `0x50`, cap detail u32.
5. Otherwise EnterCommit.

For the first three refusals, other status fields are not established. For cap
refusal, padding at +2/+3 and other bytes remain unknown. Rust uses enum variants
and never fabricates a full native status-memory layout.

Both unresolved `0x37d77e0` calls are bypassed on the selected path: the table
change call at `0x370a249`, and decrease call at `0x370a27a`. The path reaches
`0x3709cfa`; it does not establish the results of account resolution, set insert,
position mutation, accounting/index helpers, cleanup or final tag 0x186.

## Qualified API and remaining premises

The source is independently authored in
`src/node94-margin-risk/src/leverage_increase.rs`, SHA-256
`290b69719806166525afcdb2eb815266091aa04dd6a423120f1e8a5902e57baf`.
The typed table retains its existing constructor invariants. The caller must
supply the actual custom registry entry associated with the metadata id and
resolved existing position. Prior asset/price indices must be valid; relevant
storage and ordinary helper returns must remain stable and nonaliasing.

Four checked errors are **chosen safe-API domain policy**: builtin id below 50,
different position table, inactive position, or requested decrease. They are
not native rejection tags. External registry/lookup provenance, builtin builder,
other table shapes, decrease/table-change margin checks, native ownership/ABI,
concurrency and post-commit effects remain open. No economic denomination or
whole-action/runtime safety claim is made. Existing hash/selector whole-lookup
admitted vectors remain zero.

## Pre-Rust expectations and observed comparison

[pre-source/PRE-RUST-FREEZE.json](pre-source/PRE-RUST-FREEZE.json), SHA-256
`437595b12eb512837c97fd70bd46025e41008250e07f191758bbe5519051dadc`,
preceded the new Rust. Its eight payload pins include separate logical input and
expected files, an independent integer/set cap oracle and ordered decision list.

| Qualified result | Cases |
|---|---:|
| EnterCommit | 175 |
| Refuse `0x43` | 212 |
| Refuse `0x44` | 39 |
| Refuse `0x45` | 27 |
| Refuse `0x50` with cap | 34 |
| **Total qualified** |**487**|

Four API-domain records are separate. Each of four direct Rust builds
(opt0/opt3 repeated twice) matches the complete 5,892-byte output stream of
487 qualified plus 4 policy records. [driver.rs](driver.rs) receives no expected
answer, injected maximum or cap. Its framing and absent-detail placeholders are
chosen local serialization, not native ABI or memory initialization.

Nine operative source controls match full frozen wrong streams. **Seven** change
commit versus refusal; **two** distinguish refusal tag/detail only. Counts and
concrete witnesses are in
[pre-source/planned-controls.json](pre-source/planned-controls.json). Three
malformed-client framing cases exit2 with no output, separately classified.

The historical combined component at #1460 head `1e78e5ac` passes **48 Cargo tests per profile**, including
four new literal API boundary tests. Ten new Python controls authenticate native
bytes, input/output and source/mutant manifests, policy separation and compiler
project dependencies. Historical tier-cap replay has ten tests, including two
new boundary controls preserving its original source snapshot.

## Compiler/source closure and durable receipts

Official Rust 1.94.1 (commit `e408947bfd200af42db322daf0fadfe7e26d3bd1`,
LLVM 21.1.8), Python 3.12.14. Rustc SHA-256
`ef6d716e5d1c6c93def277c0afa037c21e7a74f7de3aed4ee0700646c3301b1d`.
Cargo.toml/lock and existing Rust API implementations are unchanged. There is
no root Cargo workspace, new dependency, installer or target execution.

[compiled.json.gz.b64](compiled.json.gz.b64) losslessly retains all fixed
source/input files and outputs of all 47 commands / 94 channels. It is strict base64
of one gzip JSON payload. Full source/mutant trees and inputs were guarded before
and after every command. A 160 MB projected build reserve above a 300 MB floor was
checked before build, with the floor checked throughout; final free space was
1,002,459,136 bytes. No build failure was observed.

- SOURCE-FREEZE: `6ebf1ff1533964a06e9ea870b6495e572148e276de9432073fd82138118a3b6b`.
- REPORT: `06902e6689571919e0934ad46cec1f822ee03bab310cf6d304e471f773a027ad`.
- Decoded archive: `11596125fd8213e3d296bfaff0b7b836c9cb5e34ccb51e011b4fc1d8b9bb0056`.
- Archive text: `b3dfc2e86878361ba59f2131ff132ea8ad365c9a5ec019bef0dd4bf8327499ae`.

The conservative 35-file snapshot contains the entire 23-file component, the
external compiler-read `RE-007-margin-path-94/boundaries.tsv`, input-only driver,
guarded runner and 9 pre-source files. [COMPILER-READS.json](COMPILER-READS.json)
retains 18 actual Cargo dep-info outputs and hashes: exactly 21 distinct project
compiler inputs, all within those 35 pins. This is project source closure; compiler executables are separately pinned; exhaustive sysroot and system
library inputs are outside this project-source closure and remain unproved. No raw or normalized Rust-to-native machine-code comparison was measured.

The default verifier replays the immutable snapshot and bound current files,
with current shared lib exports and the evolving auditor treated as support
files. `--current-component` additionally demands that original 23-file tree.
It intentionally rejects the later isolated-decrease extension; see
[SNAPSHOT-HISTORY.md](SNAPSHOT-HISTORY.md). Original compiled sources and outputs
remain unchanged, and current increase implementation bytes remain bound.
No full build-byte determinism, hosted CI or repository-wide suite claim is made.

## Historical receipts and reproduce

Adding the export demonstrated an actual historical tier-cap test failure on
current lib.rs. Its exact failure is recorded in validation; the minimal repair
is documented in `RE-007-tier-cap-rust-94/SNAPSHOT-HISTORY.md`. Its 33-file original
source archive, expected values, ten wrong-cap streams and REPORT 08cecadb remain
byte-identical. The original compiled lib hash remains ed8ec35b; selector/hash
archives retain their original 10b761d9/dc99cce4 versions. Current manifest export
lines are support-file integrity pins, not refreshed historical compiler inputs.
All old Rust API implementation files are unchanged.

From repository root with authenticated pinned local inputs:

```sh
python3 -B research/work-items/RE-007-custom-leverage-increase-rust-94/native.py
python3 -B research/work-items/RE-007-custom-leverage-increase-rust-94/verify.py --current-component
python3 -B -m unittest discover -s tests -p test_custom_leverage_increase_rust94.py -v
python3 -B -m unittest discover -s tests -p test_tier_cap_rust.py -v
(cd research/work-items/RE-007-custom-leverage-increase-rust-94 && sha256sum -c MANIFEST.sha256)
```

A fresh optional build uses `verify.py --build work/leverage-admission/rebuild`
with the separately installed official compiler. It downloads nothing and refuses
an existing output path. [validation.json](validation.json) preserves exact
required/focused commands, exits and full-stream hashes. Complete local streams
remain ignored. No gate/progress record was changed. Next gaps are actual table
and row admission, the excluded margin-check branches and post-commit semantics.
