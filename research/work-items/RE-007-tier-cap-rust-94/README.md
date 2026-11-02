# RE-007: node94 position tier cap in Rust

## Question and scope

Reconstruct the byte returned by `0x3333580..0x333366e`, which RE-004's
leverage-update packet explicitly leaves open. The new independently authored
`src/node94-margin-risk/src/tier_cap.rs` adds `position_leverage_cap` to the
existing dependency-free component. It accepts its existing validated
`MarginTable`, an unsigned raw price word and a signed size word. Decimal
price/size denominations are unresolved. No full leverage-update admission,
raw holder ownership, native Rust ABI, captured execution or gate advancement
is claimed.

- Component: margin-risk, RE-007; source integration base `014db965fcb0c16541bce7df8960a17c7ea224ab`
  (upstream main `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`).
- Target: Linux x86-64 node94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Coordinates: ELF virtual addresses; FDE ends are exclusive. No normalization.
- Credit: existing `RE-007-margin-path-94` establishes tier construction,
  selection/formulas and the owned component; `RE-004-update-leverage-path-94`
  establishes routing and surrounding action gates. Those claims are reused,
  not counted as new recovery. No inferred reference source was copied.

## Native contract and evidence

The complete native proof is preserved in [native/NATIVE.md](native/NATIVE.md),
frozen before the external numerical oracle and Rust addition. Full FDE/CIE,
LSDA, unwind-header pairs, body hashes and both disassembler exports are in
[native/NATIVE-FREEZE.json](native/NATIVE-FREEZE.json).

| Observation | Native sites |
|---|---|
| Holder root at `+0x18`, height at `+0x20`; null root returns **AL=50** before arithmetic | `0x3333587..3594`, `0x3333665` |
| Signed size magnitude, including `i64::MIN` → unsigned `2^63` | `0x3333594..359e` |
| Unsigned multiplication and independent wide-overflow / low-product tests | `0x33335a2..35bd` |
| Lower-unbounded tag 2; upper tag 0 when finite, otherwise tag 2; low product stored separately | `0x33335bf..35df` |
| Included upper equality, unbounded node end and selected normal traversal | `0x2fe1854..194a`, full helper `0x2fe1670..1c15` |
| Empty/equal endpoints return50; nonempty back edge−1, parent climb when edge0 | `0x33335e4..366b` |
| Actual caller uses GOT slot `0x5775998` → cap; caller explicitly zero-extends AL | `0x3709ef9`, `0x3709eff` |

For non-null valid ordered trees, let `A = abs(size)` as an unsigned magnitude,
and let unsigned multiplication produce `(high, low)`. The query is:

- finite, upper **included** `low`, when `high == 0 && low <= 0x7ffffffffffffffe`;
- upper unbounded otherwise.

The cap is the last range entry's byte at value offset `+0x18`, or 50 for an
empty selected range. Native default paths establish only AL, not all of RAX.
The range helper's selected lower tag 2 skips generic invalid-bound errors.
Its empty result initializes only the two node words; no uninitialized metadata
is read or reproduced by the owned API. The valid-tree premise includes stable
ordered keys, readable values, equal leaf depth and consistent parent/child
links. Other generic bound tags and malformed graphs are excluded.

The new cap and selected helper occupy **1,683 bytes /421 instructions**.
Credited lookup/constructor/caller context brings the retained native inventory
to5 FDEs /6,458 bytes /1,443 instructions; it does not enlarge the new semantic
claim. GNU objdump 2.44 and LLVM objdump 19.1.7 agree on every byte partition.
Four 4-entry jump tables, the unique RELATIVE relocation and 22 coordinate windows
are authenticated. Window mutations are **whole-target byte-identity controls**,
not independent semantic CFG execution. No instruction evaluator ran.

## Safe component boundary

`position_leverage_cap(Option<&MarginTable>, u64, i64) -> u8` is a chosen owned
API. `None` represents only the observed null-root branch. `Some` is the
existing constructor's nonempty 1..3 tier table: first lower bound 0, later lower
bounds at most 10^15 and decreasing leverage bytes at most 50. A singleton
zero-leverage tier is admitted and returns 0; this cap helper does no division.
The public function has no new malformed-table or native-error ABI.

Unsigned price is intentional. This helper's overflow switches to an unbounded
query; it is distinct from the checked signed-price position-margin API.
`0x2fe1670` also handles larger trees, and parent-separator extraction is closed
in the native proof. The separate 11-key height 1 endpoint examples are generic
conditional helper examples, **outside the typed Rust comparison denominator**.

This is conditional helper reconstruction. It does not establish that every
synthetic raw word pair reaches the runtime caller, nor resolve map selection,
account mode, prior action gates, lifetimes, concurrency or persistent mutation.
The caller may reject leverage before this helper; its default 50 does not imply
that the entire action admits 50.

## Frozen expectations and comparison

[pre-source/PRE-RUST-FREEZE.json](pre-source/PRE-RUST-FREEZE.json), SHA-256
`70b67fdbf4c71988a658c52a36b0d01962d14941369e601dda14bba41b5906f9`,
preceded the new Rust source. Its seven payloads contain 925 unique synthetic
conditional caller records: 185 null-root and 740 records across four valid
non-null table families. The oracle uses arbitrary-precision full products and
ordered set membership; the Rust uses unsigned magnitude and `overflowing_mul`.
Expected records are separate from [driver.rs](driver.rs), an input-only client.
The two canonical binary streams are text-packaged as `.bin.b64`; the verifier
strictly decodes them and checks their original pre-Rust SHA values. Packaging
does not change the frozen raw bytes or pre-Rust freeze.

The binary format is deliberately local: `TCP1`, u32 count; each record has u32
ID, u8 tier count, u64 price, i64 size and `(u64 lower,u8 cap)` tiers, all little
endian. Count 0 denotes this client's `None` marker. Output is `(u32 ID,u8 cap)`.
No wire/native ABI is inferred from that framing.

The frozen cases include asymmetric factorization, negative/zero/MIN sizes,
unsigned high prices, inclusive tier boundaries, the maximum constructor lower
bound, unsigned multiplication overflow and exact signed-range thresholds.
Curated [samples.json](pre-source/samples.json) is a review aid; the input and
expected streams preserve the entire corpus.

| Class | Actual result / denominator |
|---|---|
| Baseline direct Rust builds | opt0/opt3, repeated twice; each matches all 925 complete output records |
| Component Cargo tests | **44 passed** in debug and 44 in release; includes 3 new integration tests |
| Wrong cap implementations | **10/10** return normal wrong bytes on frozen witnesses; full 925-output wrong stream checked per variant |
| Client framing policy | 3 controls return exit 2 and no output; excluded from native semantics |
| New focused Python controls | 8 passed, including archive/source/output/mutant-manifest corruption |
| Existing margin static tests | 17 passed; separately credited baseline evidence |

The ten operative variants are listed with exact changed-case counts and first
witnesses in [wrong-cap-controls.json](pre-source/wrong-cap-controls.json).
The first-eligible variant changes both finite and unbounded extraction sites.
For example, a valid two-tier table `(0,25),(10^15,1)` with price `2^63`, size 2
returns 1. Ignoring the high multiplication word and using wrapped low 0 returns 25.

**Threshold-tag controls have a different denominator.** Product `i64::MAX−1`
uses numeric upper tag 0, while product `i64::MAX` uses tag 2 without wide overflow.
Both include every validated tier, so this alone cannot distinguish the final
cap on these valid tables. The six cases in
[query-construction.json](pre-source/query-construction.json) record intermediate
native bound construction. They are not compiled returned-cap mutants. Neither
these controls nor the generic endpoint examples are added to the 925-case count.

## Compiler and replay receipts

Official pinned Rust 1.94.1, host `x86_64-unknown-linux-gnu`, rustc commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, LLVM 21.1.8. Rustc binary SHA-256
`ef6d716e5d1c6c93def277c0afa037c21e7a74f7de3aed4ee0700646c3301b1d`.
Python 3.12.14. This is a real component with its unchanged Cargo.toml/lockfile;
there are no dependencies, installers or captured-code build hooks.

[compiled.json.gz.b64](compiled.json.gz.b64) is strict base64 of a single gzip
JSON archive. It retains the full fixed compiler/input snapshot, report and all
actual stdout/stderr channels. Executable hashes are receipts only. The report
contains 50 commands / 100 channels. No bit-identical native or whole-build claim
is made; no raw/normalized compiled Rust-to-native instruction window was measured.

- SOURCE-FREEZE: `05810b584396600904ebc2b5469ffad72e207f7c73de4b8e1c289cfce730702b`.
- REPORT: `08cecadbfcf82942a84c0bcbef586df3b8def1424ba3be46e9ab050703f52ff9`.
- Decoded archive payload: `c5293552c42dfaad4add694e572e3211d8daf499213cdd5fdd7ec25dd815a43a`.
- Archive text: `e3787205fdd0a1d84ac3a846d15d662101d22b4af4e998e7b81f558f058dc765`.

All 33 snapshot files are pinned. This includes the entire 21-file component,
three packet scripts, eight pre-source files and the exact external compiler-read
fixture `RE-007-margin-path-94/boundaries.tsv`. Live inputs, snapshot inputs and
the full active mutant component are guarded before/after every command.

The durable receipt is a guarded conservative component snapshot. A local
reviewer separately inspected the standalone preparation's Cargo dep-info
files; this is a local observation, not a durable membership claim for the
combined tree. Those dep-info texts are not retained in the archive,
so this is not a durable exact compiler-read membership claim. Each mutant tree
is derived from that fixed component; replay checks its complete manifest and
its actual wrong output against the frozen relation.

Two failed preparations are preserved locally: the first snapshot omitted the
existing external `include_str!` fixture; a later comparison rejected a mutant
that changed only finite extraction although its frozen wrong relation also
changed unbounded extraction. The fresh final build includes the fixture and
corrects that mutation; baseline Rust and pre-source expectations are unchanged.
No existing component test or frozen expectation was weakened. The final
guarded build covers the combined hash, selector and cap component. The
standalone v3 receipt remains historical in its original isolated worktree.
The old manifests check current support-file integrity, as documented in
`RE-007-row-selector-rust-94/SNAPSHOT-HISTORY.md`. The selector's immutable
compiled `lib.rs` is `10b761d9a015691a490e053de28a9f0fc1c62750f25e183adb2e64776118b8ff`;
the hash's immutable compiled `lib.rs` is `dc99cce4ad5fd01b7e19ce1509198f28fe4a13332cc87e65298eaa51849224ae`.
The current public lib-export integrity line is now
`ed8ec35b55cd5d4576b7d6935c0bf731aa86b8d3304369da2605746fef8f05b4` in both manifests.
Their original compiled source snapshots, expected data and output archives
remain byte-identical; these current integrity pins do not refresh old builds.

From the repository root, with authenticated pinned inputs materialized:

```sh
python3 -B research/work-items/RE-007-tier-cap-rust-94/native.py
python3 -B research/work-items/RE-007-tier-cap-rust-94/verify.py
python3 -B -m unittest discover -s tests -p test_tier_cap_rust.py -v
python3 -B -m unittest discover -s tests -p test_margin_path_static.py -v
(cd research/work-items/RE-007-tier-cap-rust-94 && sha256sum -c MANIFEST.sha256)
```

The default verifier replays the immutable historical compiler/input snapshot.
It checks current bound inputs except the evolving shared lib-export file and
replay auditor, and separately requires the tier-cap export. It does not compile.
`--current-component` optionally demands the original exact component tree; that
historical check is expected to fail after adding another independent module.
See [SNAPSHOT-HISTORY.md](SNAPSHOT-HISTORY.md). A fresh optional build uses a nonexistent ignored
output path and the separately installed official compiler, without downloads:

```sh
python3 -B research/work-items/RE-007-tier-cap-rust-94/verify.py \
  --build work/tier-cap/rebuild \
  --rust-bin /workspace/.tools/rust-1.94.1-x86_64-unknown-linux-gnu/bin
```

[validation.json](validation.json) records exact repository/focused commands,
exits and complete-stream hashes. Full streams remain in ignored local work.
The coordinator runs the repository-wide suite; this packet does not claim it
or a hosted CI result. No progress/catalogue gate was changed. Next question:
close an additional caller admission or requirement dependency without treating
this cap helper as complete leverage-update reconstruction.
