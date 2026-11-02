# RE-007: returned funding records to keyed sample storage, node 94

The prior premium and funding-distribution packets leave the connection between
the sample producer and the host's keyed append path open. This packet recovers
that connection for the **returned record stream**, including missing keys and
the complete selected insertion paths.

At the host's record-loop exit, ordinary even-tag records append their unchanged
64 payload bits to the selected key's sample vector, creating an empty vector
for a missing key. Odd-tag records insert or replace a temporary fallback-map
value only when the selected dex byte `+0x230` is exactly 3. Full tag 2 terminates
the loop before either update. The selected producer emits only tags 0 and 1:
its two-word premium result selects either result word0 or the original oracle
word. No numeric conversion occurs in this handoff.

The proof includes leaf insertion, all full-node split positions, internal child
links, cascading splits, root growth, and the returned value handle used by the
append. It requires finite valid B-trees/vectors, normal admitted paths, explicit
allocator prefix-preservation and copy/frame contracts, and capacity below the
`2^63` niche. The scheduler remains an explicit boundary: global completeness,
all-asset processing and global input order are not established. The central
theorem ends at `0x222b480`; later opaque host calls require a separate frame
premise. Temporary-map lifetime and actual deallocation are not proved.

## Review order

1. [PROOF.md](PROOF.md): active contract, prerequisites, full insertion induction,
   exact call/slot boundaries and exceptional limits.
2. [native/records.json](native/records.json): 19 complete FDE/CIE records,
   separately retained LSDA call-site metadata and native transcript identities.
3. [native/cfg.tsv](native/cfg.tsv), [native/transfers.tsv](native/transfers.tsv)
   and [native/rip-references.tsv](native/rip-references.tsv): complete structural
   census, with conditional normal-return edges rather than reachability claims.
4. [spec.json](spec.json): selected byte/operand/literal/relocation obligations;
   [verify.py](verify.py): below-digest corruption controls and independent
   PT_LOAD mapping; [consequences.py](consequences.py): mathematical list/stream
   consequences, without captured execution or an instruction interpreter.
5. [VALIDATION.md](VALIDATION.md), [validation.json](validation.json) and
   [intake.json](intake.json): observed checks and related-work exclusions.

## Native scope

Target `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
91,774,280 bytes. Research base:
`56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.

| Role | Complete FDE range |
| --- | --- |
| Selected host | 222af40..222baa1 |
| Leaf producer | 251c420..251c673 |
| Returned-list flattening | 251bc70..251bf22 |
| Outer/recursive bridges | 255d7d0..255d900; 228f410..228f62e |
| Scheduler selector (boundary) | 2428260..24282d3 |
| Asset-ID construction / leaf packaging | 24c2180..24c22b8; 24c2520..24c2615 |
| Credited metadata clone | 254e820..254e99a |
| Sample/fallback adapters | 287a610..287a76c; 2851610..285178b |
| Complete sample/fallback insertion | 1a7cc90..1a7d9cc; 1a89610..1a89ff6 |
| Sample/record growth | 32d5780..32d57e4; 454e460..454e4c4 |
| Three lower allocation wrappers | 32d6740..32d682a; 454f420..454f50a; 251aec0..251afaa |
| Flat reserve | 251b070..251b0ef |

These 13,772 bytes contain 3,208 normalized instruction rows and 717 structural
basic blocks. Full native GNU text is readable; the second provider is stored
as deterministic gzip with both raw and compressed SHA-256 recorded. For example:

```sh
gzip -dc research/work-items/RE-007-funding-sample-storage-94/native/sample_insert.llvm.txt.gz
```

The local `.gitattributes` keeps these small compressed evidence files as real
Git bytes, rather than LFS pointers.

## Reproduction

From the repository root, with the exact pinned ELF materialized:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-007-funding-sample-storage-94/verify.py
python3 research/work-items/RE-007-funding-sample-storage-94/consequences.py
```

The full verifier uses the recorded GNU objdump 2.47.20260726 and Apple LLVM
21.0.0; `--gnu PATH --llvm PATH` overrides executable paths. Exact regenerated
transcript equality requires matching native-tool output versions. Both native
tools read the same private authenticated read-only snapshot, which is hashed
before and after collection. Regeneration runs with distinct hash seeds and
timezones, once under Python `-O`, and compares every retained native byte/file.
The existing repository ELF/FDE parsers are the only project imports. Neither
another unmerged contribution nor a captured target evaluator is required.

To produce a fresh collection separately, choose a nonexistent output directory:

```sh
python3 research/work-items/RE-007-funding-sample-storage-94/collect.py --out /tmp/funding-sample-static
```

The mathematical checks are consequences of the manual conditional proof. They
are not native execution comparisons or independent evidence for an opaque
helper's behavior. No source implementation, component gate, matched-byte
coverage increment, hosted-CI result, full-suite claim or economic safety claim
is made.

## Prior work

Credit [#860](https://github.com/lalalune/hyperliquid-source/pull/860),
[#899](https://github.com/lalalune/hyperliquid-source/pull/899),
[#116](https://github.com/lalalune/hyperliquid-source/pull/116),
[#1165](https://github.com/lalalune/hyperliquid-source/pull/1165), the existing
liquidate-path metadata clone, and separately proposed impact walk
[#1422](https://github.com/lalalune/hyperliquid-source/pull/1422).
Related generic insertion slices in
[#1438](https://github.com/lalalune/hyperliquid-source/pull/1438) and
[#1457](https://github.com/lalalune/hyperliquid-source/pull/1457) concern a
different body; shared compiler/source lineage is not independent corroboration.
The exact selected storage relation and full insertion closure above are the
contribution. No prior claims or bytes are counted again as new progress.
