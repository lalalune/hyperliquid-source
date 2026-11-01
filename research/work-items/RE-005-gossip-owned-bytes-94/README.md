# Node94 owned-byte and UTF-8 state gap

The gossip helper at `0x466dc10` leaves a concrete gap after the established
u64 length wrapper: payload charging uses the full mode QWORD, shortage must
preserve the available payload, and invalid UTF-8 consumes and releases the
copied payload before reporting the first invalid sequence. This packet closes
that bounded normal-return relation with independently authored Rust.

| New native body | Extent | Bytes | Instruction rows |
| --- | --- | ---: | ---: |
| Primary helper | `0x466dc10..0x466dcf4` | 228 | 68 |
| Specialized byte collection | `0x4589a30..0x4589b2b` | 251 | 78 |
| Complete byte validator | `0x157a200..0x157a3f7` | 503 | 143 |
| Total | | 982 | 289 |

Target SHA-256 is
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The separate 559-byte/169-row u64 wrapper/Reader/error context is already
credited work. PR #1365's generic wrapper/caller scope excludes the primary
helper; its source is neither copied nor changed. The real accepted local
`hl-bincode-varint` dependency supplies the fast/Reader decoder unchanged.

`NORMAL-DOMAIN.md` fixes ordinary valid allocation, exact disjoint memcpy and
returning release premises. The original 7,906-byte allocator, TLS-sensitive
release/tail, allocation-error/unwind paths, original types/ABI, addresses,
inactive None payload and padding remain outside this projection. The native
landing pad is retained in the complete primary listing but has no unwinding
equivalence claim. Existing static captured helper excerpts do not close those
transitive gaps. No full-component gate advances.

The independent `independent/FREEZE.json` seal predates the new Rust and binds
116,179 distinct validator inputs and 45,320 distinct wire inputs. All 65,536
two-byte inputs have distributed alignments; selected ASCII/scalar-offset
families cover all eight residues. This is not a two-byte-by-eight Cartesian
claim. The validator authority was independently cross-checked with Python's
strict Unicode decoder. Wire outputs include exact active fields, counter
store traces including equal-value stores, consumption and the full unread
suffix. The separate post-seal inactive-payload clarification leaves the
original seal and all expected records unchanged. Private holdout answers are
not present in this packet or supplied to the source author.
The four complete corpora use lossless RFC1950 zlib transport to keep evidence
compact; `COMPRESSED-CORPORA.json` records packed and original hashes. The
runner compares decompressed bytes with the original unchanged pre-source seal.

`collect.py` authenticates the complete target, exact FDE/CIE extents, readable
executable mappings, all 80,300 actual RELA entries and selected call/data slots.
It rejects writes overlapping code/table/selected GOT intervals, including
cross-start writes. `test_static.py` uses altered copies only, never execution.
`run.py` builds this source and real dependency with the admitted compiler,
checks exact input-only output and normal assertion controls, performs one
additional optimized library rebuild, and retains every command and raw stream.
It guards the complete tracked physical tree, seven genuine pins, 103 provider
payloads, two installer manifests and resolved compiler/linker/tools before and
after. These narrowly scoped tools qualify this native gap; they are not a
general framework or independent recovery credit.

Current status: source/runner review pending, no compiler or tests run. The
expanded current suite, new instruction evaluators, captured program execution
and hosted CI are NOT_RUN. Planned invocation from the task checkout:

```sh
python3 -B research/work-items/RE-005-gossip-owned-bytes-94/run.py --out work/gossip-owned-bytes-982-run1
```

New independently written code/docs are under the repository MIT license.
Captured byte/listing excerpts retain the captured artifact's rights; new
source does not assert upstream source identity or relicense those excerpts.
No external inferred implementation has been copied.
