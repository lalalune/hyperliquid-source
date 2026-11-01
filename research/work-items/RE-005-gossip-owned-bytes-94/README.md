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

The first actual compiler experiment passed on clean source checkpoint
`b8cc0ec0547753707eaa55572513627526452d5c` at task-start main
`56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. O0 and O3 each matched all
116,179 validator and 45,320 wire rows byte for byte. Seven ordinary relational
tests passed per direct profile and per actual offline locked Cargo
debug/release invocation. One additional optimized library rebuild was raw equal.

| Normally compiled wrong source | Validator mismatches | Wire mismatches |
| --- | ---: | ---: |
| Payload charge uses low DWORD | — | 14,804 |
| Header charge uses full QWORD | — | 6,506 |
| Omit equal-value counter stores | — | 368 |
| Roll back invalid payload cursor | — | 21,408 |
| Accept surrogate encodings | 240 | 112 |
| Incomplete sequence reports Some(1) | 8,435 | 4,748 |
| All bad continuations report Some(1) | 22,080 | 7,168 |
| Payload shortage consumes available bytes | — | 7,571 |

Every listed stream contains its complete protocol denominator; each wrong
library also failed ordinary assertions with normal exit 101. Thirteen static
test methods cover the positive case and 14 altered-copy rejections (the
three-body method has three subcases). Seven comparator controls per protocol
check changed fields, missing/extra rows, whitespace, duplicate keys, boolean
substitution and order. The original 10,880 physical tracked files, seven pins,
103 provider payloads, two installer manifests, source checkpoint and resolved
host tools were identical before/after.

`ACTUAL-STREAMS.zip` losslessly retains 173 files / 180,028,460 original bytes:
all 68 recorded outer command pairs, seven nested binutils command pairs, native
bodies/records, actual input audits and the eight wrong sources. Its manifest
verifies complete byte-for-byte roundtrips. The 43 compiled artifacts were
independently hash-checked; binaries, full target ELF and provider payloads are
excluded from public retention. Their identities remain in the actual result
and transport manifest. Original ignored raw work is preserved.

The independent peer rechecked all streams, artifacts and fresh physical/tool
identities. Its separate presealed private replay passed 67 rows (64 novel
complete inputs plus three duplicates) per protocol on both existing clients;
changed neighboring answers did not affect output. Only its public-safe summary
is retained, with no private inputs or answers. Repository static checks are
pending on the preserved evidence checkpoint; no extra Rust rebuild is needed.

The expanded current suite, new instruction evaluators, captured program
execution and hosted CI are NOT_RUN. Exact scoped invocation:

```sh
python3 -B research/work-items/RE-005-gossip-owned-bytes-94/run.py --out work/gossip-owned-bytes-982-run1
```

New independently written code/docs are under the repository MIT license.
Captured byte/listing excerpts retain the captured artifact's rights; new
source does not assert upstream source identity or relicense those excerpts.
No external inferred implementation has been copied.
