# RE-001-node115-lu-timeout-handler: bounded question

- Component ID: `base/src/lu.rs` conversion context, timeout handler
  `0x5bb3ca0` (hash-bucket re-claim for unlink).
- Target release and full SHA-256: node #115, 105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit:
  `8fd8db680ec4bfef40996e5616bce3d5156d0b86` (upstream main,
  node-115-only migration).
- Claim status: observation for the claim loop, the return contract,
  the panic paths, and the caller census; inference for the
  "re-claim for unlink" framing (grounded in all three call sites'
  post-call walk/unlink/release shape); unresolved for the
  table-creation argument semantics and the family FDE's role.
- Scope included and excluded: included is the `0x5bb3ca0` body only
  (417 bytes, eh_frame FDE `0x5bb3ca0..0x5bb3e41`). Excluded are the
  lookup, park, cleanup, contention-helper, table-creation, and
  timed-wait bodies (prior claims or context, cited by address only)
  and the callers' unlink walks (prior claims).

## Reproduce

Working directory: a checkout of upstream main at the base commit
above. The node binary is `artifacts/node/115/hl-node`; it is never
executed. Commands (all static):

- `sha256sum artifacts/node/115/hl-node` → the target digest above.
- `objdump -d -M intel --start-address=0x5bb3ca0
  --stop-address=0x5bb3e41 artifacts/node/115/hl-node` →
  `handler.objdump.txt` (107 instruction lines, 1 nop padding).
- Handler bytes: file offset VA − 0x1000 for `.text` →
  `handler.hex` (417 bytes, SHA-256
  `861103e78cc356cb3a41a673b24a1dd995c0dc3f4cd7669c434d9c55985b547d`).
- `readelf --debug-dump=frames-interp` → FDE
  `pc=0x5bb3ca0..0x5bb3e41`, CIE `0x00000000`.
- `readelf -r` → GOT resolutions and panic `Location` relocations
  (see Evidence).
- `python3 tools/node115_lu_timeout_handler.py` → exit 0.
- `python3 -m unittest tests.test_node115_lu_timeout_handler` → 7/7.

No declared execution or side effects; no network, no node run.

## Evidence

Coordinates are ELF virtual addresses (PIE). `.text` file offset =
VA − 0x1000, `.data.rel.ro`/`.got` file offset = VA − 0x2000,
`.rodata` file offset = VA.

Validated boundaries: FDE `0x5bb3ca0..0x5bb3e41` (eh_frame),
single `ret` at `0x5bb3e23`, body proper 388 bytes, panic stubs 29
bytes (`0x5bb3e24..0x5bb3e41`), `int3` padding to the next function
at `0x5bb3e50` (begins `push rbp`). Instruction count 107
including 1 nop padding (`cs nop` at `0x5bb3ce6`).

Raw disassembly: `handler.objdump.txt`. Callers/callees: direct
`E8` callers of the handler over all of `.text` are exactly 3
(`0x5bb1f09`, `0x5bb264d`, `0x5bb2df2`); no relocation addend in
the binary equals `0x5bb3ca0`, so there are 0 GOT-indirect callers.
Callees inside the handler: contention helper via `r12` (GOT
`0x64ec160`) at `0x5bb3d8a`, cleanup via `r10` (GOT `0x64ec150`)
at `0x5bb3dc1`, table creation via `r9` (GOT `0x64ec158`) at
`0x5bb3de1`, and three GOT-indirect panic helpers (subtract
`0x1681e40`, shift `0x1681e20`, bounds-check `0x1680cbf`).

GOT resolutions (`R_X86_64_RELATIVE` addends, authoritative because
the file fields read 0 before relocation): `0x64ec148` →
`0x64fff28` (table variable), `0x64ec150` → `0x5bb66b0`
(cleanup), `0x64ec158` → `0x5bb6400` (table creation),
`0x64ec160` → `0x5bb6790` (contention helper).

Panic `Location` structs (`.data.rel.ro`, pointer fields relocated):
all three name `/home/ubuntu/hl/code_Mainnet/z_vendor/parking_lot_core/src/parking_lot.rs`
(73 bytes, `.rodata` VA `0x44f892`); lines/columns 352:45
(subtract), 352:5 (shift), 390:23 (bounds). Message prefixes
(`.rodata`): `0x46eb5c` → `attempt to shift right with overflow`,
`0x46eb80` → `attempt to subtract with overflow`, `0x4400ef` →
` index out of bounds: the len is {} but the index is {}`. The
string table packs the overflow messages adjacently with no
separators, and the two arithmetic wrappers pass `&str` lengths
(73, 67) spanning past the individual message texts; the checks are
identified by message prefix plus `Location`, not by the full span.

ABI/layout observations: table fields `[table]` base (qword),
`[table+0x8]` bucket count (qword), `[table+0x18]` bucket-bits
(dword); entry stride 64 (`shl 6`); claim value 1; release
`lock xadd -1` with cleanup exactly when old `>= 4` and bit 1
clear; hash `key * 0x9e3779b97f4a7c15 >> (64 - bits)`.

No-node-write check: the only memory writes in the body are stack
spills (`[rsp+0x8]`, `[rsp+0x10]`), the bucket-entry `lock cmpxchg`
at `0x5bb3d5c`, and the bucket-entry `lock xadd` at `0x5bb3cf7`
(verified by the tool, which rejects any other store target).

Analysis was complete over the FDE range; the callers' unlink
walks were read only far enough to establish the return contract
(bucket in `rdx`, key in `rax`).

## Implementation and comparison

No Rust implementation is claimed; this is a static evidence
packet, not yet implemented/measured as code. Comparison: the
handler vs #188's lookup — shared table layout, hash, claim,
helper, table creation, and release-and-retry shape; distinct in
argument count (one key vs two hashed arguments), return contract
(`(key, entry)` vs entry only), and the node-key stability recheck
(handler only). Helper/data/relocation closure: GOT resolutions
above; no data-table or whole-ELF gaps beyond the stated context
items.

## Results and limitations

Machine-readable metrics: see `records.json`. What passed: the
verifier (all sites, census, panic locations, no-node-write
check), 7 unit tests including 4 corruption controls, `make
doctor` (`analysis_ready` true), `make verify`, `make
catalogue-check`, and the full `make test` suite except the single
pre-existing `test_node115_catalogue` cross-device-link failure
(Errno 18, `/tmp` tmpfs vs workspace disk, identical on a pristine
checkout). What remains unknown: table-creation argument semantics,
the family FDE's role, and (since #188) the wake-site `rdx` setup.
No gate is requested, so no gate-scope claim is made. Next
question: the vtable dispatch site that would settle the wake-site
`rdx` question (still open since #188), or the family FDE
`0x5bb1a60` end to end, whose timeout path already shares this
handler.
