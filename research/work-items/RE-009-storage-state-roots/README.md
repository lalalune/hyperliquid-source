# RE-009 — Storage and ABCI-state ownership (node #94)

Target: `artifacts/node/94/hl-node`, sha256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

Produced by `tools/state_roots.py` and `tools/state_hashers.py` (stdlib only,
deterministic). Every address is a virtual address. Function bounds come from
`.eh_frame_hdr` FDEs (end exclusive). The ownership decoder ties a function to
a source file only when a RIP-relative `lea` inside the function points at a
first-party panic `Location` record. A record is an `R_X86_64_RELATIVE` slot in
`.data.rel.ro` holding a `/home/ubuntu/hl/code_Mainnet/<file>.rs` pointer,
followed by len, line and col. Literal ownership works the same way: a `lea`
points at the literal or at the start of its Rust format template, which is
the byte after the preceding NUL.

Depends on RE-005 (PR #10, `re-005-bincode-varint`) only in prose. The branch
is not based on it and imports nothing from it. The RE-005 encoder FDE starts
are listed as constants so that this packet can prove they do **not** feed
the hashers.

## Files

| File | What |
|---|---|
| `state-roots.json` | Locations, functions, literals, `/dev/null` compares, reconstruction address statuses |
| `fixture-schema.json` | Snapshot fixture schema (`re009-snapshot-fixture/v1`) |
| `hashers.json` | Hasher inventory, constants, call graph, chains from scoped/`lt_hashes` sources, RE-005 encoder check |
| `objdump-excerpts.txt` | Narrow windows for the `/dev/null` compares and every literal `lea` site |
| `hashers-objdump-excerpts.txt` | Narrow windows for the blake3 call chains |
| `verify.py` | Manifest, regenerated hashes, pinned facts for both JSON files |
| `MANIFEST.sha256` | sha256 of the packet files |

## Findings (measured)

1. **Scoped Locations: 57.** Out of 1186 first-party Location records in the
   binary, 57 come from `db/src/*` or `l1/src/abci/state.rs`:
   - `l1/src/abci/state.rs`: 28;
   - `db/src/db_home.rs`: 13;
   - `db/src/db_hub.rs`: 7;
   - `db/src/owned_db_home.rs`: 3;
   - `db/src/block_reader.rs`: 2;
   - `db/src/dh.rs`: 2;
   - `db/src/rocks_db.rs`: 2.

   46 functions reference them. The FDE count is 121299.
2. **Reconstruction addresses.** The reconstruction gives 20 `.text`
   addresses:
   - All 17 in `l1/abci/state.rs` are FDE starts whose function references
     its own `state.rs` Location.
   - The 3 in `db/block_reader.rs` (0x27b6540, 0x27bbe50, 0x27c1710) are FDE
     starts, but none references a `block_reader.rs` Location. The functions
     that do are 0x27abee0 (line 45) and 0x27ae600 (line 27).
3. **Unseeded `state.rs` functions.** Three `state.rs` functions are not in
   the reconstruction. They carry the same line sets as seeded ones:
   - 0x28127a0 (line 145), like 0x46cea60 and 0x46cfe90;
   - 0x2811e40 (line 154), like 0x46cf030;
   - 0x28122a0 (lines 188/190), like 0x46cf490 and 0x46cf990.
4. **Snapshot artifact names and their owners.**
   - `/CHECKPOINT_COMPLETE`: db_home.rs line 23 functions 0x28d1650, 0x332e0a0
     and 0x459a7f0. A second template (`/CHECKPOINT_COMPLETE_…`, anchor
     0x1f2f3e) is used by 0x15867a0, which has no first-party Location.
   - `/lt_hashes.json`: three functions:
     - 0x332d440 (db_home.rs lines 301–332);
     - 0x32699c0 (`l1/src/evm/hash.rs` line 69);
     - 0x3269ae0 (`l1/src/evm/evm_db.rs` line 154).

     Reading and writing the LtHash file therefore spans db_home and the EVM
     hash/db modules.
   - `@@ linked abci state @@` log template: `state.rs` lines 196/203
     functions 0x2208e60, 0x446da60 and 0x446e050.
   - Debug dumps ending `.rmp`. None of them sits in a `db/*` or `state.rs`
     function:
     - `/tmp/abci_state_bad_app_hash.rmp`: `l1/src/abci/engine.rs` +
       `exchange.rs` functions 0x2209d40, 0x42e4600 and 0x42e5d40;
     - `/tmp/abci_state_with_l1_hash_mismatch.rmp`: node gossip/evm_kvs
       functions 0x22615b0, 0x4356c90 and 0x4b29760, plus 0x473c930, which
       has no first-party Location;
     - `/tmp/abci_checkpoint.rmp` and `/tmp/abci_checkpoint_evm_db`: 0x4b2fda0,
       which has no first-party Location.
   - `periodic_abci_states`: referenced only by a RELATIVE relocation slot. No
     code `lea` points at it.
5. **`/dev/null` guard.** Two `state.rs` line-145 functions compare a 9-byte
   path to `/dev/null` inline: 0x46cea60 at 0x46ceaef and 0x46cfe90 at
   0x46cff1f. The sequence is `cmp r12,9` → `movabs rax,"/dev/nul"` → xor
   with `[r15]` → 9th byte `xor rcx,0x6c` → `je`. This is the "/dev/null
   skip" that the reconstruction describes for the exchange dump wrappers
   (0x46CEA60/0x46CFE90). The unseeded line-145 twin 0x28127a0 contains no
   such `movabs` immediate.

## Hashing ownership (PROVEN for LtHash write path)

`tools/state_hashers.py` replaces the earlier exploration-script negative.

### Hasher inventory (30 functions, 0 with a first-party Location)

A function is a hasher if it has a crate panic Location in
`blake3-*` / `tiny-keccak-*` / `sha2-*` / `ripemd-*`, or if its `.text` bytes
contain a pinned IV / K / RC constant, or if it `lea`s the Keccak-f round
constant table. Counts: blake3 Location 13, sha2 Location 6, tiny-keccak
Location 2, ripemd Location 1, blake3/sha IV-constant-only 3, sha2 K-constant
-only 3, keccak RC-table `lea` 1, keccak RC immediate 1. **None of the 30
also holds a first-party Location.**

Call graph (byte-scanned): 495523 rel32 `e8`/`e9` edges that land on an FDE
start, 345767 RIP-slot `ff 15`/`ff 25` edges whose slot is a RELATIVE
relocation targeting an FDE start, and 21027 over-approximate vtable edges
(every FDE-start pointer in a run of RELATIVE slots that a function `lea`s in
`.data.rel.ro`).

### Direct blake3 call from `lt_hashes.json` writer

`0x3269ae0` (`l1/src/evm/evm_db.rs` line 154) references `/lt_hashes.json` and
directly calls blake3 through a relocated slot:

| site | kind | slot | relocation addend | target |
|---|---|---|---|---|
| 0x3269d96 | `ff 15` slot | 0x57700c8 | 0x14f93e0 | blake3-1.7.0 `lib.rs` FDE `0x14f93e0..0x14fa004` |
| 0x3269fb1 | same | same | same | same |
| 0x326a1bd | same | same | same | same |

`readelf -rW` confirms `0x57700c8 → 0x14f93e0`. The same slot is also used by
`l1/src/utils.rs` function 0x37e5620 (site 0x37e572b). Of 108 first-party
functions that call a hasher directly, these two are the only ones that call
blake3; the other 106 call tiny-keccak.

### Indirect blake3 path from a scoped `state.rs` function

Among the 46 scoped db/state functions, a breadth-first search over
rel32+slot edges reaches blake3 in 2 hops:

```
0x2208e60 (state.rs:196/203, also refs "@@ linked abci state @@")
  --slot 0x57739f8 @ 0x220925c--> 0x394b410 (no Location)
  --slot 0x57700c8 @ 0x394b4de--> 0x14f93e0 (blake3-1.7.0)
```

Including the vtable over-approximation does not change the hit or the chain.

### Paths that do NOT reach a hasher

| source | edge kinds | reached | max depth | result |
|---|---|---|---|---|
| 0x332d440 (`db_home.rs`, refs `/lt_hashes.json`) | rel32+slot | 680 | 14 | exhausted, no hasher |
| 0x332d440 | +vtable | 783 | 14 | exhausted, no hasher |
| 0x32699c0 (`evm/hash.rs:69`, refs `/lt_hashes.json`) | rel32+slot | 676 | 14 | exhausted, no hasher |
| 0x32699c0 | +vtable | 778 | 14 | exhausted, no hasher |

So the LtHash *file* is referenced from three functions, but only the
`evm_db.rs` writer is proven to call blake3. The db_home reader and the
`evm/hash.rs` referencer do not reach any hasher under this call model.

### Hash constants are never inlined into first-party code

Every blake3 IV word, sha256/sha512 K word and keccak RC immediate that
appears as a little-endian constant in `.text` sits inside a hasher FDE that
has no first-party Location. The Keccak-f RC table at 0x7d04c8 is referenced
only by 0x4f59480.

### RE-005 bincode encoders do not feed the hashers

The 7 RE-005 (PR #10) integer-encoder FDE starts
(0x27ab0a0, 0x27ab280, 0x27ab300, 0x27ab5b0, 0x4aa9ae0, 0x4aa9f80, 0x4aaa230)
reach 506–510 functions each and never a hasher. Their 90 direct callers and
the 290 hasher direct callers are disjoint. None of the three
`/lt_hashes.json` referencers reaches any of those encoders. So encoded
varint output is **not** shown to be the blake3 input on this path.

## Fixture schema (summary)

`fixture-schema.json` lists 8 named artifacts. For each it gives the role, the
functions that reference it, and the first-party files those functions own:

- `CHECKPOINT_COMPLETE` marker → db_home.rs;
- `lt_hashes.json` → db_home.rs + evm/hash.rs + evm/evm_db.rs;
- linked ABCI state log → state.rs;
- four `/tmp/abci_*` dump paths;
- `periodic_abci_states`.

It also lists the two `/dev/null` guard functions. It is a fixture *shape*:
names, owners and evidence. It contains no file contents or encodings.

## Rerun

```
cd "$(git rev-parse --show-toplevel)" && \
  P=research/work-items/RE-009-storage-state-roots && \
  python3 -B tools/state_roots.py --out $P/state-roots.json --schema-out $P/fixture-schema.json && \
  python3 -B tools/state_hashers.py --out $P/hashers.json && \
  python3 -I -B $P/verify.py && python3 -O -B $P/verify.py && \
  python3 -B -m unittest tests.test_state_roots tests.test_state_hashers
```

## What this does not claim

- The semantic role of blake3 inside 0x3269ae0 (what bytes are hashed, whether
  the digest is written to `lt_hashes.json`, field order). Only the call edge
  is pinned.
- That 0x332d440 or 0x32699c0 ever hash. Their call closures of 680–783
  functions contain no hasher under rel32, relocated-slot, or vtable-run
  edges. Closures, dyn-trait calls through non-RELATIVE slots, and computed
  targets are outside the model.
- The algorithm behind any other digest (app hash, contracts_hash,
  storage_hash, ConciseLtHashes). sha2 and tiny-keccak are present and are
  called from other first-party code, but not from the scoped db/state set
  or the three `lt_hashes.json` referencers (except blake3 as above).
- That RE-005 encoding is unused by hashing in general — only that the seven
  pinned encoder FDEs do not reach a hasher and share no callers with one.
- The byte format of any snapshot file. That covers whether `lt_hashes.json`
  is JSON or a MessagePack state file, field order, versioning, and the
  reconstruction's `.rmp`-vs-JSON branch. No `rmp`/`json` immediates exist in
  the scoped functions, and the `.rmp` template `\xc0\x01/\xc0\x01/\xc0\x04.rmp`
  is used only by 0x37eac50, which has no first-party Location.
- What happens after the `/dev/null` compare succeeds. Only the compare and
  its `je` target are shown.
- That the `/tmp/*.rmp` paths are written in production. They are referenced
  addresses only.
- What the reconstruction's seed functions do semantically, or its
  constants (0x810, 0x3ae8, 0x1fb8 and the db_hub masks). Only FDE starts and
  Location ownership are checked.
- Any snapshot compatibility *between versions*. Only node #94 was examined.
