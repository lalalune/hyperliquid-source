# staking: recover the node #115 snapshot member queries (address to key, key to address) with the ring key search

This packet makes it possible to write the two member queries that sit next to the validator-membership lookup `0x36c8430` from bytes: given an epoch word, `0x36ca5b0` returns the 32-byte key of the last entry whose 20-byte address equals the signer, `0x36ca940` returns the 20-byte address stored under an exact 32-byte key and drops a `0x98` status record on the way out, both match the epoch exactly, and both answer through a 0x22-byte output record whose status word is `0x1a2` (hit), `0x2b` (address not a member), `0x98` (key absent) or `0x9b` (no snapshot of that epoch, with a zero word stored at `+8`). The ring form of the per-epoch store is searched by a new real body, `0x4559a60`, a binary search over 0x68-byte elements keyed by 32 bytes through memcmp.

- Component ID: staking (Staking and validator lifecycle); first task: validator snapshot store queries. The packet requests no gate.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository `0781ce04826eeefd89fe336cb8ea073be0c1de30` / the reference is not used for any claim here.
- Claim status: observation for everything under Evidence (ELF bytes, run by the interpreter of this tool); lines marked inference are not proved; unresolved items are under limitations.
- Scope included (real bytes): the address-to-key query `0x36ca5b0` (907 bytes), the key-to-address query `0x36ca940` (582 bytes), the ring key search `0x4559a60` (455 bytes), and the callees they reach: the ring epoch search `0x4551810`, the B-tree iterator step `0x37c5530` and the status drop `0x36dae30`. Replaced by checked stubs: the memcmp GOT slot `0x64dfb50` (returns the signed byte difference, the callers use only the sign), the sized free `0x64df4a0` and the panic slots `0x64df620`, `0x64df4c0`, `0x64df830`.
- Excluded and why: the callers of the two queries, the writers of the store, and the meaning of the 32-byte key. `0x36c8430` (membership), `0x4551810`, `0x37c5530` and `0x36dae30` are the subject of the packet `staking-validator-snapshot-lookup-115`; they are re-run here only as callees. The nearby bodies `0x36c7b30` and `0x36c7f70` appear in the RE-001 observation packets and are not claimed. No #94 address is used.

## Reproduce

From the repository root, with Python 3 and the standard library only (no external program is started, the binary is never executed, the tool reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py` and checks the input SHA-256 first):

```
python3 tools/staking_snapshot_members115.py --out research/work-items/staking-snapshot-members-115
python3 -m unittest tests.test_staking_snapshot_members115
```

Generated files: `evidence.json`, `measure.json`, `path.tsv`, `function-rows.tsv`, `constants.tsv`, `layouts.tsv`, `scenarios.tsv`, `mutations.tsv`, `controls.tsv`. `MANIFEST.sha256` covers them and this README. The tool runs in about 75 seconds and 660 MB; two regenerations into different folders are byte equal.

## Evidence

All addresses are virtual addresses of the ELF; function bounds come from the FDEs; slot targets come from `.rela.dyn` RELATIVE rows. `function-rows.tsv` holds the 687 reached instructions of the six real bodies with their bytes, `constants.tsv` every reached immediate, `path.tsv` the body size and the reached part of each function, `layouts.tsv` the field offsets used by the fixture.

### Address to key `0x36ca5b0` (rdi = output record, rsi = store, rdx = pointer to the 20-byte address, rcx = epoch word)

1. The epoch is a register argument here (the membership lookup reads it from `[store+0x58]`). The store is searched for an equal epoch: first word `0x8000000000000000` selects the B-tree (u64 keys at node `+0x218`, edges `+0x278`, length u16 `+0x272`, 0x30-byte values), any other value is the capacity of the ring of 0x38-byte elements searched by `0x4551810`.
2. No equal epoch, or a ring index at or past the length: store `0x9b` at `[out]` and zero at `[out+8]`, return the output pointer. No drop is called.
3. The 0x30-byte snapshot value is either a B-tree (`[+0] == 0x8000000000000000`: root, height, length, walked in order by `0x37c5530`) or a ring (capacity, buffer, head, length) of 0x68-byte elements walked as two slices.
4. Every element's address is compared as 16 bytes plus a dword (ring element `+0x40`, tree value `+0x20`). A match stores the 32 bytes at the element (ring `+0`, tree key) in a stack slot and the walk **continues**: the last match in key order wins, so an address that appears under two keys answers with the larger key.
5. At the end a stored match writes `0x1a2` at `[out]` and the 32 bytes at `[out+2]`; no match writes `0x2b` alone. Bytes of the record beyond these fields are never written (checked on every run).

### Key to address `0x36ca940` (rdi = output record, rsi = store, rdx = pointer to the 32-byte key, rcx = epoch word)

1. The epoch search is the same as above; a miss writes `0x9b` and a zero qword at `[out+8]`.
2. B-tree snapshot value: a descent over 32-byte keys (node `+0`, stride 0x20, up to 11 keys, values at `+0x168` stride 0x48, length u16 `+0x482`, edges `+0x488`) with memcmp of the 32-byte key against each node key: greater continues, equal is a hit, smaller descends through the edge of the index; an exhausted height is a miss.
3. Ring snapshot value: `0x4559a60(value, key)` returns al = 0 and the logical index on a hit, al = 1 on a miss; an index at or past the length is also a miss. The physical slot is `index + head` minus the capacity when that reaches it; the element is 0x68 bytes.
4. A hit calls the status drop with a `0x98` record on the stack (returns at once for that word) and stores `0x1a2` at `[out]` and the 20 bytes at element `+0x40` (tree value `+0x20`) at `[out+2]`. A miss stores only `0x98` at `[out]` and calls no drop.

### Ring key search `0x4559a60` (rdi = ring, rsi = pointer to the 32-byte key)

A branch-light binary search over the two slices of a ring of 0x68-byte elements, memcmp of 32 bytes per probe. It returns al = 0 and the logical index on a hit, al = 1 and the insertion index (the number of smaller keys) on a miss. The keys must be ascending; a descending ring is outside the claim (a range control).

## Implementation and comparison

`tools/staking_snapshot_members115.py` is the implementation: a concrete x86-64 interpreter that decodes only forms present in these bytes and raises on anything else (the interpreter and the fixture builders for rings and B-trees are those of `staking-validator-snapshot-lookup-115`), plus a rule list (`spec_by_address`, `spec_by_key`, `spec_key_search`) written from the reading above, not from interpreter output. Each case builds a store with a deterministic builder (rings with any head and spare capacity, B-trees of any height, snapshot values of either form, equal keys under different epochs, duplicate addresses), runs the real bytes, and compares the status word, the payload, the full 0x40-byte output buffer, the ordered drop record and the unchanged store with the rule list. Reference comparison: not performed.

## Results and limitations

- 17,865 cases, 0 mismatches on the first full run: address to key 4368 (status `0x1a2` 827, `0x2b` 952, `0x9b` 2589), key to address 4368 (`0x1a2` 523, `0x98` 1250, `0x9b` 2595), 6000 form-pair runs (3000 random worlds, each run as built and in the other store forms: ring and tree outside, vec and tree inside, which must give the same answer), 1617 exhaustive ring key searches (rings of 1 to 7 elements, 0 to 2 spare slots, every head, every key around and inside the ring), 1500 random ring key searches (8 to 100 elements) and 12 forced tree-height cases. Probes: first, middle, last, duplicate address, other epoch, absent, gaps below, inside and above the keys, single-bit changes in the first, middle, 16th and last byte of key and address, epochs above and below 2^40 and an epoch that equals a snapshot epoch plus 2^32.
- 233 negative controls, 233 detected (`measure.json`): 13 moved layout fields of the fixture, 24 deliberately wrong rule lists (22 for the two queries, 2 for the key search) (nearest-lower epoch, 32-bit epoch, first match instead of last, 16-byte address compares, skipped last entry, key prefix or suffix compares, nearest-lower key, a drop on a miss or none on a hit, key returned for address and conversely, insertion after an equal key, and others), 186 single-byte edits of the real code (condition flips and immediates) and 10 out-of-range inputs (wrong digest, addresses inside a function or outside every FDE or section, an arena that is too small, a step limit of 20, a rule list asked about another signer or key, a descending ring).
- Byte edits: 209 possible, 186 killed, 23 survived (`0x36ca5b0` 3: `0x36ca771`, `0x36ca78c`, `0x36ca855`; `0x4559a60` 8: `0x4559a99`, `0x4559acb`, `0x4559afb`, `0x4559b0c`, `0x4559b33`, `0x4559b9d`, `0x4559bc3`, `0x4559c0a`; `0x4551810` 5; `0x37c5530` 2; `0x36dae30` 5). They are listed in `mutations.tsv`; none of the 23 is classified in this packet (the picked cases do not separate them from a redundant or sign-equivalent edit, or the edited instruction is not on a path that changes the result).
- Fixture limits: the stores come from this tool's builder, not from a captured node; the walk reads only the fields listed in `layouts.tsv`, the other bytes of the 0x68, 0x48 and 0x38 byte records are filler. The memcmp stub returns the byte difference where the real routine may return another value of the same sign.
- Meaning: the 20-byte value is a signer address and the 32-byte value an identifier of the entry (inference from the shape); the status word `0x1a2` is only known as the hit word of these two bodies. The writers, the callers and the epoch source are not read here.

Next question: the callers of `0x36ca5b0` and `0x36ca940` (what asks for the key of an address, and for the address of a key) and the writer that fills the 32-byte key.
