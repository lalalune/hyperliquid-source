# staking: recover the node #115 validator-membership request builder (membership bit, 0x78-byte request layout, optional pair rule, expect failure) in three copies

This packet makes it possible to write, from bytes, the function that turns "is this signer in the validator snapshot" into the request handed to the next stage: it asks the validator snapshot lookup `0x36c8430` (slot `0x64e4e38`) about the 20-byte signer, derives one flag byte (set only for a non-member whose address is not all zero), picks a (word, word) pair either from the caller's optional value or, when that value's tag byte is 2, from two engine-state words (`[state+0x88]` only when `[state+0x80]` is 1, else 0), refuses with the expect-style failure `l1/src/dex_registry/clearinghouses.rs:11:29` when the engine-state cell `[state+0x7d0]` is zero, and otherwise hands a 0x78-byte request (layout in Evidence) to the sink slot `0x64e7d08`, returning the sink's result. The three bodies `0x2c54de0`, `0x55c7640` and `0x55c78a0` run as real bytes in an interpreter inside the tool, together with the real lookup chain, and agree with a separately written rule list on 15,552 constructed cases with 0 mismatches; 95 of 95 negative controls are detected.

- Component ID: staking (Staking and validator lifecycle), reached through the signer membership test of `staking-validator-snapshot-lookup-115` and the follow-up `staking-validator-reference-115` (same slot, other caller family). The packet requests no gate.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository `0781ce04826eeefd89fe336cb8ea073be0c1de30` / the reference is not used for any claim here.
- Claim status: observation for everything under Evidence (ELF bytes, run by the interpreter of this tool). Lines marked inference are not proved. Unresolved items are under limitations.
- Scope included (real bytes): the three bodies of 602 bytes each (one FDE each, 134 instructions each), the lookup chain `0x36c8430` / ring search `0x4551810` / B-tree step `0x37c5530` / status drop `0x36dae30`, and the record drops `0x2c94f00` (base), `0x5630000` (both copies) and `0x44e0810`. Hooks (recording only): the sink slot `0x64e7d08`, the expect-failure slot `0x64df6a0`, the free slot `0x64df4a0`.
- Excluded and why: the sink `0x3c48b40` (1,746 bytes, ~20 callees, vtable calls; it is the next stage and is called only from these three bodies, see `callers.tsv`), the six callers of the bodies (`0x2c51f20`, `0x2c5cce0`, `0x55c19f0`, `0x55c1f80`, `0x55d6390`, `0x55d6720`, each with allocation and vtable paths), the snapshot store writers, and the meaning of the request fields. The component of the expect-failure Location is dex-registry (`clearinghouses.rs`); the packet is filed under staking only because of the membership test it calls (disclosed, as in the reference-authorization packet). No #94 address is used.

## Reproduce

From the repository root, with Python 3 and the standard library only (no external program is started, the binary is never executed, the tool reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py` and checks the input SHA-256 first):

```
python3 tools/staking_membership_request115.py --out research/work-items/staking-membership-request-115
python3 -m unittest tests.test_staking_membership_request115
```

Generated files: `sites.tsv`, `slots.tsv`, `callers.tsv`, `bodies.tsv`, `groups.tsv`, `scenarios.tsv`, `controls.tsv`, `result.json`, `measure.json`. `MANIFEST.sha256` covers them and the README. The tool starts four forked workers, runs in about 50 seconds and peaks below 400 MB of resident memory per process. Cases are built one at a time, run, compared and counted; no per-case result list is kept.

## Evidence

All addresses are virtual addresses of the ELF; function bounds come from the FDEs; slot targets come from `.rela.dyn` RELATIVE rows (`slots.tsv`); every displacement the rule list uses is read from the body bytes by a fixed byte pattern (`sites.tsv`), per body.

### Entry

Arguments: `rdi` = out (returned to the sink untouched), `rsi` = engine state, `rdx` = pointer to the 20-byte signer, `rcx` = pointer to 32 bytes (copied whole), `r8`, `r9` = two words, first stack argument = one word, second stack argument = pointer to an optional pair (u64 at +0, u64 at +8, tag byte at +0x10).

1. Pair: if the tag byte is 2 the pair is `(0, [state+0x88])` when `[state+0x80] == 1`, else `(0, 0)` (the 0x10a status record that is built and dropped on the way is not observable); any other tag byte gives the pair read from the pointer (`+0`, `+8`).
2. Membership: `0x36c8430(state+S, signer)` with `S = 0x3f08` in `0x2c54de0` and `0x55c78a0` and `S = 0x4a78` in `0x55c7640`. A member gives flag 0; a non-member gives flag = 1 when any of the 20 signer bytes is non zero (16 bytes by `pcmpeqb`/`pand`/`pmovmskb`, 4 more by `movd`), else 0. The lookup's own status drops happen here and are part of the log.
3. Cell test: the cell at `state+0x7d0` (`state+0x1340` in `0x55c7640`) must be non zero. If it is zero the body calls the expect-failure slot `0x64df6a0` with message `0x7d3212` (43 bytes), vtable `0x648c5f8`, Location `0x648b990` = `l1/src/dex_registry/clearinghouses.rs:11:29` (Location read from `.rodata`). Order: lookup first, then the cell test, so a missing cell still runs the lookup and its drops.
4. Request: the sink slot `0x64e7d08` (target `0x3c48b40`) is called with `rdi` = out, `rsi` = `state+0x90` and `rdx` = a 0x78-byte record built on the stack. Bytes written (offsets in the record): `+0x00` 32 bytes from `rcx`; `+0x20` the word at `[state+0x7c8]` (`+0x1338` in `0x55c7640`); `+0x28`, `+0x30` the pair; `+0x38` `r9`; `+0x40` first stack argument; `+0x48` `r8`; `+0x50` `[state+0x60]`; `+0x58` the dword `[state+0x68]`; `+0x5c` the flag byte; `+0x5d` the 20 signer bytes. Bytes `+0x71` to `+0x77` are not written (stack leftovers) and are left out of every comparison. The sink's return value is returned.
5. The state, the signer, the 32-byte block and the optional pair are never written (checked on every run).

### Copies

`0x55c7640` differs from `0x2c54de0` in three displacements (store `0x4a78`, cells `0x1340` / `0x1338`) and in its call targets (`0x5630000` for the record drop); `0x55c78a0` differs only in call targets. All three have 134 instructions and the same expect-failure site. The fixture holds a different (decoy) store at the other copy's offset, so a body that reads the wrong offset disagrees with the rule list.

### Callers (byte scan, `callers.tsv`)

The slot `0x64e4e38` has 21 call sites in 14 FDEs (listed with sizes); the sink slot `0x64e7d08` has exactly the 3 call sites of this packet; the entries are called (opcode e8, checked against the FDE table) from `0x2c51f20` and `0x2c5cce0` (base), `0x55c1f80` and `0x55d6390` (copy_a), `0x55c19f0` and `0x55d6720` (copy_b).

### Coverage

`bodies.tsv`: 113 of 134 instructions reached per body. The 21 unreached are the fall-through `ud2` after the no-return expect-failure call and the unwinding cleanup (`0x2c54fef` onward in the base body), which needs an unwinding panic.

## Implementation and comparison

The tool `tools/staking_membership_request115.py` is the implementation: a concrete x86-64 interpreter (the engine of `tools/staking_validator_snapshot115.py` up to the `Lookup` fixture, with its decoder and 16-byte vector subset; it raises on any form that is not in these bytes), a `Fwd` fixture that builds the state, the signer, the 32-byte block and the optional pair, and a rule list `spec` written without the machine. A case is one (body, snapshot world, optional-pair tag and `[state+0x80]`, signer kind, cell present or not, repeat) tuple:

- 36 snapshot worlds (ring and B-tree outer stores, vector and B-tree inner snapshots, 0 to 3 snapshots, probes: member first/last/middle, other epoch's member, absent, near miss), each also used as decoy store of another case.
- 6 pair situations (tag 2 with `[state+0x80]` = 1, 0, 2; tags 0, 1, 255 with a pair), 3 signer kinds (the world's probe, all zero, 16 zero bytes plus a non zero tail), cell present or zero, 4 repeats with different random words for every field.
- The expected outcome is the sink call (out and state offsets, the 0x71 defined request bytes), the sink's return value, the status drop log of the lookup, or the expect-failure tuple. 15,552 cases, 6,563,808 interpreted steps; per body: 2,592 expect failures, 1,080 requests with flag 0 and 1,512 with flag 1 (`groups.tsv`).

Negative controls (95, all detected):

- 20 deliberately wrong rule lists (membership inverted, zero signer counted, flag from membership only, flag inverted, tag test inverted, `[state+0x80]` tested for non zero, pair swapped, `r8`/`r9` swapped, missing expect failure, dword at +0x58 dropped, address zero test on 16 bytes only, 32-byte block cut to 16, `r8` and the stack word swapped, decoy store read, `rsi` offset 0x80, sink logged before the drops, message length 44, drops not logged on the failure, `[state+0x88]` ignored, `[state+0x7c8]` ignored).
- 66 byte edits (22 per body: condition flips and immediate flips chosen round robin over both kinds): 45 killed, 21 survived. 9 of the survivors are in unreached cleanup instructions; the other 12 are immediates that store the 0x10a/0x156 status-record tags and a zero temp (`movl $0,0x50(%rsp)`) whose values no case can observe because the record drops have no effect. Survivors are not counted as controls.
- 24 byte damages of the sites the rule list reads (lea displacement and register byte, message, vtable and Location pointers, message length, both cell displacements, per body): all 24 refused or read differently.
- 6 range controls: wrong input hash, address inside an instruction as an FDE start, a 12-step limit, an entry in the middle of an instruction, the store read at the other copy's offset, an address that is not a 602-byte body.

## Results and limitations

- `measure.json`: `cases` 15,552, `negative_controls` 95, `negative_detected` 95, 66 edits tried / 45 killed / 21 survived (reasons above), 36 worlds.
- Observation limits: the fixtures are built by this tool (B-trees and rings in the layouts of the snapshot packet), not captured from a node. The sink is a recording hook; what it does with the request is not reconstructed. The unwinding cleanup is not run. The fields `[state+0x60]`, `[state+0x68]`, `[state+0x80]`, `[state+0x88]` have identical offsets in the three bodies (bytes compared) but their meaning is unknown.
- Inference (not proved, not used by the tool): the flag means "signer is not a validator in the snapshot and is not the zero address", which together with the earlier reference-authorization body (same flag) suggests that the request tells the next stage whether the signer needs to be the owner of the touched record; the expect failure at `clearinghouses.rs:11:29` suggests the cell at `+0x7d0` is a clearinghouse count or handle that must be set before such a request is made.
- No gate is requested. This is one request builder and its copies, not the component.

Next question: what the sink `0x3c48b40` does with the 0x78-byte request, and what the six callers pass in the optional pair and the 32-byte block.
