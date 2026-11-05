# RE-011: EVM storage warm/cold access path: sstore 0x2977910 and sload 0x4e33680 against the access-list warm set (node #115)

With this packet, the node #115 EVM storage access path can be rebuilt as code: given an account map, an account storage table, the access-list warm set at context +`0x2e0`, the journal and a transaction id, the reconstruction yields the exact result of a storage load (warm, cold, or "cold load skipped"), the exact result block of a storage store (`original`, `present`, `new`, `is_cold`, or failure 2), the exact storage table afterwards (control bytes with mirror, bucket positions, growth counter, slot bytes), the exact journal entries (tags 2, 8, 9, byte for byte) and the database reads, reserves and journal growth calls. This is the EIP-2929/2930 consumer of the warm set that the RE-011 access-list loader packet builds. The packet reconstructs and byte-checks:

- the store `0x2977910` (account lookup, first-touch status bit with journal tag 2, call through GOT `0x64e6d90`, result block, journal tag 8 when the value changes);
- the load `0x4e33680` (slot probe, same-transaction warm check, access-list address and key lookup, skip flag, database read or zero for created accounts, slot insert, per-transaction original-value copy, journal tag 9);
- the U256 key hasher `0x4e52a90` / `0x4e623a0`, and the foldhash byte hasher `0x1770830` they reach, executed as real code.

The reconstruction matches the real machine code in all 3,400 cases, and all 27/27 negative controls are detected.

- Component ID: `evm` (RE-011 "one bounded EVM adapter"; the RE-011 access-list packet builds the map at +`0x2e0` that this path reads)
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit: `05bc2de303c05525b71e7e257426e741bc66a390` (main at the time of the run)
- Claim status: reconstructed, for the scope below. The database read `0x5441fe0`, the storage-table reserve (GOT `0x64e7028` → `0x3ee1680`) and the journal Vec growth (GOT `0x64e6cf0` → `0x43bc980`) are stubbed at their call boundaries; their arguments, call order and effects are compared.
- Scope:
  - the whole FDEs of `0x2977910` (948 bytes), `0x4e33680` (2,156 bytes), `0x4e52a90` and `0x4e623a0`;
  - `0x1770830` runs as real code but only its 32-byte (medium) path is reachable from here; its other paths are covered by the RE-011 access-list packet;
  - the position twin `0x2977cd0` is compared byte for byte (only RIP displacements differ), but it is not executed: one of its RIP operands names GOT `0x64e6d98` → `0x433bcf0`, a different storage load (2,265 bytes, a fallible database path). That body is out of scope;
  - out of scope: the callers (`0x2994990` calls `0x2977910` twice; `0x2994490` calls the twin), gas pricing, and the internals of the stubs.

## Reproduce

```
python3 tools/re11_storage_warm115.py --out research/work-items/RE-011-storage-warm-cold-115
python3 -m unittest tests.test_re11_storage_warm115
python3 tools/artifacts.py verify
```

How the tool works:

- It checks the input SHA-256 first.
- It reads FDE extents with `tools/fde_extents.py` and sections with `tools/elf_index.py`. SHT_NOBITS sections are never used for byte reads; the global seed block `0x64ffe90` lies in `.bss` and gets synthetic per-case contents.
- It reads relocations from `.rela.dyn` and code bytes from `.text`.
- It runs the real code bytes with a small concrete x86-64 evaluator (the one from the RE-011 access-list packet). The evaluator raises on any instruction form it does not support. The binary is never executed and no external program is called.
- Each case builds the account map, storage tables, warm map and journal in synthetic memory by real hashbrown insertion order (including tombstones and nearly full tables), runs the entry point to its `ret`, then decodes the storage table, journal, status byte and result block and compares them with the model. It also checks that callee-saved registers and the stack pointer are restored, that every other context byte and every input byte is unchanged, and that the bytes after the 0x61-byte result block are untouched.
- Two generations, run with different `PYTHONHASHSEED`/`TZ` and with `PATH` pointing at no binutils, are byte-identical.

Generated files: `cases.tsv` (one row per case), `outcome-classes.tsv`, `decoded-instructions.tsv` (every instruction in scope, with an executed flag), `negative-controls.tsv`, `constants.json` (FDEs, GOT slots, checked bytes with meaning, twin operands, offsets, bucket sizes, journal tags) and `summary.json`.

Human-readable excerpt (`objdump -d`, abridged); it is not used by the tool:

```
2977924: cmpq $0x0,0x350(%rsi) ; je fail            ; account map items
297793f: g0 = *0x64ffe90 ; h = fold(fold(k1^g0, k0^seed@+0x358) ^ k2, g0)
29779c1: imul $0xa8 ; compare 16+4 address bytes    ; 0xa8-byte account bucket
2977a46: lea 0x2e0(%rsi),%r8                        ; warm map -> argument block +0x10
2977a85: test $0x4,status ; or $0x4 ; journal tag 2 ; status byte = bucket+0xa4
2977b04: call *0x64e6d90 (0x4e33680)                ; dl: 0 warm, 1 cold, 2 skipped
2977b0f: out[0]=0, out[0x60]=2                      ; failure
2977b76: present == new ? done : present=new, journal tag 8 (old present at +0x38)
4e336b4: h = fold(fold(k1^g0, k0^seed) ^ k2, k3^g0) ; 0x68-byte storage bucket
4e337e2: slot.txid == txid && slot.cold == 0 -> warm (dl 0)
4e337f5: warm map +0x2e0: items ? probe address (64-byte bucket) : cold
4e33a90: set items ? call 4e52a90(set seed, key) ; probe 32-byte bucket
4e33a05: cold && skip -> dl 2
4e33a1b: original = present ; txid ; cold = 0       ; slow-path hit
4e33c52: status & 1 ? 0 : call 5441fe0 (database read)
4e33d33: insert slot (key, value, value, txid, cold 0) ; growth -= old&1 ; items++
4e33e24: journal tag 9 (address +0x1, key +0x18) ; dl 1
```

## Evidence

All values below come from the generated files (`constants.json`, `decoded-instructions.tsv`).

| Item | Address | Bytes / value |
| --- | --- | --- |
| Store | `0x2977910..0x2977cc4` | FDE, 948 bytes; 203/212 instructions executed |
| Store twin | `0x2977cd0..0x2978084` | 948 bytes; differs only in 4 RIP displacements; 3 name the same targets, the call at `0x2977ec4` names GOT `0x64e6d98` → `0x433bcf0` |
| Load | `0x4e33680..0x4e33eec` | FDE, 2,156 bytes; 505/522 instructions executed |
| U256 hasher | `0x4e52a90`, `0x4e623a0` | length prefix 4 (`b8 04 00 00 00` at `0x4e623d0`), seed `rol 32`, 32 bytes to `0x1770830` via GOT `0x64dfa80` |
| Account map | context +`0x338` (ctrl, mask, growth, items +`0x350`, seed +`0x358`) | bucket `0xa8`: address +0, account +`0x18` (storage table header), status +`0xa4` (= account +`0x8c`) |
| Storage slot | bucket `0x68` | key +0, original +`0x20`, present +`0x40`, transaction id +`0x60` (u32), cold byte +`0x64`, 3 bytes never written |
| Warm map | context +`0x2e0` | bucket `0x40`: address +0, set header +`0x18` (items +`0x28`, seed +`0x38`); set bucket `0x20` |
| Journal | context +`0x288` cap, +`0x290` ptr, +`0x298` len | entry `0x58` bytes; tag 2 address; tag 9 address + key at +`0x18`; tag 8 address + key + old present at +`0x38` |
| Other inputs | context +`0x390` transaction id (u32), +`0x398` database | the load's argument block is {account, &journal, &warm map, &database, txid, address} |
| Status bits | `f6 c2 04` at `0x2977a85`; `f6 44 24 07 01` at `0x4e33c52` | bit `0x04` touched (journal tag 2 once); bit `0x01` means "read zero, skip the database" |

Observations from the bytes (each is exercised by cases and by a control):

1. The store fails (`out[0]=0`, `out[0x60]=2`) when the account map is empty or the address is absent. Nothing else is written.
2. The first store to an account sets status bit `0x04` and pushes journal tag 2 before the load. A later failure (skip) does not undo it.
3. The load's fast path: a slot whose transaction id equals the context id and whose cold byte is 0 is warm. The id is rewritten with the same value, and no journal entry is pushed.
4. On every other hit the code checks the warm map. `0x4e33a0c`/`0x4e33a13` re-test the same condition, so the no-copy arm `0x4e33a76` is unreachable, and the copy `original = present` runs on **every** slow-path hit. This includes a hit in the same transaction whose cold byte is set. The model first assumed "copy only when the id changed", and the code proved that assumption wrong (it stays as the control `copy_only_new_tx`).
5. A slot is warm through the access list only when the address is in the map and the key is in that address's set. Empty maps and sets short-circuit to cold.
6. Cold + skip flag (low byte of `edx`) returns `dl=2`. On a miss the storage reserve has already happened by then, but no slot is inserted.
7. On a miss: status bit `0x01` → value 0 and no database call; otherwise the database read `0x5441fe0(out, *ctx+0x398, &address, &key)`. The slot is inserted with original = present = value.
8. Journal tag 9 bytes `+0x15..+0x18` are stack bytes. They hold key bytes 0..2 only when the database path copied the key there; otherwise they hold whatever was on the stack. The model treats them exactly, using a known stack fill. Tag 8 copies the key the same way, from a slot that always holds key bytes 0..2.
9. The store result is `original ‖ present (before the store) ‖ new ‖ is_cold` (0x61 bytes). Journal tag 8 (old present at +`0x38`) is pushed only when `present != new`.

## Implementation and comparison

The reconstruction is `World.sload`, `World.sstore`, `hash_slot_key`, `hash_addr`, `hash_u256`, `bytes_hash` and `Table` in `tools/re11_storage_warm115.py` (pure Python). This is not a Rust implementation; a Rust adapter is not yet implemented.

Results (`summary.json`):

- cases: 3,400 (sload 1,700, sstore 1,700), mismatches 0;
- outcome classes: 66 (warm / cold / skipped / fail, crossed with journal tags, database reads, reserves and journal growth; `outcome-classes.tsv`);
- executed instructions: 804/961 in total (`0x1770830` 44/161; `0x2977910` 203/212; `0x4e33680` 505/522; `0x4e52a90` 23/27; `0x4e623a0` 29/39);
- negative controls: 27/27 detected (`negative-controls.tsv`):
  - model mutants: limb order, fast path removed, skip ignored, no original copy, copy only on a new transaction, created reads the database, present set to zero, always touch, always journal, address word swap, length prefix, seed rotation, wrap fix, control mirror, foldhash medium cut;
  - code-byte mutants: h2 shift, slot stride, cold-byte displacement, key-equality mask, set stride, created bit, tag 9, length prefix, touched bit, tag 8, account stride;
  - input checks: a flipped `.text` byte and an address past `.text`.

## Results and limitations

- Unexecuted instructions in `0x4e33680` (all listed with executed=0 in `decoded-instructions.tsv`):
  - the no-copy arm `0x4e33a76..0x4e33a83`, which is unreachable (observation 4);
  - the storage-probe next-group step `0x4e337c2..0x4e337cd` and the insert next-group scan `0x4e33eb0..0x4e33ed3`. These are reached only when the first probed group of a storage table holds no EMPTY/DELETED byte. The case generator's nearly-full tables did not produce that, so these two arms are not proven here. The warm-map and warm-set next-group arms are executed.
- Unexecuted instructions in `0x2977910`: the account-probe next-candidate step `0x29779ff..0x2977a0c` (an h2 match with a different address) and the next-group step `0x2977a20..0x2977a2b`. They are not proven here. In `0x4e52a90`, the flush arm of `0x4e623a0` (sponge length ≥ `0x41`) and the zero-length return are unreachable from a fresh sponge. In `0x1770830`, only the 32-byte path is reachable.
- Stubs: the database read, the storage reserve (modelled as the hashbrown capacity rule with model hashes) and journal growth (modelled as `max(4, 2*cap)`). The tool checks their arguments, but their bodies are not reconstructed here.
- Names (`sload`, `sstore`, EIP-2929, "cold", "original") are inferences from behaviour. The bytes establish the offsets, tags and rules above, not Rust identifiers.
- No gate is requested. This is one bounded path of the `evm` component.

Next question: `0x433bcf0` (GOT `0x64e6d98`), the storage load used by the twin store `0x2977cd0`. It has the same slot and warm-set logic but a fallible database path. What do its error arms write, and which caller (`0x2994490` vs `0x2994990`) selects which store?
