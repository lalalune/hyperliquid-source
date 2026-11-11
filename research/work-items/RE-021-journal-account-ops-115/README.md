# RE-021: reconstruct the node #115 journaled-state account operations (transfer, create checkpoint, set-code, Transfer log, revert) around the map lookup 0x3ed7e80

- Component ID: `evm` (task RE-021, a bounded continuation of RE-011; no separate row in the task catalogue)
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository `0781ce04826eeefd89fe336cb8ea073be0c1de30`; no reference source was read or copied. Every address, offset and constant below was read from the #115 bytes.
- Claim status: observation (real machine code evaluated and compared) plus inference (names of the Rust-level operations); the inferences are listed separately below.
- Scope included and excluded: included are six functions of one flow: lookup `0x3ed7e80`, native transfer `0x4322860`, code setter `0x4323110`, Transfer-log emitter `0x4323270`, create-account checkpoint `0x43234e0` and checkpoint revert `0x4322f30`. Excluded: the per-entry revert function behind GOT `0x64e6d68`, the storage-map functions, the Arc drop behind GOT `0x64e4fa8`, allocator and unwinding cleanup blocks, and the callers of these six functions. No progress gate is requested.

This packet lets a reconstruction decide, from evidence, exactly how the #115 journaled state mutates accounts: which journal tags are written and in which order, when an account is touched, how balances borrow and carry (and what has already been mutated when a transfer fails), what the create-account collision rule is, and what the 3-topic ERC-20 style `Transfer` log looks like byte for byte. A pure-Python model of all six functions agrees with the real #115 machine code on 11,200 generated cases (0 mismatches) and 45 of 45 negative controls are detected.

## Reproduce

Run from the repository root with only the Python standard library (no binutils on PATH, the binary is never executed):

```
python3 tools/re21_journal_account_ops115.py --out research/work-items/RE-021-journal-account-ops-115
python3 -m unittest tests.test_re21_journal_account_ops115
(cd research/work-items/RE-021-journal-account-ops-115 && sha256sum -c MANIFEST.sha256)
```

The tool checks the input SHA-256 first and fails if it differs. It writes all evidence files byte-identically on every run (checked with two output folders and `diff -r`). It imports the ELF reader and the concrete x86-64 evaluator from the merged tools (`tools/elf_index.py`, `tools/fde_extents.py` and `tools/re11_storage_cache_load115.py`) and adds only the missing instruction forms (lock prefix, `por`, `movmskps`, `not r/m8`). Peak memory is about 340 MB; cases are generated, run, compared and discarded one at a time.

## Evidence

All addresses are virtual addresses of node #115. Observations (from the code bytes and relocations):

- `0x3ed7e80` (FDE 276 bytes) is a hashbrown lookup: if the map header item count at `+0x18` is 0 it returns null; otherwise it hashes the 20-byte address with two folded multiplies keyed by the header key at `+0x20` and the global seed block (GOT `0x64dfa78`), probes 16-byte groups on the top 7 hash bits, compares the 20 key bytes, and returns bucket start + `0x18` (buckets are `0xa8` bytes, indexed downwards from the control pointer).
- The journaled state `J` has: logs Vec `{cap, ptr, len+0x10}` of `0x50`-byte entries at `+0`, journal Vec `{cap, ptr+0x20, len+0x28}` of `0x58`-byte entries at `+0x18`, a checkpoint word at `+0x40`, the account map header at `+0xc8`, the depth counter at `+0x118`, a flag byte at `+0x124` and the spec byte at `+0x126`.
- Account bucket fields (offsets from the bucket start): balance `0x40..0x60`, code hash `0x60..0x80`, nonce `0x80`, code Arc pointer `0x88`, status byte `0xa4` (bit `0x01` created, bit `0x04` touched).
- Transfer `0x4322860` (FDE 1,180 bytes) returns `3` = Ok, `0` = insufficient balance, `1` = receiver overflow. Same address: only a balance comparison, no touch and no journal entry. Zero value: touch the receiver only. Otherwise: look up the sender, touch it (journal tag 2 `{address}` once, status bit `0x04`), subtract with borrow (failure returns 0 after the touch), **store the reduced sender balance before the receiver lookup**, look up the receiver, touch it, add with carry (overflow returns 1 and leaves the sender already debited), store, push tag 4 `{from, to, 7 padding bytes, value}` and call the log emitter. A missing account panics with one of four distinct strings (`0x6485c98`, `0x6485cb0`, `0x6485cc8`, `0x6485ce0`).
- Log emitter `0x4323270` runs only if spec `>= 0xe`, flag `+0x124 == 0` and the value is non-zero. It allocates a `0x60`-byte topic block (event topic `ddf252ad...b3ef` from `0x4581e0/0x4581f0`, then `from` and `to` left-padded to 32 bytes) and a `0x20`-byte big-endian value block, and pushes a `0x50`-byte log entry (cap 3, topic ptr, len 3, vtable from GOT `0x64df8c0`, data ptr, len `0x20`, tagged ptr, 20-byte emitter address `ff..ff fe` from `0x7ca51f` plus an immediate at `0x43233ed`).
- Set-code `0x4323110`: look up, touch, journal tag `0xb` `{address}`, copy 32 hash bytes to bucket `+0x60`, drop the old code Arc (strong count at the pointer, `lock dec`, drop callback at zero) and store the new Arc pointer.
- Create checkpoint `0x43234e0`: checkpoint = `(logs len, journal len, J+0x40)`; depth `+1` (panic string `0x6485c38` at depth `2^64-1`); the target must hold the empty code hash (`0x4537f0/0x452020`) and nonce 0, else revert and `Err(2)`; otherwise status `|= 0x81`, journal tag 7 `{address, !was_created}`, drop the Arc, nonce 1 when the spec byte is above 2, touch, then for a non-zero value: receiver overflow reverts with `Err(1)` (nothing debited), else credit, debit the caller without a check, tag 4 and the Transfer log.
- Revert `0x4322f30`: depth saturating-minus 1, drop logs above the checkpoint (free topics `cap << 5` bytes, then the bytes-vtable drop), `J+0x40 = min(J+0x40, cp[2])`, truncate the journal and call the per-entry revert function top-down until a tag `0xc` entry, passing `spec >= 3`.

Machine-readable evidence beside this file: `constants.json` (FDE extents and hashes, GOT slots, panic sites, field offsets, constants), `decoded-instructions.tsv` (every instruction of the six functions and whether any case executed it), `cases.tsv` (every third case plus any failure), `outcome-classes.tsv`, `negative-controls.tsv`, `summary.json`, `measure.json`, `MANIFEST.sha256`. Analysis was complete for the six FDE extents (linear decode reaches each end exactly); 868 of 916 decoded instructions run in at least one case. The unreached ones are the unwind landing pads, `ud2` after the panic calls and one alignment `nop` (listed with `executed = 0`).

## Implementation and comparison

`tools/re21_journal_account_ops115.py` contains a pure-Python model of the six functions (`m_transfer`, `m_set_code`, `m_create`, `m_log`, `m_revert`, `St.lookup`) over a logical state: account buckets, the two Vecs, the checkpoint word, the allocator sequence and the Arc counts. For each of 11,200 generated cases (transfer 3,700, create 2,600, revert 1,900, set-code 1,500, lookup 900, log 600) the real machine code is run with a concrete evaluator on a synthetic memory image, with the allocator, Vec growth, panics, Arc drop, free and the per-entry revert replaced by recording stubs, and then compared with the model on: the return value or output buffer, every stub event in order, the full `J` bytes, every journal and log entry byte, every account bucket, the allocated blocks, the Arc counts, unchanged inputs and the callee-saved registers. Panics and allocation failures are compared as outcomes together with the state mutated before them. Case shapes: sparse and dense (32 buckets, full probe groups) maps, an empty map, missing accounts, same-address transfers, exact/short/overflowing amounts, full journals and log Vecs (growth), and every spec/flag/depth edge.

Negative controls (45, all detected): 17 wrong models (log gate, topic order, big/little endian value, same-address always Ok, zero-value without touch, no borrow check, no carry check, Arc always dropped, wrong tag, no depth check, nonce ignored, wrong spec thresholds, wrong error code, depth wrap, wrong revert flag), 26 single-byte code corruptions (tags, strides, masks, thresholds, immediates in all six functions) and 2 input controls (a flipped `.text` byte fails the digest; an address past `.text` is rejected).

## Results and limitations

Machine-readable counts are in `summary.json` and `measure.json` (`cases` 11,200, `negative_controls` 45, `negative_detected` 45, mismatches 0). Inferences (not proven by bytes): the Rust-level names (revm-style journal entries, `Transfer` event, checkpoint), and the reading of tag 4 as a balance transfer and tag 7 as account creation, which follow from the payloads. Unresolved: the semantics behind the per-entry revert callee (GOT `0x64e6d68`), the Arc drop body, and the callers of these six functions. The 7 bytes before the value inside tag-4 entries are uninitialised stack padding; the model fixes them to the harness fill byte. The seed block and hash keys are synthetic. No progress gate is requested; this packet covers six functions of the journaled-state flow, not the whole `evm` component.

Next question: the per-entry revert function behind GOT `0x64e6d68`, which consumes the entries this packet shows being pushed (tags 2, 4, 7, 0xb), and the callers that pass the spec byte into `0x43234e0`.
