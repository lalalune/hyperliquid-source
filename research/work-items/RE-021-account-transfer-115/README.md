# RE-021: node #115 account value transfer, its account-map lookup and the Transfer log hook

This packet adds an executable Python reconstruction of the EVM value transfer `0x4322860` (balance move between two accounts with its journal), the account-map lookup `0x3ed7e80` it calls three times, and the log hook `0x4323270` that records an ERC-20 style `Transfer(address,address,uint256)` log for each successful transfer. The reconstruction matches the real machine code in all 18,000 cases (12,000 transfers and 6,000 hook calls) and 56 of 56 negative controls are detected. A Rust port can therefore implement "move value between accounts" with the exact order of effects: touch entries are pushed before the balance check, the debit is stored before the receiver is looked up, a credit overflow leaves the debit in place, a missing account is an unwrap panic with one message per site, and the log record has a fixed 0x60-byte topic block, a big-endian 32-byte data block and a 0x50-byte record.

- Component ID: `evm` (task RE-021, address-09 account state; connected to RE-011)
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository main `0781ce048`. `references/can1357-hl` was not used. No node #94 result is reused.
- Claim status: observation (byte-level equality of the reconstruction with the evaluated machine code on every listed case). Names such as "touched", "Transfer log" and "level" are labelled inferences below.
- Scope included and excluded:
  - Included: the FDE `0x4322860..` (285 instructions), `0x3ed7e80..` (70 instructions) and `0x4323270..` (140 instructions). Every instruction of the first two is executed by at least one case. 127 of 140 in the hook are executed; the other 13 are the unwind landing pads after the two `ud2` allocation-failure sites (`0x43234a7..0x43234d4`), which only run during unwinding.
  - Excluded:
    - The journal vector growth routine `0x43bc980` (slot `0x64e68e8`) and the hook's record vector growth `0x1437200` (slot `0x64dfa48`) are stubs that move the old elements to a larger buffer.
    - The allocator `0x6355830` (slot `0x64df480`) and the two allocation-failure handlers (`0x141e251`, `0x141e264`) are stubs; the unwrap panic `0x1680c10` is a boundary.
    - Callers of the transfer (`0x4320857`, `0x4326b6c`) and of the hook (`0x432f553`, `0x432f693`, `0x43237d6`) are not evaluated.
    - The 20-byte-key lookup `0x3ed7e80` is evaluated for the account map only; the hash seed word behind slot `0x64dfa78` is NOBITS, so the tool supplies it.

## Reproduce

From the repository root, with Python 3 and the standard library only (no binutils are needed, and the binary is never executed):

```
python3 tools/re21_transfer_balance115.py --out research/work-items/RE-021-account-transfer-115
python3 -m unittest tests.test_re21_transfer_balance115
sha256sum -c research/work-items/RE-021-account-transfer-115/MANIFEST.sha256
```

The tool checks the input SHA-256 first and stops on any other digest. It reads the sections through `tools/elf_index.py` and the FDE extents through `tools/fde_extents.py`. Code bytes are decoded by a fixed-form decoder that raises on any form it does not know. Cases are built one at a time, evaluated, compared and folded into a SHA-256 digest, so memory stays small (peak resident set 338 MB). Two generations with different `PYTHONHASHSEED`/`TZ` and with a `PATH` lacking binutils were byte-identical. A full run takes about one minute. The unit tests take about 10 s.

## Evidence

All addresses are virtual addresses in `.text` of node #115. `constants.json` is written from the ELF bytes: FDE extents, direct call edges, the relocated targets of every indirect call slot, 28 checked byte patterns with their meaning, and the hash seed slot. The tool fails if any of them differs.

### Transfer `0x4322860(state, from, to, value)`

Arguments are `rdi` = state, `rsi` = from (20 bytes), `rdx` = to (20 bytes), `rcx` = value (four little-endian limbs). The result is the low byte of `eax`.

State object: the journal `Vec` of 0x58-byte entries is capacity `+0x18`, pointer `+0x20`, length `+0x28`; the account map is at `+0xc8` (ctrl `+0`, mask `+8`, item count `+0x18` = state `+0xe0`, secret `+0x20` = state `+0xe8`). A bucket is `0xa8` bytes: the address in bytes `0..20`, then the account at bucket `+0x18`. The four balance limbs are at bucket `+0x40` (account `+0x28`) and the flag byte is at bucket `+0xa4` (account `+0x8c`); bit 2 means touched.

| Path | Test (address) | Effect | Result |
| --- | --- | --- | --- |
| from == to (all 20 bytes) | `0x4322899` | inlined probe copy of the lookup; item count 0 or absent → unwrap panic `0x6485ce0`; no journal entry, no flag change | `3 * (balance >= value)`: 3 or 0 |
| value == 0 | `0x43228be` | look up `to` only (absent → panic `0x6485cc8`); touch it once | 3 |
| otherwise | `0x43228ca` | look up `from` (absent → panic `0x6485c98`), touch it once | continue |
| debit | `0x4322923..0x432297e` | four-limb subtract with borrow chain; borrow out of limb 3 → return 0 with the balances unchanged (the sender stays touched) | 0 |
| debit store | `0x4322998` | new sender balance stored before the receiver is looked up | |
| receiver | `0x43229b2` | look up `to` (absent → panic `0x6485cb0`, the debit already stored), touch it once | |
| credit | `0x4322a0e..0x4322a38` | four-limb add; carry out of limb 3 → return 1 with the receiver unchanged (the debit stays) | 1 |
| success | `0x4322a3e..0x4322ad5` | store the credit, push the transfer entry (tag 4), call the hook | 3 |

A touch pushes tag 2 and the 20 address bytes at `+1` and sets the flag bit; it is skipped when the bit is already set. The journal push calls the growth routine only when length equals capacity (`0x43228ec`, `0x43229db`, `0x4322a65`).

Transfer entry (tag 4): tag at `+0`, `from` at `+1..0x15`, `to` at `+0x15..0x29`, value limbs 0..2 at `+0x30..0x48` and limb 3 at `+0x48..0x50`. Bytes `+0x29..+0x30` are 7 uninitialised stack bytes (copied by a misaligned 16-byte move from frame `+0x21`) and bytes `+0x50..0x58` keep their old contents. The cases fill the stack with a per-case byte and the model expects that byte.

### Lookup `0x3ed7e80(map, address)`

Returns null when the item count (`+0x18`) is 0. Otherwise the hash is a folded multiply: `p = (a0 ^ secret) * (a1 ^ seed)`, `z = lo(p) ^ a2 ^ hi(p)`, `p = z * seed`, `h = lo(p) ^ hi(p)` with `a0` = bytes 0..8, `a1` = bytes 8..16, `a2` = bytes 16..20, secret = map `+0x20`, seed = the word behind slot `0x64dfa78`. The group probe compares `h >> 57` with 16 control bytes, confirms with a 16 + 4 byte address compare, stops at the first group with an EMPTY byte, and advances by `16, 32, 48, …` (triangular). A hit returns bucket + `0x18`.

### Hook `0x4323270(sink, from, to, value)`

| Step | Address | Observation |
| --- | --- | --- |
| Level gate | `0x432327e` | sink byte `+0x126` below `0x0e` → return |
| Flag gate | `0x432328e` | sink byte `+0x124` nonzero → return |
| Zero value | `0x432329b` | all four limbs zero → return |
| Topic block | `0x43232c5` | allocate 0x60 bytes; bytes `0..32` = rodata `0x4581e0` (`ddf252ad…b3ef`, the keccak of `Transfer(address,address,uint256)`), `32..44` zero, `44..64` = from, `64..76` zero, `76..96` = to. Allocation failure → handler slot `0x64df490` with `edi=1, esi=0x60` |
| Data block | `0x4323392` | allocate 0x20 bytes holding the value as 32 big-endian bytes (four `bswap`, limb 3 first). Failure → slot `0x64df498` with `esi=0x20` (the topic block stays written) |
| Record | `0x43233e4..0x432346d` | 0x50 bytes: `3`, topic pointer, `3`, a vtable-like word, data pointer, `0x20`, tagged data pointer, 16 bytes `ff` from `0x7ca51f`, `0xfeffffff`, 4 uninitialised stack bytes. An odd data pointer is stored as is with the word behind slot `0x64df8c8`; an even one is stored `\| 1` with the word behind `0x64df8c0` |
| Push | `0x4323420` | record vector at sink `+0` (capacity, pointer, length), element stride `0x50`; growth only when length equals capacity |

## Implementation and comparison

`tools/re21_transfer_balance115.py` holds the reconstruction (`model`, `trace_model`, `addr_hash`, `entry_bytes`, `rec_bytes`, `topic_obj`) and the machine-code evaluator (a concrete x86-64 interpreter with a fixed-form decoder). For each case it builds the hashbrown account table with real triangular insertion, tombstones and decoy buckets whose control byte equals the target's `h2` but whose address differs by one bit, loads synthetic state, journal, sink and heap regions, runs the real bytes and compares the result byte (or the panic message / allocation-failure argument), every touched account's balance and flag, the journal head, both journal buffers (including bytes that must stay unchanged), the heap blocks, the recorded hook arguments, the callee-saved registers and the stack pointer.

- Transfer cases (12,000): 20 case families (plain transfer, exact balance, short balance, borrow chain, credit exactly to 2^256-1, overflow, carry chain, zero value, self transfer with and without enough balance, self transfer on one pointer, missing sender, missing receiver, zero value with missing receiver, missing account on the self path, empty item count, a full probe window on the self path, a one-bit-different receiver, table stress). Outcomes: `transfer/transferred` 3,051, `transfer/overflow` 1,749, `transfer/insufficient` 600, `self/sufficient` 1,869, `self/insufficient` 531, `zero-value/ok` 600, `panic/from-missing` 1,200, `panic/self-missing` 1,200, `panic/to-missing` 600, `panic/to-missing-zero` 600.
- Hook cases (6,000): `logged/odd-pointer` 1,214 (+894 with growth), `logged/even-pointer` 256 (+423 with growth), `skipped/level` 813, `skipped/flag` 600, `skipped/zero-value` 600, `alloc-error/0x60` 600, `alloc-error/0x20` 600.
- Result: 0 mismatches; `summary.json` carries a SHA-256 digest over all transfer cases and all hook cases. `cases.tsv` and `trace-cases.tsv` list every 12th case plus any mismatch; the tool regenerates the rest.

Negative controls (56, all detected; `negative-controls.tsv`): 13 transfer model mutants, 22 transfer code-byte mutants (immediates, displacements and one `jb` to `jae`, each verified to change the byte), 7 hook model mutants, 11 hook code-byte mutants, a flipped `.text` byte (digest check), an address past `.text`, and a start address inside a function (no FDE).

## Results and limitations

- Observed: the call graph, indirect-call targets, checked byte patterns and instruction counts above; 0 mismatches over 18,000 cases; full instruction coverage of the transfer and the lookup, 127 of 140 for the hook.
- Inferences (not proved by bytes): that the hook's rodata hash is the ERC-20 `Transfer` event signature (the 32 bytes match the well-known keccak value, but the tool does not compute keccak); that the level byte is a spec or activation level and the flag byte a suppress flag; that bit 2 of the account flag means "touched in this transaction".
- Unresolved: the callers' use of the result byte 0/1/3; the journal rollback that consumes tag 2 and tag 4 entries; the contents of the hook's callers' sink object beyond the three fields read here; the word behind slots `0x64df8c8` / `0x64df8c0` (relocation targets `0x64040c0` / `0x64040e8`, used only as record words).
- The unwind-only landing pads of the hook are not executed.

## Next question

Reconstruct the callers of `0x4322860` (`0x4320857` and `0x4326b6c`) with their result handling, then the journal rollback that reads the tag 2 and tag 4 entries written here.
