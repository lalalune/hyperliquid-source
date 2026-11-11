# RE-011: reconstruct the node #115 EVM SELFDESTRUCT (0xff) and KECCAK256 (0x20) opcode handlers

With this packet the EVM `SELFDESTRUCT` handlers 0x2991290 / 0x2991cc0 and the `KECCAK256` handler 0x29982d0 of node #115
can be re-implemented from the bytes: the stack/static/underflow checks, the beneficiary decoding, the empty-account test
(pre- and post-Spurious-Dragon forms), the two-level host balance map walk and balance move, the three journal-entry kinds
(touch 2, destruct 1, EIP-6780 balance-only transfer 4) with their exact byte layout, the destruct-list push, the cold
and new-account gas, the refund bookkeeping with its saturating signed add and overflow panics, and for `KECCAK256` the
word-count gas, memory expansion, argument checks and the sponge buffer / `0x01 .. 0x80` padding / rate 0x88 glue.
A pure-Python reconstruction agrees with the machine code of all three handlers on 10,200 generated cases (0 mismatches),
and 50 of 50 negative controls (wrong reconstructions, corrupted code bytes, corrupted inputs) are detected.

- Component ID: evm (RE-011, EVM fork / RPC adapter area)
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
- Source commit / reference commit: repository main at the time of the run; no reference source used (labels are inferences, see below)
- Claim status: observation (addresses, byte layouts, evaluated behaviour) and inference (opcode names, field meanings), kept apart below
- Scope included and excluded: the three handler bodies and everything they do between entry and return, including every panic
  and error return; the callee bodies listed under Limits are stubbed and are not claimed. No component gate is requested.

## Reproduce

```
python3 tools/artifacts.py verify
python3 tools/re11_selfdestruct_keccak115.py --out research/work-items/RE-011-selfdestruct-keccak-115
python3 -m unittest tests.test_re11_selfdestruct_keccak115
(cd research/work-items/RE-011-selfdestruct-keccak-115 && sha256sum -c MANIFEST.sha256)
```

The tool verifies the input SHA-256 first, reads every section, relocation and FDE with `tools/elf_index.py` and
`tools/fde_extents.py`, evaluates the real machine code with the concrete x86-64 evaluator of
`tools/re11_transient_storage115.py` (extended in the tool by POR `0f eb` and MOVMSKPS `0f 50`), and never executes the binary or
calls an external program. Output is deterministic (no time, random or path data); two runs in different folders are byte-identical.
Peak memory is well below 1 GiB (cases are generated, run and compared one at a time).

## Evidence

Coordinates are virtual addresses of the #115 `.text` / `.eh_frame` and RELATIVE relocation slots.

| Handler | FDE | bytes | decoded instructions | opcode-table slots (RELATIVE addend = handler) |
| --- | --- | --- | --- | --- |
| SELFDESTRUCT copy A | 0x2991290..0x2991cbb | 2603 | 570 | 0x6441a08 |
| SELFDESTRUCT copy B | 0x2991cc0..0x29926eb | 2603 | 570 | 0x64426f8 |
| KECCAK256 | 0x29982d0..0x2998622 | 850 | 186 | 0x6441310, 0x6442000 |

- The two copies A and B are the same code: same instruction count, opcodes and lengths; only 23 of the 570 instructions
  differ, and those are RIP-relative displacements of call slots / constants / panic strings (observed by decoding both). The KECCAK256 handler
  has no twin: no other 850-byte FDE with the same first bytes has the same instruction shape, and both opcode tables point at the one body.
- Opcode tables (inference from the slot arithmetic, consistent with the existing transient-storage packet whose slot 0x54 sits at 0x64414b0):
  the tables start at 0x6441210 and 0x6441f00 with one 8-byte slot per opcode; 0x6441310 - 0x6441210 = 8 * 0x20 and 0x6441a08 - 0x6441210 = 8 * 0xff,
  so the handlers serve opcodes 0x20 and 0xff.
- Call sites (read from the code bytes, `constants.json` `call_roles`): the loader GOT slot 0x64e6ce8 -> 0x5463980 (copy B 0x4323870), journal grow -> 0x43bc980,
  destruct-list grow -> 0x43bc600, transfer 0x29714f0, burn 0x2970eb0, two panic helpers 0x1680c10 (`expect` on `None`) and 0x1681da0 (arithmetic overflow)
  with six distinct message strings per SELFDESTRUCT copy; KECCAK256 uses absorb 0x633a380, squeeze 0x633a460, resize 0x45244c0, the imports `memcpy` / `memset`
  (GOT 0x64df508 / 0x64df750, names from `.dynsym`) and three overflow messages.
- The two 16-byte constants the empty-account test compares the code hash with (0x4537f0 and 0x452020) concatenate to the Keccak-256 of the empty string
  c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470, which the tool also computes with its own Keccak-f[1600] (the tool refuses to run otherwise;
  the `abc` vector is checked too).

### SELFDESTRUCT (observations, offsets in the interpreter I = rdi, host H = rsi)

1. `I+0x1a8 != 0` -> return 0x28 (static call). `I+0x30 == 0` -> 0x2c. The top word is popped (`I+0x30` decremented at once).
2. Beneficiary: 20 bytes built from limbs 0..2 of the word (`bswap` of each limb; limb 3 and the top 32 bits of limb 2 ignored), compared bytewise with `I+0x78` (executing address).
3. `P = H+0x250`; `P+0x90 + P+0x80` (carry -> panic "sum"). The loader (stubbed) is called with the beneficiary, `gas < sum` as the cold flag input, `H+0x270` and `H+0x398`;
   its status byte 2 -> return 0x20, any other nonzero status = cold access.
4. "Empty beneficiary": fork byte `H+0x396 <= 2`: flag byte `acct+0x8c` has bit 8 and not bit 4; otherwise code hash (`acct+0x48..0x68`) is KECCAK_EMPTY or all zero, balance
   field `acct+0x28..0x48` zero, nonce `acct+0x68` zero.
5. Balance map at `H+0x338` (ctrl, mask `+0x340`, items `+0x350`, secret `+0x358`): hashbrown with 0xa8-byte buckets (20-byte address key at +0, 32-byte balance at +0x40, flag dword at +0xa4),
   hash = the folded two-multiply address hash with the process seed (GOT 0x64dfa78) already used by the SLOAD / transient maps. Items == 0 or a missing key panics (`expect`).
6. Beneficiary != executing address: look up self, look up beneficiary (flag bit 4 clear -> journal kind 2 "touch" and set bit 4), beneficiary balance += self balance (mod 2^256).
   Then look up self again, copy its balance.
7. Fork `H+0x396 >= 0x0b` and self flag bit 0x80 clear -> EIP-6780 path: if beneficiary != self zero the balance, call transfer, push journal kind 4.
   Otherwise (older fork or bit 0x80 set) -> destruct path: unless `H+0x395` push the executing address on the destruct list (`H+0x2a0..0x2b0`, 20-byte items), `flags |= 0x42`, zero the balance,
   call transfer (or burn when the beneficiary is the executing address), push journal kind 1. A self flag with bit 2 already set skips the list push and records r13 = 1 or 2 (bit 0x40).
8. Journal entries (`H+0x288/0x290/0x298`, stride 0x58) are written with the packed field layout reproduced in `sd_model`: kind 2 = tag + 20-byte address; kinds 1/4 = tag, a byte,
   the executing address, the beneficiary and the old balance at fixed offsets. Kind 4 stores both addresses shifted by one byte; six bytes at +0x2a come from uninitialised stack
   padding in the real frame (the model reproduces them as the evaluator's stack fill 0x5c). A grow helper is called when length == capacity.
9. Gas: `new_account = P+0xd8` when empty (and, from spec byte `I+0x1a9 > 2`, only when the old balance was nonzero), plus `P+0x90 + P+0x80` when cold (carry panics "cost");
   subtract from `I+0x188` (borrow -> 0x20). If `H+0x265 & charged` apply the refund counters `I+0x190/0x198` with `P+0x158` (saturating signed add, second borrow -> 0x20).
   Return 3; unless the kind byte is 2 add `P+0xb8` to `I+0x1a0` (signed overflow panics "refund").

### KECCAK256

Pops offset (top) and length; one stack slot is consumed and the hash replaces the length slot. Length limbs 1..3 nonzero -> 0x24 (before gas). Gas = ceil(len/32) * `P+0x48`
(multiply overflow = 2^64-1); borrow -> 0x20. Length 0 returns the constant above. Offset limbs 1..3 nonzero -> 0x24. Memory words needed = ceil(min(offset+len, 2^64-1)/32); above `I+0x170` the resize
helper runs and a nonzero result is returned as is. Carries in offset+len (panic "end"), offset+`I+0x18` ("base") and `I+0x18`+offset+len ("span") panic, the last two after the
borrow counter `[I+0x10]+0x10` was incremented (the counter stays incremented on those panics). The slice at `[I+0x10]+0x20 + I+0x18 + offset` is absorbed whole blocks first (length >= 0x88),
the remainder is copied (skipped when it is 0) into a 0x88-byte buffer, padded with 0x01 at the end and 0x80 on the last byte, absorbed and squeezed to 32 bytes; the digest is stored big-endian.

### Files

- `cases.tsv`: every 2nd of the 10,200 cases (all are compared; a mismatch would always be listed): label, input summary, outcome class, result with a state digest over all modelled regions, match flag.
- `outcome-classes.tsv`: 42 outcome classes with counts (each branch family of both handlers is reached: success with every event combination, 0x20 / 0x24 / 0x28 / 0x2c returns, loader-fail, resize error codes, both panic helpers).
- `negative-controls.tsv`, `coverage.tsv` (executed / decoded instructions), `constants.json` (FDEs, SHA-256 of each body, call roles, opcode slots, offsets), `summary.json`, `measure.json`.

## Implementation and comparison

Independent pure-Python reconstruction (`sd_model`, `kc_model`, `keccak_f`, `find_slot`, `satadd`) that works on byte copies of the same regions the evaluator sees (interpreter, host,
params, account, balance map, journal, list, stack, memory object, data) and predicts the return byte, the panic helper and its message string, the ordered stub events and the final bytes of every region.
A case passes only when all of these equal the evaluator's result and the callee-saved registers and stack pointer are restored. Cases: 4,200 per SELFDESTRUCT copy and 1,800 KECCAK256, drawn
from deterministic SHA-512 streams over spec/fork bytes, static flag, stack depth, same/different beneficiary, loader status, account shapes, balance carry patterns (2^64, 2^128, 2^192, 2^256-1),
flag bytes, hashbrown sizes 4..32 with h2-colliding decoys, missing keys, zero item counts, journal/list capacity == length, gas edges and overflow values. Rust is not implemented here.

Negative controls (50): 9 SELFDESTRUCT and 5 KECCAK256 wrong models; 15 corrupted code bytes in copy A, 6 in copy B and 12 in KECCAK256 (static test, loader status, fork bounds, h2 shift, bucket stride, flag masks, gas field offsets,
result bytes, padding bytes, rate, thresholds); a flipped `.text` byte, an address past `.text`, and a corrupted KECCAK_EMPTY constant. All 50 are detected (`negative-controls.tsv`).

## Results and limitations

- 10,200 cases, 0 mismatches, 50/50 controls, 42 outcome classes; executed instructions 556/570 (both SELFDESTRUCT copies) and 176/186 (KECCAK256). The unexecuted instructions were not analysed further.
- Stubbed callees (bodies not evaluated, behaviour assumed only as far as the handlers observe it): loader, transfer, burn, journal/list grow, resize, absorb/squeeze (a Python Keccak-f), memcpy, memset, panic helpers.
  Assumptions that the model encodes about them: grow adds 4 to the capacity word, resize on success stores the new word count at `I+0x170`, absorb returns the unconsumed byte count.
- Opcode names (SELFDESTRUCT / KECCAK256), "touch / destruct / transfer" journal kind names and flag meanings are inferences from the table position and the observed behaviour; no reference source was used.
- Unwritten tail bytes of journal entries keep the host fill; the six padding bytes of kinds 1/4 depend on stack contents of the real caller and are not claimed to be constant in a live node.
- No Rust build and no gate request: the component gate needs the whole `evm` scope.

Next question: the loader 0x5463980 / 0x4323870 and the transfer 0x29714f0 / burn 0x2970eb0 bodies (what they write for the journal rollback), then the two 2160-byte hosts 0x546c330 / 0x4335cf0.
