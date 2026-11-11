# RE-011: reconstruct node #115 EVM BLOCKHASH cache and CREATE/CREATE2 frame setup

With this packet you can rebuild two node #115 EVM opcode families as runnable code. The first is BLOCKHASH
(opcode `0x40`) in both compiled copies: `0x2995350` inlines a hashbrown block-hash cache, and `0x29951e0` calls the
provider directly. The second is CREATE (`0x299bea0`) and CREATE2 (`0x299b760`), from the stack pops to the boxed
0xc8-byte create-inputs record that replaces the pending action. For BLOCKHASH the reconstruction covers:

- the exact 256-block window on a u256 block number and the saturating u64 conversion;
- the cache hash, probe, reserve, insert slot and growth/item bookkeeping.

For CREATE/CREATE2 it covers:

- the static and spec gates, and the operand pops;
- the initcode limit (three sources) and the initcode charge;
- memory growth and the init-code copy into `Bytes`;
- the base and hashing charges, the reservoir step and the gas kept in the parent;
- the record layout.

One tool, sharing one ELF reader, one x86-64 evaluator, one case stream and one output tail, proves both
reconstructions against the real machine code:

- 10,800 cases (4,800 BLOCKHASH + 6,000 CREATE/CREATE2), 0 mismatches;
- 57/57 negative controls detected.

- Component ID: `evm` (task RE-011, EVM interpreter opcodes)
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: main `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. No reference source was used
  or copied.
- Claim status:
  - **Observed** (evaluated from the target bytes):
    - opcode-table slots, FDE extents and pinned byte strings;
    - GOT call targets, `Bytes` vtables and their drop entries, and panic location records;
    - every compared case result.
  - **Inferred**:
    - the opcode names BLOCKHASH / CREATE / CREATE2;
    - reading `host+0x30` as the current block number and `0x43c8b20` as the block-hash provider;
    - reading `0x4efb820` as hashbrown `reserve_rehash` and the `+0x68..+0x90` header as a provider-answer cache;
    - the CREATE field roles ("initcode word price", "reservoir", "keep divisor") and the struct reading of the
      boxed record as create inputs.
  - **Unresolved**:
    - the bodies of the provider `0x43c8b20`, the memory-growth callee `0x45244c0` and the old call-inputs drop
      `0x29e15d0`;
    - the meaning of the 24 BLOCKHASH key bytes after the number (compared, not hashed, written as zero);
    - why two BLOCKHASH copies exist;
    - live parameter-block values, and the names of the spec enums.
- Scope:
  - Included:
    - BLOCKHASH `0x29951e0` (100 instructions) and `0x2995350` (220);
    - CREATE `0x299bea0` and CREATE2 `0x299b760` (767 instructions together);
    - their FDE extents and the opcode-table slots;
    - every GOT slot they call through, and the BLOCKHASH hash seed slot.
  - Excluded: the callee bodies listed under unresolved (contract stubs record or check their arguments), the
    dispatcher that charges the static gas, and the child frame that consumes the create action. No component gate
    is advanced.

## Reproduce

From the repository root, with the Python 3 standard library only:

```
python3 tools/re11_blockhash_create115.py --out research/work-items/RE-011-blockhash-create-frame-115
python3 -m unittest tests.test_re11_blockhash_create115
cd research/work-items/RE-011-blockhash-create-frame-115 && sha256sum -c MANIFEST.sha256
```

- The tool checks the input SHA-256 first.
- It reads sections, `.rela.dyn`, `.dynsym`/`.dynstr` and `.eh_frame` through `tools/elf_index.py` and
  `tools/fde_extents.py`.
- It never runs the binary or any external program.
- It exits non-zero on any mismatch or on any undetected control.
- The two families run in two processes (`--workers 1` runs them serially with the same output). A full run takes
  about 25 s.
- `--full` keeps every case row. The committed `*-cases.tsv` files hold the header plus every 8th row. The SHA-256 and
  row count of each full listing are pinned in `summary.json` → `full_listings`.
- Two runs with different `PYTHONHASHSEED`, `TZ`, worker count and an empty `PATH` gave byte-identical output.

## Evidence

All addresses are node #115 virtual addresses. Every byte string the reconstructions rely on is re-read from the file.
Those strings are listed in `blockhash-constants.json` → `checked_bytes` and `create-frame-constants.json` →
`pinned_bytes`.

| File | Content |
| --- | --- |
| `summary.json` | totals, the shared opcode-table check, and per-family summaries and full-listing pins |
| `blockhash-constants.json` | opcode slots, GOT calls, hash seed slot, checked bytes, function extents |
| `blockhash-decoded-instructions.tsv` | 320 decoded BLOCKHASH instructions, all executed |
| `blockhash-cases.tsv` | 600 of the 4,800 BLOCKHASH cases (every 8th) |
| `blockhash-outcome-classes.tsv`, `blockhash-negative-controls.tsv` | 12 outcome classes; 24 controls |
| `create-frame-functions.tsv` | FDE extents and code SHA-256 of both CREATE bodies |
| `create-frame-constants.json` | table slots, 40 pinned byte strings, GOT targets, vtables, panic locations, field offsets, result codes, gates |
| `create-frame-decoded-instructions.tsv` | 767 decoded CREATE/CREATE2 instructions with an executed / why-not label |
| `create-frame-cases.tsv` | 750 of the 6,000 CREATE/CREATE2 cases (every 8th) |
| `create-frame-outcome-classes.tsv`, `create-frame-negative-controls.tsv` | 55 outcome classes; 33 controls |

### Shared dispatch

The RELATIVE opcode tables are indexed by the opcode, and the SLOAD slot (`0x54`) anchors each base. The tool checks
that both families read the same two tables (`summary.json` → `shared_opcode_tables`):

| Table | `0x40` BLOCKHASH | `0x54` SLOAD | `0xf0` CREATE | `0xf5` CREATE2 |
|---|---|---|---|---|
| `0x6441210` | `0x2995350` (cached) | `0x2993ff0` | `0x299bea0` | `0x299b760` |
| `0x6441f00` | `0x29951e0` (direct) | `0x2993bd0` | `0x299bea0` | `0x299b760` |

### BLOCKHASH, shared front part (both copies)

1. An empty stack (`[rdi+0x30]==0`) returns `0x2c`.
2. The handler computes `cur(host+0x30..+0x50) - top` with a borrow chain. Each of these writes zero to the top and
   returns 0:
   - a borrow;
   - a nonzero high distance limb;
   - a zero distance;
   - a distance `>= 0x101`.
3. Otherwise the number handed on is `top` limb 0, or `u64::MAX` when limbs 1..3 are nonzero (`cmove`). This case is
   reachable only when `cur >= 2^64` (classes `*/saturated`).

### BLOCKHASH direct copy `0x29951e0`

It calls `*GOT[0x64e6450]` (→ `0x43c8b20`) as `(out, [host+0x398], number)`. The four limbs of the answer are
byte-swapped in reverse order into the stack top, so `word = int.from_bytes(answer, "big")`. The handler returns 0.

### BLOCKHASH cached copy `0x2995350` (`C = [host+0x398]`)

1. Hash: `h = fold(fold((number ^ C[+0x88]) * seed) * seed)`, where `fold(x) = lo(x) ^ hi(x)`. `seed` is the word
   behind GOT `0x64dfa78` → `0x64ffe90` (NOBITS, so the tool supplies it).
2. Probe: SSE2 hashbrown with `h2 = h >> 57`, ctrl `C[+0x68]`, mask `C[+0x70]` and 0x40-byte buckets. The 32-byte key
   at bucket `-0x40` is compared with `(number, 0, 0, 0)`. A hit returns the 32 bytes at `-0x20`.
3. Miss:
   - If growth_left `C[+0x78]` is 0, it first calls `*GOT[0x64e6df0]` (→ `0x4efb820`) as `(C+0x68, 1, C+0x88, 1)`.
   - Then it calls the provider as `(out, C[+0x90], number)`.
   - It takes the first EMPTY/DELETED byte on the triangular probe, with a group-0 fix-up (`0x29956a0`) for tables
     under 16 buckets.
   - It writes `h2` to the byte and its mirror `((i-16)&mask)+16` and subtracts `old & 1` from growth_left.
   - It stores `(number, 24 zero bytes, answer)` and increments items `C[+0x80]`.

### CREATE / CREATE2 (`0x299bea0` / `0x299b760`, interpreter in `rdi`, host in `rsi`)

1. `interp+0x1a8 != 0` (static) returns `0x28`. CREATE2 only: spec byte `interp+0x1a9 <= 4` returns `0x2b`.
2. Fewer than 3 stack words returns `0x2c`. Otherwise value, offset and length are read, and the stack length is
   lowered by 3 **before** any operand check. A length with a high limb set returns `0x24`.
3. The init code starts as the empty static `Bytes` (vtable `0x6441d98`). Length 0 skips steps 4-7.
4. When spec `> 9`:
   - Limit:
     - `host+0x218` if `host+0x210 != 0`;
     - else `0xc000` (`0x10000` when `host+0x268 >= 0xe`) if `host+0x200 != 1`;
     - else `2 * host+0x208`, with no limit when its top bit is set.
   - `length > limit` returns `0x35`.
   - The charge is `ceil(length/32) * params+0x60` (saturating); short gas returns `0x20`.
5. An offset with a high limb set returns `0x24`. Memory growth goes through GOT `0x64e6de0` → `0x45244c0`; a
   non-zero result byte is returned as is.
6. Overflow panics: an `offset+length` carry panics at `0x643e110`. After the borrow counter `memory+0x10` is
   raised, `base+offset` / `base+offset+length` carries panic at `0x64bfc68` / `0x64bfc80`.
7. `malloc(length)` (null → allocation error `(1, length)`), then `memcpy`, then the static `Bytes` is dropped. The new
   `Bytes` vtable is chosen by pointer parity (GOT `0x64df8c0` / `0x64df8c8`).
8. CREATE2 pops the salt **now**: with exactly 3 words it returns `0x2c` after the limit, growth and copy. The charge
   is `params+0x68` plus, for CREATE2, `ceil(len/32) * params+0x48`.
9. Reservoir step when `host+0x265 == 1`: `params+0x168` against `interp+0x190`, with a signed saturating
   `interp+0x198`.
10. When spec `> 1`, the child gets `gas - gas / params+0x70` (a zero divisor panics at `0x6443898`).
11. `malloc(0xc8)` and the record: `+0x00` tag, `+0x08` salt, `+0x28` `Bytes`, `+0x48` value, `+0x68` gas, `+0x70`
    reservoir, `+0x78` caller.
12. The old action is dropped by tag `interp+0x110` (`0x38` = none). Then `interp+0xb8 = 2`, `interp+0xc0 = box`, and
    the result is `4`.

Excerpt for readers (objdump, not part of the generated evidence):

```
299542e: 49 81 fb 01 01 00 00   cmp    r11,0x101        ; BLOCKHASH distance window
29955dc: 49 29 75 78            sub    [r13+0x78],rsi   ; growth_left -= old & 1
```

## Implementation and comparison

The reconstructions are pure Python in `tools/re11_blockhash_create115.py`; no Rust implementation exists yet.

- BLOCKHASH (`bh_` prefix): `bh_model()`, `bh_window()`, `bh_number_hash()`, `bh_insert_slot()`, `bh_ctrl_layout()`.
  The tool lays out real hashbrown tables of 4..64 buckets with the reconstructed hash. The tables include decoys
  (same number with a padding bit, same h2 with another number), tombstones, crowded groups and growth_left 0.
- CREATE/CREATE2 (`cr_` prefix): `cr_model()`, with contract stubs for the allocator, `memcpy`, memory growth, `Bytes`
  drops, the old-action drop and panics.
- Shared core: the ELF `Image`, decoder, `Machine` evaluator and `Stream`. The CREATE core is a strict superset of the
  BLOCKHASH core, so it serves both families; it adds `lock`, `xchg`, `div`, `bt`, `shld`/`shrd`, `bsr`, `por`,
  `andps`/`orps`, `movmskps` and the signed conditions. `shared_layout()` checks the common opcode tables.
- Proof that the shared core changes nothing: every family output of the merged tool (constants, decoded
  instructions, outcome classes, controls, and the full case listings by SHA-256) is byte-identical to the
  output of the separate per-family tools it replaces.
- What a BLOCKHASH case compares:
  - the result byte, the stack length and top, and the provider/reserve calls with their arguments;
  - growth_left, items and every table byte;
  - the callee-saved registers and `rsp`;
  - every other interpreter, host, cache and stack byte.
- What a CREATE case compares:
  - the result code or noreturn helper, every interpreter byte and the borrow counter;
  - the copied buffer, the defined record bytes and the ordered callee calls with arguments;
  - the untouched host, parameter, memory, old-record and stack bytes;
  - the callee-saved registers and `rsp`.

### Negative controls (57, all detected)

- BLOCKHASH (24):
  - 11 model mutants: window 255, serving the current block, truncating instead of saturating, keeping the top out of
    the window, never hitting, ignoring the key padding, always reserving, no small-table fix-up, growth always
    decremented, a little-endian result, and a hash without the secret;
  - 11 one-byte code mutants;
  - 2 input controls.
- CREATE/CREATE2 (33):
  - 14 model mutants, for example a limit not doubled, an inclusive limit, floor words, no hashing cost, a wrapping
    counter, and a 64-bit old-action tag compare;
  - 17 code-byte mutants (two are detected by leaving the stub contract);
  - 2 input controls.
- The unit tests also move one BLOCKHASH, one CREATE2 and one SLOAD opcode-table slot and check that the shared
  layout check rejects each.

## Results and limitations

- `summary.json`: 10,800 cases, 0 mismatches, 57/57 controls detected.
  - BLOCKHASH: 4,800/4,800 cases in 12 outcome classes, with 320/320 instructions executed.
  - CREATE/CREATE2: 6,000/6,000 cases in 55 classes. 672/767 instructions are executed; the other 95 are labelled
    from bytes:
    - 86 are `ud2` or landing pads;
    - 8 are after noreturn calls;
    - 1 is CREATE2's `spec <= 1` arm, which its `spec <= 4` gate makes unreachable.
- Unit tests: 29 OK, 0 skips (`tests/test_re11_blockhash_create115.py`).
- Findings for the Rust port:
  - CREATE2 checks only 3 stack words up front. With exactly 3 it still runs the initcode charge, growth and copy, and
    only then returns `0x2c` (55 cases).
  - BLOCKHASH never serves the current block, and saturates block numbers `>= 2^64` to `u64::MAX` before the cache.
- Limits:
  - The BLOCKHASH seed word is NOBITS (tool-supplied). The reserve stub does not rehash.
  - The CREATE growth result is case-chosen.
  - Undefined record padding is not compared.
  - Parameter values are case inputs, not live chain values.
  - No gas is checked in the BLOCKHASH bodies.

## Next question

What do the two callees beyond this packet do? For the provider `0x43c8b20`: in which order does it consult the
`+0x1b20..+0x1b38` ring and the `0x35bf5a0` lookup? For the boxed create action (action word 2): which caller
consumes it, and how does it derive the CREATE / CREATE2 address from the scheme tag and salt?
