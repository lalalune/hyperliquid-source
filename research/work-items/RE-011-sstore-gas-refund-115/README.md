# RE-011: reconstruct the SSTORE handler 0x2994990, its twin 0x2994490, cost 0x299f910 and refund 0x299f680 (node #115)

This packet lets you rebuild how node #115 prices and refunds an EVM `SSTORE` from start to end. The instruction handler
`0x2994990` and its position twin `0x2994490` are now a runnable pure-Python function `model()`. It covers the static-frame
and stack checks, the EIP-2200 sentry, the static charge, the skip flag passed to the store, the store-error codes, the cost
`0x299f910` (pre-spec-6 set/reset price; from spec 6 a cold surcharge plus set/reset), the refund `0x299f680` (clear,
un-clear, restore-to-original), and a host-gated **reserve accounting for slots created from zero** (interpreter `+0x190` /
`+0x198`, params `+0x150`) that is not part of upstream EVM pricing. The model matches the real machine code in 5,200 of
5,200 cases (2,600 per handler), and 28 of 28 negative controls are detected.

- Component ID: `evm` (task RE-011, EVM execution / state access)
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: main `a1a8d54318c2713c0d4b874053e5eb62b7ee9b11`; no reference source was copied
- Claim status: observation (bytes, extents, relocations, evaluated behaviour) plus inference. The names "SSTORE handler",
  "sentry", "cold surcharge", "set/reset price", "refund", "reserve accounting" and "spec" are inferred roles matched against
  the EIP-2200/2929/3529 shape. They are not recovered symbols.
- Scope included: the handler `0x2994990..0x2994e87`, the twin `0x2994490..0x2994987`, the cost `0x299f910..0x299fa60` and
  the refund `0x299f680..0x299f90d`. All four are executed as real code.
  Scope excluded: the storage stores `0x2977910` / `0x2977cd0`, which the open RE-011 warm/cold packet (#3343) covers. Here
  they are stubbed: each call's arguments are checked and recorded, and the stub writes an explicit 0x68-byte result. The
  overflow panic entries behind GOT `0x64df520` / `0x64df848` are a boundary. There is no Rust implementation, and no gate
  is requested.

## Reproduce

From the repository root with Python 3 (standard library only, no binutils, nothing is executed):

```
python3 tools/re11_sstore_gas115.py --out research/work-items/RE-011-sstore-gas-refund-115
python3 -m unittest tests.test_re11_sstore_gas115
```

The tool checks the input SHA-256 first and fails on any other digest. It reads sections with `tools/elf_index.py` and FDE
extents with `tools/fde_extents.py`, and it applies `.rela.dyn` RELATIVE addends to the GOT words it follows. The real code
bytes run on an in-file concrete x86-64 evaluator, and unknown instruction forms raise an error. This evaluator is the one
from the earlier RE-011 packets, extended with OF for add/sub/neg and with `sar`. Two runs with different
`PYTHONHASHSEED`/`TZ` and a binutils-free `PATH` produced byte-identical output. A full run takes under a minute.
`MANIFEST.sha256` lists the hashes of the outputs.

## Evidence

Coordinates are virtual addresses in node #115; `.text` VA equals the file offset plus the section delta read from the
section header. Every row of `constants.json` is re-read from the ELF bytes on every run.

- FDE extents (`constants.json` → `functions`): `0x2994990` and `0x2994490` 1,271 bytes / 288 instructions each,
  `0x299f910` 336 / 105, `0x299f680` 653 / 187.
- Direct calls (`handler_direct_calls`): the handler calls `0x2977910` twice, plus `0x299f910` and `0x299f680`. The twin
  makes the same calls, except that both store calls go to `0x2977cd0`.
- `twin_operands`: the two handlers differ only in the trailing rel32/disp32 of 6 instructions. Resolved, these 6 operands
  name the same targets, except the store pair `0x2977910 → 0x2977cd0`.
- Panic slots: `0x64df520 → 0x1681da0` and `0x64df848 → 0x1681e40` (both RELATIVE).
- ABI observed: `rdi` is the interpreter, with:
  - `+0x28` stack pointer and `+0x30` length (32-byte words);
  - `+0x78` the address passed to the store;
  - `+0x188` gas remaining;
  - `+0x190` reserve (u64) and `+0x198` reserved (i64);
  - `+0x1a0` refund (i64);
  - `+0x1a8` static byte and `+0x1a9` spec byte.

  `rsi` is the host, with `+0x250` the gas-parameter table and `+0x265` the reserve-accounting flag. The result is in `al`.
- Store result read by the handler (0x68 bytes): `original` (0x00), `present` (0x20), `new` (0x40), then byte 0x60 =
  cold (0/1), where 2 means error. On an error, byte 0 bit 0 is the error kind.

Hand excerpt (from objdump, for reading only; the evidence files do not use it):

```
29949a1  cmpb $0x0,0x1a8(%rdi)     ; static -> al = 0x28
29949b7  cmp  $0x2,%rcx            ; stack length < 2 -> al = 0x2c
2994a15  cmp  $0x5,%bpl            ; spec > 5: gas must exceed params+0xc0, else al = 0x25
2994a47  sub  0x98(%rcx),%r15      ; static charge (borrow -> 0x20, gas not written)
2994a68  cmp  0xc8(%rcx),%r15      ; spec > 6: skip flag r9 = gas < params+0xc8
2994a8e  call 2977910              ; store (twin: 2977cd0)
2994bcf  call 299f910              ; cost (params, spec >= 6, &result, cold)
2994bf0  cmpb $0x0,0x265(%r14)     ; reserve accounting enabled?
2994e13  call 299f680              ; refund; add to +0x1a0, jo -> panic
```

Reconstruction (`model`, `sstore_cost`, `sstore_refund` in the tool). All of it is confirmed by evaluation:

1. Result codes: `0x28` static, `0x2c` stack < 2 (the length is not changed), `0x25` sentry, `0x20` out of gas, `0x36` store
   error. From spec 7, a store error whose kind bit is clear gives `0x20` instead of `0x36`. Up to spec 6 the skip flag is
   always 0. Key = top of stack, value = next; the stack length drops by 2 before any gas check.
2. Cost, before spec 6: `params+0xa0` if present == 0 and new != 0, else `params+0xa8`. The cold byte is ignored.
   Cost, from spec 6: `cold ? params+0xd0 : 0`. Add `params+0xa0` (original == 0) or `params+0xa8` (original != 0) only when
   new != present and original == present; a carry panics. A no-op store and a dirty slot pay only the cold part; the warm
   read price is already inside the static charge `params+0x98`.
3. Refund, before spec 6: `params+0xb0` if present != 0 and new == 0, else 0.
   Refund, from spec 6, where c = `params+0xb0` as i64:
   - new == present gives 0.
   - original == present and new == 0 gives c.
   - Otherwise start from 0. If original != 0: present == 0 gives −c (−i64::MIN panics), and new == 0 gives +c. Then, if
     original == new, add `params+0x138` (original 0) or `params+0x140` (original != 0); i64 overflow panics.
4. Reserve accounting runs only when host `+0x265` != 0 and new != present.
   - A slot created from zero (original == present == 0) needs q = `params+0x150`. If reserve >= q: reserve −= q. Otherwise
     the shortfall is charged to gas (out of gas → `0x20`, reserve fields unchanged) and reserve = 0. In both cases
     reserved = saturating_add_i64(reserved, q).
   - A slot restored to zero (original == new == 0, present != 0) with q != 0 gives reserved = saturating_sub_i64(reserved,
     q) and reserve = saturating_add_u64(reserve, q).
5. The refund delta is added to `+0x1a0` as i64. Overflow panics through `0x64df520`.

## Implementation and comparison

The independent Rust implementation is not yet implemented. The executable reconstruction is `model()` in
`tools/re11_sstore_gas115.py`. Each case builds synthetic memory for the interpreter (other bytes 0x33), the host (0x44), the
parameter table (0x55) and the stack words. It then runs the real bytes from the handler (even cases) or the twin (odd
cases), with `0x299f910` and `0x299f680` executed. Five things are compared with the model:

- the result byte, or the panic;
- the store call: target, interpreter offset, key, value and skip flag;
- the five written interpreter fields;
- the callee-saved registers and stack pointer;
- every other byte of the interpreter, host, parameters and stack, which must stay unchanged.

Case generation (`all_cases`, a seeded SHA-256 stream) mixes several modes: generic, fresh slots, restores to zero,
extreme parameters (`2^64−1`, `2^63`, `2^63−1`, 0), store errors, and a restore-overflow mode. Gas values sit near each
threshold ±4. Reserve, reserved and refund values sit at 0, the parameter value, the saturation edges and random values.

Negative controls (`negative-controls.tsv`, 28/28 detected):

- 12 wrong reconstructions: swapped pop order, sentry from spec 5, store error always `0x36`, pre-spec-6 price ignoring
  present, no cold surcharge, no-op charged, dirty charged, set/reset swapped, no negation, no restore refund, reserve
  shortfall not charged to gas, no release on restore.
- 14 single-byte code mutants: result codes, sentry threshold, params offsets `+0x98`/`+0xc8`/`+0x150` (twice)/`+0xb0`/
  `+0x138`/`+0xd0`/`+0xa8`, flag byte `+0x265`, plus two in the twin.
- 2 input controls: one flipped `.text` byte (digest rejected), and an address past `.text`.

## Results and limitations

- `summary.json`: 5,200 cases, 0 mismatches. Executed instructions: `0x2994990` 288/288, `0x2994490` 288/288, `0x299f910`
  105/105, `0x299f680` 185/187.
  The 2 missed instructions are the `params+0x138` overflow panic `0x299f8e2..0x299f8e9`. It is unreachable: the
  `+0x138` arm runs only when original == 0, and then the running refund is 0, so adding a u64-as-i64 cannot overflow.
- Outcome heads (from `outcome-classes.tsv`): ok 1,703, out of gas 1,284, store error 711, sentry 704, underflow 396,
  panic 207, static 195.
- Limits:
  - The stores `0x2977910` / `0x2977cd0` are boundaries, modelled by their result layout. That the twin's store writes the
    same layout is inferred from the byte-identical handler, not proven here.
  - The gas parameter values are synthetic. Which spec byte value is which hard fork, and the parameter values the
    node actually loads, are unresolved.
  - The meaning of the reserve accounting (`+0x190`/`+0x198`/`params+0x150`) is described by behaviour only.
- No PROGRESS gate is requested.
- Next question: who fills host `+0x265` and the parameter table `+0x150`, and where are interpreter `+0x190`/`+0x198`
  settled at the end of a frame?
