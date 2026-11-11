# evm: send_to_evm_data pretty-JSON path, its four entry writers, three itoa bodies and serde_json helpers (node #115)

This packet reconstructs, as an executable Python model checked against the real bytes, the pretty-JSON
serialization of the `send_to_evm_data` struct in node #115: the struct body `0x22f2810`, its four out-of-line
entry writers (u32 `0x25ac6f0`, u64 `0x2590810`, u64 `0x25a3fb0`, bytes `0x2591f70`), the three decimal writers they
call (u32 itoa `0x243bf10`, u64 itoa `0x25fba40` and its rip-relative copy `0x2caca90`), and serde_json's key writer,
string escaper and `end_object`. A Rust port can now reproduce byte for byte the JSON object of this struct (key
order `destination_recipient`, `destination_chain_id`, `gas_limit`, `nonce`, `data`; struct offsets `+0x20`,
`+0x50`, `+0x40`, `+0x48`, `+0x00`), every reserve call, the 32-bit width of `destination_chain_id` (junk in the
upper half of its qword is ignored), the fact that `data` is written through a callee whose result the entry
ignores, and the state left behind by the only failing value (the recipient serializer: no `}`, `current_indent`
still raised, `has_value` still 0). It also corrects the earlier reading of `0x22f2810` as a "bytes JSON serializer":
the `Some` arm of the L1ToEvm record's `send_to_evm_data` is this five-field struct.

- Component ID: `evm` (docs/COMPONENTS.md); no gate change requested.
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: lalalune/hyperliquid-source `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.
  No reference source was used. Key names come from the binary's own texts (rip-relative `lea rsi` targets read
  with the following `mov edx, imm32` length).
- Claim status: observation for every table row and case result (bytes and tool output); inference for the Rust
  names (`SerializeStruct::serialize_field`, `SerializeMap::serialize_key`, `format_escaped_str_contents`,
  `PrettyFormatter::end_object`, `RawVec::reserve`, serde_json `Error::syntax`); unresolved items are listed below.
- Scope included: 11 FDE-bounded functions, all run REAL by the evaluator:

  | function | role | bytes |
  |---|---|---|
  | `0x22f2810` | send_data_json (struct body) | 519 |
  | `0x25ac6f0` | entry_chain_u32 | 251 |
  | `0x2590810` | entry_gas_u64 | 258 |
  | `0x25a3fb0` | entry_nonce_u64 | 251 |
  | `0x2591f70` | entry_data_bytes | 147 |
  | `0x26077c0` | serialize_key | 520 |
  | `0x25bf330` | format_escaped_str_contents | 552 |
  | `0x232b070` | end_object | 311 |
  | `0x243bf10` | u32_itoa | 321 |
  | `0x25fba40` | u64_itoa | 322 |
  | `0x2caca90` | u64_itoa_copy | 322 |

  Instruction counts and reached counts per function are in `functions.tsv`. `serialize_key`,
  `format_escaped_str_contents`, `end_object` and the itoa bodies are shared library code; they run as dependencies
  of this path (their bytes decide its output), get their own direct cases and byte-flip controls, but only their
  behaviour as used here is claimed. `0x243bf10` is disassembled in `RE-012-snapshot-priority-u32-format-115` and
  `0x25fba40` in `RE-012-snapshot-followup-decimal-format-115`; `0x2590810` is a call target in
  `RE-009-node115-state-output-format`. This packet adds their executable models and direct cases, not new owner
  claims. `0x2caca90` (free) differs from `0x25fba40` only in rip-relative displacements and reads its own copy of
  the digit-pair table.
- Scope excluded (recording contract stubs, `callees.tsv`): `RawVec::reserve` `0x231e050`, the recipient JSON
  serializer `0x298c400` (named in RE-002 records), the bytes writer `0x25ce7e0` (named in RE-001 caller lists),
  `memcpy` (GOT `0x64df508`), the serde_json error constructor (GOT `0x64e0b08`) and the three panic entries (GOT
  `0x64df520` add overflow, `0x64df730` unreachable, `0x64df848` sub overflow).

## Reproduce

From the repository root, with the node #115 binary at `artifacts/node/115/hl-node` (Python 3 standard library and
the shared `tools/fde_extents.py` / `tools/elf_index.py` parsers only; no binutils, no subprocess, the binary is
read, never executed):

```
python3 tools/send_to_evm_data_json_115.py --out research/work-items/evm-send-to-evm-data-json-115
python3 -m unittest tests.test_send_to_evm_data_json_115
```

The tool checks the input SHA-256 first and fails on any other binary. It regenerates every `.tsv`/`.json` file
here byte for byte (two runs with `PYTHONHASHSEED`/`TZ` = 0/UTC and 987/Asia/Seoul, PATH without binutils, were
compared with `diff -r`). `--scale 0.1` runs a 1,500-case subset for quick checks; the committed files use the
default scale 1.0. `cases-sample.tsv` keeps every 5th case of each group; all 15,000 case results are hashed into
`summary.json` (`all_cases_sha256`).

## Evidence

All addresses are node #115 virtual addresses. The tool maps every VA to a file offset through the section headers
(`tools/elf_index.py`, skipping `SHT_NOBITS`) and takes function extents from `.eh_frame` FDEs
(`tools/fde_extents.py`).

How the path was found: the L1ToEvm JSON body `0x22ea830` hands its `send_to_evm_data` `Some` arm to `0x22f2810`
(through `0x2598140`). Its direct calls give the four entry writers; each entry writer calls one decimal writer or
the bytes writer. An ownership scan of the research tree and of the open/merged PR file lists finds none of
`0x22f2810`, `0x25ac6f0`, `0x25a3fb0`, `0x2591f70`, `0x2caca90`.

### The struct and its entries (fields.tsv)

| # | key (text VA, len) | value | struct offset | written by |
|---|---|---|---|---|
| 0 | `destination_recipient` (`0x5eae24`, 21) | recipient | `+0x20` | body: key writer, `": "`, `0x298c400` |
| 1 | `destination_chain_id` (`0x5eae39`, 20) | u32 | `+0x50` | `entry_chain_u32` `0x25ac6f0` -> `0x243bf10` |
| 2 | `gas_limit` (`0x5eae4d`, 9) | u64 | `+0x40` | `entry_gas_u64` `0x2590810` -> `0x25fba40` |
| 3 | `nonce` (`0x5ea968`, 5) | u64 | `+0x48` | `entry_nonce_u64` `0x25a3fb0` -> `0x2caca90` |
| 4 | `data` (`0x45a158`, 4) | Vec<u8> (ptr `+0x08`, len `+0x10`) | `+0x00` | `entry_data_bytes` `0x2591f70` -> `0x25ce7e0` |

### Rules taken from the bytes

- Body `0x22f2810`: `current_indent` (`+0x18`) `cmp $-1; je` -> add-overflow panic (Location `0x642dc18`) before
  any write; `current_indent + 1`; `has_value` (`+0x20`) = 0; `{` (reserve 1 when full); local compound =
  `movw $0x100` (Map, First); recipient inline: key writer, `": "` (reserve 2 when `cap - len <= 1`),
  `0x298c400(&struct+0x20, ser)`; `rax != 0` returns it at once, else `has_value` = 1. Then the four entry writers
  with `(compound, key, len, &field)`; after each of the chain/gas/nonce entries `cmpb $0, state; jne` -> serde_json
  error constructor `(&10, 0, 0)` (unreachable: nothing writes the local state byte). At the end `testb $1, state`
  / `cmpb $0, first` -> `end_object(&ser.indent, vec)` (always taken after five keys), `rax` = 0.
- Integer entries `0x25ac6f0` / `0x2590810` / `0x25a3fb0`: key writer; `cmpb $1, state; je unreachable!()` (never
  fires, the key writer already panicked); `": "`; itoa into a stack buffer; reserve `len` when
  `len > cap - len`; memcpy; `has_value` = 1; `rax` = 0. `0x25ac6f0` loads the field with `mov edi, [r14]`
  (32 bits).
- Data entry `0x2591f70`: key writer, `": "`, `0x25ce7e0(ptr = [field+8], len = [field+0x10], ser)`; the returned
  `rax` is not read; `has_value` = 1; `rax` = 0.
- u32 itoa `0x243bf10`: 10-byte buffer, 4-digit chunks while the value is >= 10,000 (reciprocal constant
  `0xd1b71759`), pairs from the table `0x5ee1da`; returns `(buf + 10 - n, n)`.
- u64 itoa `0x25fba40` / `0x2caca90`: 20-byte buffer, 4-digit chunks (`mul` by `0x346dc5d63886594b`, `shr 11`), pairs
  from `0x5f1383` / `0x60ec25`; returns `(buf + 20 - n, n)`. All three pair tables equal `"00".."99"`.
- Key writer `0x26077c0` and escaper `0x25bf330` as in the L1ToEvm JSON packet: state `== 1` -> `unreachable!()`;
  First `== 1` -> `"\n"`, else `",\n"`; indent x `current_indent`; `"` escaped key `"`; ESCAPE table (GOT
  `0x64e13d8`, 34 non-zero entries), `\u00XX` with lowercase hex digits (GOT `0x64e13e0`).

Human-readable excerpt (objdump, not used by the tool):

```
22f281b: mov    rax,[rsi+0x18]        ; current_indent
22f2823: je     22f2a0a               ; add-overflow panic, Location 0x642dc18
22f2836: mov    byte [rsi+0x20],0x0   ; has_value = 0
22f2856: mov    word [rsp],0x100      ; Compound::Map, First
22f28b4: call   298c400               ; recipient value
22f28c7: lea    rcx,[rbx+0x50]        ; destination_chain_id, edx = 20
22f28da: call   25ac6f0
22f28e8: cmp    byte [rsp],0x0        ; state re-check -> error code 10
22f294b: mov    rcx,rbx               ; data at +0x00, edx = 4
22f294e: call   2591f70
22f295a: test   byte [rsp],0x1
22f2960: cmp    byte [rsp+0x1],0x0
22f2973: call   232b070               ; end_object
25ac739: mov    edi,[r14]             ; u32 chain id
25ac73f: call   243bf10               ; u32 itoa
2591faf: mov    rdi,[rbx+0x8]         ; data ptr
2591fb3: mov    rsi,[rbx+0x10]        ; data len
2591fba: call   25ce7e0               ; rax ignored
2591fbf: mov    byte [r14+0x20],0x1   ; has_value = 1
```

### Callees (callees.tsv)

Every direct call, tail jump and GOT call of the 11 functions is listed with its role. `check_static` re-derives
from the bytes and asserts: the body's call order (key, recipient, chain entry, gas entry, nonce entry, data entry,
end_object), its five key texts and lengths, its struct offsets (`+0x20`, `+0x50`, `+0x40`, `+0x48`), each entry
writer's callees (key writer, then its own itoa or the bytes writer), and the byte tables against the model
(ESCAPE, hex digits, the three digit-pair tables found through each itoa's first rip-relative `lea`).

## Implementation and comparison

- Reconstruction: `tools/send_to_evm_data_json_115.py`, class `JsonFlow` (`record`, `entry_recipient`,
  `entry_int`, `entry_data`, `key`, `escape`, `indent`, `end`, `byte`, `two`, `run`) and `itoa_text`, plus
  `escape_table` (serde_json's ESCAPE table written from its definition, then compared with the bytes).
- Evaluator: the concrete x86-64 interpreter of the earlier `evm` encoder packets runs the original bytes; one
  instruction form was added for this path (`imul r, r/m` `0f af`, used by the u32 itoa).
- Inputs are seeded regions: 2 struct slots (`0xc0` bytes of hash-stream bytes; chain id, gas limit and nonce set
  from edge and random values, the upper half of the chain id qword left as junk), the serde_json pretty
  Serializer (`&Vec`, indent pointer, indent length, `current_indent`, `has_value`), the Compound (`state`,
  `First/Rest`, `&Serializer`), the key text, the indent text and the output buffer with a random prefix and
  capacity slack.
- Stubs record their arguments (value pointer or data pointer/length, serializer, error code word) and answer from
  a per-case word plan; the recipient call fails on a share of cases. The bytes writer answers random words
  (including error-looking ones) and the model requires them to be ignored. `RawVec::reserve` must be called with
  `(vec, len, additional, 1, 1)` and grows capacity by `additional + extra`; `memcpy` copies.
- Compared per case: ordered call list (every reserve with its length and size), every byte appended to the Vec and
  nothing past its length, final capacity and pointer, `rax`, the panic with its argument, the serializer bytes
  (`current_indent`, `has_value` as modelled, everything else unchanged), the compound bytes (entry cases: state,
  First/Rest), callee-saved registers and stack, and that the structs, key and indent texts are unchanged. itoa
  cases compare the digits, the untouched buffer prefix, `rax` and `rdx`.
- Cases: 15,000 from a deterministic SHA-512 stream: body 6,000, chain entry 1,500, gas entry 1,500, nonce entry
  1,500, data entry 1,500, u32 itoa 1,000, u64 itoa 1,000, u64 itoa copy 1,000. Body cases: `current_indent` 0, 1, 2,
  3, 5, `u64::MAX - 1` (empty indent) and `u64::MAX`; indents `""`, `" "`, `"  "`, `"\t"`, `"\t\t"`, `"--"`, 9 spaces
  and random 1..12-byte texts; tight capacities on every third case; prefixes up to 3,000 bytes; integers from 28
  edge values and random 1..20-digit numbers. Entry cases add compound state 0/1/2/0x80/0xff, First/Rest
  0/1/2/3/0xff and keys that hit every escape arm. u32 itoa cases put junk in the upper 32 bits of `rdi` on every
  third case.
- Negative controls: 226, all detected (`controls.tsv`): 33 wrong models (`model:*`: indent wrap instead of
  panic, hex / zero-padded digits, u64 truncated to 32 bits, u32 not truncated, chain id read as a qword, digit
  reserve threshold, `has_value` set on error / never set / not cleared, `end_object` on error / keeping the indent
  / without newline, newline always, First for any non-zero byte, `:` without space, reserve thresholds of `": "`
  and single bytes, one extra indent, upper-case hex escapes, tab as `\u0009`, DEL escaped, escape always
  reserving, key writer panicking for any non-zero state, `data` first, gas/nonce swapped, recipient at `+0x00`,
  chain id at `+0x4c`, data pointer/length swapped, bytes writer result checked, `has_value` not set by `data`,
  state re-check inverted) and 193 byte flips: one byte of every immediate operand the cases reach in all 11
  functions. Controls run on every 10th case of each group first and on every case when that subset finds no
  difference (`control_case_step` in `summary.json`). Four flips use a pattern other than bit 0 because bit 0 needs
  a witness the case streams almost never produce or is never reachable (`SITE_XOR`, commented in the tool). Two
  immediates are excluded as equivalent mutants by construction (`EQUIVALENT_SITES`, counted in `summary.json`):
  the `testb $1, state` mask before `end_object` (`0x22f295a`, the local state byte is always 0) and
  `has_value = 1` after the recipient value (`0x22f28c2`, the infallible chain entry writes 1 before any read).
  Out-of-range inputs (wrong digest, out-of-range FDE start, code outside `.text`, `.bss` reads, a changed callee,
  key length, digit-pair byte or ESCAPE entry) are rejected by the unit tests.
- Unit tests (`tests/test_send_to_evm_data_json_115.py`, 45 tests): regeneration equals the committed files,
  manifest, scale, unreached rows explained, static facts, FDE sizes, key texts and offsets, byte tables, the two
  u64 itoa copies, hand-built cases for every finding, mutants on hand cases, byte flips of `": "` and the chain
  offset, a corrupted result, and that the byte-flip sites cover every function.

## Results and limitations

- 15,000 cases, 0 mismatches (first full run matched; the evaluator gained `imul r, r/m`, and four control flip
  patterns plus one equivalent site were adjusted); 226/226 controls detected; 935 of 976 instructions of the 11
  functions reached.
- Per group (`summary.json` `per_group`): body 6,000 (5,014 ok, 296 recipient error, 690 panic, 126,971 reserve
  calls); chain entry 1,500 (1,338 ok, 162 panic); gas entry 1,500 (1,342 ok, 158 panic); nonce entry 1,500 (1,340
  ok, 160 panic); data entry 1,500 (1,329 ok, 171 panic); each itoa group 1,000 (all ok). The four entry writers
  never return an error.
- Findings:
  1. Whole object for `current_indent = n`, indent `I`, recipient text `R` and data text `D` written by the stubs:
     `{` `\n` `I*(n+1)` `"destination_recipient": R` `,\n` `I*(n+1)` `"destination_chain_id": C` `,\n` ...
     `"data": D` `\n` `I*n` `}`; integers are bare decimal digits, never quoted.
  2. Key order differs from memory order: `+0x20`, `+0x50`, `+0x40`, `+0x48`, `+0x00`.
  3. `destination_chain_id` is a u32: the entry loads 32 bits and the u32 itoa ignores the upper half of `rdi`.
  4. `data` cannot fail at this level: `0x2591f70` drops the bytes writer's `rax` and always returns Ok.
  5. Only the recipient serializer can fail; it leaves `has_value` 0 (cleared at object start), no `}`, and
     `current_indent` raised by one.
  6. The body re-checks its own compound state after three entries and only skips `end_object` for an odd state
     or an Empty First byte; none of these arms is reachable from this body.
- Unreached (`unreached.tsv`, all explained): body 9 (state re-check error arm, end skipped), each entry writer 4
  (state 1 panic after the key writer, which already panicked), each itoa 4 (overflow panic arm), `end_object` 3
  (`current_indent == 0` panic), escaper 1 (nop padding).
- Limits:
  - The recipient serializer `0x298c400` and the bytes writer `0x25ce7e0` are stubbed; their texts are not
    reconstructed here.
  - The error constructor behind GOT `0x64e0b08` is stubbed; that code word 10 is serde_json's `ErrorCode` for this
    case is inference.
  - Callers of `0x22f2810` other than the L1ToEvm Option entry are not covered; only behaviour on this path is
    claimed for the shared helpers.
- Next question: the bytes writer `0x25ce7e0` (check RE-001 ownership first), then the sibling entry writers of
  the L1ToEvm guard (`0x2339480` slotNumber -> `0x29677b0`, `0x2339660` -> struct body `0x2756cb0`).
