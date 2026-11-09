# evm: L1ToEvmNativeTokenTransfer pretty-JSON path, entry helpers, escaper and u64 itoa (node #115)

This packet reconstructs, as an executable Python model checked against the real bytes, the whole pretty-JSON
serialization path of the 0xc0-byte L1ToEvmNativeTokenTransfer record in node #115: the record body `0x22ea830`,
its three out-of-line entry writers (u64 `0x259bc50`, address `0x259fdc0`, Option guard `0x2339440` -> Option
bytes `0x2598140`), serde_json's key writer, string escaper and `end_object`, and the u64 decimal writer
`0x25fba40`. A Rust port can now reproduce byte for byte the JSON object this record produces (key order `token`,
`system_address`, `contract`, `wei`, `user`, `send_to_evm_data`; record offsets `+0x20`, `+0x80`, `+0x94`, `+0x00`,
`+0xa8`, `+0x28`), every reserve call, the `null` arm of `send_to_evm_data`, the serde_json error raised when the
Option entry is handed a non-Map compound, the `unreachable!()` panic for compound state 1, every escape arm of the
key escaper, and the state left behind by each failure (no `}`, `current_indent` still raised, `has_value` already
1 because the infallible `token` entry always succeeds first).

- Component ID: `evm` (docs/COMPONENTS.md); no gate change requested.
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: lalalune/hyperliquid-source `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.
  No reference source was used. Key names come from the binary's own texts (rip-relative `lea rsi` targets read
  with the following `mov edx, imm32` length); the record name L1ToEvmNativeTokenTransfer is the one the pending
  rmp-encoder packet of the same record uses (inference, see Limits).
- Claim status: observation for every table row and case result (bytes and tool output); inference for the Rust
  names (`SerializeMap::serialize_key`, `format_escaped_str_contents`, `PrettyFormatter::end_object`,
  `RawVec::reserve`, serde_json `Error::syntax`); unresolved items are listed below.
- Scope included: 9 FDE-bounded functions, all run REAL by the evaluator:

  | function | role | bytes | instructions | reached |
  |---|---|---|---|---|
  | `0x22ea830` | l1_transfer_json | 746 | 176 | 167 |
  | `0x259bc50` | entry_u64 | 258 | 71 | 67 |
  | `0x259fdc0` | entry_address | 151 | 44 | 40 |
  | `0x2339440` | entry_option_guard | 55 | 14 | 14 |
  | `0x2598140` | entry_option_bytes | 228 | 64 | 60 |
  | `0x26077c0` | serialize_key | 520 | 131 | 131 |
  | `0x25bf330` | format_escaped_str_contents | 552 | 140 | 139 |
  | `0x232b070` | end_object | 311 | 87 | 84 |
  | `0x25fba40` | u64_itoa | 322 | 81 | 77 |

  `serialize_key`, `format_escaped_str_contents`, `end_object` and the itoa are shared library code; they run as
  dependencies of this path (their bytes decide its output), get their own direct cases and byte-flip controls,
  but only their behaviour as used here is claimed. The itoa `0x25fba40` is also disassembled in
  `RE-012-snapshot-followup-decimal-format-115` (decimal formatting of a snapshot follow-up field); this packet
  adds its executable model and 3,000 direct cases, not a new owner claim.
- Scope excluded (recording contract stubs, `callees.tsv`): `RawVec::reserve` `0x231e050`, the address JSON
  serializer `0x298b150`, the U256 JSON serializer `0x29fed00`, the bytes JSON serializer `0x22f2810` (the `Some`
  arm of `send_to_evm_data`), `memcpy` (GOT `0x64df508`), the serde_json error constructor (GOT `0x64e0b08`) and the
  three panic entries (GOT `0x64df520` add overflow, `0x64df730` unreachable, `0x64df848` sub overflow).

## Reproduce

From the repository root, with the node #115 binary at `artifacts/node/115/hl-node` (Python 3 standard library and
the shared `tools/fde_extents.py` / `tools/elf_index.py` parsers only; no binutils, no subprocess, the binary is
read, never executed):

```
python3 tools/evm_l1_transfer_json_115.py --out research/work-items/evm-l1-transfer-json-path-115
python3 -m unittest tests.test_evm_l1_transfer_json_115
```

The tool checks the input SHA-256 first and fails on any other binary. It regenerates every `.tsv`/`.json` file
here byte for byte (about eight minutes; two runs with `PYTHONHASHSEED`/`TZ` = default/UTC and 987/Asia/Seoul, PATH
without binutils, were compared with `diff -r`). `--scale 0.1` runs a 1,650-case subset for quick checks; the
committed files use the default scale 1.0. `cases-sample.tsv` keeps every 5th case of each group; all 16,500 case
results are hashed into `summary.json` (`all_cases_sha256`).

## Evidence

All addresses are node #115 virtual addresses. The tool maps every VA to a file offset through the section headers
(`tools/elf_index.py`, skipping `SHT_NOBITS`) and takes function extents from `.eh_frame` FDEs
(`tools/fde_extents.py`).

How the path was found: the pending rmp-encoder packet of the same record left its JSON serializer `0x22ea830` as
the next question. Its direct calls give the three entry writers; the guard `0x2339440` ends in a tail jump to
`0x2598140`; the u64 entry calls `0x25fba40`. An ownership scan of the research tree and of the open/merged PR file
lists finds none of `0x22ea830`, `0x259bc50`, `0x259fdc0`, `0x2339440`, `0x2598140`.

### The record and its entries (fields.tsv)

| # | key (text VA) | value | record offset | written by |
|---|---|---|---|---|
| 0 | `token` (`0x5ead43`, len 5) | u64 | `+0x20` | `entry_u64` `0x259bc50` -> itoa `0x25fba40` |
| 1 | `system_address` (`0x5ead48`, len 14) | address | `+0x80` | body: key writer, `": "`, `0x298b150` |
| 2 | `contract` (`0x4590a0`, len 8) | address | `+0x94` | body: key writer, `": "`, `0x298b150` |
| 3 | `wei` (`0x5ead56`, len 3) | U256 | `+0x00` | body: key writer, `": "`, `0x29fed00` |
| 4 | `user` (`0x459fa4`, len 4) | address | `+0xa8` | `entry_address` `0x259fdc0` -> `0x298b150` |
| 5 | `send_to_evm_data` (`0x453740`, len 16) | Option (tag word) | `+0x28` | guard `0x2339440` -> `entry_option_bytes` `0x2598140` |

### Rules taken from the bytes

- Body `0x22ea830`: `current_indent` (`+0x18`) `cmp $-1; je` -> add-overflow panic (Location `0x642dc18`) before
  any write; `current_indent + 1`; `has_value` (`+0x20`) = 0; `{`; compound = `movw $0x100` (Map, First); six
  entries; after the first entry `cmpb $0, state` -> serde_json error arm (unreachable, state is 0); at the end
  `testb $1, state` / `cmpb $0, first` -> `end_object` (always taken after six keys).
- Key writer `0x26077c0`: compound state byte `== 1` -> `unreachable!()` (message `0x5f2167`, len `0x28`); any
  other state is a Map; First byte `== 1` -> `"\n"` (reserve 1 when full), else `",\n"` (reserve 2 when
  `cap - len <= 1`); First := 2; indent text x `current_indent` (each copy reserves `len(I)` when
  `len(I) > cap - len`); `"`, escaped key, `"`.
- Escaper `0x25bf330`: scans the key with the 256-byte ESCAPE table (GOT `0x64e13d8`); before each escapable byte
  flushes the pending run (reserve `run` when `run > cap - len`, memcpy); `u` entries write `\u00XX` with the hex
  digit table (GOT `0x64e13e0`, lowercase), reserving 6 when `cap - len <= 5`; other entries write `\` + entry,
  reserving 2 when `cap - len <= 1`; the final run is flushed the same way. ESCAPE has 34 non-zero entries:
  `0x00..0x1f` (`b t n f r` for 8, 9, 10, 12, 13, else `u`), `"` and `\`; DEL and bytes >= 0x80 pass through.
- `": "`: `movw $0x203a` with reserve 2 when `cap - len <= 1`, written by the body and by each entry writer.
- u64 entry `0x259bc50`: key, `": "`, itoa into a 20-byte stack buffer, reserve `len` when `len > cap - len`,
  memcpy, `has_value` = 1 (no error path).
- itoa `0x25fba40`: 4-digit chunks while the value is >= 10,000 (`mul` by `0x346dc5d63886594b`, `shr 11`), two-digit
  pairs from the table `0x5f1383` (`"00".."99"`), last digit `| 0x30`; returns `(buf + 20 - n, n)`. The `jo` and
  `cmp $0x14, rax` overflow arms are never taken for a u64.
- Option guard `0x2339440`: compound state byte `!= 0` -> GOT `0x64e0b08` with `(&10, 0, 0)` and returns its `rax`;
  else tail jump `0x2598140` with key `send_to_evm_data`.
- Option entry `0x2598140`: key, `": "`; tag word `+0x28 == 0` -> `null` (`movl $0x6c6c756e`, reserve 4 when
  `cap - len <= 3`), `has_value` = 1; else bytes JSON `0x22f2810(&option, ser)`, `has_value` = 1 only on success.
- Address entry `0x259fdc0`: key, `": "`, `0x298b150(&value, ser)`, `has_value` = 1 only on success.
- The three entry writers keep a `cmpb $1, state; je unreachable!()` after the key writer; it can never fire (the
  key writer already panicked for state 1).

Human-readable excerpt (objdump, not used by the tool):

```
22ea83b: mov    rax,[rsi+0x18]        ; current_indent
22ea83f: cmp    rax,-1
22ea843: je     22eab0d               ; add-overflow panic, Location 0x642dc18
22ea856: mov    byte [rsi+0x20],0x0   ; has_value = 0
22ea86b: mov    byte [rcx+rax],0x7b   ; '{'
22ea876: mov    word [rsp],0x100      ; Compound::Map, First
22ea885: lea    rsi,[rip+...]         ; "token", edx = 5, rcx = record+0x20
22ea894: call   259bc50               ; u64 entry
22ea8f1: mov    word [rax+rsi],0x203a ; ": "
22ea9ff: add    rbx,0x28
22eaa09: call   2339440               ; Option guard
2339440: cmp    byte [rdi],0x0
2339443: jne    2339459               ; -> error constructor (code 10)
2339454: jmp    2598140               ; "send_to_evm_data", len 16
25981b1: mov    dword [rax+rsi],0x6c6c756e ; "null"
25bf3d9: cmp    r13b,0x75             ; escaper: 'u' -> \u00XX
25bf40b: mov    dword [rax+rsi],0x3030755c ; "\u00"
```

### Callees (callees.tsv)

Every direct call, tail jump and GOT call of the 9 functions is listed with its role. `check_static` re-derives from
the bytes and asserts: the body's call order (u64 entry, key, address, key, address, key, U256, address entry,
Option guard, end_object), its five key texts and lengths, its record offsets (`+0x20`, `+0x80`, `+0x94`, `+0xa8`,
`+0x28`), the guard's key text and callees (tail `0x2598140`, error constructor), each entry writer's callees (key
writer, then its value writer), and three byte tables against the model (ESCAPE, hex digits, itoa digit pairs).

## Implementation and comparison

- Reconstruction: `tools/evm_l1_transfer_json_115.py`, class `JsonFlow` (`record`, `entry_u64`, `entry_value`,
  `guard`, `entry_option`, `key`, `escape`, `indent`, `end`, `byte`, `two`, `run`) and `itoa_text`, plus
  `escape_table` (serde_json's ESCAPE table written from its definition, then compared with the bytes).
- Evaluator: the concrete x86-64 interpreter of the earlier `evm` encoder packets runs the original bytes; no
  instruction form had to be added for this path (itoa's `mul`, `imul r, r/m, imm32`, `jo` and the escaper's
  table loads were already covered).
- Inputs are seeded regions: 2 record slots (`0x180` bytes of hash-stream bytes; the `+0x28` tag word forced to 0 on
  odd cases and to a single set bit on others), the serde_json pretty Serializer (`&Vec`, indent pointer, indent
  length, `current_indent`, `has_value`), the Compound (`state`, `First/Rest`, `&Serializer`), the key text, the
  indent text and the output buffer with a random prefix and capacity slack.
- Stubs record their arguments (value pointer, serializer, error code word) and answer from a per-case word plan;
  one value call per failing case returns an error word, walking every error arm. `RawVec::reserve` must be called
  with `(vec, len, additional, 1, 1)` and grows capacity by `additional + extra`; `memcpy` copies.
- Compared per case: ordered call list (every reserve with its length and size), every byte appended to the Vec and
  nothing past its length, final capacity and pointer, `rax`, the panic with its argument (Location, or message
  pointer and length), the serializer bytes (`current_indent`, `has_value` as modelled, everything else
  unchanged), the compound bytes (entry cases: state, First/Rest), callee-saved registers and stack, and that the
  records, key and indent texts are unchanged. itoa cases compare the digits, the untouched buffer prefix, `rax`
  and `rdx`.
- Cases: 16,500 from a deterministic SHA-512 stream: body 6,000, u64 entry 2,500, address entry 1,500, Option guard 1,500, Option entry 2,000, itoa 3,000. Body cases: `current_indent` 0, 1, 2, 3, 5, `u64::MAX - 1` (empty indent) and `u64::MAX`; indents `""`, `" "`, `"  "`, `"\t"`, `"\t\t"`, `"--"`, 9 spaces and random 1..12-byte texts; tight capacities (`cap - len` 0..8) on every third case; prefixes up to 3,000 bytes; token values from 24 edge values (0, 9, 10, 99, ..., `10^19`, `2^64 - 1`) and random 1..20-digit numbers. Entry cases add compound state 0/1/2/0x80/0xff, First/Rest 0/1/2/3/0xff and keys that hit every escape arm (control bytes, `"`, `\`, DEL, bytes >= 0x80).
- Negative controls: 187, all detected (`controls.tsv`): 31 wrong models (`model:*`: indent wrap instead of panic, key order, hex / zero-padded / 32-bit token, reserve thresholds of digits, `null`, `\u00XX`, `": "`, single bytes, one extra indent, upper-case hex escapes, tab as `\u0009`, DEL escaped, escape always reserving, guard ignoring the state, key writer panicking for any non-zero state, First for any non-zero byte, newline always, `:` without space, Option tag read as one byte, `has_value` set on error or never set, `end_object` on error / keeping the indent / without newline, wrong field offsets, swapped value kind, error code 9) and 156 byte flips: one byte of every immediate operand the cases reach in all 9 functions (key lengths, record offsets, reserve sizes, spare-capacity tests, `{`/`}`/`"`/`\n`/`": "`/`",\n"`/`null`/`\u00` bytes, state and First tests, the error code word, itoa divisors, multipliers and bounds). `cmpb $0, first` (`0x22eaa1b`) is flipped to `$2` and the itoa bound `cmp $0x14` (`0x25fbb52`) to `$0x0b` (bit 0 gives the same machine for every reachable state). One immediate is excluded as an equivalent mutant by construction (`EQUIVALENT_SITES`, counted in `summary.json`): `has_value = 0` at object start (`0x22ea856`), which the infallible token entry overwrites before any read. Out-of-range inputs (wrong digest, out-of-range FDE start, code outside `.text`, `.bss` reads) are rejected by the unit tests.
- Unit tests (`tests/test_evm_l1_transfer_json_115.py`, 38 tests): regeneration equals the committed files,
  manifest, scale, unreached rows explained, static facts, FDE sizes, key texts and offsets, byte tables, wrong
  digest, redirected callee, changed key length, changed ESCAPE entry, out-of-range start, `.bss` read rejected,
  hand-built cases for every finding (whole object, Some arm, token extremes, each value error, indent overflow,
  reserve order, Rest state, state 1 panic, other states as Map, guard error, null reserve edge, every escape arm,
  escape reserve edges, itoa edges), mutants on hand cases, byte flips of `": "` and `null`, a corrupted result,
  and that the byte-flip sites cover every function.

## Results and limitations

- 16,500 cases, 0 mismatches (the first full run matched; only the static key-text extractor and four control flip patterns were adjusted); 187/187 controls detected; 779 of 808 instructions of the 9 functions reached.
- Per group (`summary.json` `per_group`): addrf 1,500 cases (1,137 ok, 209 error, 154 panic, 4,756 reserve calls); body 6,000 cases (4,285 ok, 1,016 error, 699 panic, 137,470 reserve calls); guard 1,500 cases (794 ok, 706 error, 0 panic, 2,491 reserve calls); itoa 3,000 cases (3,000 ok, 0 error, 0 panic, 0 reserve calls); optf 2,000 cases (1,729 ok, 43 error, 228 panic, 7,220 reserve calls); u64f 2,500 cases (2,214 ok, 0 error, 286 panic, 9,649 reserve calls).
- Findings:
  1. Whole object for `current_indent = n`, indent text `I`, token `T`, value texts `A1`, `A2`, `W`, `U` written by
     the stubs, tag word 0: `{` `\n` `I*(n+1)` `"token": T` `,\n` `I*(n+1)` `"system_address": A1` ... `,\n`
     `I*(n+1)` `"send_to_evm_data": null` `\n` `I*n` `}`; `current_indent` ends at `n`, `has_value` at 1.
  2. The key order is not the record's memory order: `token` (+0x20) first, `wei` (+0x00) fourth,
     `send_to_evm_data` (+0x28) last.
  3. `token` is written as bare decimal digits (`0`, `18446744073709551615`), never quoted; the u64 entry cannot
     fail. So every error return leaves `has_value` = 1 and `current_indent` = `n + 1`, with no `}`.
  4. `send_to_evm_data` is `null` exactly when the whole tag word `+0x28` is 0 (a tag of `1 << 63` is `Some`).
  5. The Option entry is reached through a guard that rejects any non-Map compound with a serde_json error
     (code word 10) instead of a panic, while the key writer panics (`unreachable!()`) only for state 1 and treats
     every other state as a Map.
  6. Reserve rules: single bytes reserve 1 when full; `": "` / `",\n"` reserve 2 when `cap - len <= 1`; `null`
     reserves 4 when `cap - len <= 3`; `\u00XX` reserves 6 when `cap - len <= 5`; `\X` reserves 2 when
     `cap - len <= 1`; runs (key text, digits, indent copies) reserve their length when it exceeds the spare
     capacity.
- Unreached (`unreached.tsv`, all explained): `0x22ea830` 9 - state byte != 0 error arm / end skipped: the body builds Compound::Map {state 0, First} itself; `0x259bc50` 4 - state byte == 1 panic arm: serialize_key already panicked for state 1; `0x259fdc0` 4 - state byte == 1 panic arm: serialize_key already panicked for state 1; `0x2598140` 4 - state byte == 1 panic arm: serialize_key already panicked for state 1; `0x25bf330` 1 - alignment padding (multi-byte nop) between two blocks of the escape loop, never executed; `0x232b070` 3 - current_indent == 0 panic: the body incremented it before the call; `0x25fba40` 4 - overflow panic arm: the write index never leaves 0..20 for a u64.
- Limits:
  - The four stubbed value writers (`0x298b150`, `0x29fed00`, `0x22f2810`, reserve) are not reconstructed here;
    the address and U256 JSON forms are the next question.
  - The error constructor behind GOT `0x64e0b08` is stubbed; that the code word 10 is serde_json's
    `ErrorCode` for this case (and the Rust variant name) is inference.
  - The record type name (L1ToEvmNativeTokenTransfer) comes from the pending rmp-encoder packet, not from a text
    next to this body. Callers of `0x22ea830` are not covered.
  - Only behaviour on this path is claimed for the shared helpers; their other callers may pass states this
    packet does not drive.
- Next question: the address JSON serializer `0x298b150` and U256 JSON serializer `0x29fed00` (check RE-002
  ownership of `0x298b150` first), then the bytes JSON serializer `0x22f2810` of the `Some` arm.
