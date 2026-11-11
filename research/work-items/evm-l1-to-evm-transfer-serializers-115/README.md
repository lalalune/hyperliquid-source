# evm: msgpack serializers of the L1ToEvmNativeTokenTransfer record, its sequence and send_to_evm_data writer (node #115)

This packet reconstructs, as an executable Python model checked against the real bytes, how node #115 msgpack-encodes
the 192-byte `L1ToEvmNativeTokenTransfer` record (token, system_address, contract, wei, user, send_to_evm_data) and a
chained pair of record slices: both serializer shapes (the output `Vec<u8>` used directly, and the rmp `Serializer`
wrapper), the `send_to_evm_data` field writer with its fallible nil push, and the `SerializeSeq` body that chooses
between them per compound, advances the iterator and counts elements. A Rust port can now reproduce the exact bytes,
call order, error records and panic of this encoder, including behaviours a clean serde derive would not show: the
inline-Vec header byte is computed as `((flag ^ 1) << 4 | 0x86) & 0xff` (so flag 2 writes `0xb6`, a fixstr marker,
and flag `0x11` writes a fixmap with no names), the record body names fields only when the struct-as-map byte is
exactly 1 while the `send_to_evm_data` writer names itself for any non-zero byte (flag 2 gives a 6-entry map with
one key), and a failed Vec growth while pushing nil returns the fixed error record `(0x8000000000000000, 0,
0x2600000003)` instead of aborting. Both copy families of all four bodies (8 bodies) follow the same model.

- Component ID: `evm` (docs/COMPONENTS.md); no gate change requested.
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: lalalune/hyperliquid-source `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.
  No reference source was used. Field names come from the binary's own name texts (rip-relative `lea` targets read
  as bytes) and inline name immediates; the record type name is the `.rodata` text that sits next to the `wei` key
  (`weiL1ToEvmNativeTokenTransferEvmBlockWir...` at `0x5ead56`).
- Claim status: observation for every table row and case result (bytes and tool output); inference for the Rust
  names (record type name, `Option` for send_to_evm_data, `Chain<slice::Iter, slice::Iter>`, `SerializeSeq`
  compound); unresolved items are listed below.
- Scope included: 8 FDE-bounded bodies, all run REAL by the evaluator:

  | role | family a | family b | bytes a / b | instructions a / b |
  |---|---|---|---|---|
  | record_vec (record -> inline-Vec rmp) | `0x22ea250` | `0x38c1280` | 926 / 926 | 227 / 227 |
  | record_ser (record -> rmp Serializer) | `0x22ea5f0` | `0x38c1040` | 574 / 574 | 139 / 139 |
  | send_to_evm_data_ser (field writer) | `0x233baf0` | `0x391a6f0` | 325 / 325 | 86 / 86 |
  | chain_seq (Chain of record slices) | `0x251abd0` | `0x450b020` | 622 / 574 | 154 / 146 |

- Scope excluded (recording contract stubs, see `stubs.tsv`): rmp header/str/uint writers, the 20-byte and U256
  value serializers, `RawVec::reserve`, `finish_grow`, the destination-call serializers `0x22f2a20`/`0x44dad80`,
  the inline-Vec `send_to_evm_data` writers `0x233aa80`/`0x391ae30` (the family-a one belongs to a separate pending
  block-header packet and is not claimed here) and the add-overflow panic reached through GOT `0x64df520`.
  Those bodies are not claimed here.

## Reproduce

From the repository root, with the node #115 binary at `artifacts/node/115/hl-node` (Python 3 standard library and
the shared `tools/fde_extents.py` / `tools/elf_index.py` parsers only; no binutils, no subprocess, the binary is
read, never executed):

```
python3 tools/evm_l1_to_evm_transfer_115.py --out research/work-items/evm-l1-to-evm-transfer-serializers-115
python3 -m unittest tests.test_evm_l1_to_evm_transfer_115
```

The tool checks the input SHA-256 first and fails on any other binary. It regenerates every `.tsv`/`.json` file
here byte for byte (about one minute; two runs with different `PYTHONHASHSEED`/`TZ` were compared with `diff -r`).
`--scale 0.1` runs a 2,000-case subset for quick checks; the committed files use the default scale 1.0.

## Evidence

All addresses are node #115 virtual addresses. The tool maps every VA to a file offset through the section headers
(`tools/elf_index.py`, skipping `SHT_NOBITS`) and takes body extents from `.eh_frame` FDEs (`tools/fde_extents.py`).

How the bodies were found: an `e8 rel32` caller scan of the inline-Vec `send_to_evm_data` writer `0x233aa80` (the
last tail-call target named in the block-header writer packet) gives one caller, `0x22ea250`. Its callers are
`0x251abd0` (twice) and `0x2258820`; `0x251abd0` also calls `0x22ea5f0` four times, and `0x22ea5f0` calls
`0x233baf0`. A byte scan for the `system_a` / `contract` immediates finds the same-size copies `0x38c1280` and
`0x5af6ea0`; `0x38c1280`'s caller `0x450b020` and its sibling `0x38c1040` / writer `0x391a6f0` form family b.
`0x5af6ea0` (family c) and `0x2258820` already appear in caller lists of merged packets and are not touched here.

### The record (fields.tsv)

| # | key | value | record offset | inline-Vec key | rmp-Serializer key |
|---|---|---|---|---|---|
| 0 | token | u64 by value | `+0x20` | fixstr `0xa5` + `movl "toke"` + `movb 'n'` | str writer, text `0x5ead43` |
| 1 | system_address | 20 bytes by pointer | `+0x80` | fixstr `0xae` + two overlapping `movabs` | str writer, text `0x5ead48` |
| 2 | contract | 20 bytes by pointer | `+0x94` | fixstr `0xa8` + `movabs "contract"` | str writer, text `0x4590a0` |
| 3 | wei | U256 by pointer | `+0x00` | Vec str writer, text `0x5ead56` | str writer, text `0x5ead56` |
| 4 | user | 20 bytes by pointer | `+0xa8` | Vec str writer, text `0x459fa4` | str writer, text `0x459fa4` |
| 5 | send_to_evm_data | Option, qword tag | `+0x28` | delegated to `0x233aa80` | delegated to `0x233baf0` (text `0x453740`) |

The sequence body steps through records with `add rbp, 0xc0`, so the record is 192 bytes.

### Flag rules (bodies.tsv `flag_tests`)

- record_vec: header byte from `movzx ebp, [rdx+0x1b]; xor bpl, 1; shl bpl, 4; or bpl, 0x86`, then five
  `cmp byte [r15+0x1b], 1` (names only when the byte is exactly 1).
- record_ser: `cmp byte [rdx+0xb], 0` chooses map (`!= 0`, `0x25e7670`) or array (`== 0`, `0x25e7940`), length 6;
  five `cmp byte [r15+0xb], 1` gate the names.
- send_to_evm_data_ser: `cmp byte [rsi+0xb], 0` - the name is written for any non-zero byte.

Human-readable excerpt (objdump, not used by the tool):

```
22ea267: movzbl 0x1b(%rdx),%ebp
22ea26f: xor    $0x1,%bpl
22ea273: shl    $0x4,%bpl
22ea277: or     $0x86,%bpl
...
233bb01: cmpb   $0x0,0xb(%rsi)          ; send_to_evm_data: name when != 0
233bb27: cmpq   $0x0,(%r14)             ; Some -> jmp 22f2a20
233bb9e: lea    (%rsi,%rsi,1),%rax      ; None with a full Vec: new cap = 2*len ...
233bba2: cmp    $0x9,%rax               ; ... but at least 8
233bbc6: call   231dc90                 ; finish_grow, failure -> (ERR, 0, 0x2600000003)
...
251ad17: mov    0x20(%r15),%eax         ; element counter
251ad1b: cmp    $0xffffffff,%eax
251ad1e: je     251ae31                 ; add-overflow panic, Location 0x642c1e0
```

### Callees (callees.tsv, stubs.tsv)

Every direct call, tail jump, out-of-body conditional jump and GOT call of the 8 bodies is listed with its role.
`check_static` re-derives from the bytes and asserts, for both families: the record_vec call order (uint, b160,
b160, str `wei`, U256, str `user`, b160, send writer), the record_ser call order (map, array, then str/value pairs,
then the send writer), the send writer callees (str, destination tail call, finish_grow, reserve), the sequence
callees (4 x record_ser, 2 x record_vec, panic last), the key texts, the inline name immediates, the flag-test
offsets and immediates, and the panic `Location` argument (`0x642c1e0` family a, `0x6481ff8` family b).

## Implementation and comparison

- Reconstruction: `tools/evm_l1_to_evm_transfer_115.py`, `vec_marker`, `grow_target` and class `Flow`
  (`record_vec`, `record_ser`, `send_ser`, `seq`) - one model for both families; only the callee addresses differ.
- Evaluator: a concrete x86-64 interpreter for the instruction forms of these bodies runs the original bytes.
  Inputs are seeded regions: 8 records (`0x600` bytes of hash-stream bytes with chosen option tags), the compound /
  Vec (cap, ptr, len, flag, counter, inner pointer), the rmp Serializer (word 0 = &Vec, flag `+0xb`), the Chain
  iterator (4 words) and the output buffer with a random prefix and capacity slack.
- Stubs record their arguments (slot, serializer, value or record pointer, text bytes) and answer from a per-case
  word plan; one call per failing case returns an error word, walking every error arm. `RawVec::reserve` must be
  called with `(vec, len, additional, 1, 1)` and grows capacity by `additional + extra`; `finish_grow` must be called
  with `(out, len, ptr, new_cap, 1, 1)` and fails when its out byte is non-zero.
- Compared per case: ordered call list, every byte appended to the Vec and nothing past its length, final capacity
  and pointer, the 24-byte result record (only word 0 is written on success), the Chain iterator words, the element
  counter, the panic and its `Location`, callee-saved registers and stack, and that the records are unchanged.
- Cases: 20,000 (per family: record_vec 2,500, record_ser 2,500, send writer 1,500, sequence 3,500), from a
  deterministic SHA-512 stream; flags `0, 1, 2, 3, 0x10, 0x11, 0x80, 0xff` and random bytes; counters near
  `0xffffffff`; full-Vec states that force growth; both compound variants.
- Negative controls: 212, all detected (`controls.tsv`):
  - 22 wrong models (`model:*`): header-byte rule, names on any non-zero flag, map only for flag 1, header length 5,
    the send writer naming only for flag 1, tag tested on 32 bits or `== 1`, nil skipped, growth minimum 9, growth
    failure tested on the whole word, reserve thresholds, error records not wrapped, swapped fields, absolute
    record offsets, halves swapped, iterator advanced only after success, no counting, wrapping counter;
  - 190 byte flips: one byte of every immediate operand of the 8 bodies that the cases reach (flag tests, header
    base, fixstr markers, name bytes and lengths, spare-capacity tests, growth minimum, nil byte, error words,
    record stride, counter limit, reserve and finish_grow arguments). 8-byte immediates are flipped in their top
    byte because the low two bytes of the `"_address"` store are overwritten by the `"system_a"` store that
    follows it (a flip there is invisible by construction). `cmp $9` is flipped in bit 1, since `cmp $8` is the
    same rule (`2 * len == 8` picks 8 either way).
- Unit tests (`tests/test_evm_l1_to_evm_transfer_115.py`): regeneration equals the committed files, manifest,
  scale, unreached rows explained, static facts, wrong digest, redirected callee, out-of-range start, hand-built
  cases for every finding in both families, mutants on hand cases, a byte flip and a corrupted result.

## Results and limitations

- 20,000 cases, 0 mismatches; 212/212 controls detected; 1,134 of 1,204 body instructions reached.
- Per body: every body has Ok and error results and flag 1 / 0 / other cases; both sequence bodies reach the
  counter-overflow panic (`summary.json` `per_body`).
- Findings (all both families):
  1. Inline-Vec header byte `((flag ^ 1) << 4 | 0x86) & 0xff`: flag 0 -> `0x96` fixarray 6, 1 -> `0x86` fixmap 6,
     2 -> `0xb6` (a fixstr marker), `0x10` -> `0x96`, `0x11` -> `0x86` (a map without names), `0xff` -> `0xe6`.
  2. Names are written only for flag == 1 in both record bodies, but the rmp-Serializer path opens a map for any
     non-zero flag and its `send_to_evm_data` writer names itself for any non-zero flag.
  3. `send_to_evm_data` is `Some` for any non-zero 64-bit tag (`cmpq $0`), and `None` pushes nil `0xc0` through
     an inline fallible growth: new capacity `2 * len`, at least 8; an allocation failure returns
     `(0x8000000000000000, 0, 0x2600000003)` and leaves the Vec unchanged.
  4. The sequence body advances the iterator before serializing an element, so a failing element is consumed;
     the rmp-Serializer variant (compound word 0 `0x8000000000000000`, inner serializer at `+0x28`) does not count
     elements; the inline-Vec variant increments the u32 at `+0x20` after each successful element and panics
     (add overflow) when it is already `0xffffffff` - after the element's bytes were written.
- Unreached (`unreached.tsv`, 70 instructions): in both send writers, the `reserve` after a successful growth
  (the new capacity is always larger than the length); in both sequence bodies, the per-element re-check that would
  switch to the inner-serializer variant in the middle of an inline-Vec loop (needs the Vec capacity to equal
  `0x8000000000000000`) and nop padding.
- Limits: the value serializers, rmp writers, the destination-call serializer and the inline-Vec send writer are
  stubs; their own encodings are not claimed. The record type name is an inference from the adjacent `.rodata`
  text. Family c (`0x5af6ea0`, `0x4ff1c10`) and the other caller `0x2258820` are not covered. No progress gate
  is requested.
- Observation data: `cases-sample.tsv` keeps every 10th body case and every 4th sequence case; all 20,000 results
  are covered by `all_cases_sha256` in `summary.json`, which the tool recomputes.

Next question: reconstruct the other callers of the record serializers (`0x2258820`, `0x4178960`, `0x52edfd0`) -
the EVM block / system-transaction structure that holds the two record slices - and the JSON serializer of the same
record (`0x22ea830`, `serde_json` with `{`, `: ` and comma writers).
