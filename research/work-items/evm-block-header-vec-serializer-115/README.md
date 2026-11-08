# evm: inline-Vec rmp serializer of the EVM block header and 20 field writers (node #115)

This packet reconstructs, as an executable Python model checked against the real bytes, how node #115 msgpack-encodes
an EVM block header when the rmp-serde serializer is the output `Vec<u8>` itself: the map-vs-array choice, the
header count computed from raw option tags, which of the 23 field names are written for each value of the
struct-as-map byte, the RawVec growth requests, the nil encoding of non-canonical options and the error records.
With it a Rust port can reproduce the exact bytes of this encoder, including two behaviours a clean serde derive
would not have: the field writers disagree on the flag rule (`== 1` in 6 writers, `!= 0` in 7), so a flag of 2..255
gives a map that names only some fields, and an option word that is non-zero but not 1 is counted, announced (key
written) and then serialized as nil `0xc0`. Seven more writers of the same copy family (transaction-body fields)
are reconstructed with the same model.

- Component ID: `evm` (docs/COMPONENTS.md); no gate change requested.
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: lalalune/hyperliquid-source `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.
  No reference source was used; field names come from the binary's own inline name bytes and name texts.
- Claim status: observation for every table row and case result (bytes and tool output); inference for the Rust
  type names (block header, Option fields, newtype `AccessList`); unresolved items are listed below.
- Scope included: 21 bodies, all FDE-bounded and all run REAL by the evaluator:
  - block header serializer `0x22da880` (1,661 bytes, 375 instructions);
  - 13 field writers it calls: `0x2339730`, `0x23399c0`, `0x2339a80`, `0x2339ce0`, `0x233a150`, `0x233a670`,
    `0x233a940`, `0x233ad90`, `0x233ae70`, `0x233aff0`, `0x233b050`, `0x233b190`, `0x233b700`;
  - 7 transaction-body field writers of the same copy family: `0x2339e80`, `0x233a300`, `0x233a3b0`,
    `0x233a4f0`, `0x233aa80`, `0x233b510`, `0x233b630`.
- Scope excluded (recording contract stubs, see `stubs.tsv`): rmp length headers `0x25e7540`/`0x25e7c10`, rmp str
  writer `0x25e8bf0`, `RawVec::reserve` `0x231e050`, value serializers `0x298bad0` (32 bytes), `0x298c770`
  (20 bytes), `0x29feb10` (u64), `0x298be50` (8 bytes), `0x298b910` (bloom), `0x29fe7f0` (U256), `0x2967e20`,
  `0x2262880`, `0x2225910`, `0x2275200`, the keyed extraData serializer `0x233b960` and the inline destination-call
  serializer `0x22f2c20`. Those bodies are not claimed here.

## Reproduce

From the repository root, with the node #115 binary at `artifacts/node/115/hl-node` (Python 3 standard library and
the shared `tools/fde_extents.py` / `tools/elf_index.py` parsers only; no binutils, no subprocess, the binary is
read, never executed):

```
python3 tools/evm_block_header_vec_115.py --out research/work-items/evm-block-header-vec-serializer-115
python3 -m unittest tests.test_evm_block_header_vec_115
```

The tool checks the input SHA-256 first and fails on any difference. Output is deterministic (no time, randomness,
dict-order or absolute path in any file): two runs into different folders compare equal with `diff -r`. A full run
takes about two minutes (28,000 cases plus 120 controls). `--per-body N` and `--head-cases N` scale the case set;
the committed files are produced by the defaults (1,000 per writer, 8,000 for the header).

Generated files (all reproduced byte-for-byte by the tool; `MANIFEST.sha256` lists their hashes):

| file | content |
|---|---|
| `bodies.tsv` | per body: FDE end, size, instructions, instructions reached, key, key form, flag test, value shape, value callee, reserve call sites (decoded from bytes) |
| `fields.tsv` | the header's 23 fields in byte order: name, form, presence rule, target, struct offset, when the name is written |
| `stubs.tsv` | stubbed callees and their contract kind |
| `cases-sample.tsv` | every 6th header case and every 10th writer case: flag, failing call, Vec prefix/capacity, final length/capacity, result record, appended bytes, ordered call list |
| `controls.tsv` | 24 model mutants and 96 single-byte code flips, each with the first case that exposes it |
| `summary.json` | totals, per-body ok/error/flag counts and `all_cases_sha256`, the hash over all 28,000 case results |
| `unreached.tsv` | instructions of the 21 bodies never executed (header only: none are left) |

## Evidence

Coordinates are virtual addresses of node #115; the tool maps them to file bytes through the section headers
(`elf_index`), never through a fixed offset. Body extents are the FDE ranges from `.eh_frame` (`fde_extents`).

Calling convention (observed from argument moves before each call and confirmed by every case):

- header `0x22da880(out, &header, vec)`; field writer `(slot, vec, &field)` or, for writers that receive the name,
  `(slot, vec, name, len, &field)`; value serializers `(slot, &value, vec)`; two sequence serializers
  (`0x2262880`, `0x2225910`) take `(slot, vec, &value)`; `0x2275200` takes `(slot, vec, "AccessList", 10, &value)`.
- The serializer is the `Vec<u8>`: capacity `+0`, pointer `+8`, length `+0x10`, struct-as-map byte `+0x1b`.
- Result record: 3 words; Ok is word 0 = `0x8000000000000004`; the header copies all 3 slot words out on the first
  nested result whose word 0 differs. Length-header and str writer errors become `(0x8000000000000000, w0, w1)`.

Header count (bytes `22da8a0..22da8d5`): `movzbl 0x27c; cmpq $1,(rsi); sbb $0; add 0x10(rsi); add 0x20(rsi);
movzbl 0x29d/0x2be/0x2df; mov 0x30(rsi); add $0x10` = 16 - (word0 == 0) + raw bytes + raw low dwords, mod 2^32.
Map header if `cmpb $0x0,0x1b(%r15)` is non-zero, array otherwise. Own names (`parentHash`, `sha3Uncles`,
`miner` inline; `stateRoot`, `transactionsRoot` via the str writer) only under `cmpb $0x1,0x1b(%r15)`.

Field writers (all from `bodies.tsv`, decoded from bytes):

| writer | key | key form | name written when | value |
|---|---|---|---|---|
| `0x2339730` | slotNumber | inline `0xaa` | byte != 0 | Option: dword `[p]` == 1 -> u64 `[p+8]` via `0x29feb10`, else nil |
| `0x23399c0` | nonce | inline `0xa5` | byte == 1 | tail `0x298be50(p)` |
| `0x2339a80` | gasUsed | inline `0xa7` | byte == 1 | `0x29feb10(&copy of [p])` |
| `0x2339ce0` | number | inline `0xa6` | byte == 1 | `0x29feb10(&copy of [p])` |
| `0x233a150` | argument (receiptsRoot, mixHash) | str writer | byte != 0 | tail `0x298bad0(p)` |
| `0x233a670` | timestamp | inline `0xa9` | byte == 1 | `0x29feb10(&copy of [p])` |
| `0x233a940` | excessBlobGas | inline `0xad` | byte != 0 | Option dword, as `0x2339730` |
| `0x233ad90` | gasLimit | inline `0xa8` | byte == 1 | `0x29feb10(&copy of [p])` |
| `0x233ae70` | logsBloom | inline `0xa9` | byte == 1 | tail `0x298b910(p)` |
| `0x233aff0` | argument (difficulty) | str writer | byte != 0 | tail `0x29fe7f0(p)` |
| `0x233b050` | blobGasUsed | inline `0xab` | byte != 0 | Option dword |
| `0x233b190` | argument (withdrawalsRoot, parentBeaconBlockRoot, requestsHash, blockAccessListHash) | str writer | byte != 0 | Option: byte `[p]` == 1 -> tail `0x298bad0(p+1)`, else nil |
| `0x233b700` | baseFeePerGas | inline `0xad` | byte != 0 | Option dword |
| `0x2339e80` | authorizationList | inline `0xb1` | byte == 1 | `jne 0x2262880` before the frame (conditional tail call) and tail call after the name |
| `0x233a300` | to | inline `0xa2` | byte == 1 | tail `0x298c770(p)` |
| `0x233a3b0` | blobVersionedHashes | inline `0xb3` | byte == 1 | conditional / tail `0x2225910` |
| `0x233a4f0` | maxFeePerBlobGas | inline `0xb0` | byte == 1 | tail `0x2967e20(p)` |
| `0x233aa80` | send_to_evm_data | inline `0xb0` | byte != 0 | Option: qword `[p]` != 0 -> tail `0x22f2c20(p)`, else nil |
| `0x233b510` | to (Option) | inline `0xa2` | byte != 0 | Option byte, as `0x233b190`, value `0x298c770(p+1)` |
| `0x233b630` | accessList | inline `0xaa` | byte == 1 | tail `0x2275200(slot, vec, "AccessList", 10, p)` |

Inline name rule (every inline writer and the header): if `cap == len` reserve 1; store marker `0xa0 | n`; if
`cap - len <= n - 1` reserve n; store the name bytes (movabs/movl/movw/movups immediates). The nil rule: if
`cap == len` reserve 1; store `0xc0`; result word 0 = Ok.

Header field order and presence (`fields.tsv`): 15 always-present fields, then baseFeePerGas if qword `+0x0` != 0,
withdrawalsRoot if byte `+0x27c` == 1, blobGasUsed if qword `+0x10` != 0, excessBlobGas if qword `+0x20` != 0,
parentBeaconBlockRoot / requestsHash / blockAccessListHash if bytes `+0x29d` / `+0x2be` / `+0x2df` == 1,
slotNumber if qword `+0x30` != 0.

Static checks the tool repeats from bytes before any case runs (any difference fails the run): the header's direct
call sequence equals the field table (33 calls, 6 of them reserve), the 10 `lea name; mov $len` texts equal the
table names, the 3 inline marker lengths, the flag tests `{0, 1}`, the 4 tag bytes of the count and the `add $0x10`
base; per writer the value call (call/jmp) and role, the single flag-test immediate, the inline marker length, the
nil store count, the option tag compare and, for `0x233b630`, the newtype name text.

## Implementation and comparison

Not a Rust implementation; the reconstruction is the executable Python model `Flow` / `model` in
`tools/evm_block_header_vec_115.py` (field table `HEAD_FIELDS`, writer table `WRITERS`, `header_count`, the inline
name, nil, reserve, presence and error rules). It is compared with a concrete x86-64 evaluator that runs the real
bytes of all 21 bodies; only the callees listed under "Scope excluded" are stubs. Each stub records its arguments
in normalized form (struct offset, 8-byte stack copy, name text, header count, Vec pointer) and answers from a
per-case plan; one planned call per failing case returns an error word.

Per case the comparison covers: the ordered call list with arguments, every byte appended to the Vec, the final
length and capacity (the reserve stub grows capacity to `len + add + extra`), the 24-byte result record, the six
callee-saved registers and the stack pointer, and the untouched struct and serializer bytes.

Case generation (deterministic SHA-512 streams): flags 0, 1, 2, 3, 0x80, 0xff and random bytes; option words from
{0, 1, 2, 0xffffffff, 2^32, 2^32+1, 2^48+1, random}; option bytes from {0, 1, 2, 0xff, random}; Vec prefix 0..23
bytes with spare capacity 0..39, 120 or 400; header cases fail at every call position on every third case; writer
cases at k mod (n + 2).

Controls (all must be detected, else the tool fails):
- 24 model mutants: count from presence only / from low bytes / plus one, map only on flag 1, names on flag != 0 /
  on flag == 1 for all writers, writer flag tests swapped, first two fields swapped, raw str / header error words,
  continue after error, option tag as qword / as `!= 0` / value at `p+0`, None without nil, presence always /
  low-dword / byte `!= 0`, `opt_qword` as `== 1`, serializer-first argument order swapped, key instead of newtype
  name, reserve test `< n`, no reserve before the marker, marker off by one.
- 96 single-byte flips of code bytes (flag-test immediates and displacements, fixstr markers, nil stores,
  spare-capacity tests, option tag immediates, the count base, a name length), each run on its own body's cases.

## Results and limitations

| metric | value |
|---|---|
| bodies (FDE-bounded, run real) | 21 |
| body instructions reached / total | 1,562 / 1,562 |
| cases (header + writers) | 28,000 (8,000 + 20 x 1,000) |
| mismatches | 0 |
| controls detected / total | 120 / 120 (24 model mutants, 96 byte flips) |
| `all_cases_sha256` | `357a737f2a34d5d7573c8cb592ddfe28a09acf13aeb9b74b359a3c20e15039ba` |
| unit tests | 25 tests, all pass, none skipped (about 2.5 minutes) |

Findings (observations, each reproduced by cases and pinned by a control):
- Flag 2..255 writes a map header but only the names of the `!= 0` writers (receiptsRoot, difficulty, mixHash and
  the optional fields); the header's own five names and the six `== 1` writers stay silent.
- The header count adds raw tags; the head tests word presence with `!= 0`; the writers test the dword with
  `== 1`. A word of 2 is counted as one field, its key is written (flag != 0) and the value is nil `0xc0`.
- `0x233b630` gives its callee the Rust newtype name `AccessList` (rodata text, length 10), not the key.
- `0x2339e80` and `0x233a3b0` start with `cmpb $0x1,0x1b(%rsi); jne callee` - a conditional tail call before
  the stack frame.

Limits: the stubbed value serializers are not reconstructed here, so the value bytes they would append are not
modelled; the struct's Rust layout is inferred only from the offsets the bodies touch; the callers of the seven
transaction-body writers are not identified in this packet; no Rust implementation and no gate change.

Next question: which inline-Vec transaction-body serializers call `0x2339e80`, `0x233a300`, `0x233a3b0`,
`0x233a4f0`, `0x233aa80`, `0x233b510` and `0x233b630`, and does their header count use the same raw-tag rule?
