# evm: EVM transaction-type name codec and signed-transaction envelope in node #115

This packet makes the node #115 EVM transaction-type codec reconstructible from
byte evidence: the unit enum `Legacy`/`Eip2930`/`Eip1559`/`Eip4844`/`Eip7702`
(tags 0..4), all eight exact-name visitors in three copy families, and the two
MessagePack signed-transaction envelope serializers that write the type name as
the key of an externally tagged one-entry map. An independent Rust implementation
can now fix the tag order, the visitor accept/reject set and error text (including
the lossy UTF-8 path and the owned-copy free), and the exact envelope wire bytes:
- the map-or-array header taken from the serializer's struct-as-map flag;
- the `signature` and `transaction` keys, which are written only in map form;
- the inner-call order (signature value at `+0xe0`, then the typed payload at `+0x10`);
- every reserve call;
- the error propagation of both inner serializers.
It also fixes two dispatch facts the names alone do not give:
- the envelope tag dispatch is an unchecked jump table on a u64, so only tags
  0..4 are defined;
- the `&[u8]` visitors pick the `Eip` name by a jump table on the fourth byte
  (`'1'..'7'`).

- Component ID: `evm`. This is the EVM transaction model. RE-011 owns EVM execution
  paths, but no work item or open PR names these bodies, pools or names. See
  Limits.
- Target release and full SHA-256: Linux x86-64 node #115,
  `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `05bc2de303c05525b71e7e257426e741bc66a390`.
  No reference source was used. The names come from the binary's own pools and
  immediates. No #94 result is used.
- Claim status:
  - Observation: the 10 body extents, instruction bytes, jump-table rows, name
    literals, pools and relocations, callee roles, and the interpreted outcome of
    every case.
  - Inference: the EIP-2718 meaning of the tags, and that the envelope is a
    signed EVM transaction.
  - Unresolved: the payload and signature serializers, and the family-3 users
    (see Limits).
- Scope included:
  - two signed-transaction envelope serializers (`0x2336410` family 1,
    `0x44f1bd0` family 2);
  - three `&[u8]` tagged visitors (`0x22dc0f0`, `0x44456f0`, `0x5ae3e10`);
  - three `&str` tagged visitors (`0x22dc290`, `0x44458a0`, `0x5ae3fc0`);
  - two `&str` Result visitors (`0x22dde20`, `0x4445960`);
  - three name pools (`&[&str; 5]`: `0x642d068`, `0x648a4c8`, `0x64bc630`).
- Scope excluded:
  - the ten typed payload serializers and the two signature serializers named
    in `envelope-payload-calls.tsv` and `summary.json` (stubbed by call contract);
  - the family-3 record serializer `0x5b5e2e0`, a four-field map whose `tx_type`
    field is written as a plain string through the table `0x93e1e8`;
  - the family-3 tail-call writer `0x5b69bb0` (table `0x93e278`).

## Reproduce

From the repository root, with Python 3 and no other program:

```
python3 tools/evm_tx_type_name_codec_115.py --out research/work-items/evm-tx-type-name-codec-115
python3 -m unittest tests.test_evm_tx_type_name_codec_115
```

The producer:
1. Refuses any input whose SHA-256 is not the #115 digest.
2. Locates every body by its `.eh_frame` FDE through the shared
   `tools/fde_extents.py` parser and reads sections through `tools/elf_index.py`.
   NOBITS sections are excluded from VA reads.
3. Decodes each body linearly with a fixed x86-64 subset decoder. Any byte outside
   the subset is rejected, not skipped.
4. Runs every case through the original instructions in a small interpreter.
   External callees are replaced by stubs whose role is derived from the body
   shape. Stores outside the scratch regions are rejected.

All outputs are deterministic. No timestamps, no absolute paths, and sorted
iteration only. A run takes about 10 s.

Human-readable excerpt (GNU objdump, `-M intel`) of the family-1 envelope
`0x2336410`. It is not used by the tool:

```
2336427: movzx ebp,BYTE PTR [rdx+0x1b] ; xor bpl,0x1 ; shl bpl,0x4 ; or bpl,0x82   # 0x82 map / 0x92 array
233645a: cmp BYTE PTR [r14+0x1b],0x1 ; jne ...          # "signature" key only in map form
2336489: movabs rcx,0x727574616e676973 ; ... 0x65       # "signatur" + "e"
23364b7: call 298e9f0 (rsi = tx+0xe0) ; cmp [rsp],r13   # r13 = 0x8000000000000004 (Ok)
23364f9: movabs rax,0x746361736e617274 ; ... 0x6e6f6974 # "transaction"
2336517: mov rax,[r15] ; add r15,0x10 ; lea rcx,[rip+...] # 0x5ea7d0 ; movsxd ; add ; jmp rax
2336545: ... 0x81 ; 0xa6 ; "Lega" "cy" ; call 2331e60 (rsi = tx+0x10)   # {"Legacy": payload}
```

## Evidence

Coordinates are virtual addresses in the #115 image. `name-pools.tsv` also records
the file offset of each `.rela.dyn` entry.

| File | Rows | Content |
| --- | ---: | --- |
| `functions.tsv` | 10 | role, FDE extent, decoded instruction/byte counts (decoded bytes = FDE bytes for all 10), LSDA, body SHA-256, callees |
| `instructions.tsv` | 1,419 | every decoded instruction: VA, length, raw bytes, operation, branch target |
| `callees.tsv` | 8 | visitor callee roles: 5 unknown-variant callees (2 Result form, 3 tagged form), the lossy-UTF-8 and free slots `0x64df640`/`0x64df4a0`, `_Unwind_Resume` on landing pads only |
| `envelope-jump-tables.tsv` | 10 | each envelope's five jump-table rows read as rel32 from `.rodata` (`0x5ea7d0`, `0x7d0254`), the arm VA, the payload callee and the name the arm stores |
| `envelope-unchecked-heads.tsv` | 4 | every indirect jump with its six-instruction head (`mov add lea movsxd add jmp`, no compare) |
| `envelope-literals.tsv` | 68 | per envelope: msgpack marker stores, key `movabs` words, name-byte stores, reserve bounds, struct-as-map flag compares |
| `envelope-payload-calls.tsv` | 10 | the payload call site of each arm and its callee |
| `visitor-literals.tsv` | 127 | per visitor: length gates, byte compares, xor immediates, result stores |
| `name-pool-refs.tsv` | 8 | the single RIP-relative `lea` into `.data.rel.ro` of each visitor and the pool it names |
| `name-pools.tsv` | 15 | each pool slot: RELATIVE relocation file offset, text VA, length and text |
| `envelope-cases.tsv` | 1,880 | every envelope case: tag, flag, capacity, length, failure mode, appended bytes, grow calls, final length, result words, inner calls, verdict |
| `visitor-cases.tsv` | 2,023 | every input against all 8 visitors (16,184 cells) with the reconstruction's tag |
| `paths.tsv` | 157 | distinct interpreted (function, step count, outcome) paths with input counts |
| `negative-controls.tsv` | 14 | each deliberately wrong reconstruction with the number of cases that catch it |
| `summary.json` | - | counts, names, pools, callee roles (visitor and envelope), unchecked heads, verdict flags |

Byte observations:

- Envelopes (`0x2336410`, `0x44f1bd0`, both 1,634 bytes and 383 instructions).
  - The first byte is `0x82 | ((flag ^ 1) << 4)` from the byte at serializer
    `+0x1b`: `0x82` (fixmap 2) in map form, `0x92` (fixarray 2) otherwise.
  - In map form (`cmp [vec+0x1b],1`), `0xa9 "signature"` follows. The signature
    serializer (`0x298e9f0` / `0x3d42d10`) is then called with `tx+0xe0` and the
    vector. A result word other than `0x8000000000000004` is copied out as the
    24-byte error, and nothing more is written.
  - When the flag is non-zero, `0xab "transaction"` follows. Then the u64 tag at
    `tx+0` indexes a five-row table with no bound check. Each arm writes `0x81`
    (fixmap 1), the fixstr marker (`0xa6` or `0xa7`) and the name, then calls its
    own payload serializer with `tx+0x10`. The result is either `Ok` or the
    payload's error, unchanged.
  - Every single-byte write grows by 1 when `len == cap`. Every key or name grows
    by its length when `cap - len <= len - 1`, with the grow helper (`0x231e050` /
    `0x43bd910`) called as `(vec, len, additional, 1, 1)`.
  - The table rows map tag 0..4 to Legacy, Eip2930, Eip1559, Eip4844, Eip7702,
    which is the pool order. The arms are laid out in a different code order.
- Visitors.
  - `&str` visitors gate on the length (6 for `Legacy`, 7 for the four `Eip`
    names). They then compare a dword plus a word (`Lega`+`cy`), or two
    overlapping dwords (`Eip2`+`2930` at +3, and so on).
  - `&[u8]` visitors compare byte by byte. For the `Eip` names they compare `E`,
    `i`, `p`, then index a jump table with `byte[3] - '1'` (bound `<= 6`), then
    compare the last three bytes. On failure they call the lossy UTF-8 conversion
    (slot `0x64df640`) and report the converted text. They free the owned copy
    (slot `0x64df4a0`) when one was made.
  - Result-form visitors write `{0, tag}`, or `{1, error@+8}` on failure.
    Tagged-form visitors write `0x09 | tag << 8` or the 32-byte error.
- Pools. Every visitor's single RIP-relative `lea` into `.data.rel.ro` names its
  family's pool. The unknown-variant call receives `(text, len, pool, 5)`. The
  pools are read through their RELATIVE relocations; their order is the
  declaration (tag) order.

## Implementation and comparison

The reconstruction is the pure-Python functions `recon_envelope`,
`recon_classify`, `recon_visitor` and `lossy` in the producer. They are written
from the observations above, not derived from the interpreter. Results:

- Envelope cases: 1,880 / 1,880 match.
  - Per envelope, every tag in both forms (flag 0 and 1) at lengths 0/1/7/64
    with 0..21 spare bytes. This covers every reserve edge of the header, the
    keys and each arm.
  - Each tag and form is also run with a failing signature serializer and with a
    failing payload serializer.
  - The inner serializers are stubs that append a fixed two-byte mark
    (`c1 53` / `c1 50`) or return a fixed 24-byte error.
- Visitor cases: 16,184 / 16,184 match.
  - The 2,023 inputs are every name, every prefix and one-byte extension,
    case-folds, every digit at the fourth byte, and byte mutations at each
    position with 55 byte values plus a case flip.
  - They also include cross-name splices, runs of `A` and `0x80`, and 155 inputs
    that are not valid UTF-8.
  - Exactly 5 inputs are accepted (the 5 names). 465 cases free an owned lossy
    copy.

Negative controls. Each wrong reconstruction runs through the same comparison and
must disagree with at least one case. All 14 are caught:

| Control | Caught by |
| --- | ---: |
| envelope header inverted (`0x92` in map form) | 1,880 |
| `signature` key also in array form | 940 |
| variant name written as a bare string (no `0x81` map) | 1,820 |
| alphabetical tag order (Eip1559, Eip2930, Eip4844, Eip7702, Legacy) | 1,456 |
| inner error swallowed (writing continues) | 120 |
| reserve on `cap - len == name_len` | 118 |
| `transaction` written before `signature` | 1,880 |
| visitor prefix match | 280 |
| visitor case folding | 184 |
| `Legacy`/`Eip2930` swapped | 16 |
| first dword only | 6,320 |
| length gate only | 15,504 |
| length + first byte only | 13,152 |
| report raw bytes instead of the lossy conversion | 465 |

The unit tests (25) also cover these checks:
- a wrong digest is refused;
- the packet files are byte-identical to a fresh run;
- MANIFEST hashes;
- known outputs of the visitors and of both envelopes in both forms;
- error propagation from each inner serializer;
- byte mutations of the image that must change the interpreted outcome:
  - a swapped envelope jump-table row;
  - an envelope reserve bound;
  - a name immediate;
  - a row of the visitor's fourth-byte table;
- rejection of `ud2`, unmodelled calls, a wrong pool argument, stores outside
  scratch, and out-of-range reads;
- the unchecked-head rule refuses a compare, and a body with no table jump.

Rust implementation: not yet implemented.

## Results and limitations

- 10 / 10 selected bodies decode fully (decoded bytes = FDE bytes).
- 1,880 / 1,880 envelope cases and 16,184 / 16,184 visitor cases match.
- 14 / 14 negative controls are caught.
- The EIP-2718 meaning is an inference: tags 0..4 equal the EIP-2718 type bytes
  of Legacy (0), EIP-2930 (1), EIP-1559 (2), EIP-4844 (3) and EIP-7702 (4).
  These tags are the in-memory enum discriminants. The type byte of the RLP
  encoding is not covered here.
- That the envelope is a signed transaction is also an inference, from its two
  keys and the value offsets.
- Only the selected bodies are interpreted. The callees are stubs, so the
  allocator, the payload and signature serializers, the lossy conversion and the
  error constructors are modelled by their call contract, not executed.
- Family 3 has visitors but no envelope of this shape. Its two writers
  (`0x5b5e2e0`, `0x5b69bb0`) have other layouts and are out of scope.
- No progress gate is requested. This is one bounded codec family, not the
  `evm` component scope.

Next question: reconstruct the family-3 record serializer `0x5b5e2e0`, a
four-field map with `tx_type` from byte `+0x21` through the table `0x93e1e8`, and
the tail-call writer `0x5b69bb0`. Then reconstruct the five typed payload
serializers of family 1 (`0x2331e60`, `0x2332ac0`, `0x23326f0`, `0x2333450`,
`0x2333850`).
