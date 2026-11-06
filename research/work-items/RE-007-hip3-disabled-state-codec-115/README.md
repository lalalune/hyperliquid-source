# RE-007: reconstruct the node #115 HIP-3 DEX `disabled_state` codec (decode, JSON encode, rmp record encode)

With this packet the HIP-3 per-DEX `disabled_state` enum can be rebuilt as a
complete wire codec. It covers decoding (8 exact-name visitors), serde_json
encoding (3 unit-variant writers) and the MessagePack encoding of the
enclosing per-DEX state record (3 writers, 5 fields, every failure exit). The
enum is `Na = 0`, `UserDisabled = 1`, `ValidatorDisabled = 2`, `m = 3`. A
reconstruction can now fix the four wire names, their tag order and the
record's field order. It can also reproduce the serializer-flag rule that writes
the `disabled_state` key for any non-zero flag, while the four other keys are
written only for flag 1.

- Component ID: `dex-registry` (DEX metadata and clearinghouse registry).
  Task: RE-007 (`l1/clearinghouse/*` leads). The record is the HIP-3 per-DEX
  clearinghouse state.
- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (`artifacts/node/115/hl-node`).
- Source commit / reference commit: repository `05bc2de303c05525b71e7e257426e741bc66a390`.
  No reference source was used. The names come from the binary's own string
  pools and `lea` operands.
- Claim status:
  - **Observation:** bodies, jump tables, literals, pools, keys and callee
    sites are read from the file bytes, and the interpreted behaviour is
    compared with a pure-Python reconstruction.
  - **Inference:** the callee roles (escape writer, reserve, rmp header/str/
    u64/u8/time writers) and the meaning of the flag byte.
  - **Unresolved:** the callee bodies themselves.
- Scope included and excluded:
  - **Included (14 bodies, 1,388 decoded instructions):**
    - 8 visitors in 3 copy families: `&[u8]` tagged, `&str` Result and `&str`
      tagged.
    - 3 serde_json unit-variant writers.
    - 3 rmp writers of the record `{last_settlement_time, deploy_time,
      n_reserve_deployments_used, disabled_state, m}`.
  - **Excluded:**
    - The serde_json writer of the same record (`0x2bc0900` family), which our
      earlier dex-registry packet (`dex-registry-hip3-limits-schema-state-115`)
      holds.
    - The callee bodies and the record's readers.

## Reproduce

From the repository root, with Python 3 (standard library only). No binutils
are needed, the capture is never executed, and no external program is run.

```
python3 tools/hip3_disabled_state_codec_115.py --out research/work-items/RE-007-hip3-disabled-state-codec-115
python3 -m unittest tests.test_hip3_disabled_state_codec_115
```

The tool first checks the input SHA-256 and refuses any other file. It locates
each body by its `.eh_frame` FDE through `tools/fde_extents.py` and reads
sections through `tools/elf_index.py`. NOBITS sections are excluded. It decodes
each body linearly up to its trailing `int3` padding and then runs the original
machine code in an interpreter for the fixed x86-64 subset those bodies use.

Output is deterministic: no times, no random values and no absolute paths, with
sorted keys. Two regenerations into different folders are byte-identical.
`MANIFEST.sha256` lists every other file in this folder.

## Evidence

The coordinate system is virtual addresses of the #115 ELF. Pool slots are tied
to `.rela.dyn` RELATIVE entries by their file offset.

| family | bytes visitor (tagged) | str visitor (Result) | str visitor (tagged) | JSON writer | rmp record writer | name pool |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | `0x2b95310` | `0x2b954f0` | `0x2b955c0` | `0x2bc4310` | `0x2bc06a0` | `0x644cbe8` |
| 2 | `0x4446b40` | `0x4446dd0` | `0x4446d20` | `0x44a0ca0` | `0x449d950` | `0x648a5b8` |
| 3 | `0x546a1a0` | - | `0x546a380` | `0x549f030` | `0x549b410` | `0x64a9c70` |

Generated files:

- `functions.tsv`: FDE extent, decoded instruction and byte counts, LSDA,
  body SHA-256 and callees for all 14 bodies.
- `instructions.tsv`: every decoded instruction (raw bytes, operation, branch
  target).
- `name-pools.tsv`: the three 4-slot `&[&str]` pools. Each slot is backed by
  a RELATIVE relocation, and the text is read at its addend.
- `name-pool-refs.tsv`: the pool `lea` in each visitor. Each family uses
  its own pool.
- `jump-tables.tsv`:
  - 17-entry length tables (lengths 1..17) for the 8 visitors;
  - the 4-entry tag tables of the 3 JSON writers (`0x60924c`, `0x7cf6f4`,
    `0x9265ac`);
  - the 4-entry tag tables of the 3 rmp record writers (`0x60922c`,
    `0x7cf6d4`, `0x92658c`).

  In every tag table, tag 1 and tag 2 land on arms placed in the opposite
  order in the code, and the table, not the code layout, fixes
  `1 = UserDisabled`.
- `visitor-literals.tsv`: the bytes each visitor compares, read from the
  instructions:
  - `Na` as a word compare (bytes visitor: two byte compares);
  - `UserDisa` as a movabs plus `bled` as a dword xor (bytes visitor:
    12 byte compares);
  - `ValidatorDisabled` as an SSE2 16-byte `pcmpeqb` block at `.rodata`
    `0x450550` plus one byte at `0x450fb0` (str visitors) or as 17 byte
    compares (bytes visitors);
  - `m` as one byte;
  - the stored results `0x09 | tag << 8` (tagged form) and `0, tag` (Result
    form).
- `writer-names.tsv`: for each JSON writer arm, the name `lea` and the
  length immediate.
- `record-keys.tsv`: each rmp key call with its `lea`, text and length.
  - The row at the shared enum call site shows the arm that falls through to
    that call (`UserDisabled`). All four arms are listed in `jump-tables.tsv`.
- `callees.tsv`: callee roles, bound from the call-site shape.
  - **Visitors:**
    - The bytes visitor's first `.got` slot is the lossy UTF-8 conversion and
      its second slot is the free.
    - The direct call is the unknown-variant constructor, with 4 names.
  - **JSON writers:** the call after `mov r8d, 1` is `RawVec` reserve(len, 1,
    1, 1); the other call is the escaped-string writer.
  - **Record writers:**
    - the two calls after `mov edx, 5` are the two header writers (the first
      for a non-zero flag, the second for flag 0);
    - a call with a `.rodata` `lea rsi` before it is the str writer;
    - `mov rdx, r12` comes before the u64 writer and `movzx edx, r15b`
      before the u8 writer;
    - the remaining call is the time-field writer.
  - Family 1 passes the time field as (vtable `0x459f78`, 4, `&field`).
    Families 2 and 3 pass `&&field`. The stub accepts both forms and checks
    that it gets the same field offset (+0x8 or +0x14).
- `visitor-cases.tsv`, `writer-cases.tsv`, `record-cases.tsv`: one row per
  input, or per (writer, input), with the interpreted result and the verdict
  `match`/`MISMATCH`.
- `paths.tsv`: distinct (function, instruction count, outcome) paths reached.
- `negative-controls.tsv`: deliberately wrong reconstructions and how many
  cases each one fails.
- `summary.json`: totals.

Record layout, from the operands (observation):

| offset | content |
| --- | --- |
| `+0x0` | `n_reserve_deployments_used` (u64) |
| `+0x8` | `last_settlement_time` |
| `+0x14` | `deploy_time` (12 bytes after `+0x8`) |
| `+0x20` | `disabled_state` tag byte |
| `+0x21` | `m` (u8) |

The writer emits these fields in the order `last_settlement_time`,
`deploy_time`, `n_reserve_deployments_used`, `disabled_state`, `m`.

The serializer flag is the byte at serializer `+0xb`:

- `cmp $0, 0xb(%r14)` selects the header writer and gates the
  `disabled_state` key.
- `cmp $1, 0xb(%r14)` gates the other four keys.

Error exits:

- A failed header, str or u64 write stores
  `(0x8000000000000000, w0, w1)` into the 24-byte result.
- A failed time or u8 write copies the callee's 24-byte result unchanged.
- Success stores only `0x8000000000000004` in the first word.

## Implementation and comparison

The reconstruction is the set of pure functions in
`tools/hip3_disabled_state_codec_115.py`: `recon_classify`, `recon_visitor`,
`recon_writer` and `recon_record`. Each one is compared, case by case, with the
interpreted original bytes. No Rust implementation exists yet.

Callees are stubbed:

- Lossy conversion: borrowed when the input is valid UTF-8; otherwise an
  owned copy with U+FFFD substitutions.
- Unknown-variant constructors: return a sentinel, or fill 32 bytes; the
  pool and count of 4 are checked.
- Escape writer: appends the bytes, grows the buffer when needed, and rejects
  any byte that would need escaping.
- Reserve: moves the buffer to a new address with doubled capacity, so a
  writer that does not reload the pointer would be caught.
- Record callees: each logs its call and, on a chosen call index, returns a
  distinct error value.

| comparison | cases | matches |
| --- | --- | --- |
| visitors (8 bodies × 1,903 inputs: every name, all prefixes, single-byte and case mutations, digit swaps, cross-name splices, invalid UTF-8, lengths 0..19) | 15,224 | 15,224 |
| JSON writers (3 × 1,189: 4 tags × prefixes 0..40 × capacity slack 0/1/2/n/n+1/n+2/n+3/64) | 3,567 | 3,567 |
| rmp record writers (3 × 420: flag 0/1/2/0xff × 4 tags × 3 value pairs × no failure or failure at each call) | 1,260 | 1,260 |

There are 278 distinct paths, 1,179 reserve calls and 1,116 propagated record
errors. There are 438 frees of an owned lossy copy, from 146 invalid UTF-8
inputs.

Every one of the 17 negative controls is caught:

- **visitors:** prefix match, case fold, swapped tags, first dword only,
  length only, first byte only, raw (non-lossy) error text;
- **writers:** reversed names, swapped UserDisabled/ValidatorDisabled,
  single quote, missing closing quote, growing at one free byte;
- **record:** `disabled_state` key only at flag 1, non-zero header only at
  flag 1, reversed names, u64 before the time fields, a key typo.

The unit test adds byte-corruption controls. Each one changes a single byte and
checks that the interpreted original then disagrees with the reconstruction:

- the `U` of the `UserDisa` immediate;
- two swapped JSON-writer tag-table entries;
- the record's `disabled_state` flag compare changed from 0 to 1;
- the record header count changed from 5 to 6. Role binding rejects it, and
  run with the original roles it logs a 6-field header.

The unit test also checks rejection of:

- a wrong digest;
- an unsupported opcode;
- an unmodelled call;
- a wrong pool;
- a store outside scratch memory;
- an out-of-range address;
- a `.bss` read.

## Results and limitations

- 20,051 of 20,051 cases match, and 17 of 17 negative controls are caught.
  The jump tables, name pools and keys come from the bytes.
- No progress gate is requested. This packet covers one enum codec and one
  record writer family, not the dex-registry identifier, lookup or ownership
  scope.
- **Limits:**
  - Callee bodies are stubbed, so the exact bytes the rmp str, u64 and u8
    writers produce, and the time-field encoding, are not reconstructed here.
  - Tags 4..255 are outside every 4-entry tag table. They are not exercised,
    because the enum invariant excludes them; the table bytes past index 3
    belong to neighbouring data.
  - The meaning of the flag byte (struct-as-map mode) is inferred from the
    rmp convention. Only its values 0, 1, 2 and 0xff are observed to behave
    as recorded.
  - The meaning of `m` (wire name `m`, both as a variant and as a u8 field
    key) is not resolved.
- **Next question:** which callers write `disabled_state` (UserDisabled
  versus ValidatorDisabled)? What do the rmp time-field writer `0x226f130` and
  its 12-byte field produce?
