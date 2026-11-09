# risk: oracle outcome enum serde_json entry (deserialize_enum, both copies) in node #115

This packet reconstructs, from byte evidence, how node #115 reads the oracle outcome enum
(`StandaloneOutcome`, `Question`, `QuestionOutcome`) from JSON: the two `deserialize_enum`
bodies `0x25d8cb0` and `0x4490cd0` that call the already-reconstructed leaf readers. New facts that
an independent Rust implementation can now fix, each checked against the original machine code on
every case: only `Question` is a unit variant (bare `"Question"` or `{"Question":null}`);
`StandaloneOutcome` and `QuestionOutcome` are struct variants with exactly one named field each
(pool lists of length 1) and are an invalid-type error in the bare-string form; the map form
charges and refunds the reader's recursion budget (flag at `+0x48`, remaining depth at `+0x49`,
limit error 24 when the remaining depth reaches 0, panic when it is 0 on entry); and every
failure exit with its serde_json error code, index left behind and payload drop. This corrects the
"unit enum" wording of the merged `risk-outcome-kind-codec-115` packet: its readers match names
only, the entry decides what follows the name.

- Component ID: `risk` (clearinghouses and oracles; the enum's pool is adjacent to
  `l1/src/clearinghouse/oracle/oracle.rs`). No task ID is claimed.
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `0781ce048` (main when generated). No reference
  source and no #94 result was used.
- Claim status:
  - Observation: the two entry bodies (FDE extents, instruction bytes), call-site order and
    callee roles, both jump tables, every error-code immediate, the niche constants, the
    budget field offsets, and the interpreted outcome of every case.
  - Inference: the serde_json names of the error codes (3 EofWhileParsingObject, 5
    EofWhileParsingValue, 10, 24 RecursionLimitExceeded), the meaning of the `+0x48/+0x49`
    bytes as `disable_recursion_limit` / `remaining_depth`, and `Unexpected::UnitVariant` for
    the value 13 passed to the invalid-type constructor.
  - Unresolved: the contents of the two struct payload readers (`0x1e0c420`/`0x1e07570`,
    `0x3f96950`/`0x3fa9340`), the field semantics of `side_names` and `parent`, the callers of
    the entries, and the MessagePack entries (`0x1a0a030`, `0x310f970`, `0x4adb6d0`).
- Scope included: entries `0x25d8cb0`, `0x4490cd0` (843 bytes each, LSDA present); run as
  original code and nested: key readers `0x1debf40`/`0x3f7ea60`, identifier readers
  `0x1e21040`/`0x3fba720`, `null` matchers `0x1e3e7c0`/`0x3fd2750`.
- Scope excluded (stubbed by role): the two struct payload readers per copy, the string
  scanner, the error constructors, the payload drop.

## Reproduce

From the repository root, Python 3 standard library only:

```
python3 tools/risk_outcome_enum_entry_115.py --out research/work-items/risk-outcome-enum-entry-115
python3 -m unittest tests.test_risk_outcome_enum_entry_115
```

The producer checks the SHA-256 of `artifacts/node/115/hl-node` first and refuses other input.
It reads sections through `tools/elf_index.py`, FDEs through `tools/fde_extents.py` and
reuses the interpreter of the merged `tools/risk_outcome_kind_codec_115.py` (imported; three
instruction forms are added: byte `test`/`inc`/`dec`, `cmp al,imm8`, `ud2`). It never
executes the capture and starts no external program. Output is byte-identical across runs.

## Evidence

All addresses are virtual addresses in node #115.

| File | Content |
| --- | --- |
| `functions.tsv` | the 2 entry bodies: FDE extent, instruction count, LSDA, body SHA-256 |
| `instructions.tsv` | every decoded instruction of both bodies with raw bytes |
| `callee-roles.tsv` | per entry: the 8 direct and 4 slot callees bound by first-call order, nested vs stub |
| `jump-tables.tsv` | the two 4-entry relative jump tables (result tag -> arm) |
| `paths.tsv` | distinct (family, budget state, outcome, entry calls) paths and their case counts |
| `cases-sample.tsv` | every 29th case with the interpreted outcome |
| `negative-controls.tsv` | 30 deliberately wrong reconstructions or corrupted bytes and cases lost |
| `summary.json`, `measure.json` | totals |

Entry shape (objdump, for reading only; family 1):

```
25d8cb0: loop: skip bytes in mask 0x100002600 ; EOF -> mov [rsp],5 ; call 1d75420 (peek error)
25d8d34: cmp rdi,0x22 ; call 1e21040 (identifier reader) ; jump table 5efff4[tag]
25d8d6f: cmp edi,0x7b ; else mov [rsp],0xa ; peek error
25d8d78: cmp BYTE [rsi+0x48],0 ; dec BYTE [rsi+0x49] ; zero -> mov [rsp],0x18 ; peek error
25d8db2: call 1debf40 (key reader) ; jump table 5f0004[tag]: 1e0c420 / 1e3e7c0 / 1e07570 / error
25d8e8f: inc BYTE [rdi+0x49] ; cmp [rsp+0x18],0x8000000000000002 ; skip blanks ; cmp esi,0x7d
```

Jump tables (read from the file): identifier result tag 0 and 2 -> invalid-type exit
(`mov BYTE [rsp],0xd`), 1 -> `Ok(Question)`, 3 -> pass the reader error; key result tag 0 ->
struct payload with pool `["side_names"]` (copy 1), 1 -> `null` matcher, 2 -> struct payload with
pool `["parent"]`, 3 -> pass the reader error. The result enum uses the niche constants
`0x8000000000000002` (Err) and `0x8000000000000000` (Question); struct payloads are copied
verbatim (48 bytes).

## Implementation and comparison

There is no Rust implementation yet. The reconstruction is the pure-Python `recon_enum`
(with `reader_at` and `null_at`) in `tools/risk_outcome_enum_entry_115.py`, written from the
semantics above and independent of the interpreter. The interpreter runs the original bytes
for the fixed subset and rejects any other opcode, unset read, store outside scratch, unmodelled
call or unbalanced stack. The leaf readers and the `null` matcher run as nested original code on
the same memory; only the struct payload readers are stubbed (one JSON value is consumed and a
marker block is written) so the comparison proves the entry's own control flow, error codes,
index and budget bookkeeping, and the call order, not the payload parsing.

| Comparison | Cases | Match |
| --- | --- | --- |
| entry bodies (2 copies x 11816 inputs/budget states) | 23632 | 23632 |

The inputs (11816 distinct JSON slices per copy): 36 base documents (each variant in bare and map
form, whitespace, truncations, wrong names, payload shapes), every prefix of each, every single-byte
replacement from a 12-byte set and every single-byte deletion, with the default budget (128), plus
budget states (enabled, 2), (enabled, 1), (enabled, 0), (disabled, 0), (disabled, 7) on every third input.

Negative controls (30, all caught): 11 wrong reconstructions (tab not whitespace, prefix
name match, bare struct variant accepted, wrong map opener, wrong limit, wrong limit code, budget
charged when disabled, no refund, refund when disabled, wrong closer, swapped tags) and 15 code
corruptions in both copies (compare immediates, error codes, flag compare, dec/inc, mask bit,
field counts) plus 4 jump-table swaps. A corrupted image counts as caught when it is
rejected by the interpreter or disagrees with the reconstruction; `negative-controls.tsv` lists
the cases lost by each. The unittest also checks a `ud2` at the entry, a wrong binary, a read
below the first section, an unset scratch read and an unmodelled-call rejection.

## Results and limitations

- 23632 of 23632 cases match, 30 of 30 negative controls are caught, 160
  distinct paths are exercised (`paths.tsv`).
- The payload readers, the string scanner and the error constructors are stubs, so struct
  payload parsing, escape handling and exact error values of those callees are not proven.
- The serde_json names above are inferences from the public crate; only numbers are observed.
- The family-2 copy has the same shape; its pools and the `null` matcher expected-type argument
  are read from its own bytes and differ from family 1.
- No progress gate is requested.

Next question: the MessagePack (rmp-serde) enum entries `0x1a0a030`, `0x310f970` and `0x4adb6d0`
(1,769 bytes each) that call the merged `&str`/`&[u8]` visitors, and the callers `0x1f0284c`,
`0x1f0291e`, `0x40e86fb`, `0x40e87cc` of the JSON entries.
