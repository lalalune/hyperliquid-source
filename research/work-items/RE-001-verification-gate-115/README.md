# RE-001: the OptionTypeInfo verification gate (node #115)

## Question

What does the OptionTypeInfo verification field (`record+0xac`) decide?
This packet pins the gate in the two per-entry functions that consult
it: the apply `0x60bedc0` and the serializer `0x60bb9a0`. It resolves
the open unknown from #4263 ("what verification 1/2/3/5 each check").

## Answer (read from the binary)

### Apply (`0x60bedc0..0x60bf5bc`, 493 lines)

| verification | parse outcome | result |
| --- | --- | --- |
| 4 | (not attempted) | Status OK immediately (`0x60bedeb`, `cmpl $0x4,0xac(%rsi); je 0x60bf000`); the value is never parsed and the options struct is untouched |
| 0, 1, 2, 3, 5 | parse succeeds | Status OK (`0x60bf287`) |
| 1, 2, 3 | parse fails | Status code 3 (kNotSupported): `Deserializing the option <name> is not supported` (`0x60bf09c`, literals `0x4373e9` + `0x437403`, code 3 at `0x60bf1a3`) |
| 0, 5 | parse fails | Status code 4 (kInvalidArgument): `Error parsing:<name>` (`0x60bf460`, literal `0x4477ed`, code 4 at `0x60bf472`) |

Verifications 1, 2 and 3 are indistinguishable in the binary: one
range check (`0x60bf08a..0x60bf096`: `sub $0x1; cmp $0x2; ja`) covers
all three and they share the single path. Verifications 0 and 5
share the other path. The parse itself runs through the type jump
table at `0x9786b4` (`0x60bf030..0x60bf057`); on a failed parse, types
21/22 fall to the `0x60bf1e0` fallback arm (re-parse via `0x60b9d70`
and `0x6099e70`) instead of the verification error paths — that arm's
exact error outcome is an open unknown, not modelled here.

### Serialize (`0x60bb9a0..0x60bbdeb`)

Verification 4 skips the entry in the dump: `0x60bb9d4`
(`cmpl $0x4,0xac(%rsi); je 0x60bbae8`) jumps to `0x60bbae8`, which
writes Status OK and returns without emitting anything. Every other
verification value serializes normally (the record's serialize
function at `record+0x38` when non-null, else the type dispatch).

So verification 4 means "this option is not part of the
text round-trip at all": never parsed on apply, never dumped on
serialize. The 33 verification-4 entries over the 214 mapped options
are listed in `records.json` (`verification_4_names`).

### Distribution over the 214 mapped entries

Computed from the records.json files of the two map packets that
first published the entries: #4237 (DBOptions 81 + MutableDBOptions
19 = 100 entries) and #4263 (CFOptions 114 entries).

| verification | DBOptions | CFOptions | combined |
| --- | --- | --- | --- |
| 0 | 83 | 83 | 166 |
| 1 | 1 | 6 | 7 |
| 2 | 1 | 2 | 3 |
| 3 | 1 | 1 | 2 |
| 4 | 14 | 19 | 33 |
| 5 | 0 | 3 | 3 |

Observation (not a proven enum name): the 1/2/3 set is the
factory/comparator/extractor group — `comparator`,
`compaction_filter`, `table_factory`, `merge_operator`,
`prefix_extractor`, `wal_filter`, `listeners`,
`file_checksum_gen_factory` — whose values cannot be deserialized
from a string, which is exactly what the kNotSupported message says.
The verification-5 set is the three table factories (`memtable`,
`block_based_table_factory`, `plain_table_factory`).

## Evidence

- `fn-60bedc0.objdump.txt` — the whole apply function, verbatim
  objdump output. Re-shipped byte-identical from the
  RE-001-optiontypeinfo-maps-115 packet (#4237), which first
  exported it.
- `fn-60bb9a0.objdump.txt` — the whole serializer function, verbatim
  objdump output, generated fresh here.
- `records.json` — semantic records only: the gate decision table,
  the distribution, the named entry sets, the caller lists, the
  literals. No per-instruction mnemonic list.
- `callers.tsv` — every direct call site of the apply (13) and the
  serializer (16), from a byte-level `E8 rel32` scan. Neither
  function is address-taken (no `lea` site targets either).
- `literals.tsv` — the three message literals, read from `.rodata`.
- `frames.txt` — the two FDE ranges from readelf.
- `census.py`, `export_excerpts.py`, `gen_records.py`, `verify.py` —
  the generators and the checker committed in the packet.

Regenerate the excerpts with (from the repo root):

```
python3 research/work-items/RE-001-verification-gate-115/export_excerpts.py
```

and verify the packet with:

```
python3 research/work-items/RE-001-verification-gate-115/verify.py
```

The objdump command for each excerpt is
`objdump -d --start-address=<start> --stop-address=<stop>
work/hl-node-115.bin`. Instruction mnemonics such as `endbr64` are
genuine instructions present in the target binary, not placeholders.

## Model

`tools/option_verification_gate_115.py` models the gate
(`apply_outcome`, `serialize_outcome`, the distribution and the named
sets); `tests/test_option_verification_gate_115.py` tests the full
decision table end to end (every verification value x parse outcome,
the type-21/22 fallback, the distribution totals, and every named
entry against its group outcome).

## Environment limits

This VM has no cargo/rustc, no git-lfs, no Ghidra/Java. The binary
is `work/hl-node-115.bin`, node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`, `artifacts/node/115/hl-node`).
`make verify`, `make test` and `make catalogue-check` could not be
run in the tooled environment here; the packet's own `verify.py`
(which checks the artifact digest, the manifest, excerpt
regeneration, census reproduction, three seeded gate spots against
fresh objdump and the raw binary bytes, the FDE ranges, every cited
instruction, the model constants and the model tests) passes.

## Open unknowns

- The exact error outcome of the type-21/22 fallback arm at
  `0x60bf1e0` when its own parse fails.
- The C++ enum names for the verification values 0..5 (the binary
  pins the behavior per value, not the source names).
- Whether the type-21/22 arm is a fallback after a failed primary
  parse or the primary parse for those types.
- The serializer's type-21/22/22 arms at `0x60bbbf0` and `0x60bbb78`.
