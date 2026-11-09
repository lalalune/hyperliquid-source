# bridge: reconstruct the node #115 Bridge2 state struct serializer (three copies) and prove it against the machine code

With this packet a Bridge2 state serializer can be rebuilt from bytes: the
fifteen-member write order, the five member names that only appear when the
serializer's flag byte is exactly 1, the u64/u32/f64 scalar sources
(`+0x1c8`, `+0x1d0`, `+0x1e4`, `+0x1c0`), the nine-word slice descriptor of
the 0x68-byte ring at `+0x160..+0x178` (including its `0x8000000000000000`
niche form) and the two error exits (wrap `0x8000000000000000, rax, rdx` for
raw writes, copy the callee's three words for member writers) are now an
executable Python model that agrees with the original code of all three
monomorphised copies on 15,960 of 15,960 injected cases, and 44 of 44 wrong
reconstructions, byte corruptions and out-of-range inputs are caught.

- Component ID: bridge
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository `0781ce04826eeefd89fe336cb8ea073be0c1de30` (tool and tests are new files only); no reference source was copied
- Claim status: observation (addresses, layouts, call order, error words) with inference (names of roles) kept in the Inferences list below
- Scope included and excluded: the three bodies at 0x291e600, 0x44d2370 and 0x5afb950 and the behaviour of the code around fifteen stubbed callees; excluded are the callees themselves (the member writers, the rmp string and header writers), the three compact twins 0x291ea40, 0x44d27a0 and 0x5afb5a0 (a different shape with slot calls) and every Rust implementation (not yet implemented)

## Reproduce

```
python3 tools/artifacts.py verify
python3 tools/bridge_state_serializer_115.py --out research/work-items/bridge-state-serializer-115
python3 -m unittest tests.test_bridge_state_serializer_115
```

The tool checks the SHA-256 of `artifacts/node/115/hl-node` first and stops on a
mismatch.  It reads the file with the repository parsers (`tools/fde_extents.py`,
`tools/elf_index.py`) and imports the interpreter of the merged
`tools/bridge_event_name_codec_115.py`, extended in the tool by `imul`, `cmovae`,
`cmovb`, `setcc`, `movsd`, `test r/m8, imm8` and aligned 16-byte moves.  It
never executes the binary and calls no external program.  Output is
deterministic (fixed pseudo-random seed, sorted tables); regeneration takes
about 18 s and about 430 MB.  `MANIFEST.sha256` covers every other file here.

## Evidence

All addresses are virtual addresses of the loaded image; the tool also reads
bytes through the section table (file offset = section offset + VA - section
address).  The three bodies are FDE starts (`functions.tsv`):

| entry | FDE end | bytes | instructions | direct calls |
| --- | --- | --- | --- | --- |
| 0x291e600 | 0x291ea40 | 1088 | 262 | 22 |
| 0x44d2370 | 0x44d279a | 1066 | 257 | 22 |
| 0x5afb950 | 0x5afbd84 | 1076 | 260 | 22 |

Every instruction decodes with the fixed subset (`instructions.tsv`, 779 rows
with raw bytes).  Observations (all from `instructions.tsv`, `callee-roles.tsv`,
`state-accesses.tsv`, `key-literals.tsv`):

1. Arguments: `rdi` is the Result slot, `rsi` the state record, `rdx` the
   serializer; the flag byte is `[rdx+0xb]`.
2. `[rdx+0xb] == 0` calls the first header callee (`0x25e7940` in the root copy)
   and any other value the second (`0x25e7670`); both receive count `0xf`.  A
   header result word other than 2 is an error.
3. `[rdx+0xb] == 1` (and only 1) writes five names through the string writer
   (`0x25e8750`, a call per name, result 2 = ok): `eth_id_to_deposit_votes`,
   `finished_deposits_data`, `dvp`, `dvpd`, `dvs` before the members at `+0x18`,
   the ring, `+0x60`, the double and `+0x180`.  The names are read from
   `.rodata` at runtime addresses (0x5fe820.. in the root copy, 0x7d09dd..
   and 0x93e500.. in the others; `dvpd` is shared at 0x459f80).
4. Member order after the double: `+0x1d8`, `+0x80`, `+0xb8`, `+0x1a0`, `+0xf0`,
   `+0x128`, then three named scalars (`bal` from the u64 at `+0x1c8`,
   `last_pruned_deposit_block_number` from the u64 at `+0x1d0`, `oaw` from the
   u32 at `+0x1e4`), then one writer that receives the whole state record.
5. Member writers return a three-word Result in the slot; the code compares
   word 0 with `0x8000000000000004` (kept in r12) and on a mismatch copies the
   three words to the caller unchanged.  Header, name and double failures are
   wrapped as `0x8000000000000000, rax-or-tag, rdx-or-word1`.  Success stores
   only `0x8000000000000004` in word 0.
6. Ring member: a niche test `[+0x160] == 0x8000000000000000` (the optional
   form) builds `[some, 0, p, h, some, 0, p, h, last]` where some = (p != 0)
   and last = len when p != 0; otherwise with `len = [+0x178] == 0` all
   slice bounds are the base pointer; otherwise
   `cap = [+0x170]`, `head = [+0x160]`, `first = cap - (head if cap >= head else 0)`,
   `gap = head - first`, and the descriptor is
   `[2, p+first*0x68, p+second*0x68, p, p+third*0x68, 0, p+second*0x68, p, third]`
   with (second, third) = (head, len-gap) when len > gap and (len+first, 0)
   otherwise.  The descriptor is passed by pointer to the ring writer
   (`0x222f910` in the root copy) whose Result slot is the second stack slot
   (frame + 0x48).
7. Copy differences read from bytes: in 0x44d2370 and 0x5afb950 the
   `last_pruned_deposit_block_number` writer takes only (slot, serializer, value)
   (the name lives in the callee), and in 0x44d2370 the double writer uses the
   three-word Result slot protocol instead of returning 2.  The tool detects
   both from the decoded bodies (`callee-roles.tsv`, `key-literals.tsv`) and the
   model takes them as parameters.

`ring-descriptors.tsv` lists the model output for the 20 fixed ring fixtures,
`paths.tsv` the number of cases per copy, flag class, last call and outcome,
`ring-classes.tsv` the number of cases per ring class, `cases-sample.tsv` every
fourth case (3,990 rows) with steps, call count, last call and out words.
Analysis is complete for the three bodies (every instruction decoded, the
whole run executed); callees are stubs.

## Implementation and comparison

`model_events`, `model_run` and `ring_words` in `tools/bridge_state_serializer_115.py`
are an independent pure-Python reconstruction written from the decoded bodies
(no Rust yet).  For every case the original bytes run in the interpreter with a
recording stub per callee; the recorded call list (role, normalised arguments:
frame slot, serializer, state offset, name text read from the bytes, scalar
value, ring words) and the final three Result words must equal the model.

Case design (15,960 cases = 3 copies x 4 flags {0, 1, 2, 0xff} x 40 ring states x
every call position with one or two result shapes plus one clean run): the
ring states are 20 fixed edge fixtures (niche with and without pointer,
`len == gap`, head above capacity, huge head/cap/len, pointer wrap) and 20
pseudo-random ones; the failure shapes are eight three-word results including
the near-miss marker `0x8000000000000005` and the plain tag 2 (an error for
member writers).  The state and serializer bytes are pseudo-random so
displacement mutants cannot hide.  The stubs only fail at the injected
position; nothing may run after the failure, which the model also asserts.

Negative controls (44, all caught, `negative-controls.tsv`):

- 28 wrong reconstructions (begin arms swapped, names written for any flag,
  element size 0x60, niche off by one, strict capacity compare, third slice
  off by one, swapped member order, `bal` read from the pruned word, u32 read
  as 16 bits, double error not wrapped, extra wrapping of the first member,
  success marker + 1, swapped names, member count 14, ring slot 0x40, success
  clearing the other words, begin error copied, no capacity compare, swapped
  tail arguments, wrong name lengths, no error wrapping, ...), each checked
  against 1,228 cached machine-code results;
- 10 byte corruptions in the root copy (one byte of each of eight
  displacements, the `cmpb $1` immediate and the `imul $0x68` immediate), each
  rerun over 160 cases;
- 6 out-of-range inputs (wrong digest, entry not at an FDE start, FDE end inside
  the body, callee without a stub, tiny step limit, unset state bytes).

## Results and limitations

- 15,960 / 15,960 cases match (5,320 per copy); 44 / 44 negative controls
  detected; `measure.json` carries these three numbers; 1,948,790 interpreted
  instructions in the main run.
- Tests: `tests/test_bridge_state_serializer_115.py` (31 tests), no skips.
- Inferences (not byte facts): the callee roles (member writers, header
  writers) and the label "optional ring slice descriptor" are names for
  observed behaviour; the framing as rmp map/array with names when the flag is
  1 is suggested by the string writer's `0xa0/0xd9` length prefix bytes and
  the repeated `fixarray` marker code but the callees are not modelled here.
- Not covered: the callee bodies (tracker and ring member writers), the
  decoder side, the three compact twins, and any Rust port.  No progress gate is
  requested.
- Next question: the member writers at 0x28a9370, 0x21fe290, 0x2d571d0 and the
  tail writer 0x293dae0 (what each of the fifteen members writes into the
  stream) and the decoders 0x1e75780 / 0x40b5b20 that read the same members back.
