# transport: reconstruct node #115 LZ4 block compressor drivers 0x477e950 and 0x477f040 with their match counter and last-literals writer

With this packet the two compressor drivers of the node #115 transport codec can be re-implemented end to end as pure functions:
the probe loop with its accelerating step, the hash-table update rules (including the cell that is written before it is judged
and the seed store two bytes before the end of every match), the backward extension, the token / literal-excess / offset /
match-excess byte layout, the tail writer, and the "output too small" status. 10,252 generated states are executed through the real
function bytes (interpreted, never run natively) and the reconstruction agrees with them on return value, appended bytes and final
hash table in every one; 52 deliberately wrong variants are rejected (50 detected, 2 byte patches shown to be output-equivalent).

- Component ID: **transport** (Network transport, TCP framing / LZ4); task family RE-012.
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: research base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.
- Claim status: **observation** for every value in `cases.tsv`, `helper-cases.tsv`, `coverage.tsv`, `signatures.tsv` (executed bytes);
  **inference** for the role names used below (hash table, match, literal run), which are chosen from behaviour only.
- Scope included: five FDE-delimited functions listed in `signatures.tsv`. Excluded: the callers that decide which driver runs, the
  allocator and panic slots (served by the interpreter), the decoder, framing, sockets. No progress gate is requested.

The existing RE-012 packets pin pieces of these bodies (hash widths, the candidate judge, the token nibbles, the literal and match
excess runs). This packet differs by reconstructing the **whole driver flow** and proving it on complete inputs: it is the only
artifact here that says what a full call produces, byte for byte, including the interaction between pieces (for example that the
seed store after a match uses the hash of the two bytes before the new position, and that the next probe resumes at the match end
with the step counter reset).

## Reproduce

Working directory: repository root; Python 3 standard library only; no network, no execution of the target binary.

```
python3 tools/transport_lz4_compress_115.py --out research/work-items/transport-lz4-compress-driver-115
python3 -m unittest tests.test_transport_lz4_compress_115
```

The tool checks the SHA-256 above first and fails on any other input. It writes `cases.tsv`, `helper-cases.tsv`, `signatures.tsv`,
`coverage.tsv`, `controls.tsv`, `equivalent-mutants.tsv`, `summary.json`, `measure.json` deterministically (two runs under
different hash seeds and time zones are byte-identical; about 2.3 minutes, well under 1 GB). `MANIFEST.sha256` lists them.
The interpreter inside the tool is the shared x86-64 core (decoder, memory, machine) carried in the tool file; it reads ELF bytes via
the repository `tools/elf_index.py` and `tools/fde_extents.py` and never calls an external program.

## Evidence

All addresses are ELF virtual addresses; function extents come from `.eh_frame` FDEs (`signatures.tsv`):

| function | extent | bytes | instructions | role (inference) |
| --- | --- | ---: | ---: | --- |
| 0x477e950 | 0x477e950..0x477f036 | 1,766 | 401 | driver, 4096 x u16 table |
| 0x477f040 | 0x477f040..0x477f746 | 1,798 | 408 | driver, 4096 x u32 table |
| 0x477e7c0 | 0x477e7c0..0x477e941 | 385 | 113 | forward match counter |
| 0x477f750 | 0x477f750..0x477f8ba | 362 | 89 | last-literals writer |
| 0x477e5c0 | 0x477e5c0..0x477e6d4 | 276 | 74 | sink append (size-class copy) |

Observed calling convention of both drivers (read from the prologue, the stack accesses and the callers' register use):
`rdi` source pointer, `rsi` source length, `rdx` start position, `rcx` sink record `{ptr @0, capacity @8, length @16}`,
`r8` pointer to a word holding the table pointer, stack argument 1 (`0x90(%rsp)` at entry+0x90) must be zero (non-zero reaches a
panic slot), stack argument 2 is an absolute-position offset added to every stored cell. Return `al` is 0 (done) or 1 (not enough room).

Reconstructed behaviour, with the evidence address of each rule (`n` = source length):

1. **Room check** (0x477e999..0x477e9c6): `capacity - length < floor(110 * (n - start) / 100) + 20` returns 1 and writes nothing;
   `110 * x` overflow panics; `n < start` and `capacity < length` panic.
2. **Short input** (0x477e9dc): `n - start <= 12` goes straight to the tail writer.
3. **Seed** (0x477ea06..0x477ea1d): when `start | offset == 0` the cell of the hash of the first word is set to 0 and probing starts at 1.
4. **Probe loop** (0x477ea60..0x477ea90): step counter starts at 32 and grows by one per miss; the next probe is
   `cur + (counter >> 5)`; leaving condition `cur > n - 12`; after a match the counter returns to 32.
5. **Cell rules** (0x477eab4..0x477eaf7, 0x477f1a4..0x477f1f5): hash of the 4-byte word (u16 table: low32(word * 0x9e3779b1) >> 20)
   or of the 8-byte word (u32 table: low64(word * 0xcf1bbcdcbb000000) >> 52); the old cell is loaded and the new value
   `(cur + offset)` truncated to the cell width is stored **before** judging. A cell larger than `cur + offset` panics; a cell below the
   offset or a distance of 65,536 or more is a miss; the candidate must match on **four** bytes in both drivers.
6. **Backward extension** (0x477eb0a..0x477eb76): while bytes before `cur` and before the candidate agree, stop at the previous match end
   or at candidate 0.
7. **Forward count** (0x477e7c0): compares eight-byte words then single bytes up to `min(n - 6 - pos, n2 - q)`, where `n - 6` wraps.
8. **Emit** (0x477ebb5..0x477ee59): table cell for the hash at `end - 2` is set to `end - 2 + offset`; token =
   `min(literals,15) << 4 | min(match-4,15)`; literal excess is `floor(x/255)` bytes 255 then `x mod 255`; the literals are copied by
   0x477e5c0; the distance is stored little-endian in two bytes; the match excess uses the same convention.
9. **Tail** (0x477f750): token with only the literal nibble, the excess run, the literals.
   The append helper (0x477e5c0) panics when `length + count` exceeds capacity; copies of 33 bytes or more go through the slot at 0x64df508
   (a plain copy in the interpreter).

`coverage.tsv` lists, per function, the instruction ranges **never executed** by any generated state. After adding the long-literal and
64 KiB-distance cases the remaining unexecuted ranges are only panic-slot blocks (overflow and index checks of the form
"load rdi from the table, call the slot") and alignment padding; every non-panic instruction of the five bodies is executed.

## Implementation and comparison

`tools/transport_lz4_compress_115.py` holds the model (`model_compress`, `model_count`, `model_tail`, flags for wrong variants), the
harness (`native_compress`, `native_count`, `native_tail`, which prime memory, run the real bytes and read the sink, the table and the
return value), and the generators. Each state is made of: source bytes (random, small alphabets, periodic, repeated blocks with a
gap, zeros), a start position, an absolute offset, a sink capacity from far too small to ample, a sink start position and an initial
table (empty, random, or sparse).

The comparison demands: identical return status; identical appended bytes; identical final table (status 0); or a panic on both sides.
Special states: 64 KiB distance probes at 65,533..65,538 (with and without a diverging byte after the match), and long literal runs of
14, 15, 16, 269..271, 524, 525, 1,034..1,036, 1,290, 1,291 and 2,100 bytes before a match (bulk 0xff fill boundaries).

Corruption controls (`controls.tsv`): 22 wrong model variants (hash multiplier / shift, tail gap 11 / 13, step shift 4 / 6, step start 16,
distance limits 65,535 / 65,537, nibble cap 14, no backward extension, store before load, seed store offsets, count gap 5 / 7, room
percentage 100, room add 19, no first seed, excess base 254, forward skip 3); 22 single-byte patches of the real instructions
(immediates and condition bytes in both drivers, the counter and the tail writer); 8 out-of-range or contract-violating inputs.
A baseline control runs first and the tool aborts if the unmodified model or bytes are ever flagged.

## Results and limitations

Measured (`summary.json`, `measure.json`): 10,252 cases (8,052 full-driver states: 2 x (4,000 random + 26 special); 1,500 match-count
calls; 700 tail-writer calls), all agree; of the driver states 5,006 finish with status 0, 1,620 with status 1 or short rooms and 1,426
end in a panic slot on both sides. 52 negative controls: 50 detected, 2 equivalent (`equivalent-mutants.tsv`: both patches only change
how many of a 255-run are written by the four-byte fill loop instead of the one-byte loop; the emitted bytes are identical, shown
by the test on literal runs up to 2,100). The row chain hash in `summary.json` covers every case line; `cases.tsv` and
`helper-cases.tsv` keep the first 1,500 / 500 / 300 rows per group.

Limits: role names are inferences; which panic slot a failure reaches is not distinguished (panic vs panic is compared); the table
holder, sink record and stack argument 1 are described by access pattern only; the interpreter is not a proof about unexecuted
instructions (the panic blocks); no claim of native equality with a compiled Rust crate; the append slot 0x64df508 is modelled as a copy.
No gate is requested.

Next question: the caller that picks between the two drivers and builds the table holder (the size threshold that selects the u16 table),
and the decoder-side counterpart for a full round trip.
