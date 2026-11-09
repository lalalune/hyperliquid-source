# RE-009: reconstruct the node #115 MessagePack header writers over a growable byte vector and prove them against the machine code

This packet lets a reimplementation reproduce, bit for bit, how node #115 appends MessagePack map headers, unsigned integers and strings to a `Vec<u8>`: the marker/length-class decisions, the exact byte order, the capacity growth policy (doubling, element-size minimums, the layout limit), the two distinct failure words (`marker` failure vs `data` failure) and the stale register residue that is left in the result slot. Seven function bodies are reconstructed as one call graph, and 10,477 generated cases are executed twice (a Python reconstruction and the real machine bytes on an x86-64 evaluator with stubbed allocator) and compared, 0 mismatches; 57 negative controls are all detected.

- Component ID: RE-009 (state serialisation path; the same writers sit under the state-export serializers)
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository commit `0781ce04826eeefd89fe336cb8ea073be0c1de30`; reference tree `references/can1357-hl` consulted only for naming hints, nothing copied
- Claim status: observation (address ranges, constants, branch conditions, executed behaviour) / inference (function roles, allocator slot roles) — separated below
- Scope included and excluded: the seven bodies listed below; excluded are the callers (serializer drivers), the real allocator behind the GOT slots (stubbed, see Limits), and the unreached `reserve` fallback pads (listed, not executed)

## Reproduce

```
python3 tools/rmp_vec_writers_115.py --out research/work-items/RE-009-rmp-vec-writers-115
python3 -m unittest tests.test_rmp_vec_writers_115
sha256sum -c research/work-items/RE-009-rmp-vec-writers-115/MANIFEST.sha256
```

The tool verifies the binary digest first, never executes the binary, calls no external program and imports only the standard library plus the repository's shared evaluator `tools/decimal_scaled_u64.py`. Regeneration takes about 65 s and 0.65 GB peak memory; output is deterministic (no clock, no randomness beyond a fixed LCG, no paths). The 24 unit tests (known answers, round trips of the machine-written bytes through an independent MessagePack reader, quirks, controls) take about 35 s.

## Evidence

All addresses are virtual addresses of node #115 (function extents come from the `.eh_frame_hdr` table through the shared reader, `coverage.tsv`).

| Body | VA | bytes | Role (inference from the compared behaviour) | Signature seen on the machine |
|---|---|---|---|---|
| finish_grow | 0x4787da0 | 233 | `RawVec::finish_grow` for byte/word elements | rdi out{tag,ptr,size}, rsi old cap, rdx old ptr, rcx new cap, r8 align, r9 element size |
| reserve | 0x4787e90 | 142 | `RawVec::reserve` (amortised) | rdi vec, rsi len, rdx additional, rcx align, r8 element size |
| grow_one32 | 0x4787d30 | 100 | `grow_one` for 32-byte, 8-aligned elements | rdi vec |
| write_marker | 0x477bd40 | 273 | `rmp::encode::write_marker`-style single byte with payload folding | rdi `&mut &mut Vec`, sil marker, dl payload; rax 0 or error word |
| write_map_len | 0x477be60 | 1031 | map header (fix / 16 / 32) | rdi out, rsi `&mut &mut Vec`, edx length |
| write_uint | 0x47789c0 | 1966 | unsigned integer (fix / 8 / 16 / 32 / 64) | rdi out, rsi `&mut &mut Vec`, rdx value |
| write_str | 0x4778560 | 1117 | string header + bytes | rdi `&mut &mut Vec`, rsi data, rdx length; rax/rdx result pair |

Observations reproduced by the reconstruction (every one is checked by the 10,477 cases):

1. Vec layout: capacity at +0, pointer at +8, length at +0x10. Empty vectors use pointer 1 (dangling) and capacity 0.
2. `finish_grow`: size = element size x new capacity; an overflow of the 64-bit product, or a product above `2^63 - align`, returns tag 1 with pointer 0 and **leaves +0x10 untouched** (no allocator call). Otherwise it calls one of four allocator slots: GOT 0x64df588 (plain realloc) / 0x64df580 (aligned realloc, `tzcnt(align)` in rdx) when the old capacity is non-zero, GOT 0x64df480 (malloc) / 0x64df590 (aligned alloc) when it is zero; a zero-size first allocation returns the alignment itself without a call. The plain variants are chosen when `align < 0x11 and align <= size`, or when `tzcnt(align) == 0`. A null result returns tag 1 with the alignment and size.
3. `reserve`: element size 0 or a `len + additional` carry calls the error slot 0x64df498 with (0, len); otherwise the new capacity is `max(len+additional, 2*cap)` raised to 8 for 1-byte elements, 4 for elements up to 1024 bytes, 1 above that; a failed growth calls the error slot with (pointer-or-align, size), where size is stale stack when the layout check failed.
4. `write_marker`: markers 0xc0..0xdf are written as is; marker 0 writes the payload byte, markers 1..0x8f write `(payload & 0xf) | 0x80`, 0x90 writes `(payload & 0xf) | 0x90`, 0xa0 writes `(payload & 0x1f) | 0xa0`, every other marker writes the payload byte unchanged. A full vector grows to `max(2*cap, 8)`; failure returns the word 0x2600000003.
5. `write_map_len`: classes by the **32-bit** length (< 16 fixmap, < 65536 `0xde`+be16, else `0xdf`+be32). Success writes tag 2 and the marker byte at +8; byte +9 is the residual register byte (length low byte for fixmap, bits 8..15 for map16, bits 24..31 for map32). A failure writing the marker gives tag 0, a failure reserving the length bytes gives tag 1, both with 0x2600000003 at +8.
6. `write_uint`: < 0x80 one byte; < 0x100 `0xcc`+1; < 0x10000 `0xcd`+be16; < 2^32 `0xce`+be32; else `0xcf`+be64. Same tag-0/tag-1 failure split as the map header; in the first class the marker slot is byte 0 and +9 holds the value.
7. `write_str`: classes by the **low 32 bits** of the length (< 32 fixstr via the marker writer, < 256 `0xd9`, < 65536 `0xda`, else `0xdb`), but the data is copied with the **full 64-bit** length. So a length of 2^32+5 is classified as a 5-byte fixstr and then asks for a 4 GiB copy (the stub allocator refuses it: result pair (1, 0x2600000003) after the marker byte already landed). Result pair: rax 2 / rdx 0 success, rax 0 marker failure, rax 1 data failure, rdx 0x2600000003 for both failures. The copy is skipped for length 0.
8. Executed coverage (`coverage.tsv`): `finish_grow`, `reserve`, `grow_one32` are executed to every instruction; in the four writers the only never-executed instructions are 13 runs, **all** of which contain the direct call to `reserve` (0x4787e90) after a growth that already guaranteed room — a defensive second capacity check that cannot fire while `finish_grow` returns a larger capacity (`coverage.tsv`, column `unexecuted_runs`, every run tagged `reserve-pad`).

## Implementation and comparison

`tools/rmp_vec_writers_115.py`:

- `Env` is a deterministic allocator/memcpy/error-handler stand-in used by **both** sides, so heap addresses and the call log (allocator arguments, memcpy arguments, error-handler arguments) must match, not only the produced bytes. Allocation requests above 16 MiB are refused; the k-th allocation can be forced to fail (`fail_at`).
- The reconstruction (`finish_grow`, `reserve`, `grow_one32`, `model_marker`, `model_map_len`, `model_uint`, `model_str`) is plain Python over a byte-addressed memory dict with a table of constants `K`.
- The machine side runs the real instruction bytes with `RMachine` (the shared evaluator plus `bswap`, rotate, allocator-slot stubs); callee-saved registers are checked to be restored (a violation is a mismatch).
- Each case compares: termination kind, return words, vec capacity/pointer/length, SHA-256 of the written bytes, the full 32-byte result slot (pre-filled with 0xa5 so stale/untouched bytes are visible), and the complete stub call log.
- Cases (`cases.tsv` lists every 2nd; the chain digest per row covers the full snapshot): 18 vec states x 3 failure schedules (none / first / second allocation fails) x boundary values per function, plus 2,400 pseudo-random cases: marker 3,940, uint 1,568, map_len 1,550, reserve 1,329, str 1,280, finish_grow 756, grow_one32 54.
- Negative controls (`controls.tsv`): 35 constant mutations of the reconstruction and 22 single-byte corruptions of the binary (immediates and limits inside the instruction at the listed address). 57 of 57 are detected; `equivalent-mutants.tsv` is empty (an earlier draft left `layout_cap=2^62` undetected because no probe case sat between 2^62 and 2^63; that probe was added, not the mutant dropped).

## Results and limitations

Machine-readable: `measure.json` — cases 10,477, mismatches 0, negative controls 57, detected 57, equivalent 0. `outcomes.tsv` shows which terminations/return words the cases reach (for example `reserve` halts 965 times in the error handler, `str` returns the marker-failure word 112 times and the data-failure word 300 times). `coverage.tsv` gives per-function instruction coverage and the unexecuted pads.

Limits:
- The four allocator slots and memcpy are stubs; their roles (malloc / realloc / aligned realloc / aligned alloc, error handler, memcpy) are inferred from argument shapes and the `tzcnt` alignment argument, not proven from the allocator code. The reconstruction therefore proves the writers' behaviour *given* an allocator with those argument semantics.
- Cases use vectors up to 300 bytes of capacity and data up to 70,000 bytes; lengths above that are reached only through forced allocation failure.
- The 13 reserve-fallback pads are not exercised (shown unreachable by construction, not by execution).
- No caller has been mapped here; the packet requests no progress gate.

Next question: map the serializer drivers that call these writers (the state-export body at 0x4783f20 and the f64 writer at 0x4774eb0 sit in the same module) and reconstruct one complete record serialization on top of them.
