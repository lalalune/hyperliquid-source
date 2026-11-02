# RE-001: input sources of every slice checked by the node #115 fee-schedule gate

- Component: `fees`; follow-up to `RE-001-node115-fee-schedule-gate`.
- Target #115: 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: `c53a681` (the gate packet's branch; #2153).
- Question: the gate packet decodes nine ordering predicates over local slices but binds only their element 0. Which input fields supply the remaining elements of each slice?
- Claim status: byte-derived bindings plus conditional normal-path relations. Source names are not recovered. No Rust reconstruction, oracle or progress gate.

## Result

All sources are decoded from bytes. "tier" is the 48-byte record list at
`input+0x08` (pointer) / `input+0x10` (length). "second" is the 16-byte record
list at `input+0x20` / `input+0x28`.

| Slice (gate packet #) | Predicate (gate packet) | Element 0 | Elements 1..n |
| ---: | --- | --- | --- |
| 1 `[rsp+0x90]` | f64 non-increasing | `input+0x68` | `tier[i]+0x00` |
| 2 `[rsp+0xa8]` | f64 non-increasing | `input+0x70` | `tier[i]+0x08` |
| 3 `[rsp+0xc0]` | f64 non-increasing | `input+0x78` | `tier[i]+0x10` |
| 4 `[rsp+0xd8]` | f64 non-increasing | `input+0x80` | `tier[i]+0x18` |
| 5 `[rsp+0x20]` | f64 non-increasing | `input+0x70` | `second[i]+0x08` |
| 6 `[rsp+0x38]` | f64 non-increasing | `input+0x80` | `second[i]+0x08` |
| 7 `[rsp+0x68]` | u64 strictly increasing | `0` | `tier[i]+0x20` (u64) |
| 8 `r14`/`rbx` | f64 strictly increasing (NaN passes) | `+0.0` | `second[i]+0x00` |
| 9 `[rsp+0x50]` | `fees.rs:259` helper, non-increasing | `1.0` | `tier[i]+0x28` |

So, in this normal-path relation, a fee schedule is rejected unless:
- each tier field `+0x00/+0x08/+0x10/+0x18` never rises across tiers and never exceeds its input-level base;
- the u64 `+0x20` strictly increases from a value above 0;
- `+0x28` never rises from 1.0;
- in the second list, `+0x00` strictly increases from 0.0 and `+0x08` never rises and stays at or below both bases `input+0x70` and `input+0x80`.

NaN behaviour is inherited from the gate packet.

## Tier loop (`0x36a1df7..0x36a2040`)

- **List geometry**:
  - the end is `ptr + len*3*16`, from `lea rax,[rax+rax*2]; shl rax,4` at `0x36a1e10`;
  - the cursor advances by `add rcx,0x30` at `0x36a1e48`;
  - an empty list (`test rax,rax` at `0x36a1dfb`) skips the loop.
- **Field loads**: `+0x20` (u64) goes to `[rsp+0x258]`; `+0x00` to `[rsp+0x110]` and `[rsp+0x8]`; `+0x08` to `[rsp+0x10]`; `+0x10` to `[rsp+0x268]`; `+0x18` to `[rsp+0x260]`; `+0x28` to `[rsp+0x248]`.
- **Dispatch**: a jump table at `0x799c8c` (.rodata) holds five int32 entries relative to its base, decoding to `0x36a1f10, 0x36a1f77, 0x36a1fb0, 0x36a1f90, 0x36a1ff0`.
  - The index is `state >= 4 ? 4 : state` (`cmovae ecx,r15d`, where `r15d=4`), and the next state is `min(state,3)+1`.
  - From state 0 this gives **0, 1, 2, 3, 4** per record (`state_sequence_per_record`).
  - State 4 ends the record.
- **What each state pushes**, through the generic `{cap,ptr,len}` push at `0x36a1f10`/`0x36a1fd0` (value in `[rsp+0x8]`):

  | State | Vector header | Value slot | Record field |
  | ---: | --- | --- | --- |
  | 0 | `0x88` (r13) | `0x8` | `+0x00` |
  | 1 | `0xa0` | `0x10` | `+0x08` |
  | 2 | `0xb8` | `0x268` | `+0x10` |
  | 3 | `0xd0` | `0x260` | `+0x18` |
  | 4 | `0x60` (u64 store) | `0x258` | `+0x20` |
  | 4 | `0x48` (via `0x36a1e40`) | `0x248` | `+0x28` |

A header `H` carries its pointer at `H+8` and its length at `H+0x10`. The gate
packet's slice pointer slots `0x90/0xa8/0xc0/0xd8/0x68/0x50` therefore match
headers `0x88/0xa0/0xb8/0xd0/0x60/0x48`.

## Second list (`0x36a2040..0x36a2438`, `0x36a29a4..0x36a2a0d`, `0x36a2c56..0x36a2d59`)

`rbp` is the spilled input. The list pointer is `[rbp+0x20]` (`0x36a20b5`) and
its length is `[rbp+0x28]` (`0x36a20b9`). Each extend has a 4-wide vector body,
a remainder loop and a 4×-unrolled loop. The decoded field offset is the same on
every path:

| Vector header | Body (`base` + disp, stride 16) | Remainder | Unrolled | Field |
| --- | --- | --- | --- | --- |
| `0x18` (slice 5) | `rbx+0x38` − 0x30.. | `2*r10`, r10=4 | `+8` pre-add, `2*0x18-0x30` | `+0x08` |
| `0x30` (slice 6) | `rbx+0x38` − 0x30.. | `2*r10`, r10=4 | `+8` pre-add | `+0x08` |
| `0xe8` (slice 8) | `rbx+0x30` − 0x30.. | `[rsi]`, stride 0x10 | no pre-add | `+0x00` |

Element-0 seeds of slices 5 and 6 are loaded in the prologue
(`input+0x70` → `[rsp+0x80]`, `input+0x80` → `[rsp+0x78]`), reloaded at
`0x36a2054`/`0x36a208c` and published as the vector pointers at
`[rsp+0x20]`/`[rsp+0x38]`. Slice 8 has header `0xe8`, is seeded with the
u64 0 bit pattern (`+0.0`, at `0x36a2402`) and is checked through registers:
`r14` is reloaded from `[rsp+0xf0]` after growth (`0x36a29c4`), and `rbx`
holds the length (`mov rbx,r15` at `0x36a260e`, with `r15 = r13`, which is
stored to `[rsp+0xf8]` at `0x36a243c`). An empty second list sets `r12b`, and
`test r12b` at `0x36a242f` skips its extend.

## Relation to retired #94 evidence

The labels of #128 `fields.tsv` line up with these offsets: "vip" records have
stride 0x30 at `+0x08/+0x10`, and "mm" records have stride 0x10 at
`+0x20/+0x28`, with `makerFractionCutoff` at `+0` and `add` at `+8`.
#128's ordered rows 1–9 map to slices 1–9 above, including "mm add seeded with
add/spotAdd" (slices 5 and 6). These are **leads only**; no #94 name is
asserted for #115.

## Reproduce and validation

Python 3.13.18, Linux x86_64, GNU objdump 2.42. From repository root:

```sh
python3 -B tools/fee_schedule_sources_static.py --output work/fee-schedule-sources115
python3 -B -m unittest discover -s tests -p test_fee_schedule_sources_static.py -v
make doctor verify test catalogue-check
(cd research/work-items/RE-001-node115-fee-schedule-sources && sha256sum -c MANIFEST.sha256)
```

`_analyze()` decodes every binding from byte templates whose variable fields
(displacements, the table, immediates) are extracted, not assumed. It then runs
the gate packet's `_analyze()`, which pins both FDE bodies, and joins the
decoded sources to the gate's slice pointers. An unresolved or inconsistent
source raises.

Five focused tests cover:
- byte-identical regeneration;
- the decoded table of sources and the state sequence;
- **14 synthetic fee schedules** run through the joined model (sources plus the
  gate packet's predicates). These include a tier rate rising above its base,
  equal adjacent rates (pass), non-increasing u64 cutoffs, a first cutoff of 0,
  `+0x28` above 1.0, NaN cases and empty lists;
- **four counterfactuals** that mutate real bytes:
  - swapping two jump-table entries reorders states without moving values;
  - moving the `+0x10` load to `+0x30` moves slice 3's source;
  - changing the remainder start to 0;
  - moving the slice-8 body base;
- **14 corruption controls** below the identity gate, each rejected. They change the stride, table base, clamp constant, a vector header, two value slots, a capacity slot, the second-list field, the body stride, the unrolled start, the slice-8 seed and length register, a seed input field and an unrelated caller byte.

The synthetic schedules are inputs to an interpretation of decoded bytes, not
executions of the target.

## Limits and next question

- **Opaque call before the checks.** `0x3d3b6c0` (called at `0x36a2651`)
  receives the addresses of vector headers `0x88/0xa0/0xb8/0xd0` and begin/end
  pairs for slices 5, 6, 9 and 8. The checked slices equal the constructed ones
  only if that call does not mutate them, which is not proved here.
- **Growth helpers assumed.** `0x64e6148`, `0x64e8d58` and `0x43bd910` are
  assumed to preserve `{cap,ptr,len}` and the existing elements, with
  normal-path returns.
- **Not recovered:** source names; the success path; the `input+0x48` map and
  `input+0x50..0x60` fields that feed `0x3d3b6c0`.

Next question: what `0x3d3b6c0` computes over the four tier vectors, the
second-list slices and the `input+0x48` structure, and whether it can fail the
gate before the ordering chain.

No captured code was executed. Imports, pins and gates are unchanged.
