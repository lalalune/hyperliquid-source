# RE-008: node #115 line framer census (stage 79)

- Component ID: abci. Question: stage 78 (open PR #6077) split the 96 functions that call the line writer `0x14c37f0` into 21 that call the time writer `0x4fcd860`, 39 that store `[` (`c6 00 5b`) without it, and 36 that do neither. It left open what the 39 bracket framers write before the `,`, and which writer each framer belongs to.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). Continues #5874 (writer names) and #6077 (stage 78). It imports only the merged `tools/freeze_snapshot_115.py` helpers.
- Claim status: instruction bytes, RIP targets, call and reference censuses and FDE extents are observations. "Time writer", "hex", "date", "time" and "writer name" are inferred labels. The binary was not executed.
- Scope: the first direct call after the `[` store in each bracket framer, the two twin time writers and their Display functions, the hex writers' first bytes, and a two-level caller walk to static writer names. Excluded: the value serializers after the `,`, the bodies of the date and time formatters, and data-flow ties of writers to framers.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/line_framer_census_115.py --check
python3 -m unittest tests.test_line_framer_census_115
```

The tool reads the ELF only. The four `*.objdump.txt` files were made with GNU objdump 2.42 for review; the tool does not read them.

## Evidence 1: 33 of the 39 bracket framers start with a quoted time

| First call after `[` | Framers | What it writes |
|---|---|---|
| `0x2506050` | 29 | `"`, `core::fmt::write` (slot `0x64df6f0`, `0x25060c2`) with Display `0x26a1370`, `"` |
| `0x4779470` | 4 | `"` (`0x47794ad`), `core::fmt::write` (`0x47794f6`) with Display `0x4783120` |

Both Display functions have the same three steps as stage 78's `0x57a6f10`: a call through the date slot `0x64e1158` (at `+0x13`), `mov esi, 0x54` (`T`, at `+0x24`), and a tail jump through the time slot `0x64e1160` (at `+0x4b`). The tool decodes all three and requires the same slot pair. So these 33 framers write `[<"YYYY-MM-DDTHH:MM:SS…">,<value>]`, the same frame as `0x4fcd860` callers (inference: the twins are separate builds of one time writer).

The 29 `0x2506050` framers sit in one block, `0x25ebdb0..0x25f7350`. The 4 `0x4779470` framers are `0x4774080`, `0x47742b0`, `0x47744e0` and `0x4774800`.

## Evidence 2: 6 bracket framers start with a non-time value

| First call after `[` | Framers | Evidence |
|---|---|---|
| `0x4e2d7f0` | 2 (`0x50dfa20`, `0x50e32a0`) | `mov word [rsp+6], 0x7830` (`"0x"`) at `0x4e2d811`: hex |
| `0x3d3f240` | 1 (`0x38dc850`) | `lea rcx, [0x455d40]` (hex digit table) at `0x3d3f283` |
| `0x3d40850` | 1 (`0x38dd130`) | `lea rax, [0x455d40]` at `0x3d4089d` |
| `0x50fc010` | 1 (`0x50e4c70`) | decimal u64 writer (#6036) |
| `0x50a3510` | 1 (`0x50e5300`) | string escaper (#6036) |

## Evidence 3: totals

| Framing | Functions |
|---|---|
| `[time,value]` through `0x4fcd860` | 21 |
| `[time,value]` through a twin time writer | 33 |
| `[<hex/number/string>,value]` | 6 |
| bare (no `[` store, no time writer) | 36 |
| total | 96 |

So 54 of the 96 line-writer callers frame their lines with a leading timestamp. The per-function rows are in `evidence.json`.

## Evidence 4: writer names

The tool finds every `lea` to the 14 static writer names it lists (#5874 and the #5883 write flags) and walks two levels of direct callers up from each framer. Only `0x50e50b0` reaches a name: `visor_abci_states` (#6076). `0x50e5fc0` (abci_hashes) and `0x50e6fe0` (abci_digest_quorum) are tied by the call paths in #6034 and #6033. The other 93 rows are marked `untied`: writers are passed in as values, so a name tie needs data flow this census does not follow.

## Results and limitations

- Result: the stage 78 class "bracket without time writer" is mostly a time frame through two twin writers. Only 6 framers lead with a hex, decimal or string value.
- Limits: the first-call rule takes the first direct `call` after the first `[` store; a framer that calls a helper before writing its first value would be misread (none was seen in the six non-time rows). Value serializers, the date/time formatter bodies, and writer ties beyond two call levels are not mapped. No gate changes.
- Next lead: tie the 29 `0x25ebdb0..0x25f7350` framers to their writers through the line-writer argument they receive.
