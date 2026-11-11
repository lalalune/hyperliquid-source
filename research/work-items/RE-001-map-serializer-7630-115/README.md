# RE-001: the options-map serializer 0x6097630 (node #115)

## Question

What does `0x6097630` do — the S0 writer behind the delimiter
pre-step `0x6098510`? It resolves the open unknown left by #4334
("0x6097630 internals (the S0 writer behind the delimiter
pre-step)").

## Answer (read from the binary)

`0x6097630` (FDE `0x6097630..0x60984e8`) is the map-level serializer:
it walks the Configurable object's option-group range and appends
`prefix + name + "=" + value + delimiter` into the output string
S0, one entry per serialized option.

### Signature

```
0x6097630(Status* out, const ConfigOptions* opts,
          const Configurable* object, const std::string* prefix,
          std::string* out_text)
```

Returns void; the final Status is written into `*out`. It has exactly
two direct callers: the delimiter pre-step `0x6098510` (`0x6098566`)
and the reset-and-serialize wrapper `0x60985e0` (`0x609861f`).

- `0x6098510` (FDE `0x6098510..0x60985af`, 5 callers) truncates S0 to
  empty and forwards `(out, object, C1, empty prefix string, S0)`.
- `0x60985e0` (FDE `0x60985e0..0x609865e`, sole caller `0x609e0a9` in
  `0x609e510`) resets `*S` to an empty SSO string, calls `0x6097630`
  with a stack Status temp (discarded, its message freed), forwards
  its own `rcx` as the prefix, and returns `S`.

Both known call paths pass an **empty** prefix string in practice, so
the emitted text is `name + "=" + value + delimiter` at every live
call site.

### Iteration

The object holds the range at `+0x08` (begin) / `+0x10` (end) of
0x30-byte elements (vtable at `+0x00`). Per element:

- `element+0x28` is the per-group OptionTypeInfo map pointer (null
  skips the element); `element+0x20` is the options-base pointer
  (field address = base + `record+0x00`).
- The map is an `unordered_map<string, OptionTypeInfo>` (56 bytes,
  same layout as #4334: buckets `+0x00`, bucket_count `+0x08`,
  before_begin `+0x10`, element_count `+0x18`).
- Each node: next `+0x00`, key (name) string `+0x08`/`+0x10`/`+0x18`,
  embedded OptionTypeInfo record at `+0x28` (type at node `+0xd0` =
  record `+0xa8`, verification at node `+0xd4` = record `+0xac`,
  flags at node `+0xd8` = record `+0xb0`). Nodes are walked via
  `node+0x00`; the cursor advances `0x30` bytes per element.

### Skip rules (checked in this order per node)

| condition | site |
| --- | --- |
| element `+0x28` == 0 | `0x60976ab` |
| first node == 0 | `0x60976b4` |
| verification in {4, 5} | `0x609772a` (`sub $0x4; cmp $0x1; jbe`) |
| flags & `0x2000` | `0x6097738` (`test $0x20, %ah` on `+0xd9`) |
| `ConfigOptions+0x04 != 0`, bit 0 of `+0xd9` clear, type not in {21, 22} | `0x60976e9..0x60976fb` |
| type in {21, 22}, `ConfigOptions+0x28 != 2`, bit 7 of `+0xd9` set | `0x6097ef8` |

Note the verification rule: the map-level dump drops verification-**5**
entries too, while the bare per-entry serializer `0x60bb9a0` drops
only verification 4 (`0x60bb9d4`). The three table factories
(verification 5) are therefore never dumped by this path.

### Dispatch (on `ConfigOptions+0x04`, `0x6097747`)

| block | condition | serializer `rdx` |
| --- | --- | --- |
| A (`0x6097778`) | `+0x04 == 0` | original ConfigOptions |
| B (`0x6097bd8`) | `+0x04 != 0` and `+0xd9` bit 0 set | a full 0x50-byte stack copy |
| C (`0x6097f08`) | `+0x04 != 0`, bit 0 clear, type in {21, 22} (and `+0x28 == 2` or `+0xd9` bit 7 clear) | original ConfigOptions |

Block B copies the whole ConfigOptions to `0x110(%rsp)`, bumps the
`+0x48` shared_ptr refcount (plain `addl` at `0x6097c92`, or `lock
addl` at `0x6098118` when the `0x64ed290` flag byte is 0), and
releases it after the call (`xadd -1` at `0x6098263`; count reaching 1
calls `0x5d35070`, then the `0x6098298` path calls vtable slots
`0x10` and `0x18`). The copy's `+0x04` byte is written 1 at
`0x6097bdf` and back to 0 at `0x6097ca7`, so the serializer receives
the copy with `+0x04 == 0` (why the transient 1 is written is an
open unknown).

### Per-entry serialization

Before each call the name temp is built as `prefix + name`. The
serializer `0x60bb9a0` is called at `0x6097853` (A), `0x6097d82` (B),
`0x6097fe3` (C) with `(Status@0x80(%rsp), record at node+0x28,
ConfigOptions, name temp, options_base, value_out T2@0x90(%rsp))`.

- Serializer Status byte 0 != 0: the 6 Status bytes + pointer are
  copied into `*out` (`0x6097e6f..0x6097ea4`) and the function returns
  immediately; later entries are not visited.
- Empty range (`begin == end`): `*out` is zeroed (16 bytes,
  `0x609827a`) and the function returns (kOk).

### Emission

Only when the serialized value string T2 is non-empty
(`T2.size` at `0x98(%rsp)`, `0x60978cf`) does the entry emit
anything: `prefix + name + "=" + value + delimiter` is appended to
S0 (`0x60978f8..0x6097b3e`). `"="` is the 1-byte literal at
`0x445245`; the delimiter is the `ConfigOptions+0x08` string (slot 9
forces it to `"; "` — `0x4409b0`, 2 chars — when `ConfigOptions+0x00`
byte 0 == 0).

## Evidence

- `fn-6097630.objdump.txt` — the whole function, verbatim objdump
  output, generated fresh here.
- `fn-6098510.objdump.txt` — the whole pre-step, verbatim objdump
  output. Re-shipped byte-identical from the #4334 packet, which
  first exported it.
- `fn-60985e0.objdump.txt` — the whole wrapper, verbatim objdump
  output, generated fresh here.
- `records.json` — semantic records only (no per-instruction
  mnemonic list).
- `callers.tsv` — every direct call site of the three functions,
  from a byte-level `E8 rel32` scan (`census.py`).
- `literals.tsv` — the two literals, read from `.rodata`.
- `frames.txt` — the FDE ranges from readelf.
- `census.py`, `export_excerpts.py`, `gen_records.py`, `verify.py` —
  the generators and the checker committed in the packet.

Regenerate the excerpts with (from the repo root):

```
python3 research/work-items/RE-001-map-serializer-7630-115/export_excerpts.py
```

and verify the packet with:

```
python3 research/work-items/RE-001-map-serializer-7630-115/verify.py
```

The objdump command for each excerpt is
`objdump -d --start-address=<start> --stop-address=<stop>
work/hl-node-115.bin`. Instruction mnemonics such as `endbr64` are
genuine instructions present in the target binary, not placeholders.

## Model

`tools/map_serializer_7630_115.py` models the dispatch table
(`dispatch`), the emission format (`emit_entry`), the Status
propagation and the empty-range kOk (`serialize_map`); the tests in
`tests/test_map_serializer_7630_115.py` cover every skip reason, all
three blocks, the empty-value gate, the error early-return, and the
verification-5 map-level drop.

## Environment limits

This VM has no cargo/rustc, no git-lfs, no Ghidra/Java. The binary
is `work/hl-node-115.bin`, node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`, `artifacts/node/115/hl-node`).
`make verify`, `make test` and `make catalogue-check` could not be
run in the tooled environment here; the packet's own `verify.py`
(which checks the artifact digest, the manifest, excerpt
regeneration, FDE ranges, raw-binary spot bytes, literals, the caller
census, the semantic-only records, and the model tests) passes.

## Open unknowns

- Element `+0x00..+0x18` fields and the element struct's C++ name.
- The map's C++ name: the layout matches
  `unordered_map<string, OptionTypeInfo>` (before_begin `+0x10`,
  node key `+0x08` / value record `+0x28`), but the node hash offset
  and total node size are not verified.
- Why block B writes 1 then 0 to the copy's `+0x04` byte
  (`0x6097bdf`, `0x6097ca7`); only the end state (`+0x04 == 0` at the
  call) is pinned.
- `0x609e510` host identity (FDE `0x609e510..0x609f073`); it calls
  both `0x6098510` (`0x609e80f`) and `0x60985e0` (`0x609e0a9`).
- What the release helper `0x5d35070` does exactly (cited only, from
  the block-B shared_ptr release path).
- Slot-9 arg5 C++ meaning (still open from #4334).
- `ConfigOptions+0x00/+0x04/+0x08/+0x28` C++ names and defaults
  (still open from #4334).
