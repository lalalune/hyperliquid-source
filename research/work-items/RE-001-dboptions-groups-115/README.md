# RE-001: pin node #115 the two DBOptions option groups registered by DBOptionsConfigurable

Task: RE-001 (RocksDB options reconstruction).
Work item: `RE-001-dboptions-groups-115`.

## Bounded question

What are the 0x30-byte option-group elements at `object+0x08..+0x10` —
their `+0x00..+0x18` fields and C++ name — and which groups does the
DBOptions configurable register? This resolves the open unknown left by
#4337 ("element +0x00..+0x18 fields and C++ name") for the DBOptions
object, and #3257's open unknown ("the keys and fields of the other 34
push-back call sites") for the two sites in this host.

## Answer (read from the binary)

### The element

One element is a `Configurable::RegisterOptions` group record, 0x30
bytes (`#3257` pinned the helper and the layout; this packet pins the
two DBOptions registrations):

| offset | field |
| --- | --- |
| `+0x00` | `std::string name`, data pointer (SSO: points at `+0x10`) |
| `+0x08` | `std::string name`, size |
| `+0x10` | `std::string name`, SSO buffer (16 bytes, `+0x10..+0x20`) |
| `+0x20` | options-base pointer |
| `+0x28` | `OptionTypeInfo` map pointer |

`RegisterOptions` (`0x6099ce0`, FDE `0x6099ce0..0x6099e34`,
`rocksdb::Configurable::RegisterOptions(const std::string&, void*,
const std::unordered_map<std::string, OptionTypeInfo>*)` per the
`docs/PROGRESS.md` vendor census) copies the name into a stack record,
then appends it to the vector at `object+0x08` (begin `+0x08`, end
`+0x10`, capacity-end `+0x18`): SSO names copy inline, heap names via
`_M_create` + `memcpy`, base and map by one `movdqa` (`0x6099d7f`),
then `end += 0x30` (`0x6099d89`). When `end == capacity-end` it calls
the growth helper `0x6099790` (`0x6099e0a`; capacity 1 for an empty
vector, else `min(2*size, MAX_SIZE)`, `#3257`).

### The host

`0x60a47f0..0x60a636b` is
`rocksdb::DBOptionsConfigurable::DBOptionsConfigurable(const DBOptions&,
const std::unordered_map<std::string, std::string>*)` (vendor census in
`docs/PROGRESS.md`). It stores the ctor's third argument (the input
string map) at `object+0x90`, zeroes the group vector triple
(`0x60a486e` / `0x60a4895` / `0x60a48a6`), and registers exactly two
groups, in order:

1. **"MutableDBOptions"** — call at `0x60a492a`:
   `(rdi=object, rsi=stack string at 0x2f0(%rsp), rdx=object+0x20,
   rcx=0x6506dc0)`. The name is built from the 16-byte literal at
   `0x4541e0` (`movdqa` at `0x60a48f1`, size 16); the map is the
   19-entry MutableDBOptions map (`#4237`); the base is `object+0x20`
   (`lea` at `0x60a48e7`). 16 chars exceeds the 15-char SSO limit, so
   the element name is heap-backed. The vector is empty, so the growth
   path runs and capacity becomes 1.
2. **"ImmutableDBOptions"** — call at `0x60a50f2`:
   `(rdi=object, rsi=stack string at 0x2f0(%rsp), rdx=object+0x98,
   rcx=0x6506d80)`. The name is built from the 16-byte literal chunk
   at `0x450aa0` (`"ImmutableDBOptio"`, `movdqa` at `0x60a50aa`) plus
   the 2-byte immediate `0x736e` (`"ns"`, `mov` at `0x60a50c9`),
   size 18; the map is the 81-entry DBOptions map (`#4237`); the base
   is `object+0x98` (`lea` at `0x60a495b`, staged in `(%rsp)` at
   `0x60a4965` — the only write to `(%rsp)` before the call, so it is
   still live). 18 chars, heap-backed. After group 0 the vector has
   size 1 and capacity 1, so the growth path runs again and capacity
   becomes 2.

Resulting vector: 2 elements, capacity 2 —
`[{"MutableDBOptions", object+0x20, 0x6506dc0},
{"ImmutableDBOptions", object+0x98, 0x6506d80}]`.

Between the two registrations the ctor overwrites the vtable pointer
at `(%rbx)` from `0x64d3638` (`0x60a48ae`) to `0x64d36b8`
(`0x60a4958`); why is an open unknown. The adjacent calls
(`0x60a43c0` at `object+0x98`, `0x5d38750` at `object+0x2d8`,
`0x60a3b60`) are recorded only by their arg registers, not pinned.

### What does NOT read the name

The map serializer `0x6097630` (`#4337`) and the apply loop `0x609c8c0`
(`#4334`) walk the same vector but read only `element+0x20` (base)
and `element+0x28` (map); neither reads the name at `+0x00..+0x18`.
Slot 12's `rcx` string comes from the literal `0x4376fd` (`#4328`),
not from an element. Which code reads the group name at runtime
remains open.

## Evidence

Artifact: `work/hl-node-115.bin`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`, `artifacts/node/115/hl-node`).

| File | Contents |
| --- | --- |
| `fn-60a47f0-dboptions-configurable-ctor.objdump.txt` | Whole-function objdump of the host ctor (first exported by #4237) |
| `fn-6099ce0-register-options.objdump.txt` | Whole-function objdump of RegisterOptions (first exported by #4237) |
| `callers.tsv` | All 37 direct call sites of 0x6099ce0 with enclosing FDE (matches #3257 exactly) |
| `literals.tsv` | The group-name literals and the two maps |
| `frames.txt` | FDE ranges for 0x60a47f0, 0x6099ce0, 0x6099790 |
| `records.json` | Semantic records only: host, helper, both registrations, resulting vector, census, open unknowns |
| `export_excerpts.py` | Generates the two excerpts (objdump commands recorded here) |
| `census.py` | Regenerates callers.tsv / literals.tsv / frames.txt |
| `gen_records.py` | Builds records.json from the census, with cross-checks |
| `verify.py` | Runs every check below; prints ALL CHECKS PASSED |

Excerpt commands (run from the repo root):

```sh
objdump -d --start-address=0x60a47f0 --stop-address=0x60a636b work/hl-node-115.bin
objdump -d --start-address=0x6099ce0 --stop-address=0x6099e34 work/hl-node-115.bin
```

The mnemonics in the excerpts (`endbr64`, `movdqa`, `movups`, …) are
genuine instructions present in the target binary, reproduced
verbatim by objdump, not placeholders.

Section map used (readelf -S): `.text` vaddr 0x1419300, file offset
0x1418300 (offset = vaddr − 0x1000); `.rodata` offset == vaddr.

## Verification

```sh
python3 research/work-items/RE-001-dboptions-groups-115/verify.py
python3 -m pytest tests/test_dboptions_groups_115.py -q
```

`verify.py` checks: the artifact digest against
`provenance/artifacts.json`; every MANIFEST hash; byte-for-byte
regeneration of both excerpts; the FDE ranges against the unwind
tables; 17 cited instructions against the raw binary bytes; the
37-site RegisterOptions census reproduced by byte-scan and matched
against `callers.tsv`; the literals; the semantic-only records and
the full 64-char digest; and the model tests. The model
`tools/dboptions_groups_115.py` reproduces the two-element vector
(SSO/heap split, growth 0→1→2, bases, maps) and is covered by 10
tests in `tests/test_dboptions_groups_115.py`.

## Open unknowns

- The keys and fields of the other 32 RegisterOptions call sites
  (listed in `callers.tsv`, not individually analysed).
- Which code reads the element name string (`+0x00..+0x18`) at
  runtime; the serializer and apply loop read only `+0x20`/`+0x28`.
- Why DBOptionsConfigurable overwrites its vtable pointer
  (`0x64d3638` → `0x64d36b8`) between the two registrations.
- The internals of the adjacent ctor calls in `0x60a47f0`
  (`0x60a43c0` at `object+0x98`, `0x5d38750` at `object+0x2d8`,
  `0x60a3b60`); only their arg registers are recorded here.
- The contents of the `.bss` maps at `0x6506dc0` / `0x6506d80`
  beyond their entry counts from #4237 (file-unbacked; only
  addresses are pinned).

## Environment

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so `make
verify test catalogue-check` could not be run here; the packet's own
`verify.py` and the model tests were run instead. The binary used is
the materialized `work/hl-node-115.bin` whose SHA-256 matches
`provenance/artifacts.json`.
