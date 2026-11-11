# RE-001: pin node #115 the two ColumnFamilyOptions option groups registered by ConfigurableCFOptions

Task: RE-001 (RocksDB options reconstruction).
Work item: `RE-001-cfoptions-groups-115`.

## Bounded question

Which option groups does the ConfigurableCFOptions ctor `0x6086e00`
register — names, bases, maps — and what is the resulting group
vector? This resolves the open unknown left by #4372 ("not
individually analysed") for the two RegisterOptions sites in this
host, and pins precisely what #4263 only claimed loosely ("the
Mutable/Immutable split is proven by the consumer `0x6086e00`").

## Answer (read from the binary)

### The element

One element is a `Configurable::RegisterOptions` group record, 0x30
bytes (`#3257` pinned the helper and the layout; this packet pins the
two CFOptions registrations):

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

`0x6086e00..0x608818d` is
`rocksdb::ConfigurableCFOptions::ConfigurableCFOptions(const
ColumnFamilyOptions&, const std::unordered_map<std::string,
std::string>*)` (vendor census in `docs/PROGRESS.md`). It stores the
ctor's third argument (the input string map) at `object+0x630`
(`0x6087cc8`, from `0x20(%rsp)`, set at entry `0x6086e28`), zeroes the
group vector triple (`0x608723f` / `0x608725c` / `0x6087268`), and
registers exactly two groups, in order:

1. **"MutableCFOptions"** — call at `0x608749a`:
   `(rdi=object, rsi=stack string at 0x250(%rsp), rdx=object+0x20,
   rcx=0x6506b20)`. The name is built from the 16-byte literal at
   `0x43fa91` (sole binary-wide lea site `0x6087473`; built by the
   `std::string(const char*)` ctor `0x607d9f0` at `0x6087485` into
   `0x250(%rsp)`, held in `r14`); the map is the 62-entry
   MutableCFOptions map (`#4263`); the base is `object+0x20` (`lea`
   at `0x6087235`, kept in callee-saved `r15` at `0x608724a`, passed
   as `rdx` at `0x6087491`). 16 chars exceeds the 15-char SSO limit,
   so the element name is heap-backed. The vector is empty, so the
   growth path runs and capacity becomes 1.
2. **"ImmutableCFOptions"** — call at `0x6087ce8`:
   `(rdi=object, rsi=stack string at 0x250(%rsp), rdx=object+0x218,
   rcx=0x6506ae0)`. The name is built from the 18-byte literal at
   `0x433249` (sole binary-wide lea site `0x6087cc1`; rebuilt by
   `0x607d9f0` at `0x6087ccf` into the same `0x250(%rsp)` slot, reached
   via the `0x18(%rsp)` pointer); the map is the 31-entry
   ImmutableCFOptions map (`#4263`); the base is `object+0x218`
   (`lea` at `0x6087544`, staged in `0x28(%rsp)` at `0x608754e`,
   passed as `rdx` at `0x6087cd4`). 18 chars, heap-backed. After
   group 0 the vector has size 1 and capacity 1, so the growth path
   runs again and capacity becomes 2.

Resulting vector: 2 elements, capacity 2 —
`[{"MutableCFOptions", object+0x20, 0x6506b20},
{"ImmutableCFOptions", object+0x218, 0x6506ae0}]`.

Between the two registrations the ctor overwrites the vtable pointer
at `(%rbx)` from `0x64d3138` (`lea 0x64d3128` at `0x608724d` + `0x10`,
store at `0x6087270`) to `0x64d31b8` (`lea 0x64d31a8` at `0x6087533` +
`0x10`, store at `0x6087541`); both tables are recorded by #3567, and
why the pointer changes is an open unknown. The adjacent calls
(`0x6086cd0` at `0x608722c` with `rdi=0x50(%rsp)`, `0x6081e40` at
`0x6087553` with `rdi=object+0x218`, `0x5d35c00` at `0x6087c83` with
`rdi=object+0x618`) are recorded only by their arg registers, not
pinned.

### Lea censuses

Both name literals are used only by this host (one lea site each).
The other lea sites of the two maps sit inside the static initializer
`0x6089b50..0x6091e5c` (`#4263`), which builds the maps:
`0x6506b20` → `0x608748a` (this packet), `0x608ec34`, `0x608f329`;
`0x6506ae0` → `0x6087cde` (this packet), `0x6090e46`.

## Evidence

Artifact: `work/hl-node-115.bin`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`, `artifacts/node/115/hl-node`).

| File | Contents |
| --- | --- |
| `fn-6086e00-cfoptions-configurable-ctor.objdump.txt` | Whole-function objdump of the host ctor (first exported by #4263) |
| `fn-6099ce0-register-options.objdump.txt` | Whole-function objdump of RegisterOptions (first exported by #4237) |
| `callers.tsv` | All 37 direct call sites of 0x6099ce0 with enclosing FDE (matches #3257 and #4372 exactly) |
| `literals.tsv` | The group-name literals, the two maps, and their lea sites |
| `frames.txt` | FDE ranges for 0x6086e00, 0x6099ce0, 0x6099790, 0x607d9f0 |
| `records.json` | Semantic records only: host, helper, both registrations, resulting vector, census, open unknowns |
| `export_excerpts.py` | Generates the two excerpts (objdump commands recorded here) |
| `census.py` | Regenerates callers.tsv / literals.tsv / frames.txt |
| `gen_records.py` | Builds records.json from the census, with cross-checks |
| `verify.py` | Runs every check below; prints ALL CHECKS PASSED |

Excerpt commands (run from the repo root):

```sh
objdump -d --start-address=0x6086e00 --stop-address=0x608818d work/hl-node-115.bin
objdump -d --start-address=0x6099ce0 --stop-address=0x6099e34 work/hl-node-115.bin
```

The mnemonics in the excerpts (`endbr64`, `movdqa`, `movups`, …) are
genuine instructions present in the target binary, reproduced
verbatim by objdump, not placeholders.

Section map used (readelf -S): `.text` vaddr 0x1419300, file offset
0x1418300 (offset = vaddr − 0x1000); `.rodata` offset == vaddr.

## Verification

```sh
python3 research/work-items/RE-001-cfoptions-groups-115/verify.py
python3 -m pytest tests/test_cfoptions_groups_115.py -q
```

`verify.py` checks: the artifact digest against
`provenance/artifacts.json`; every MANIFEST hash; byte-for-byte
regeneration of both excerpts; the FDE ranges against the unwind
tables; 28 cited instructions against the raw binary bytes; the
37-site RegisterOptions census reproduced by byte-scan and matched
against `callers.tsv`; the lea censuses for the two name literals and
two maps; the literals; the semantic-only records and the full 64-char
digest; and the model tests. The model
`tools/cfoptions_groups_115.py` reproduces the two-element vector
(SSO/heap split, growth 0→1→2, bases, maps) and is covered by 10
tests in `tests/test_cfoptions_groups_115.py`.

## Open unknowns

- The keys and fields of the other 28 RegisterOptions call sites
  (listed in `callers.tsv`, not individually analysed).
- Why ConfigurableCFOptions overwrites its vtable pointer
  (`0x64d3138` → `0x64d31b8`) between the two registrations.
- The internals of the adjacent calls in `0x6086e00` (`0x6086cd0`,
  `0x6081e40` at `object+0x218`, `0x5d35c00` at `object+0x618`); only
  their arg registers are recorded here.
- The ColumnFamilyOptions C++ layout names for the bases
  `object+0x20` and `object+0x218` and for the input-map slot
  `object+0x630`.
- The contents of the `.bss` maps at `0x6506b20` / `0x6506ae0`
  beyond their entry counts from #4263 (file-unbacked; only
  addresses are pinned).

## Environment

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so `make
verify test catalogue-check` could not be run here; the packet's own
`verify.py` and the model tests were run instead. The binary used is
the materialized `work/hl-node-115.bin` whose SHA-256 matches
`provenance/artifacts.json`.
