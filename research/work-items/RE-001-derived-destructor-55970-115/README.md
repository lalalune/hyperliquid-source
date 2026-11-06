# RE-001: map node #115 derived-class destructor pair 0x5d55970 / 0x5d559c0

- Component ID: RE-001
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (bound via `provenance/artifacts.json`; local copy `work/hl-node-115.bin`
  hashes to the same value).
- Source commit / reference commit: upstream main `05bc2de30`.
- Claim status: observations, inferred semantics and unknowns are kept
  separate below; `records.json` holds semantic records only.
- Scope included and excluded: the complete-object destructor at
  0x5d55970, the deleting destructor at 0x5d559c0, and the base
  destructor at 0x5fe70b0 they both delegate to, end to end. The
  refcount-release helper at 0x5d350c0 is pinned only by its call
  sites and its release contract (its body is not excerpted here).
  Caller bodies beyond the call sites are NOT pinned. This pair is a
  different class from the destructor pair in
  research/work-items/RE-001-destructor-pair-115/ (0x5f10180 /
  0x5f10d00); no routine is shared between the two items.

## Bounded question

How is one 0x48-byte derived-class object torn down: what do its two
destructor variants do, in what order, and what does the base
destructor they delegate to do?

## Reproduce

Working directory: the repository root. Tool versions on this VM:
`objdump`/`readelf` from GNU binutils (rerun `objdump --version` for
the exact build). Commands:

```
objdump -d --start-address=0x5d55970 --stop-address=0x5d559b9 work/hl-node-115.bin
objdump -d --start-address=0x5d559c0 --stop-address=0x5d55a16 work/hl-node-115.bin
objdump -d --start-address=0x5fe70b0 --stop-address=0x5fe7135 work/hl-node-115.bin
readelf --debug-dump=frames work/hl-node-115.bin
readelf -r work/hl-node-115.bin
python3 research/work-items/RE-001-derived-destructor-55970-115/census.py
python3 research/work-items/RE-001-derived-destructor-55970-115/verify.py
python3 tests/test_derived_destructor_55970_115.py
```

Virtual addresses are objdump's addresses; file offset = virtual
address - 0x1000 within the executable LOAD segment (file offset
0x1418300, vaddr 0x1419300). No execution, no network, no side
effects beyond reading the binary.

Note on instruction mnemonics: tokens such as `endbr64` in the
excerpts are genuine instructions present in the target binary, not
placeholders; the excerpts are verbatim objdump output (only the
binary path in the header is normalized to the bare binary name) and
`verify.py` checks every excerpt instruction line byte-for-byte
against the raw binary.

## Evidence

The two variants are instruction-identical except for their endings:
both set the vptr to the derived table (0x64d08a8), release the
+0x38 refcounted pointer through 0x5d350c0 when non-null, set the
vptr to the middle table (0x64cf200), release the +0x28 refcounted
pointer through the same helper when non-null, and then reach the
base destructor. The complete-object variant (0x5d55970) tail-jumps
to the base destructor and returns from there; the deleting variant
(0x5d559c0) calls the base destructor and then sized-deletes the
object itself with size 0x48. The vtable reading is confirmed by
relocation records, not just by the stores: the derived table's slot
0 (0x64d08a8) relocates to 0x5d55970 and its slot 1 (0x64d08b0) to
0x5d559c0, so the pair are the two destructor slots of one vtable,
and a second stored reference to 0x5d55970 sits at 0x64ed3f0.

The base destructor sets the vptr to the base table (0x64d3430),
then tears down the vector<string> at +0x08/+0x10/+0x18: per
0x30-byte element, a data pointer equal to the element's own +0x10
address is a short string and frees nothing, any other data pointer
is freed with the sized delete using capacity + 1; afterwards the
vector buffer is freed with (begin, capacity end minus begin) when
begin is non-null, so an empty but non-null vector still frees its
buffer. The routine writes nothing back to the holder.

The refcount helper's contract, as observed at its call sites and
from its own body shape: the pointed-to object's +0x08 field is one
64-bit count; releasing decrements the strong count (plain or
atomic, chosen by a global flag byte, with the same observable
outcome) and destroys the managed object through its vtable when the
count reaches zero; the packed value 0x100000001 takes the destroy
path after zeroing the field. A null field is skipped by the caller
and never passed to the helper.

## Callers

The two destructor variants themselves have ZERO direct call or
tail-jump sites in the executable LOAD segment: as virtual functions
they are reached only through their vtable slots (the relocation
records in `relocations.txt`) plus the second stored reference to
0x5d55970 at 0x64ed3f0. The shared base destructor has 30 direct
sites, listed in `callers.tsv` (direct calls and tail jumps from the
exhaustive executable-LOAD E8/E9 scan, reproduced by `census.py` and
re-run inside `verify.py`); only the first two of those sites belong
to this pair, the rest are other delegating destructors sharing the
same base, whose bodies are NOT pinned here.

## Observations, inferences, unknowns

- Observation: the exact destruction order, the vptr values, the
  field offsets, the vector teardown rules, and the 0x48 self-free
  size.
- Inference: the layer reading (derived / middle / base) follows the
  vptr descent order; the classes' source names are not established.
- Unknown: the middle table's first two function slots (0x64cf200,
  0x64cf208) carry no relocation in this file, so their load-time
  values are not claimed; the classes' source names, the other
  virtual functions' behavior, what constructs this object type,
  what the +0x28/+0x38 refcounted objects are, and the role of the
  containing table at 0x64ed3f0 are all open.
