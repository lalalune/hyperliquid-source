# RE-013: visor allocator local fast-return provenance

- Component: visor, through the already observed child-argument collection.
- Target: captured visor, 8,305,392 bytes, SHA-256
  `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
- Source base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Question: which word is returned by the actual allocation helper's two
  local return paths, which guards and memory events precede it, and what
  remains unknown about size/alignment/null/freshness?
- Claim: conditional static value/address def-use. No allocator correctness,
  private type, initialized-cache invariant, target defect or gate claim.

The child-argument collection leaves the actual helper at `0x70bf30` opaque.
This packet closes its **local** return-word provenance without assigning
unobserved contents to `.bss` tables or promising allocated storage. It
preserves #45 lifecycle, #407 Rust-associated cleanup/unwind, #988 parser
and #1029 UTF-8 boundaries and does not reinterpret their held scopes.

## Result

The actual FDE `[0x70bf30,0x70bff2)` is 194 bytes, with 37 native rows,
six branches and one local RET. The finite local graph has two RET paths
and three transfers to the open slow target `0x70a170`; 35 rows are reached
and two padding NOP rows are excluded. These are graph counts, not recovered
functions or completion percentages.

[PROOF.md](PROOF.md) derives the complete local guard partition. On each local
return, RAX is the qword previously loaded from the selected cursor's cell.
The cell is read **before** either low16 cursor comparison, including a route
that then transfers to the slow target. Neither the returned word's nullness
nor alignment is checked locally. The proof records cursor/boundary/TLS stores
in their actual order; the final counter ADD reads after preceding stores,
so independent pre-entry final-field equations are not assumed.

Architectural FS base B is distinct from T=`load64(B+0)`. Class-header
addressing uses T+24*class-0xc80, while total/limit cells are FS-relative at
B-0x948/B-0x940. No equality T==B or private TLS ABI is inferred. The captured
ELF is ET_DYN; table VAs are linked coordinates and their actual runtime
load bias is also unobserved.

For unsigned requests <=4096, `(request+7)>>3` is an address index in 0..512.
The 513-byte class-map and 2048-byte conservative class-size-table envelopes
are **SHT_NOBITS `.bss`**. They have no captured initialized values. The code
does not establish class-size>=request, nonwrapping accounting, live cache
invariants, non-null/aligned/fresh return values or lifetime. Those remain
external premises, not demonstrated runtime counterexamples or defects.

All three slow transfers preserve RDI, forwarding the request unchanged.
The slow target's 7,611-byte extent/hash is metadata-only and was not decoded.
Three collection windows totaling **34 revisited bytes** and the actual
RELA slot bind existing size-argument callers; they are excluded from novelty
and do not re-prove the collection's capacity or complete behavior.

## Reproduce

Recorded platform: Linux x86-64, Python 3.12.14, GNU objdump 2.44. From repository
root with genuine pinned artifacts, use a new output file and short owned
physical `/tmp` storage:

```sh
mkdir -p work/visor-allocator-cache
PYTHONDONTWRITEBYTECODE=1 python3 -B tools/visor_allocator_cache.py \
  --output work/visor-allocator-cache/record.json
cmp research/work-items/RE-013-visor-allocator-cache/record.json \
    work/visor-allocator-cache/record.json
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  research/work-items/RE-013-visor-allocator-cache/check_packet.py
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests \
  -p test_visor_allocator_cache.py -v
sha256sum -c research/work-items/RE-013-visor-allocator-cache/MANIFEST.sha256
make doctor verify test catalogue-check reproduce
```

The producer authenticates one full in-memory byte snapshot. Native decoding
receives only an owned 194-byte, mode-0400 non-executable slice in a mode-0700
directory, with byte/identity checks before and after use. It never reopens
the original ELF pathname. Every native row binds the admitted slice and all
nine byte blocks/edges. `LC_ALL=C`, UTF-8 and LF are explicit; raw output is
retained without instruction/data normalization. The CLI verifies the final
source identity/hash before exclusive report creation. No canonical image
is mutated or copied as a file/fixture.

Real-byte controls cover guard strictness, request rounding, RIP and FS
addressing, cursor/threshold widths, memory destinations and the returned
register; FDE, NOBITS metadata, RELA and used caller changes are also rejected.
Real private native input mutation followed by restoration is rejected,
and an owned source-symlink replacement refuses report publication while
GNU remains on admitted bytes. Repeat, wrong full identity and actual CLI
preservation of existing output are checked. Symbolic address/wrap examples
support the explicit proof limits; they are not target execution or parity.

## Domain and remaining work

The proof requires valid actually accessed cells, immutable code, no modeled
asynchronous interference and preservation of the original valid return slot,
live caller frame and required immutable regions by every local write.
Permissions, aliases, FS base/state, image load bias and actual cache ownership
are not runtime-checked. Ordered events allow role-cell aliasing and do not
invent disjointness to close an allocator invariant.

This standalone MIT producer/proof is independently authored from binary
evidence and project-authored tooling patterns. No unlicensed inferred source
was read or copied. Raw observations retain original artifact ownership.
Rust reconstruction, dependencies/compiler/build identity, raw/normalized
binary equality, slow allocator semantics, global cache initialization,
size/alignment/freshness/lifetime and all completion gates remain unqualified.
The next concrete prerequisites are the producer of the two runtime tables
and the separate slow-path allocation/result contract; this packet does not
pretend either is closed.
