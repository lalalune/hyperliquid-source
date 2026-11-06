# RE-015: the S-map grow family's panic side, closed as one unit

Node #115 (`hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).

Two earlier packets settled this family's panic question one body at
a time: the map-grow packet (`RE-015-node115-map-grow-panic`) for the
grow at `0x4742aa0` and its insert caller, and the sibling-hasher
packet (`RE-015-node115-sibling-hasher-panic`) for the sibling grow's
seeded hasher at `0x4744490`. Each left the family boundary open.
This packet closes the family as one unit: every body that loads the
shared panic message, every hash body over the shared absorb, every
first-frame caller of any of them, and the boundary censuses that
prove nothing else belongs to the family. **Open gaps at the end of
this packet: none.**

## The family

A binary-wide census of `lea` references to the message string at
`0x49bd80` ("Hash table capacity overflow") finds exactly three
sites in the `0x4740000..0x474c000` cluster — one per grow body:

| body | extent | home slot | settled by |
| --- | --- | --- | --- |
| grow | `0x4742aa0..0x4743347` | `0x64eaf78` | map-grow packet |
| **variant grow** | `0x4743350..0x474398c` | `0x64eaf80` | **this packet** |
| sibling grow | `0x4743990..0x4743ff0` | `0x64eaf88` | map-grow packet |

The hash side is three instantiations of one seeded SipHash body
over the shared buffered absorb at `0x4744980..0x4744b57`:

| body | extent | argument shape | settled by |
| --- | --- | --- | --- |
| **hash A** | `0x4744330..0x4744490` | `rsi`=ptr, `rdx`=len | **this packet** |
| hasher | `0x4744490..0x47445fb` | `[rsi+8]`=ptr, `[rsi+0x10]`=len | sibling-hasher packet |
| **hash B** | `0x4744600..0x474476a` | `[rsi]`=ptr, `[rsi+8]`=len | **this packet** |

Plus the sibling's marked-record cleanup at `0x47425c0` and pad
helper at `0x4742680` (both settled by the map-grow packet and
re-pinned here by extent and SHA-256, because this packet's verdict
rests on them).

## Verdicts

**(a) The variant grow has the grow's exact failure shape.** Its
three pre-split sizing branches (checked-add `jb` at `0x4743370`,
capacity-cap `ja` at `0x4743413`, size-overflow `jo` at `0x4743457`)
reach the fallibility dispatch at `0x474348a`; the dispatch's `jne`
at `0x474348d` and the fresh-path null-allocation block at
`0x47438e9..0x47438ee` are the only other routes to the failure tail
at `0x474395b`. A raw branch census of the whole body returns exactly
those five branches. All of them fire before any record is marked:
the conversion loop at `0x4743670` and the relocation scan at
`0x4743836` sit after the last failure branch, in the region the tail
itself jumps back into (`0x47436d7`). The tail loads the same
message, the same location object the sibling's tail loads
(`0x641cc98`), and the same `0x39` length, then calls the pinned
formatter and allocation-error slots. Its slot inventory — alloc
`0x64df480`, memset `0x64df750`, memmove `0x64df568`, dealloc
`0x64df4a0`, formatter `0x64df6b8`, allocation-error `0x64df490` —
is the grow's six slots verbatim. The install tail frees the old
table through the dealloc slot at `0x4743946`, before the tail, so
both failure continuations leak nothing the grow does not also leak:
the tail's two callees are non-returning, and the continuation both
tails jump to is unreachable on the failure path.

**(b) The variant's one new exposure is sound, because its callee
cannot panic.** The variant differs from the grow in exactly one
way: it calls hash B once per record in both paths — fresh at
`0x474358e`, and in-place at `0x4743700`, the second call inside the
marking window (the relocation scan runs after the control bytes are
converted). That is the sibling's exposure shape, but the variant's
frame is the plain-`zR` frame with no LSDA where the sibling carries
marked cleanup. What closes it is the callee: instruction-exact
classification of hash A, the hasher and hash B shows **no branch,
no division and no trap in any of the three**; their only calls are
the two absorb calls each, and the absorb is a leaf. On top of the
static proof, a behavioural differential executes all three bodies
natively over **20,000 frozen cases** (four seeds, key lengths
0..288 from a fixed stream) and finds one identical output stream,
SHA-256 `78e5eef7d6a9c96deb6e4db34a16c425b214331506d0c90785f2caa4a0a`.
No panic can be raised inside any marking window of the family, and
no unwind can arrive from below one.

**(c) Every first-frame caller is accounted for.** Direct-call and
slot-call censuses over the whole `.text` give the complete caller
set; each caller's LSDA coverage is decoded and pinned:

| caller | calls | coverage |
| --- | --- | --- |
| insert `0x474b620` | grow slot at `0x474ba06` | pad `0x474ba2e` (settled) |
| caller A `0x4748500` | hasher at `0x4748984`, `0x47491b3` | pads `0x4749948`, `0x4749814` |
| caller B `0x474a160` | hasher at `0x474a1c3` | pad `0x474a361` |
| caller C `0x474ba60` | hasher at `0x474ba7e`, sibling slot at `0x474bc91` | both under range `0x474bc81..0x474bc97`, pad `0x474bcb4` |
| caller `0x4747a70` | variant slot at `0x4747b5d` | pad `0x4747b79` (drop glue `0x4742810`, then `_Unwind_Resume`) |
| caller `0x474bce0` | variant slot at `0x474bf02`, hash B at `0x474bd13` | plain-`zR`, no LSDA — none needed map-side, per (a) and (b) |
| twins `0x4749d80`, `0x4749f70` | hash A at `0x4749f0a`, `0x474a0fa` | sites precede the first LSDA ranges — no pad; moot, per (b) |

Caller C's pad frees only the caller's own pending buffer through
the dealloc slot (guarded by a null test) before resuming the
unwind; map-side cleanup stays with the sibling's own pads, exactly
as the map-grow packet settled. The sibling's internal hasher sites
(`0x4743be4`, `0x4743d5d`) are likewise re-covered here (pads
`0x4743fc0`, `0x4743fd5`). A cluster-wide sweep decodes every LSDA
in the band: 56 FDEs, 270 entries, 169 landing pads — **every pad
inside its own body**, no exceptions.

**(d) The boundary is censused, not assumed.** Each grow's address
occurs as a qword only inside its own `.rela.dyn` record (the
relocation addend field); the other family bodies' addresses and the
message address occur nowhere as qwords; no `movabs` immediate in
`.text` names any family body or the message; each home slot is
referenced only by its pinned call sites. The neighbouring
5,696-byte body at `0x4744b60` — the other map's business, whose four
small pads sit just below the hash cluster — makes no direct call to
any family body and no call through any family slot, and neither
does the body at `0x4743ff0` wedged between the sibling and the hash
bodies. They are outside the family, and the censuses prove it.

## Evidence

- `tools/grow_family_panic_static.py` — `analyze()` re-derives every
  fact above from the raw artifact (body extents and SHA-256s, slot
  bindings, byte pins, branch/call/slot/address censuses, LSDA
  decodings and coverage, the cluster sweep, the neighbour census);
  `behavioral()` runs the 20,000-case native differential;
  `generate()` rebuilds all evidence files.
- `records.json` — the full `analyze()` output.
- `classification.json` — instruction-exact inventories (calls,
  branches leaving the body, divisions, traps) for the variant, the
  three hash bodies and the absorb.
- `behavior.json` — the differential's frozen parameters and the
  three output-stream hashes.
- `frames.txt` — the `readelf --debug-dump=frames-interp` lines for
  the 24 pinned bodies (the predecessors' format).
- `*_objdump.txt` — disassembly windows over the variant's entry,
  fresh rehash, in-place scan, install/tail, the three hash bodies,
  and the two new caller pads; every window's pinned sites are
  verified against the instruction-exact decode by `generate()`.
- `tests/test_grow_family_panic_static.py` — artifact pin, verdict
  assertions, one-byte counterfactuals (branch displacement, call
  displacement, LSDA byte, message byte, hash-body byte, relocation
  addend — each makes `analyze()` fail at the specific check it
  attacks), the live differential against the committed
  `behavior.json`, and a byte-exact `generate()` round-trip.

Reproduce with the artifact materialised:

```
python3 -m unittest tests.test_grow_family_panic_static -v
```

## Scope

Static-plus-behavioural analysis of node #115 only. The verdicts are
about panic reachability and unwind coverage inside this one family;
what the maps store, and the grow policy above the sizing branches,
are other packets' questions. The settled bodies are re-pinned, not
re-argued: their proofs stand as published in the two predecessor
packets, and this packet's new proofs are (a), (b), (c) for the
callers the predecessors did not cover, and (d).
