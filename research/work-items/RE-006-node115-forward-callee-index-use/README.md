# RE-006: node 115 forward callees' use of the forwarded slab slot index

## Claim

The RE-006 ring-append twins (`0x5911890` / `0x5911b30`) return the
shared insert routines' result -- the pre-insert slab head, i.e.
the index of the slab slot that received the order copy. The four
insert-order callers above the twins capture that index and
forward it, register-only, to two callees (packet
RE-006-node115-twin-caller-index-use). This packet traces both
callees end to end. **Both store the index durably** -- the index
is a durable order handle one level down, in two different
structures:

**Forward 1 -- `0x4eeed90` (index in `rcx`), an ordered-map
insert.** The structure at `rsi` holds 24-byte entries in the
buffer at `[rsi+0x8]` (length `[rsi+0x10]`), probed through a
hash control array at `[rsi+0x18]` using a scrambled hash of the
key `rdx` (`r15 = rol(rdx * 0xf1357aea2e62a9c5, 0x14)`).

1. **Spill.** The index is stored to `[rsp+0x10]` at entry. An
   operand scan of the whole body shows that stack slot is read
   at exactly two later sites -- the two durable stores below --
   so no other use of the index exists in this callee.
2. **New key (append).** The entry at the pre-append length
   receives the triple {`+0x0`: scrambled hash, `+0x8`: key
   `rdx`, `+0x10`: **the index**} (store at `0x4eef00a`), the
   length is incremented, the entry's position is written into a
   hash bucket slot (`0x4eeef34`; the bucket holds the position,
   not the index), control bytes are set, the table count at
   `[rsi+0x30]` is incremented, and the out record at `rdi` gets
   `[out+0x8] = 0` (no previous value).
3. **Existing key (overwrite).** The probe compares `rdx`
   against the key field at entry `+0x8` (`0x4eeee4c`). On a hit
   the index replaces the entry's value field (store at
   `0x4eef042`) and the previous value is returned through the
   out record: `[out] = entry position`, `[out+0x8] = 1`,
   `[out+0x10] = old value`.

Growth/allocation helpers (direct calls `0x5963980` / `0x5963800`,
slot calls through `0x64e6258` / `0x64e6260`) run only on the
new-key path, before the append store; the index stays in its
stack slot until the store sites, so they never receive it.

**Forward 2 -- `0x51d1b00` (index in `rsi`), a sorted-set
insert.** The handle at `rdi` is `{+0x0: root node, +0x8:
height, +0x10: total count}`. Nodes hold sorted qword keys from
`node+0x8` with a key-count word at `node+0x62` (at most 11) and
child edges from `node+0x68`.

1. **Capture and search.** `mov rbx, rsi` (`0x51d1b07`); each
   visited node is scanned linearly: `cmp rbx, key` with
   `seta`/`sbb` folding the comparison into a three-way result
   (`0x51d1b35`--`0x51d1b49`) -- the scan advances while the index
   is greater, descends through the child edge at `0x51d1b69`
   (height decremented per level), and stops on equal or less.
   An operand scan shows `rbx` is read at exactly four sites:
   the comparison, the two stores below, and the helper forward.
2. **Duplicate.** If the index is already a member, the callee
   returns `AL = 1` (`0x51d1b70`) and stores nothing.
3. **Empty handle.** A fresh `0x68`-byte node is allocated
   (slot `0x64df480` -> `0x6355830`), zeroed, installed as root
   with height 0; the index is stored as its first key at
   `node+0x8` (`0x51d1bca`), the key-count word becomes 1, the
   handle total is incremented, and `AL = 0` is returned.
4. **Full leaf (one level down, boundary).** When the height
   count underflows at a leaf, the index is forwarded to the
   node insert/split helper `0x4c49f90` -- as `rdx` and inside a
   stack context record (`[rsp+0x10]` at `0x51d1be2`, record
   passed in `rcx`). After it returns, the handle total is
   incremented (`0x51d1bcf`) and `AL = 0` is returned.

**Shared callees.** A whole-`.text` census finds exactly six
direct `E8` call sites into each callee and no `E9` references:
the four RE-006 caller sites and two more sites in unrelated
FDEs (`0x4ed91d4`, `0x4edd2bd` into forward 1; `0x481fbe2`,
`0x4a44879` into forward 2), and no relative relocation binds
either callee. The callees are generic container inserts; this
packet establishes what they do with the value/member argument,
which in the RE-006 callers is the slab slot index. The values
the two extra callers pass are not traced.

## Scope

| Owner | FDE range | Bytes | SHA-256 | Index argument |
| --- | --- | ---: | --- | --- |
| `forward_1` | `0x4eeed90..0x4eef13b` | 939 | `399e403494b758bc98103adc72979271e0d22326718a30881de3f904b812e015` | `rcx` |
| `forward_2` | `0x51d1b00..0x51d1c5f` | 351 | `b94dcaca1a7e4fadeb833f24fa47bd30eb9bab8b4900a14b314e6b3f19eff3c6` | `rsi` |

The measured denominator is the two complete callee FDEs: 1,290
bytes. Both bodies are small enough that their full disassembly
exports are retained. The four RE-006 caller FDEs and the two
extra caller FDEs per callee are hash-pinned boundaries (call
sites only); the downstream helpers (`0x5963980`, `0x5963800`,
`0x4c49f90`) are likewise hash-pinned boundaries, cited by their
call sites and slot bindings, not re-derived.

## Method

`tools/forward_callee_index_use_static.py` authenticates the
whole node 115 capture by size and SHA-256 before generation.
Analysis derives all thirteen FDE ranges from the FDE extents,
re-derives every body hash, scans the whole `.text` for direct
`E8`/`E9` references to the two callees, confirms no relative
relocation reaches or is held by any of the thirteen bodies, and
verifies every recorded slot binding. Every flow instruction is
pinned byte-exactly (each validated as a native instruction start
during generation) and the use sets are operand-level scans over
the decoded bodies: the `[rsp+0x10]` index-slot read set and the
`[rsp+0x8]` out-record read set in forward 1, and the `rbx` read
set (excluding prologue/epilogue push/pop) in forward 2.

## Trace

1. **Forward 1 entry.** Spills: index to `[rsp+0x10]`, out
   record pointer to `[rsp+0x8]`; hash of `rdx` computed into
   `r15`; entries buffer and length loaded from the map.
2. **Forward 1 probe.** Control-byte probing over
   `[rsi+0x18]` with mask `[rsi+0x20]`; candidate entries are
   confirmed by comparing `rdx` with entry `+0x8`.
3. **Forward 1 stores.** Existing key: value field at entry
   `+0x10` overwritten with the spilled index, old value
   returned. New key: hash-bucket position store, control
   bytes, table count increment, then the entry triple append
   with the index at `+0x10` and the length incremented.
4. **Forward 2 entry/search.** Capture into `rbx`; root and
   height loaded; per node, the key-count word is read and the
   sorted keys are scanned for the index.
5. **Forward 2 outcomes.** Duplicate -> `AL = 1`, no store.
   Empty handle -> allocate, install root, store first key,
   count increments, `AL = 0`. Full leaf -> helper `0x4c49f90`
   with the index in `rdx` and in the context record, total
   increment, `AL = 0`.

## Boundary

The packet ends at the two callee bodies. The internals of the
growth helpers (`0x5963980` / `0x5963800`), the allocation and
table-initialisation slot targets (`0x43bbf00`, `0x3ed9150`,
`0x6355830`), and the node insert/split helper (`0x4c49f90` --
in particular, which node field it writes the index into on a
split) are recorded by address and binding only. What the
forward-1 map key (`rdx`, a caller frame qword) denotes, what
the forward-2 handle's owner does with the `AL` result, and the
values passed by the two extra callers of each callee are not
established here.

## Next question

Does the node insert/split helper `0x4c49f90` store the index as
a node key on every path (insert into a non-full leaf, split of
a full leaf, root split), completing the forward-2 trace -- and
who reads the forward-1 map back (which lookup function returns
the slab slot index for a key, and where is that returned index
consumed)?

## Validation

```sh
python3 tools/forward_callee_index_use_static.py
python3 -m unittest tests.test_forward_callee_index_use_static
sha256sum -c MANIFEST.sha256  # run in this directory
```

The test regenerates the packet into a temporary directory and
requires byte identity with the retained files, checks the
census, trace facts (spill/read sets, both durable store sites
per callee, verdicts) and the classification models, and mutates
eight pinned bytes or records -- the entry spill, both index
stores of forward 1, a grow-call displacement, forward 2's
capture, its key comparison, its empty-handle store, and a
caller call opcode (census) -- requiring `analyze` to reject
each mutation.
