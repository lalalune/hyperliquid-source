# RE-001: map node #115 sibling drain driver 0x5f140c0 with its wrapper, pre-call and lazy-init callees

## Bounded question

Who is the sibling driver of the drain driver mapped by #2242, what
runs before and after its drain, and what observable state changes
besides the drain itself? This packet pins the whole behavior end to
end — not a lone-window fragment: the 185-byte driver whole, its
40-byte wrapper whole, the wrapper's 70-byte pre-call whole, the
pre-call's cold block, the 62-byte lazy-init callee whole, the
dispatch check that guards the indirect call, and all three
census-confirmed callers of the driver with the argument each passes.

## Windows

- Driver: 0x5f140c0..0x5f14179 (185 bytes), FDE at .eh_frame offset
  0x359330, length 0x30, CIE 0 (no LSDA). The window ends at the
  `__stack_chk_fail` call at 0x5f14174; the `int3` padding from
  0x5f14179 and the next function at 0x5f14180 are excluded.
- Wrapper: 0x5f14090..0x5f140b8 (40 bytes), FDE at .eh_frame offset
  0x359308, length 0x24, CIE 0 (no LSDA). The window ends at the tail
  jump at 0x5f140b3; the `int3` padding from 0x5f140b8 and the next
  function at 0x5f140c0 are excluded.
- Pre-call: 0x5f127b0..0x5f127f6 (70 bytes), FDE at .eh_frame offset
  0x358e5c, length 0x28, CIE 0 (no LSDA). The window ends at the `ret`
  at 0x5f127f5; the cold block from 0x5f127f6 is a separate excerpt.
- Cold block: 0x5f127f6..0x5f12833 (61 bytes), no FDE of its own. It
  is the block immediately following the pre-call's `ret`, using the
  pre-call's own registers (rbx, r12, rbp); this packet does not pin
  the edge that enters it. It is included as a supplementary excerpt,
  not as a separate function.
- Lazy-init: 0x605e860..0x605e89e (62 bytes), FDE at .eh_frame offset
  0x367840, length 0x1c, CIE 0 (no LSDA). The window ends at the `ret`
  at 0x605e89d; the `int3` padding from 0x605e89e and the next
  function at 0x605e8a0 are excluded.
- Artifact: work/hl-node-115.bin, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  matching provenance/artifacts.json entry artifacts/node/115/hl-node.

## How the excerpts were produced

From the repository root:

```
objdump -d --start-address=0x5f140c0 --stop-address=0x5f14179 work/hl-node-115.bin
objdump -d --start-address=0x5f14090 --stop-address=0x5f140b8 work/hl-node-115.bin
objdump -d --start-address=0x5f127b0 --stop-address=0x5f127f6 work/hl-node-115.bin
objdump -d --start-address=0x5f127f6 --stop-address=0x5f12833 work/hl-node-115.bin
objdump -d --start-address=0x605e860 --stop-address=0x605e89e work/hl-node-115.bin
```

The excerpt files are that output verbatim, whole-function. All five
windows start with `endbr64` except the cold block, which is not a
function entry; every mnemonic in the excerpts is genuine objdump
output from the target binary, not a placeholder, and verify.py
checks sampled instructions byte-for-byte against a fresh objdump run
and the raw binary. Instruction-level detail lives only in the
verbatim excerpts; records.json carries semantic records, not a
per-instruction list.

## Semantics (literal)

### Driver 0x5f140c0

Arguments: rdi = outer object, rsi = collection, rdx = predicate
argument. Returns 1 unconditionally.

```
prepare(outer, collection, predicate_arg)   # 0x5f13f90, mapped by #2242, args forwarded unchanged
inner = [outer + 0x08]                      # re-read AFTER prepare: prepare may replace it
wrapper(inner, collection, predicate_arg)   # 0x5f14090, return ignored
obj = [collection + 0xa50]
slot = [obj + 0x50]
if slot != default (0x5f04d50):            # compared against the .got slot at 0x64ed768
    slot(obj)                               # indirect call, return ignored
lazy_init(collection + 0x80)                # 0x605e860
counter = ([outer + 0x10] + 1) mod 2**32    # 32-bit wrapping increment
if counter == 1:
    byte [outer + 0x00] = 1
refresh(outer)                              # 0x5f13450, mapped by #2242
if byte [outer + 0x01] == 1:                # lock cmpxchg at 0x5f1413e
    byte [outer + 0x01] = 0
# any other value at [outer + 0x01] is left unchanged
return 1
```

Notes, stated literally:

- The dispatch default is the runtime value of the `.got` slot at
  0x64ed768, which carries a R_X86_64_RELATIVE relocation with
  addend 0x5f04d50; the static file holds 0 there, so the packet
  models the comparison as "slot == 0x5f04d50" without claiming a
  runtime base address. The indirect call passes the dispatch object
  itself (rdi = [collection + 0xa50]).
- The stack byte at rsp + 0x07 is written (1, then possibly the
  cmpxchg result) but never read, exactly as in the #2242 driver.
- Unlike the #2242 driver, this driver does not return the drain's
  result: the wrapper's tail-jumped drain result is discarded and
  the driver returns 1 on every path.

### Wrapper 0x5f14090

```
pre_call(inner, collection)                 # 0x5f127b0
drain(inner, collection, 0)                 # tail jump to 0x5f14000, mapped by #2236
```

The driver's predicate argument never reaches the drain: the wrapper
saves it, then replaces it with 0 for the tail jump. The drain's
result becomes the wrapper's return value, which the driver ignores.

### Pre-call 0x5f127b0

```
position = [inner]                          # saved before the allocation
node = operator_new(0x18)
node + 0x10 = collection
_M_hook(node, position)                     # libstdc++ list-node hook, by contract
[inner + 0x10] += 1
*[inner + 0x48] += aggregate(collection)    # 0x5f0e2d0, mapped by #2046
```

The hook call is recorded by contract only: per the libstdc++
contract, `_M_hook` inserts the fresh node before the position node,
but the resulting list topology is not modelled beyond the call's
arguments. The cold block (supplementary excerpt) deletes 0x18-byte
nodes along the [inner + 0x18] chain until it reaches [inner], then
along the [inner] chain until it reaches inner itself, then resumes
the unwind with the collection argument.

### Lazy-init 0x605e860

Argument: rdi = collection + 0x80. Returns void.

```
inner = [arg]
if inner == null: return                   # flag untouched
if byte [arg + 0x10] != 0: return          # flag untouched
if [inner] != 0 or qword [inner + 0x20] != 0:
    callback(inner, [arg + 0x08])           # 0x606a110, by contract only
byte [arg + 0x10] = 1                       # set whether or not the callback ran
```

### Callers of the driver (all three, census-confirmed)

- 0x5e83a33 in 0x5e82cc0..0x5e844e1: outer = objectA + 0x8f0,
  collection = qword at objectA + 0x8e8, predicate argument =
  objectB + 0xc8. The return value is not tested.
- 0x5e8aba9 in 0x5e8a890..0x5e8c518: outer = stack object,
  collection = qword at rbx + 0x8e8, predicate argument =
  r12 + 0x218. The return value is overwritten, not tested.
- 0x5ed1c20 in 0x5ed01f0..0x5ed2238: outer = object at r13 + 0x48
  plus 0x8f0, collection = rbx, predicate argument = object at
  r13 + 0x140 plus 0xc8. The return value is not tested.

All three callers ignoring the return is consistent with the
driver's unconditional return of 1.

## By-contract items (not read, nothing claimed about internals)

Prepare 0x5f13f90 and refresh 0x5f13450 (mapped by #2242), drain
0x5f14000 (mapped by #2236), aggregate 0x5f0e2d0 (mapped by #2046),
the dispatch slot implementations including the default 0x5f04d50,
the lazy-init callback 0x606a110, operator new/delete,
`_M_hook` and `_Unwind_Resume`.

## Unknowns

See records.json: the meanings of the counter, the first-run byte
and the flag byte; the slot implementations; the callback's second
argument; the inner object's remaining fields and the hook's list
topology; the cold block's entry edge; caller internals beyond the
three call sites.

## Environment

`make doctor` fails on missing providers (pre-existing, unchanged by
this change). `make verify` / `make catalogue-check` fail on the
LFS-pointer artifact here (pre-existing); this packet binds to the
materialized work/hl-node-115.bin instead. pytest is not installed,
so the pytest-style test file runs under plain python3 via its
`__main__` runner.
