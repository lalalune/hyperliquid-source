# RE-001: map node #115 predicate-gated drain 0x5f14000 with its transfer callee 0x5f13e00

## Bounded question

While the predicate at 0x5f13240 stays true, what does the loop at
0x5f14000 pop from the object, where does each popped payload go, and
who drives the loop? This packet pins the whole behavior end to end —
not a lone-window fragment: the 142-byte drain loop whole, its
147-byte transfer callee whole, the predicate and aggregate it relies
on (both already mapped, cited by reference, not re-read), and every
census-confirmed consumer of both functions.

## Windows

- Drain loop: 0x5f14000..0x5f1408e (142 bytes), FDE at .eh_frame
  offset 0x3592c0, length 0x44, CIE 0 (no LSDA). The window ends at the
  `ret` at 0x5f1408d; the `int3` padding at 0x5f1408e and the next
  function at 0x5f14090 are excluded.
- Transfer: 0x5f13e00..0x5f13e93 (147 bytes), FDE at .eh_frame offset
  0x35924c, length 0x34, CIE 0 (no LSDA). The window ends at the `ret`
  at 0x5f13e5e / the fall-through region; the `int3` padding from
  0x5f13e93 and the next function at 0x5f13ea0 are excluded.
- Artifact: work/hl-node-115.bin, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  matching provenance/artifacts.json entry artifacts/node/115/hl-node.

## How the excerpts were produced

From the repository root:

```
objdump -d --start-address=0x5f14000 --stop-address=0x5f1408e work/hl-node-115.bin
objdump -d --start-address=0x5f13e00 --stop-address=0x5f13e93 work/hl-node-115.bin
```

The excerpt files are that output verbatim, whole-function. Both
functions start with `endbr64`; every mnemonic in the excerpts is
genuine objdump output from the target binary, not a placeholder, and
verify.py checks sampled instructions byte-for-byte against a fresh
objdump run and the raw binary. Instruction-level detail lives only in
the verbatim excerpts; records.json carries semantic records, not a
per-instruction list.

## Semantics (literal)

### Drain loop 0x5f14000

Arguments: rdi = object, rsi = collection (saved on the stack),
rdx = predicate argument (saved in r12). Returns an int: 0 when
nothing was popped, 1 once at least one node has been popped.

```
popped = 0
while predicate(object, predicate_arg):   # 0x5f13240, mapped by #2182
    if [object + 0x18] == object + 0x18:  # second list empty
        break
    node = [object + 0x20]                # last node (_M_prev)
    payload = [node + 0x10]
    [object + 0x28] -= 1                  # list size
    _M_unhook(node)                       # PLT, std list node unhook
    operator_delete(node, 0x18)
    popped = 1
    transfer(object, collection, payload) # 0x5f13e00
return popped
```

Notes, stated literally:

- The predicate is called before every pop, with the same predicate
  argument each time. The predicate itself sums the lists at
  object + 0x00 and object + 0x18 (see #2182), so popping from the
  +0x18 list is what can turn the predicate false on a later pass.
- The pop takes the LAST node ([object + 0x20] is the header's
  _M_prev), not the first; the loop is a pop-back drain.
- No stack canary is used (no %fs reference appears in-window) and no
  rip-relative reference appears in-window. The only PLT calls
  in-window are _M_unhook, operator delete, transfer and the
  predicate.

### Transfer 0x5f13e00

Arguments: rdi = object, rsi = collection, rdx = payload. Returns
void.

```
count = [payload + 0x70] (signed 32-bit) - 1
[payload + 0x70] = count
if count > 0: return
n = [collection]                            # entry count
if n > 7:
    # overflow-vector path at collection + 0x50
    if [collection + 0x58] == [collection + 0x60]:  # end == cap end
        grow(collection + 0x50, [collection + 0x58], &payload)  # 0x5d90f50, by contract
    else:
        [[collection + 0x58]] = payload
        [collection + 0x58] += 8
else:
    # inline path
    [[collection + 0x48] + n * 8] = payload
    [collection] = n + 1
*[object + 0x48] -= aggregate(payload)      # 0x5f0e2d0, mapped by #2046
```

Notes, stated literally:

- The +0x70 field is a remaining-reference count: the transfer only
  happens once it reaches zero (or below); a still-positive count
  returns with no other effect.
- The inline path holds indices 0..7 (eight slots through the buffer
  pointer at collection + 0x48); index 8 and beyond go through the
  vector at collection + 0x50. The grow helper 0x5d90f50 was not read;
  only its call site and argument registers are claimed.
- The aggregate 0x5f0e2d0 was mapped by #2046 (spinlock-guarded
  aggregate total); here only its single argument (the payload) and
  the subtraction of its return are claimed.
- No stack canary is used (no %fs reference appears in-window) and no
  rip-relative reference appears in-window.

## Consumers (call sites only; containing-function internals not read)

Drain 0x5f14000 — one direct call, two tail jumps, no qword hits,
no RELATIVE addends:

- Direct call 0x5f141b4 in 0x5f14180: object argument is
  [caller + 0x08], collection and predicate arguments forwarded.
- Tail jump 0x5f140b3 in 0x5f14090: that function first calls
  0x5f127b0 (not read, by contract), then tail-delegates to the drain
  with (object, original rdx as collection, 0 as predicate argument).
- Tail jump 0x5f14327 in 0x5f14200: an exit path of a larger function
  (internals not read) tail-delegating with (r12, r15, 0).

Transfer 0x5f13e00 — three direct calls, one tail jump, no qword
hits, no RELATIVE addends:

- Direct call 0x5f14066 in the drain loop itself (the transfer step
  above).
- Direct calls 0x5f13eda and 0x5f13f02 in 0x5f13ea0: that function
  walks the lists at object + 0x00 and object + 0x18, transferring
  each payload, then deletes the list nodes and the 0x50-byte object
  itself (only the call sites are claimed here).
- Tail jump 0x5f1435f in 0x5f14200: an exit path of the same larger
  function as above, tail-delegating with (r12, r15, r13).

## Model

tools/predicate_drain_115.py implements the drain loop and the
transfer with the predicate, the aggregate and the vector-grow step as
injected callables (they are mapped elsewhere or by contract, so the
model takes them as inputs rather than re-implementing them). The
model's guards (cycle/unknown checks) are model-side only and are
stated as such in the tool docstring; the binary has no such guards.
