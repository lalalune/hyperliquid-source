# RE-001-two-flag-callback-exits-115

Bounded question: what do the two callees of the callback 0x606a890
actually do? RE-001-two-flag-lazy-init-115 pinned the callback's
three arms but reached both of its exits only "by contract": the
direct call to 0x606a170 on the [object + 0x20] != 0 arm, and the
tail jump to 0x606a650 that ends every path. This packet pins both
bodies end to end — control flow, memory effects, call contracts
and unwind behaviour — against node #115
(sha256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

Four-line header:

- Reaching action: the callback 0x606a890, reached from the
  two-flag lazy-init variant when a holder's inner object is
  released; every callback path ends in 0x606a650, and the
  [object + 0x20] != 0 path passes through 0x606a170 first.
- Basis: the merged RE-001-two-flag-lazy-init-115 records both
  exits as its first unknown ("Internals of 0x606a170 and of the
  tail-jump target 0x606a650 (by contract only)").
- Loss if left unpinned: the callback's amount accounting cannot
  be reconstructed — the subtract it skips on one arm is performed
  inside 0x606a170 in a different form, and the side effects of
  the always-taken tail jump (a list notify-and-drain) are
  invisible from the callback alone.
- Duplicate judgement: full sweep of the 703 open PRs' file lists
  plus the merged tree in every notation found no owner for either
  address; the nearest packet, RE-001-two-flag-lazy-init-115,
  names both as unknowns, so this packet is its continuation, not
  a duplicate.

Identity (from the RE-002 vendor census byte-window table, stated
as census identity, not as a symbol in this binary): 0x606a170 is
the window registered as rocksdb::WriteBufferManager::FreeMemWithCache(unsigned long)
and 0x606a650 as rocksdb::WriteBufferManager::MaybeEndWriteStall().
The semantics below are pinned from the bytes alone; the names are
consistent with them (a size is freed against a total and pushed
to constituent caches; a stall flag gates a notify-and-drain of a
waiter-style list) but nothing below depends on the names.

## 0x606a170 — subtract and propagate down a cache chain

Arguments: rdi = this, rsi = size. Returns void, by tail-jumping
to pthread_mutex_unlock. Window 0x606a170..0x606a3d6 (614 bytes).

```
lock(this + 0x30)                       # fail: throw, see below
total = [this + 0x10] - size            # 64-bit wrapping, stored back
obj = [this + 0x20]; expect = 0x5d8aee0 # runtime value at 0x64ece40
for level in 1..4:
    fn = [[obj] + 0x10]
    if fn != expect:
        fn(&out, obj, total)            # this level's own flavour
        goto epilogue                   # held locks released first
    lock(obj + 0x18)                    # fail: throw, see below
    expect = fn; obj = [obj + 0x40]
fn = [[obj] + 0x10]                     # fifth object, unconditional
fn(&out, obj, total)
unlock level-4, 3, 2, 1 mutexes         # reverse order
epilogue:
if out.second_qword != 0: operator delete[](out.second_qword)
tail-jump pthread_mutex_unlock(this + 0x30)
```

Pinned details:

- The subtract happens only after the this + 0x30 mutex locks,
  and the new total — not the amount — is what every chain call
  receives (rdx at 0x606a2f5 / 0x606a305 / 0x606a315 / 0x606a2e5 /
  0x606a278). This is the subtract the callback skips on its
  [object + 0x20] != 0 arm, in propagated form; the callback's
  other arm subtracts the amount from [object + 0x10] directly.
- The chain has exactly five objects: [this + 0x20], then four
  [obj + 0x40] hops. At each of the first four levels the object's
  +0x10 virtual ("flavour") is compared with the previous level's
  flavour (level 1 against the sentinel 0x5d8aee0, the runtime
  value of the qword at 0x64ece40). A mismatch delegates to that
  object's own flavour and stops the descent; a match locks the
  object's mutex at +0x18 and descends. The fifth object's
  flavour is called unconditionally and its own +0x40 field is
  never read.
- The out struct is 0x18 bytes of stack at rsp + 0x10, passed by
  pointer as the first argument of every chain call. Only its
  second qword (rsp + 0x18) is consumed by this function, as an
  operator delete[] argument in the epilogue.
- Every lock failure (the this + 0x30 mutex or any chain mutex)
  re-checks the stack canary and calls __throw_system_error with
  the lock's return code; there is no body-level unlock on those
  paths. The LSDA assigns each throw call a landing pad whose
  shared cascade (0x606a126..0x606a151, outside the window)
  unlocks exactly the mutexes held at that point in reverse
  order — except the this-mutex failure itself, whose call site
  (0x606a334) has no landing pad. Each of the five chain calls
  likewise maps to the pad that unlocks the mutexes held at its
  level. The full decoded call-site table is in records.json.

## 0x606a650 — gated notify-and-drain of an embedded list

Argument: rdi = this. Returns void. Window 0x606a650..0x606a88e
(574 bytes).

```
if [this + 0x98] == 0: return
if [this + 0x10] >= [this + 0x00] (unsigned): return   # read unlocked
lock(this + 0x70)                       # fail: throw, list untouched
if [this + 0x99] == 0: unlock; return   # list left exactly as found
[this + 0x99] = 0
for node in embedded list at this + 0x58, in order:
    elem = [node + 0x10]
    if [[elem] + 0x18] == 0x5d48820:    # runtime value at 0x64ed568
        0x60d5230(elem + 0x08); [elem + 0x68] = 1 (dword)
        0x60d52f0(elem + 0x08); 0x60d5700(elem + 0x30)
    else:
        [[elem] + 0x18](elem)
    node = [node]                       # loaded after the notify
splice the whole list into a stack-local list:
    last node's next and first node's prev are re-pointed at the
    local head, the embedded head at this + 0x58 is self-linked
    and [this + 0x68] (the size) is set to 0
unlock(this + 0x70)
for each detached node, in order: operator delete(node, 0x18)
```

Pinned details:

- The [this + 0x98] flag is never written by this function; only
  [this + 0x99] is cleared, and only under the mutex, before the
  notify walk.
- The payloads (node + 0x10) are never freed — only the 0x18-byte
  list nodes are, after the mutex is released. The list is
  therefore drained of its nodes, not of its elements.
- The notify callees 0x60d5230, 0x60d52f0 and 0x60d5700 are
  pinned by call site and argument only; their internals are not
  read here. The second of the three calls (0x606a766) is the
  only throwing-capable call in either window with no LSDA
  call-site row; the gap is recorded in records.json as observed.
- Unwind: exceptions from the notify calls land on pad 0x606a876
  (unlock this + 0x70, free the still-empty local list, resume);
  the lock-failure throw call lands on pad 0x606a882 (free the
  local list only, no unlock — the lock never succeeded). The
  splice cannot be reached by an unwind: it runs only after the
  walk completes.

## Model and verification

tools/two_flag_callback_exits_115.py models both functions over a
flat byte-addressed memory with the PLT and virtual callees
injected; tests/test_two_flag_callback_exits_115.py pins 16
hand-derived cases and, when the unicorn package is importable,
differentially runs the real bytes against the model (event log,
final memory image and outcome compared): 299 cases passed in
this packet's verification run (19 fixed + 280 randomised, seed
20261106). verify.py re-checks the binary digest, this packet's
manifest, the excerpt bytes, the census (live and recorded), the
call-site bytes in the callback, and the model tests.

## Unknowns (stated, not filled in)

- Field names and meanings beyond the offsets pinned here; the
  WriteBufferManager identification comes from the RE-002 vendor
  census, not from any symbol in this binary.
- What the +0x10 chain virtual and the +0x18 notify virtual
  compute; only addresses, flavour identity and call contracts
  are pinned.
- Internals of the three known-flavour notify callees.
- The meaning of the out struct's first and third qwords.
- Why the second known-flavour notify call has no LSDA row.
- Caller internals beyond the callback 0x606a890 itself.
