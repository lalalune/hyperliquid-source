# RE-002 · Node #115 RocksDB Bytewise / ReverseBytewise comparator factories

Component: storage / comparators. Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Bounded question

How does node #115 construct the two plain comparator singletons —
`rocksdb::BytewiseComparator()` and `rocksdb::ReverseBytewiseComparator()`
— which guard/instance addresses hold them, what does the 0x30-byte
object contain, and who calls the factories versus the 9-byte forwarder
stubs beside them? Both body hashes match the vendor census exactly;
both source hashes are reproduced by zeroing the census relocation
fields — and the two source hashes are IDENTICAL (see `functions.tsv`).
This is the continuation of the comparator family: #5844 (the
Bytewise/Reverse ordering and separator functions the vtables point
to), #5847 (the U64Ts wrapper layer), #5852 (the U64Ts factory +
Name). It closes the open unknown the merged
RE-001-options-default-init-115 packet left on the 0x61be810 singleton
("the concrete dynamic type behind the singleton 0x61be810 is not
pinned"): it is a `BytewiseComparatorImpl`, primary vptr 0x64d7038.

## Answer (pinned)

**Call shape.** Each factory is a 184-byte function-local-static
singleton getter with no arguments and a `const Comparator*` return.
The two 9-byte stubs (`endbr64; jmp rel32`) tail-jump to the bodies.

**1. Fast path.** Load the guard byte — bytewise 0x65088e8, reverse
0x65088d8; if nonzero, load the instance slot — bytewise 0x65088f0,
reverse 0x65088e0 — and return it. No lock, no call.

**2. Slow path.** `__cxa_guard_acquire(guard)` (PLT 0x63f0fc0). A 0
return means another thread initialized the singleton meanwhile:
load the instance slot and return it. Otherwise `operator new(0x30)`
(PLT 0x63f0dd0), then initialise the object in this exact store
order: `[obj+0x08]=0`, `[obj+0x10]=0`, `[obj+0x18]=0`, `[obj+0x28]=0`,
`[obj+0x00]=primary vptr`, `[obj+0x20]=secondary vptr` (primary +
0xf8), store the object into the instance slot,
`__cxa_guard_release(guard)` (PLT 0x63f0fd0), return the instance.

**3. Abort path.** If `operator new` throws, the landing pad
(bytewise 0x61be8bc → shared block 0x61be7fb; reverse 0x61be99c →
shared block 0x61be8d9) calls `__cxa_guard_abort(guard)` (PLT
0x63f10b0) and then `_Unwind_Resume` (PLT 0x63f0a50). The guard stays
0, the instance slot stays unset, and a later call retries
construction.

**4. Never destroyed.** Neither body registers an `__cxa_atexit`
handler: the singletons are intentionally leaked
(`STATIC_AVOID_DESTRUCTION`). This differs from the U64Ts Name factory
(#5852), which does register its cached `std::string` for destruction
— the difference is source-level (a `Comparator` singleton vs a
`std::string` cache), not an omission. The 0x30-byte object holds only
the two vtable pointers and zeroed fields: the `Comparator` base
contributes `timestamp_size_` (0 here) and the derived classes add no
members.

**5. One source body, two copies.** Both bodies reproduce the SAME
census source hash
(`55ccba1f251d91c8f0e4d144ba8ca8384beb212d0ab04e4e828c34761337069c`);
their body hashes differ only through the relocation targets
(guard/instance addresses, vtable addresses, landing-pad targets).
The census record's symbol field is
`_ZN7rocksdb18BytewiseComparatorEv` for BOTH copies, so the
Bytewise/Reverse assignment is pinned independently: 0x61be810 stores
vptr 0x64d7038 whose Name slot (+0x70) is 0x61bd720 returning
"leveldb.BytewiseComparator", and `CreateFromString` calls it from the
26-char name branch (0x61c0451); 0x61be8f0 stores vptr 0x64d7158 whose
Name slot is 0x61bd7e0 returning "rocksdb.ReverseBytewiseComparator",
and `CreateFromString` calls it from the 33-char name branch
(0x61c0a93).

**6. Vtables.** Bytewise primary 0x64d7038: D1 0x61bdee0, D0 0x61be000,
Name 0x61bd720 (+0x70), EqualWithoutTimestamp 0x61bd950 (+0x98/+0xd8),
FindShortestSeparator 0x61bd9e0, FindShortSuccessor 0x61bd990,
IsSameLengthImmediateSuccessor 0x61bd730,
CanKeysWithDifferentByteContentsBeEqual 0x61bd7d0 (+0xb8, `xor
eax,eax; ret` → false), CompareWithoutTimestamp 0x61bdc40,
Compare 0x61bdbf0. Reverse primary 0x64d7158: D1 0x61bdf70, D0
0x61be090, Name 0x61bd7e0, FindShortestSeparator 0x61bdab0,
FindShortSuccessor 0x61bd7f0 (no-op), IsSameLengthImmediateSuccessor
0x61bd800 (false), CompareWithoutTimestamp 0x61bdc90, Compare
0x61bdcf0; the shared slots (EqualWithoutTimestamp, the base-class
entries, CanKeys...) are identical. Secondary vtables (offset-to-top
-32): bytewise 0x64d7130 holds thunk D1 0x61be480, thunk D0 0x61be640,
Compare copy 2 0x61bdd50; reverse 0x64d7250 holds thunk D1 0x61be510,
thunk D0 0x61be5a0, Compare copy 2 0x61bdda0. All slots are readelf -r
RELATIVE addends; the Compare copies are the second copies
reconstructed in #5844.

**7. Who calls what.** The caller census (`census.py`, whole-`.text`
E8/E9/LEA scan, Capstone-validated from enclosing FDE starts) finds:
BytewiseComparator() has 9 direct callers plus the stub tail jump;
ReverseBytewiseComparator() has exactly 1 direct caller (0x61c0a93,
the reverse branch of `Comparator::CreateFromString` 0x61c0180) plus
its stub tail jump. Each stub has exactly 1 LEA ref, both inside
`RegisterBuiltinComparators` 0x61c1210..0x61c1a1a (bytewise stub at
0x61c1261, reverse stub at 0x61c135b; the third LEA at 0x61c1439 takes
the U64Ts stub 0x61beac0). The ObjectLibrary factory lambdas take the
STUB address, not the body address: the stubs are the canonical entry
points for function-pointer registration, while direct calls go to the
bodies. Neither factory is reached through a vtable. The two stubs are
byte-identical (same body hash): each ends exactly 0xc9 bytes past its
factory's start, so both `jmp` displacements are -0xc9.

## Cases

2,400 deterministic cases (`cases.tsv`, generated by
`tools/bytewise_reverse_factories115.py gen-cases`;
`tests/test_bytewise_reverse_factories115.py`, 17 tests pass): 800
bytewise-factory + 800 reverse-factory state machine (each 300 first
call, 300 repeat call, 100 acquire-returns-0, 50 alloc-failure abort,
50 stub call) + 800 vtable/name/layout (200 name-slot, 200
primary-slot, 100 secondary-slot, 100 layout-zero, 100 shared-source,
100 stub-identity). The tool models the guard/singleton state machine
in Python; no engine call is needed for a factory. See `records.json`
for the full ledger.

## Reproduction

Run from the repository root with the node artifact materialized:

```sh
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  work/hl-node-115.bin' | sha256sum -c -
python3 research/work-items/re-002-node115-bytewise-reverse-factories-115/gen_records.py
python3 research/work-items/re-002-node115-bytewise-reverse-factories-115/export_excerpts.py
python3 tools/bytewise_reverse_factories115.py gen-cases
python3 research/work-items/re-002-node115-bytewise-reverse-factories-115/census.py
python3 -m unittest tests.test_bytewise_reverse_factories115
```

## Upstream confirmation (RocksDB v8.1.1)

`util/comparator.cc`: `BytewiseComparator()` at lines 569–575 and
`ReverseBytewiseComparator()` at lines 578–584 both use
`STATIC_AVOID_DESTRUCTION` on a function-local static and return its
address — the singleton pattern the binary implements, with no
destructor registration. `BytewiseComparatorImpl::kClassName()` is
"leveldb.BytewiseComparator" (line 58) and
`ReverseBytewiseComparatorImpl::kClassName()` is
"rocksdb.ReverseBytewiseComparator" (line 285); both classes have empty
ctors and no members of their own. The reverse overrides match the
binary's trivial bodies: `FindShortSuccessor` is a no-op (lines
391–395; binary 0x61bd7f0 is `endbr64; ret`),
`IsSameLengthImmediateSuccessor` returns false (lines 398–414; binary
0x61bd800 is `xor eax,eax; ret`), and
`CanKeysWithDifferentByteContentsBeEqual` returns false (lines 417–421
and 249–253; binary 0x61bd7d0 is `xor eax,eax; ret`).
`RegisterBuiltinComparators` (lines 598–634) registers all three
builtin comparators with lambdas returning the factories — the three
LEA sites in 0x61c1210. `Comparator::CreateFromString` (lines 637–723)
is the 0x61c0180 routine: `call_once` registration,
`Customizable::GetOptionsMap`, then the three name branches (26 / 33 /
32 chars), the empty-value → nullptr + OK path, and the unknown-id
registry path.

## Open unknowns
- The nine direct callers of `BytewiseComparator()` are named by FDE
  only: their source-level identities are not pinned here, except
  0x60b3fb0 (Options default-init) and 0x61c0180
  (`Comparator::CreateFromString`).
- The shared base-class vtable slots (+0x10..+0x68, +0x78..+0x90,
  +0xc0/+0xc8) are recorded by address only; their source-level method
  names are not pinned in this packet.
- `Comparator::CreateFromString` 0x61c0180..0x61c0cb4 (3244 B) has no
  vendor census record, so its body/source hashes cannot be bound the
  census way; its reconstruction is the follow-up, not this packet.

## Environment limits

No cargo/rustc/git-lfs/Ghidra on this VM; the target binary is never
executed; the tool models the guard/singleton state machine in Python
with no engine call. `make verify` / `make test` /
`make catalogue-check` in a tooled environment is still owed upstream.
