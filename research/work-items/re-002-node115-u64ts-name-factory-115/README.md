# RE-002 · Node #115 RocksDB U64Ts comparator name + factory

Component: storage (RocksDB comparators). Target: Linux x86-64 node #115,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Upstream base commit `0781ce048`. Disassembly: GNU objdump 2.42.
Model and tests: `tools/u64ts_name_factory115.py`,
`tests/test_u64ts_name_factory115.py` (2,400 deterministic cases).

## What is reconstructed

The follow-up the merged RE-002 U64Ts-comparator-wrapper packet
(#5847) left open: the string building (`Name`,
`kClassNameInternal`) and the singleton construction
(`BytewiseComparatorWithU64Ts`) for
`rocksdb::ComparatorWithU64TsImpl<BytewiseComparatorImpl>`. All
three functions are census-bound (vendor census, member
`6cca28ae25285154-comparator.o`, crate `librocksdb-sys`
0.11.0+8.1.1, published-crate rebuild, Ubuntu GCC 13.3 native
build); each body hashes exactly to the census
`target_body_sha256`, and each census `source_body_sha256` is
reproduced exactly by hashing the body with its census
relocation fields zeroed (see [functions.tsv](functions.tsv)).
The `objdump --dwarf=frames` pc ranges were re-checked against
the census ranges and agree for all five bodies.

* `rocksdb::BytewiseComparatorWithU64Ts()` at
  `0x61be9d0..0x61beabe` (238 bytes, census
  `node115-vendor-61be9d0`, body SHA-256
  `4ef3dd02c39343d9bdd38d032ae7a794e28216a17f8b1b4098b47c73fe794779`,
  source `06ff1f1e2b815b335e5b40114b1d0fca9807ca8358471b99aae635a69d2aa373`,
  12 relocations, published-crate rebuild agreement 202/238):
  a function-local-static singleton factory. On the first call
  it acquires the `__cxa_guard` at `0x65088c8`, allocates a
  96-byte object (`operator new(0x60)`), and initialises it:
  primary vptr `0x64d7278` at +0x00, secondary vptr `0x64d7370`
  (= `0x64d7278 + 0xf8`) at +0x20, timestamp size 8 at +0x28,
  the inner Bytewise vptr `0x64d7038` at +0x30, the inner
  secondary vptr `0x64d7130` at +0x50, and zeroes +0x08/+0x10/
  +0x18 (the first member vector) and +0x38/+0x40/+0x48 (the
  second member vector) and +0x58. It stores the object at
  `0x65088d0`, releases the guard and returns the singleton
  pointer; later calls return the stored pointer without
  allocating. The factory's in-FDE landing-pad stub at
  `0x61beab2..0x61beabe` (`endbr64; mov %rax,%rbp; jmp
  0x61be9b9`) is part of the 238-byte body.

* `rocksdb::(anonymous namespace)::ComparatorWithU64TsImpl<rocksdb::
  (anonymous namespace)::BytewiseComparatorImpl>::kClassNameInternal()`
  at `0x61bebd0..0x61bef66` (918 bytes, census
  `node115-vendor-61bebd0`, body SHA-256
  `e7bae44a5679b505343d1fdd2124cbb2abb92111c691ba9210399d54a5b0e914`,
  source `03e4ada40219b430c66f618507d4eb1d970ea5323212a94fb462bf66b693a0e8`,
  28 relocations, published-crate rebuild agreement 827/918):
  builds the class name with a `std::ostringstream`
  (libstdc++ `basic_stringstream`, vtable/VTT at `0x64ed600` /
  `0x64ed608`): it inserts the 26-byte literal
  "leveldb.BytewiseComparator" (.rodata `0x44e0fe`,
  `mov $0x1a, %edx`) and then the 6-byte literal ".u64ts"
  (.rodata `0x43c8ab`, `mov $0x6, %edx`) via
  `__ostream_insert`, and copies the stream's string into the
  out `std::string` (sret, returned in rax) with
  `basic_string::_M_replace(0, 0, ptr, len)`. The result is
  exactly "leveldb.BytewiseComparator.u64ts" (32 chars). The
  exception cleanup lives in the `.cold` part at
  `0x61beac9..0x61bebc6` (253 bytes, census
  `node115-vendor-61beac9`, body SHA-256
  `4a22c39add303fde0d181d2b9e64b8ed53c8c516d77c919e598063bfa2eb2116`,
  source `a3cea38332f4b685155d871bdb3646ba9c40135f1bbf63328f820e2c0fd7da11`,
  12 relocations): it disposes the out string and destroys the
  stringstream, then `_Unwind_Resume`s. One local jump field
  inside the hot body (offset 849, the `jmp` at `0x61bef20` to
  the next landing-pad stub) is not in the census relocation
  list; its displacement is identical in the source and target
  builds, so the source hash already matches with only the
  census fields zeroed.

* `...::Name() const` at `0x61bef90..0x61bf02b` (155 bytes,
  census `node115-vendor-61bef90`, body SHA-256
  `2797ccf24611e0570b6894d840b2f7a6fd01abcba7fe3a75fab57ea348763dd3`,
  source `159ed939dec9f51b2fb78fd720a2c49ca32efdc4793887fdd526828a14c48236`,
  12 relocations, published-crate rebuild agreement 117/155):
  a function-local-static cache of the name string. On the
  first call it acquires the `__cxa_guard` at `0x6508898`,
  calls `kClassNameInternal` into the static `std::string` at
  `0x65088a0`, registers the libstdc++ `~basic_string`
  destructor (GLOB_DAT slot `0x64ed5d8`) with `__cxa_atexit`,
  releases the guard, and returns the string's data pointer
  (`const char*`, i.e. the cached
  "leveldb.BytewiseComparator.u64ts"). Later calls return the
  cached pointer directly. The exception path jumps to the
  shared landing pad at `0x61bef66..0x61bef8b` (37 bytes, body
  SHA-256
  `1c9b40188e6e4beeb7f148be0dc22f6328f8cb96b3d1a247a85ed1158f0d468f`):
  `__cxa_guard_abort` + `_Unwind_Resume`.

* The 9-byte tail-call stub at `0x61beac0..0x61beac9`
  (`endbr64; jmp 0x61be9d0`, body SHA-256
  `63d0fbe8397c36521e87839a36a225f96e90f556840d1e32ad245d15ca199124`,
  its own FDE, no census record): a second entry point that
  forwards to the factory.

## Object layout (confirmed by the factory)

96 bytes: primary vptr at +0x00, member vector 1 at
+0x08/+0x10/+0x18, secondary vptr at +0x20, timestamp size 8
at +0x28, inner Bytewise vptr at +0x30, member vector 2 at
+0x38/+0x40/+0x48, inner secondary vptr at +0x50, zero at
+0x58. This is the same layout the #5847 packet's destructors
assume (they reset the same three vptrs and destroy the same
two vectors).

## Vtable binding

R_X86_64_RELATIVE slots, from `readelf -r` (the file holds zeros in
`.data.rel.ro`; the RELA addends are the evidence, as in #5844).
The wrapper primary vtable (stored vptr `0x64d7278`) holds D1 at
+0x00, D0 at +0x08, `Name` at +0x70 (slot 14),
`CompareTimestamp` at +0xc8 (slot 25),
`CompareWithoutTimestamp` at +0xd0 (slot 26) and `Compare` at
+0xe0 (slot 28); the secondary vtable (stored vptr `0x64d7370`,
offset-to-top -32) holds thunk D1 at +0x00, thunk D0 at +0x08
and thunk `Compare` at +0x10 (slot 2).

CORRECTION to the #5847 packet: it wrote `Name` at +0x68. That
slot holds `0x609d980`, a shared base-class function present in
the Bytewise vtable too (`0x64d7038` + 0x68 is the same
`0x609d980`); the `Name` functions sit at +0x70 in both
vtables (wrapper `0x61bef90` at `0x64d72e8`, Bytewise
`0x61bd720` at `0x64d70a8` -- the Bytewise `Name` is
`lea 0x44e0fe,%rax; ret`, returning the
"leveldb.BytewiseComparator" literal directly).

## Caller census

Whole-.text E8/E9/LEA scans (method validated against
`0x61b0660` -> exactly 2 sites and `0x61bd540` -> exactly 49):

* Factory `0x61be9d0`: exactly ONE direct E8 call site,
  `0x61c0aa0`, inside the comparator-by-name selection routine
  at `0x61c0180..0x61c0cb4` (a large routine that compares an
  input string against cached comparator names with `strlen`
  + 16-byte XOR compares and returns the matching factory's
  singleton; it also calls the sibling factory at `0x61be8f0`).
  Plus the E9 tail jump from the forwarder stub at `0x61beac4`.
* `kClassNameInternal` `0x61bebd0`: exactly ONE direct E8 call
  site, `0x61beff5`, inside `Name`. (The selection routines
  inline the name-string *construction* as well -- see below --
  but they do not call this function.)
* `Name` `0x61bef90`: ZERO direct calls, tail jumps, or LEA
  references anywhere in .text -- reached only through the
  vtable slot +0x70.
* The `Name` guard (`0x6508898`) and static string
  (`0x65088a0`) ARE referenced directly by the selection
  routines at `0x61c0180..0x61c0cb4` and `0x61c1210..0x61c1a1a`
  (18 sites: `movzbl` guard checks, `lea guard, %rdi` +
  `__cxa_guard_acquire` init blocks that build the
  ostringstream inline, and direct uses of the cached string,
  e.g. `strlen` on it at `0x61c0370`). The compiler inlined
  the `Name()` static initialisation into those callers
  instead of calling it. The atexit cleanup function at
  `0x61bffe8..0x61c0173` (395 bytes, body SHA-256
  `44491e497572cb7e02b2f2dbcc12b6728923c02c4b541105cb1c5f44e53a7cc2`)
  disposes the cached string at exit.
* The sibling factory at `0x61be8f0` (FDE `0x61be8f0..0x61be9a8`,
  184 bytes, census `node115-vendor-61be8f0`, body SHA-256
  `322fd2cf015ca9435663e3a73d93009727c2b0714ef556bd06dfb73c6d34dd05`)
  is one of 2 identical copies: the census lists both
  `rocksdb::BytewiseComparator()` and
  `rocksdb::ReverseBytewiseComparator()` as candidates, and
  the stored vtable `0x64d7158` -- whose Name slot
  (`0x64d71c8`) holds `0x61bd7e0`, which returns
  "rocksdb.ReverseBytewiseComparator" -- pins this copy to the
  reverse one. (The other copy at `0x61be810..0x61be8c8`
  stores the Bytewise vtable.)

All 2,400 cases are committed in [cases.tsv](cases.tsv). The
three functions produce constant values (one 32-byte string,
one 96-byte singleton layout, one cached pointer), so the case
battery checks the ostringstream assembly rule over real
.rodata strings (800) plus the factory guard/singleton state
machine (800) and the name-cache state machine (800) over
seeded call sequences, with every constant verified against
the binary by `tools/u64ts_name_factory115.py --verify`.

## Unknowns (kept separate from observations)

* The two member vectors' element type beyond the leading
  std::string, and their member names (see also #5847): each
  48-byte element holds a string at offset 0 and 16 further
  bytes the destructor never touches. Not pinned from the
  binary alone.
* The selection routines at `0x61c0180..0x61c0cb4` and
  `0x61c1210..0x61c1a1a` are described only as far as they
  touch this packet's functions (one factory call, the inlined
  `Name` guard checks, the `strlen` + XOR name compares);
  their full dispatch tables and the remaining comparator
  names they select between are not reconstructed here.
* The `.cold` landing-pad stubs inside the `kClassNameInternal`
  hot body (five `endbr64; mov %rax,%rbp; jmp` fragments at
  `0x61bef11..0x61bef66`) are recorded as bytes only; which
  call site each stub serves is inferred from its jump target,
  not proven.

## Reproduction

Run from the repository root with the node artifact materialized
as `work/hl-node-115.bin` (SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`):

```
python3 tools/u64ts_name_factory115.py --verify --binary work/hl-node-115.bin
python3 -m pytest tests/test_u64ts_name_factory115.py -q
python3 tools/verify_packets.py
```

Environment limits (stated honestly): no cargo/rustc/git-lfs/Ghidra
on this VM, so `make verify` / `make test` / `make catalogue-check`
in a tooled environment were not run; the checks above are the
offline Python verification for this packet. The `.hex` files are
the raw FDE bytes and the `.objdump.txt` files are whole-function
verbatim objdump output (GNU objdump 2.42) with repo-relative
binary paths.
