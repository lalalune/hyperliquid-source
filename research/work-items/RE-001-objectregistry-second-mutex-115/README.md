# RE-001: pin node #115 the ObjectRegistry's second mutex (objects_mutex_ +0x70..0x98) and the complete lock discipline of both registry mutexes

## Question

Answer #4015's open unknown — what is the 40-byte region at
ObjectRegistry `+0x70..0x98` — and pin the complete lock discipline of
the registry's two mutexes: who locks which one, who never locks, and
who (never) destroys them.

## Answer

The region is the registry's **second `std::mutex`, `objects_mutex_`**
(a 40-byte `pthread_mutex_t`), guarding the `+0x30`
`managed_objects_` map. The `+0x98` mutex is **`library_mutex_`**,
guarding `libraries_`. `objects_mutex_` is never locked, read, written
or destroyed by any code in this binary: the managed-object methods
that would lock it (`SetManagedObject`, `GetManagedObject`,
`ListManagedObjects`) are absent from the binary, and the whole-binary
census finds no `+0x70` lock, read or write in any registry-referencing
function. Both mutexes are zero-initialized by the ctor/clone and
never destroyed — the binary's only `pthread_mutex_destroy` call site
is elsewhere, in a helper called from 74 non-registry sites.

## What this packet pins

- The registry layout (0xc0 bytes, re-shipped from #4015 with the two
  open fields now identified): libraries vector `+0x00`, names vector
  `+0x18` (upstream name `plugins_`), `managed_objects_` map `+0x30`
  (`std::map<std::string, std::weak_ptr<Customizable>>`, 0x50-byte
  nodes), parent shared_ptr `+0x60`, `objects_mutex_` `+0x70..0x98`,
  `library_mutex_` `+0x98..0xc0`.
- `objects_mutex_` (`+0x70`, 40 bytes): the ctor zeroes it with
  `movups +0x70`, `movups +0x80`, `movq +0x90` — the identical 16+16+8
  pattern the ctor uses for the `+0x98` mutex (`movups +0x98`,
  `movups +0xa8`, `movq +0xb8`). The clone zeroes it the same way
  (`movups +0x80/+0x90` on the block, `movq +0xa0` for `+0x90`). The
  dispose never touches it (nor the `+0x98` mutex): its order is
  parent, map tree, names vector, libraries vector.
- `library_mutex_` (`+0x98`, 40 bytes): locked by exactly three
  routines, all of which mutate `libraries_` — `AddLibrary`
  (`lea 0x98(%rbp),%r14`; lock `0x61f8f09`, unlock `0x61f8f4f`),
  the big registry method `0x5ff88c0` (`lea 0x98(%rbx)`; lock
  `0x5ff8a28`, unlock `0x5ff8a7b`), and the TTL registration
  (`lea 0x98(%rbp),%r15`; lock `0x6206b73`, unlock `0x6206bb4`).
  Each locks, appends to the libraries vector, unlocks.
- The whole-binary lock census (one streaming objdump pass; 135,313
  FDEs): 1,632 pthread-mutex PLT call sites (lock 224, unlock 916,
  trylock 487, init 4, destroy 1). The 8 sites with a `+0x70`
  displacement (5 lock, 3 unlock) sit in 5 FDEs, all other classes'
  mutexes — a TableCache-area routine (`0x5f44c80`), a cache routine
  (`0x5f44db0`), two list-hook helpers (`0x606a450`, `0x606a900`),
  and a routine whose object carries a flag byte at `+0x98` and a
  mutex at `+0x70` (`0x606a650`). The 28 sites with a `+0x98`
  displacement include the 6 registry sites above and 22 other
  classes' `+0x98` mutexes (`ObjectLibrary`'s `mu_` and
  Env/Statistics-area mutexes); none of the 22 is in a
  registry-marked FDE.
- The displacement census: 32 registry-marked FDEs (functions that
  call a registry routine or `lea` a registry global), 216
  instructions with displacements `0x70..0x97` inside them. Every
  non-stack hit is resolved: the ctor/clone zeroing, the
  `ObjectLibrary` name-string SSO init at block `+0x70` (TTL
  `0x6206ad7..0x6206b42`, big method `0x5ff8962..0x5ff89e4`), the
  Options-struct field copies in `0x611fb10` (read before the
  `NewInstance` call at `0x612073b`), the vtable indirect call
  `*0x78(%rax)` in `0x61c8370`, the clone's block `+0x70` store
  (object `+0x60`, the parent shared_ptr), and the dispose's block
  `+0x78` read (object `+0x68`, the parent control block). After
  resolving them, no function reads or writes registry `+0x70..0x98`
  except the ctor and clone zeroing it.
- The destroy census: the binary's only `pthread_mutex_destroy` call
  is at `0x60d5189`, inside helper `0x60d5170` (`0x60d5170..0x60d5200`,
  the `std::mutex`-destructor helper). The helper has 74 callers; none
  passes a `+0x70` or `+0x98` displacement, and none is in a
  registry-marked FDE. The dispose `0x61f8760` never calls the helper
  (verified in its excerpt). The 4 `pthread_mutex_init` sites
  (`0x5fe2a3e`, `0x60d50dc`, `0x63bf8d9`, `0x63bfa21`) are all
  non-registry: both registry mutexes are zero-initialized, never
  `pthread_mutex_init`'d.
- The absence of the managed-object methods: the exact strings
  `"Object already exists: "` (the `SetManagedObject` error) and
  `"Registered Plugins:"` (`Dump`) do not occur in the binary. The
  binary's only case-insensitive `"managed"` string (file offset
  `0x95f620`) is the unrelated RocksDB iterator error message
  `"Managed iterator is not supported anymore."`. The getter has
  exactly the 3 known callers (`0x5ff88fc`, `0x61f9420`, `0x6206a3d`).
- Relocations: the 7 mutex PLT/GOT records (`pthread_mutex_lock` /
  `unlock` `GLOB_DAT` + `JUMP_SLOT`, `init` / `destroy` / `trylock`
  `JUMP_SLOT`) and the 24 control-block vtable-region records
  (re-shipped from #4015's 20 `RELATIVE` records plus the 4
  `R_X86_64_64` typeinfo-pointer records in the same span).
- Source corroboration: the member names and guard roles come from
  the upstream `object_registry.cc`, stable across the bracketing
  versions — RocksDB 7.8.3 (electrs-librocksdb-sys 0.9.0-e3+7.8.3)
  and 9.10.0 (ckb-librocksdb-sys 9.10.0) both show `objects_mutex_`
  guarding `managed_objects_` and `library_mutex_` guarding
  `libraries_`. The 8.1.1 header 404s on raw.githubusercontent.com,
  so the 8.1.1 declaration order itself is not directly confirmed;
  the binary identification rests on size (40 = `pthread_mutex_t`),
  identical zeroing, identical dispose treatment, the `+0x98`
  lockers proving `library_mutex_`, and elimination for `+0x70`.

## Corrections to #4015

- The `+0x70..0x98` region is `objects_mutex_`, a second `std::mutex`
  (40-byte `pthread_mutex_t`) — not "possibly a second mutex or plain
  data".
- The `+0x98` field is `library_mutex_`, the mutex guarding
  `libraries_` — its locker set is exactly `AddLibrary`, the big
  registry method `0x5ff88c0`, and the TTL registration.
- The `+0x30` map is `managed_objects_`
  (`map<string, weak_ptr<Customizable>>`), guarded by
  `objects_mutex_`.
- The `+0x18` vector's upstream name is `plugins_`
  (`vector<string>`); the binary shows `AddLibrary` appending the
  name there.
- Neither mutex is destroyed: the dispose never calls the
  mutex-destructor helper, and the binary's only
  `pthread_mutex_destroy` site is elsewhere.

## Evidence

- `records.json` — semantic records only (layout, both mutexes, the
  lock/destroy/init/displacement censuses, relocations, source
  corroboration, corrections, open unknowns). No per-instruction
  mnemonic list: instruction-level detail lives only in the verbatim
  objdump excerpts.
- `*.objdump.txt` — 12 whole-function verbatim excerpts (GNU objdump
  2.42). The ctor, clone, dispose, `AddLibrary`, TTL registration and
  big-method excerpts are byte-identical to the ones shipped by #4015
  / #4028, re-shipped with credit; the destroy-helper and five
  `+0x70`-lock excerpts are new.
- `frames.txt` — the 13 FDEs (12 windows + the getter).
- `lock-sites.tsv` — all 1,632 mutex PLT call sites with FDE and
  `%rdi` source; `destroy-sites.tsv` — the 74 destroy-helper call
  sites; `disp-hits.tsv` — the 216 displacement hits;
  `marked-fdes.txt` — the 32 registry-marked FDEs; `callers.tsv` —
  the 113 sites the claims rest on (36 `+0x70`/`+0x98` lock/unlock
  sites, 74 destroy-helper calls, 3 getter calls).
- `relocations.txt` — the 31 relocation records above.
- `census.py`, `export_excerpts.py`, `gen_records.py`, `verify.py` —
  the generators and the checker (see `verify.py` for the check list).
- `tools/objectregistry_second_mutex_115.py` +
  `tests/test_objectregistry_second_mutex_115.py` — the Python model
  (29 checks) covering the two-mutex layout, the identical zeroing,
  the lock discipline (library ops require the library lock;
  `objects_mutex_` is never acquired), the dispose order, the absent
  managed-object methods, and the census constants.

## Verification

`python3 research/work-items/RE-001-objectregistry-second-mutex-115/verify.py`:
ALL CHECKS PASSED (digest vs provenance, manifest, excerpt
regeneration byte-for-byte, fixed samples + 3 seeded random gate spots
byte-for-byte vs fresh objdump and the raw binary, frames, census
reproduction, model constants, relocations, absent-string checks, 28
model tests).

Note the mnemonics in the excerpts (e.g. `endbr64`) are genuine
instructions present in the target binary, not placeholders: every
excerpt regenerates byte-for-byte from a fresh objdump run, and the
gate spots are verified byte-for-byte against the raw binary as well.

## Open unknowns

- The 8.1.1 header itself was not read (404 on the raw URL); the
  member names rest on the 7.8.3/9.10.0 bracket plus binary
  elimination.
- Whether the managed-object methods exist in the 8.1.1 source but
  were stripped at link time, or were never referenced: the binary
  cannot distinguish these.
- The exact identities of the five `+0x70`-locking classes (named by
  code area only).
- A hypothetical free function taking the registry as its second
  argument and locking `+0x98` would escape the registry-marker
  filter; no such function exists in the upstream source (all locking
  sites are methods), so this is a source-backed exclusion, not a
  binary proof.

## Environment limits

This VM has no cargo/rustc, no git-lfs, no Ghidra/Java, so the repo
gates (`make verify`, `make test`, `make catalogue-check`) cannot run
here; the packet's own `verify.py` and the model tests are the checks
that ran. The packet is evidence + a Python model, not a Rust
reconstruction, so it does not touch those gates.
