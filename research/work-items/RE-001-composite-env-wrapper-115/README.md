# RE-001: CompositeEnvWrapper construction and destruction end-to-end (node #115)

Task ID: **RE-001**. Bounded question: what does node #115's
`CompositeEnvWrapper` do when it is built, used through its vtable,
and destroyed — which routines, in which order, with which
observable effects?

This packet resolves the open unknowns carried by PR #3948 (the
CompositeEnv builder 0x5fd7360, the holder initializer 0x5fe2860
full body, the factory control-block dispose/destroy, the node
vtable slot 2).

## Evidence

Target: `work/hl-node-115.bin`, node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(from `provenance/artifacts.json`).

40 verbatim objdump excerpts (whole functions, one file per
window), generated with:

```
objdump -d --start-address=<start> --stop-address=<stop> work/hl-node-115.bin
```

The mnemonics in these excerpts (including `endbr64`) are genuine
instructions present in the target binary, not placeholders.
Instruction-level detail lives only in the excerpts; `records.json`
holds semantic records only.

- `builder-5fd7360.objdump.txt` — the builder 0x5fd7360.
- `install-5fceb20.objdump.txt` — the install helper 0x5fceb20.
- `string-init-5fd5cc0.objdump.txt` — the std::string default ctor.
- `wrapper-d2-5fd72d0.objdump.txt`, `wrapper-d0-5fd7510.objdump.txt`,
  `basedtor-5fcf4d0.objdump.txt` — the destructors.
- `wslot5-5fd7560.objdump.txt`, `wslot12-5fd5e00.objdump.txt`,
  `wslot14-5fd4e60.objdump.txt`, `wslot16-5fd6240.objdump.txt`,
  `wslot17-5fd4e70.objdump.txt` — the wrapper vtable overrides.
- `fwd-*.objdump.txt` (20 files) — the forwarder slots 45–52, 59,
  63–69, 71, 79–81.
- `holder-init-5fe2860.objdump.txt` — the default holder initializer.
- `node-slot2-5fcc7e0.objdump.txt` — the FactoryEntry node slot 2.
- `cb-dispose-6025950.objdump.txt`, `cb-destroy-6025b90.objdump.txt`
  — the factory control-block dispose/destroy.
- `helper-5fcf390.objdump.txt`, `accessor-5fcf430.objdump.txt`,
  `invoker-composite-5fcf450.objdump.txt`, `append-6099ce0.objdump.txt`,
  `grow-6099790.objdump.txt` — shared helpers; the last four are
  re-shipped byte-identical from the
  RE-001-systemclock-installers-115 packet (open PR #3948), with
  SHA-256 values recorded in `records.json`.

`census.py` reproduces the call/jump/lea census (2297 caller rows in
`callers.tsv`, 186 RELATIVE records in `relocations.txt`,
`frames.txt` with the 40 FDE ranges). `gen_records.py` builds
`records.json` from those outputs. `verify.py` re-derives every
pinned value from a fresh objdump/readelf/census run and from the
raw binary, and runs the model tests; it prints `ALL CHECKS PASSED`
on success.

## What is pinned

- **Layout.** The wrapper is 0x60 bytes: vtable +0x00, options
  vector +0x08..+0x18, shared_ptr A +0x28/+0x30, shared_ptr B
  +0x38/+0x40, wrapped Env\* +0x48, shared_ptr C +0x50/+0x58.
- **Builder 0x5fd7360** `(this, wrapped_env, sp_a_slot, sp_b_slot)`:
  calls the install helper, stores the wrapped env at +0x48, zeroes
  shared_ptr C, installs the wrapper vtable, appends three
  empty-named records `{"", this+0x48, 0x6504c60}`,
  `{"", this+0x28, 0x6504c20}`, `{"", this+0x38, 0x6504be0}`.
  Exactly 2 callers: the CompositeEnv invoker 0x5fcf450 and the
  MockEnv ctor 0x60289f0.
- **Install 0x5fceb20**: installs the Env vtable, zeroes
  +0x08..+0x20, copies both shared_ptrs with a selector-gated
  use-count bump (byte at 0x64ed290: 0 selects `lock addl`,
  non-zero selects plain `addl`).
- **Destructors.** Wrapper D2 releases +0x58, installs the
  CompositeEnv vtable, tail-jumps to the base D2. Wrapper D0 calls
  the base D2 and does `operator delete 0x60`. Base D2 releases
  +0x40 then +0x30, installs the Configurable vtable, destroys the
  options vector. Reached by 5 calls and 3 tail jumps (including
  the MockEnv D2/D0 and the TSU atexit dtor).
- **Slot 5 PrepareOptions 0x5fd7560**: resolves the target's wrapped
  env (shared_ptr C object, else +0x48, else the default holder),
  lazily copies the wrapped env's +0x28/+0x38 shared_ptrs in,
  then calls the base PrepareOptions 0x6095e70.
- **Slot 12 SerializeOptions 0x5fd5e00**: calls the base 0x609de80,
  then appends `"target="` plus the wrapped env's serialization
  when the wrapped env is non-null and is not the default holder.
- **Slot 14** returns `"CompositeEnv"`; **slot 16** returns 1 iff
  the arg string is exactly `"CompositeEnv"` (length 12), else the
  base 0x5d2e770; **slot 17** returns `this+0x48`.
- **20 forwarders**: jmp-form loads `this+0x48` and tail-jumps to
  the wrapped env's same slot; call-form loads `arg+0x48`, calls
  the wrapped env's same slot, and returns `this`. The dispatch
  offset is always slot\*8.
- **Vtables** (85 slots each): Env `N7rocksdb3EnvE`, CompositeEnv
  `N7rocksdb12CompositeEnvE` (nulls at 0, 1, 46, 48, 59, 63, 64,
  66), CompositeEnvWrapper `N7rocksdb19CompositeEnvWrapperE` (no
  nulls), MockEnv `N7rocksdb7MockEnvE` (differs from the wrapper in
  slots 0, 1, 14 only). The wrapper differs from CompositeEnv in
  27 slots.
- **Holder initializer 0x5fe2860** (17 call sites): guard 0x6504ca8,
  returns &0x6504cc0; builds the holder via the install helper, a
  4-entry record array, a `"mutex_init"` mutex, and a 0xd8-byte
  ThreadStatusUpdater (field map pinned), registers `__cxa_atexit`.
- **Node slot 2 0x5fcc7e0**: forwards `this+0x08`'s vtable slot 2.
- **Control block** (`_Sp_counted_ptr_inplace<EmulatedSystemClock>`):
  dispose 0x6025950 tail-jumps to the managed object's slot 0;
  destroy 0x6025b90 is `operator delete 0x60`.
- **Shared_ptr release** (`_M_release` 0x5d350c0, 1273 calls, 25
  jumps; dispose tail 0x5d35070, 654 calls, 36 jumps): fast path at
  counts (1, 1), otherwise selector-gated decrement and the
  dispose tail.

The Python model is `tools/composite_env_wrapper_115.py` with tests
in `tests/test_composite_env_wrapper_115.py` (246 checks, run with
`python3 tests/test_composite_env_wrapper_115.py`).

## Environment limits

This VM has no cargo/rustc, no git-lfs, no Ghidra/Java, so the
repository's `make verify test catalogue-check` gates cannot be run
here. `verify.py` is the packet's own check and runs fully offline
against the retained node #115 binary. The model tests are not a
substitute for the repo gates; they pin the reconstructed semantics
against the binary evidence in this packet.

## Unknowns (kept separate)

- Record third fields 0x6504c60/0x6504c20/0x6504be0 are in .bss
  (runtime-initialized); their contents are not statically
  determinable.
- Holder-init callees 0x61d2ca0, 0x61c21b0, 0x61d4570, 0x61d4740,
  0x61d4730, 0x61d4420 and the PosixFileSystem holder accessor
  0x60029f0 internals are by contract, not excerpted.
- ThreadStatusUpdater methods are not excerpted; only its
  construction-time field map is pinned.
- The full MockEnv slot map beyond slots 0, 1, 14 (shared with the
  wrapper) is open; MockEnv's own D2/D0/Name bodies are not
  excerpted.
- Configurable vtable slots beyond 0–7 are open.
- The preceding vtable's last slot at 0x64ce2c0 → 0x5fd5360
  (forwards `this+0x08`'s slot 5) is a boundary observation, not in
  this packet.
- Slot 61 (0x5fd5f10) is cited only, not excerpted.
- The `"Environment"` string at 0x44a397 is part of the "Cannot make
  a shared Environment from a guarded one" error text; the Env
  create-host registry is a separate work item.
- The slot-12 first argument is the output string as observed in the
  binary; no C++ signature is asserted beyond that.
