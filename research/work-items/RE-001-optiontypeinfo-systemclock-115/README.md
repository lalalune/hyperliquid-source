# RE-001: node #115's OptionTypeInfo::AsCustomSharedPtr<SystemClock> record

## Bounded question

How does node #115 build the OptionTypeInfo record for a custom
shared_ptr SystemClock option, and how do the record's two create
hooks resolve that option by name?

## Answer (pinned)

- **Builder** (`0x5fd0180`, 370 bytes): `rocksdb::OptionTypeInfo::
  AsCustomSharedPtr<SystemClock>(offset, verification, flags)` fills
  a 0xb8-byte record: offset at +0x00 (esi), 16 zero bytes at
  +0x08, the create-hook pair at +0x18/+0x20, zeroes at +0x28..+0xa8,
  type 22 at +0xa8, verification at +0xac (edx), flags at +0xb0
  (ecx). The hooks are the std::function manager `0x5fcc660` and
  the invoker `0x5fd4c30`, copied from the GOT RELATIVE slots
  0x64ed8d0/0x64ed958 — link-time constants, not computed. The
  builder first fills an identical record as a stack temporary at
  rsp+0x20 and installs it into out with the record-copy helper
  `0x5e332c0` (site 0x5fd0266). The +0x04 padding dword is never
  written by the builder or the copy helper. After the copy, the
  builder destroys the temporary's functor (manager op 3, site
  0x5fd0280) and the temporary record (record dtor 0x5d3f950, site
  0x5fd0285); both are proven no-ops because the lambda captures
  nothing and the other functor members are zero.
- **Copy helper** (`0x5e332c0`, 655 bytes): OptionTypeInfo
  copy-assignment. Copies the 4-byte offset, then for each of the
  five std::function members at +0x08/+0x28/+0x48/+0x68/+0x88
  zeroes the destination member, clones it through the source
  member's manager with op 2 when the manager is non-null, and
  copies the manager+invoker pair; then copies type+verification
  (8 bytes at +0xa8) and flags (4 bytes at +0xb0). Shared by every
  OptionTypeInfo installer in the binary (91 direct call sites,
  including the SliceTransform sibling builder's site 0x6083b76).
  The Statistics sibling builder 0x6071520 (open PR #3685) does
  NOT call it: it copies field-wise and calls the manager directly
  instead.
- **Manager** (`0x5fcc660`, 45 bytes): the std::function manager
  for the lambda. Op 0 (get_type_info) writes the typeinfo object
  0x64cda00; op 1 (get_functor_ptr) copies the functor pointer;
  ops 2 (clone), 3 (destroy) and anything else return 0 without
  touching memory. It has no direct call site: it is reached only
  through the GOT slot 0x64ed8d0 and the copy helper's indirect
  manager call. Pinned here for the first time.
- **Invoker** (`0x5fd4c30`, 145 bytes): the std::function _M_invoke
  for the lambda. When the id-string (rcx) has length 2 and starts
  with "id" (word 0x6469) and the name-string (r8) is empty, it
  releases the shared_ptr at *(dest_slot) — zeroing the slot and
  calling _M_release 0x5d350c0 (site 0x5fd4ca1) — writes an empty
  Status and returns. Unlike the Statistics invoker, it does not
  inline the packed fast path; that lives inside _M_release,
  pinned by open PR #3674. Otherwise it forwards to the
  create-by-name host `0x5fd46c0` with (out, config_options,
  name_string, *dest_slot).
- **Create host** (`0x5fd46c0`, 1390 bytes): loads the current clock
  via the accessor 0x5fe2680 (site 0x5fd46f4) and bumps its use
  count (0x64ed290 atomicity selector). Name dispatch: vtable slot
  0x80 vs the global 0x64eceb8 (RELATIVE -> 0x5d2e770, the default
  name predicate, FDE 0x5d2e770..0x5d2e832 — returns true when the
  input name is non-empty and equals the slot-0x70 name or the
  slot-0x90 name) — when they differ, slot 0x80 (current, name)
  decides; an empty name goes to the default path; slot 0x70's name
  matching the input adopts the current clock; slot 0x90 vs the
  global 0x64eceb0 (RELATIVE -> 0x5d2ca10, the default second-name
  getter, FDE 0x5d2ca10..0x5d2ca1c: 7 bytes returning the empty
  string at 0x4376fd) — when they differ, slot 0x90's name matching
  adopts.
  The adopt path installs the current clock into *dest_slot
  (releasing the old control when it differs) and writes an empty
  Status. The default path runs pthread_once (once control
  0x6504b68, initializer 0x5fd20d0), then the registry translator
  0x609e510 (by contract, open PR #3440): translator Status code
  != 0 moves to out; code == 0 with a non-empty translated name
  calls the factory helper 0x5fd4080 (by contract) then normalizes
  the Status (code 3 + config_options+1 != 0 resets it to empty;
  code 0 calls the second translator 0x609e2d0, by contract);
  code == 0 with an empty name and a non-null error out-param
  builds an error Status (code 3, "Cannot reset object " + name)
  via 0x61cf670 (by contract); code == 0 with an empty name and a
  null error releases *dest_slot and writes an empty Status.
- **Accessor** (`0x5fe2680`, 214 bytes): function-local-static
  accessor for the current SystemClock shared_ptr (guard
  0x6504c98, static 0x6504ca0). The slow path allocates the
  0x10-byte control block and the 0x30-byte combined allocation:
  the control block holds table 0x64ced00 and the packed counts
  0x100000001 (use 1, weak 1, copied from the global at 0x459b20),
  and the PosixClock object at +0x10 holds table 0x64ce930. The
  object table resolves (RELATIVE 0x64ce928) to the typeinfo at
  0x64ce870, `rocksdb::(anonymous)::PosixClock`; the control table
  resolves (RELATIVE 0x64cecf8) to `_Sp_counted_ptr_inplace<
  PosixClock, ...>`. Called from 189 sites across the node; only
  the create host's use is pinned in detail here.
- **Default initializer** (`0x5fd20d0`, 333 bytes): the pthread_once
  initializer the host passes by lea (0x5fd47c1). Builds the
  "TimeEmulatedSystemClock" string, allocates the 0x30-byte
  registry entry and the 0x70-byte clock object (table
  0x64d8ec0+0x10, byte +0x48 = 1), and registers it under the name
  "SystemClock" via the registry helper 0x5fd1da0 under the mutex
  from 0x61f8b60. The registry structure and the helper contracts
  are open.
- **Status move** (`0x5fcdf70`, 111 bytes): Status move-assignment.
  Copies bytes 0..5, zeroes src bytes 1..5 (src byte 0, the code,
  is kept), moves the state pointer at +0x08 (freeing dst's old
  state), returns dst. The create host uses it four times.
- **Installer**: the builder's sole direct caller is 0x5fd1a14 in
  the static initializer FDE 0x5fd19a0..0x5fd1c56 (not pinned),
  installing the record with offset 0, verification 1, flags
  0x2000, then assigning the string "target" (literal 0x44a390).

## Census correction

The GOT-resolved hooks prove **SystemClock**, not Statistics or
FileSystem: the manager's kind-0 typeinfo name at 0x972460 is the
`AsCustomSharedPtr<SystemClock>` lambda, and the invoker calls the
SystemClock create host 0x5fd46c0, whose name dispatch and default
path resolve against the PosixClock current clock. The builder
shares the record field map with the Statistics builder 0x6071520
(open PR #3685) — same 0xb8-byte record, same type 22, same
hook-pair layout — but installs it differently (copy helper vs
field-wise copy). There is exactly one copy of this body in the
binary. The SliceTransform sibling builder 0x6083a90 shares this
builder's install shape and its own GOT-resolved hooks (manager
0x607d190, invoker 0x60809e0; typeinfo name at 0x976100 is the
AsCustomSharedPtr<const SliceTransform> lambda); it is a separate
work item.

## Target

Node #115 binary `work/hl-node-115.bin`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`, `artifacts/node/115/hl-node`).

## Evidence

- `builder-5fd0180.objdump.txt`, `manager-5fcc660.objdump.txt`,
  `invoker-5fd4c30.objdump.txt`, `host-5fd46c0.objdump.txt`,
  `accessor-5fe2680.objdump.txt`, `default-init-5fd20d0.objdump.txt`,
  `status-move-5fcdf70.objdump.txt`, `copy-5e332c0.objdump.txt` —
  whole-function objdump excerpts, verbatim as objdump emitted
  them. Generated by `export_excerpts.py` with:
  `objdump -d --start-address=<start> --stop-address=<stop> work/hl-node-115.bin`
  (run from the repository root; GNU objdump 2.42). The mnemonics
  in the excerpts — `endbr64` included — are genuine instructions
  present in the target binary, not placeholders.
- `records.json` — semantic records only: the builder field map,
  the copy helper, the manager op dispatch, the invoker's two
  paths, the create host's adopt/default dispatch, the accessor's
  combined allocation, the default initializer, the Status move,
  the factory-helper contract, the installer, the sibling note,
  the literals and the open unknowns. No per-instruction mnemonic
  list.
- `frames.txt` — the eight window FDEs from objdump --dwarf=frames.
- `callers.tsv` — the 300 direct call sites (1 builder, 1 host,
  189 accessor, 17 status-move, 91 copy-helper, 1 factory-helper),
  each verified as a real call in its containing FDE. The manager
  and invoker have no direct call sites (GOT-slot only); the
  default initializer has none (pthread_once only).
- `relocations.txt` — the two hook GOT slots, the lambda typeinfo
  relocations, the PosixClock typeinfo relocations, the host's
  sentinel globals, and why no RELATIVE entry points at a window.
- `verify.py`, `census.py`, `export_excerpts.py`, `gen_records.py`
  — the packet's own runnable checks and generators.
- `MANIFEST.sha256` — SHA-256 of every packet file.

## Environment limits

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so the
repo gates (`make verify`, `make test`, `make catalogue-check`)
could not be run here; the packet is validated only by its own
`verify.py` (digest, manifest, excerpt regeneration, byte-for-byte
gate spots, frames, census reproduction, relocations, literals and
the model tests). The model in `tools/optiontypeinfo_systemclock_115.py`
and its tests in `tests/test_optiontypeinfo_systemclock_115.py` are
the executable form of the pinned behaviour.

## Open unknowns

See `records.json` "unknowns": the enum spellings for verification
1 / flags 0x2000; the semantic names of the invoker's two string
args beyond their observed roles; the vtable-header attribution
(typeinfo cells at stored base minus 0x08, verified on five
vtables); the default-init's registry structure; the factory helper
0x5fd4080's internals; the translator 0x609e510's stack struct
layout and the second translator 0x609e2d0's contract; the
config_options+1 byte's meaning; whether the "id" fast path means
"reset to default" or "release and return empty" in the caller's
terms; the "target" string's role in the installer; the host's
landing-pad stubs and LSDA call-site tables.
