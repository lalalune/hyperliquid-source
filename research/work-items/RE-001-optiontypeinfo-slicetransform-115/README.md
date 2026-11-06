# RE-001: node #115's OptionTypeInfo::AsCustomSharedPtr<SliceTransform> record

## Bounded question

How does node #115 build the OptionTypeInfo record for a custom
shared_ptr SliceTransform option, and how do the record's two
create hooks resolve that option by name?

## Answer (pinned)

- **Builder** (`0x6083a90`, 499 bytes): `rocksdb::OptionTypeInfo::
  AsCustomSharedPtr<const SliceTransform>(offset, verification,
  flags)` fills a 0xb8-byte record: offset at +0x00 (esi), 16 zero
  bytes at +0x08, the create-hook pair at +0x18/+0x20, zeroes at
  +0x28..+0xa8, type 22 at +0xa8, verification at +0xac (edx),
  flags at +0xb0 (ecx). The hooks are the std::function manager
  `0x607d190` and the invoker `0x60809e0`, copied from the GOT
  RELATIVE slots 0x64eda68/0x64edb70 — link-time constants, not
  computed. The builder first fills an identical record as a stack
  temporary at rsp+0x20 and installs it into out with the
  record-copy helper `0x5e332c0` (site 0x6083b76). The +0x04
  padding dword is never written by the builder or the copy
  helper. After the copy, the builder destroys the stack functor
  (manager op 3, site 0x6083b90) and each of the temporary record's
  five std::function members in turn (manager op 3, sites
  0x6083c19/0x6083c00/0x6083be7/0x6083bce/0x6083baf); every one is
  a proven no-op because the lambda captures nothing and the other
  members are zero. The record destructor `0x5d3f950` runs ONLY on
  the landing pad (site 0x6083c55), not on the normal path. This
  differs from the SystemClock sibling builder `0x5fd0180` (open
  PR #3715), whose normal path calls the record destructor (site
  0x5fd0285) and emits no per-member op-3 calls: the SliceTransform
  builder inlines the destructor's member destroys.
- **Copy helper** (`0x5e332c0`, 655 bytes): OptionTypeInfo
  copy-assignment, pinned by open PR #3715 and cited here by
  contract. Copies the 4-byte offset, then for each of the five
  std::function members at +0x08/+0x28/+0x48/+0x68/+0x88 zeroes
  the destination member, clones it through the source member's
  manager with op 2 when the manager is non-null, and copies the
  manager+invoker pair; then copies type+verification (8 bytes at
  +0xa8) and flags (4 bytes at +0xb0). Shared by every
  OptionTypeInfo installer in the binary (91 direct call sites,
  including this builder's site 0x6083b76 and the SystemClock
  builder's site 0x5fd0266).
- **Manager** (`0x607d190`, 45 bytes): the std::function manager
  for the lambda. Op 0 (get_type_info) writes the typeinfo object
  0x64d3018; op 1 (get_functor_ptr) copies the functor pointer;
  ops 2 (clone), 3 (destroy) and anything else return 0 without
  touching memory. It has no direct call site: it is reached only
  through the GOT slot 0x64eda68 and the copy helper's indirect
  manager call. Pinned here for the first time.
- **Invoker** (`0x60809e0`, 145 bytes): the std::function _M_invoke
  for the lambda. When the id-string (rcx) has length 2 and starts
  with "id" (word 0x6469) and the name-string (r8) is empty, it
  releases the shared_ptr at *(dest_slot) — zeroing the slot and
  calling _M_release 0x5d350c0 (site 0x6080a51) — writes an empty
  Status and returns. Unlike the Statistics invoker, it does not
  inline the packed fast path; that lives inside _M_release,
  pinned by open PR #3674. Otherwise it forwards to the
  create-by-name host `0x61ca3d0` with (out, config_options,
  name_string, *dest_slot).
- **Create host** (`0x61ca3d0`, 4108 bytes): the create-by-name
  host for the SliceTransform option. It runs pthread_once over
  the once control 0x6508928 with the initializer `0x61ccfa0`
  (via __once_proxy, TLS __once_callable 0x64ed818 / __once_call
  0x64ed820), then the registry translator `0x609e510` (site
  0x61ca53b; by contract, open PR #3440): translator Status code
  != 0 moves to out; code == 0 with an empty translated name
  releases *dest_slot and writes an empty Status; code == 0 with
  a non-empty translated name calls the registry find `0x61c9d70`
  (site 0x61ca580) with (out std::function at rsp+0x110,
  config_options+0x40, key = the translated-name string). If no
  factory is found (manager at rsp+0x120 null), the host builds
  an error Status code 3 with ("Could not load SliceTransform",
  translated name) via the Status builder `0x61cf670` (site
  0x61cafbc). If a factory is found, the host invokes it through
  its invoker (indirect call *0x128(%rsp), site 0x61ca5fc) with
  (functor at rsp+0x110, translated-name string, object out-slot
  at rsp+0xa0 pointing at rsp+0x58, detail out-string at rsp+0x90
  pointing at rsp+0x130). The create outcomes: factory returns
  null with a non-empty detail string -> error Status code 4
  with (detail string, translated name) (site 0x61cb05c);
  factory returns null with an empty detail string -> error
  Status code 4 with ("Could not load SliceTransform", translated
  name) (site 0x61cabc8); factory returns non-null but the object
  slot is null -> error Status code 4 with ("Cannot make a shared
  SliceTransform from unguarded one ", translated name) (site
  0x61cae1b); factory returns non-null with an object -> install:
  allocate a 0x18-byte control block via _Znwm (site 0x61ca696),
  packed counts 0x100000001 from the global at 0x459b20, table
  0x64d7878+0x10 = 0x64d7888 (the _Sp_counted_ptr<const
  SliceTransform*, _S_atomic> table), install {object, control}
  into *dest_slot, release the old dest control, write an empty
  Status. Status normalization (0x61ca7ae): code 3 with
  config_options+1 != 0 resets the intermediate Status to empty;
  code 0 calls the second translator `0x609e2d0` (site 0x61ca9c9;
  by contract), then moves the result out; any other code moves
  the intermediate Status out unchanged. The host has two direct
  callers: the invoker (site 0x6080a10) and a direct
  options-parser caller (site 0x6120761, FDE
  0x611fb10..0x61213db).
- **Registry find** (`0x61c9d70`, 2805 bytes): locates the
  "SliceTransform" type node in the registry and copies the
  matching entry's create functor into out. It locks the mutex at
  registry+0x98 (site 0x61c9dad) for the whole lookup, builds the
  literal "SliceTransform" (14 bytes, movabs sites 0x61c9ded/
  0x61c9e00), and walks the bucket vector [registry+0x0,
  registry+0x8) backwards by 0x10, locking each bucket's lock at
  bucket-0x10 (site 0x61c9de0). With a bucket count (bucket+0x40)
  <= 0x14 it scans the list at bucket+0x38 linearly, matching a
  node when its name length (node+0x10) is 0xe and its name data
  equals "SliceTransform" (first 8 then next 6 bytes). Above 0x14
  it hashes the literal with _Hash_bytes("SliceTransform", 14,
  0xc70f6907) (site 0x61c9fe5) and walks the bucket hash % table
  size (table at bucket+0x28, size at bucket+0x30), matching on
  stored hash % size, stored hash, name length and memcmp. On a
  type-node match it scans the entries [node+0x28, node+0x30),
  calling each entry's vtable slot 0x10 with (entry, key) (site
  0x61c9e96); on true it copies the entry's create functor at
  entry+0x20 into out (manager op-2 clone, site 0x61c9ed5, then
  the 16-byte copy, then op-3 destroy of the temp). If no bucket
  matches and the parent registry at registry+0x60 is non-null,
  it recurses into the parent (self-call site 0x61c9f32); if the
  parent is null, out is zeroed. Its callers are the self-recursion
  and the create host (site 0x61ca580).
- **Default initializer** (`0x61ccfa0`, 123 bytes): the pthread_once
  initializer the host passes by lea (site 0x61ca450). Builds an
  empty std::string at rsp+0x10, calls the registry-mutex getter
  `0x61f8b60` (site 0x61ccfd0), then the register helper `0x61cbd50`
  (site 0x61ccfd8) with the dereferenced pointer, registering the
  default SliceTransform(s). It has no direct call site: it is
  reached only through __once_proxy. The registry structure and
  the helper internals are open.
- **Installers**: the builder's two direct callers, both in the
  options-table construction function FDE 0x6089b50..0x6091e5c
  (not pinned): site 0x608d894 installs with offset 0x40,
  verification 2, flags 0x1100, then assigns the name
  "prefix_extractor" (literal 0x445493) and inserts the record;
  site 0x6090205 installs with offset 0xc0, verification 2,
  flags 0, then assigns the name
  "memtable_insert_with_hint_prefix_extractor" (literal 0x959c80)
  and inserts the record. The same record shape is installed
  twice with different offsets/flags — two different option
  fields.

## Census correction

The GOT-resolved hooks prove **SliceTransform (const)**, not
Statistics, FileSystem or SystemClock: the manager's kind-0
typeinfo name at 0x976100 is the `AsCustomSharedPtr<const
SliceTransform>` lambda, the invoker calls the SliceTransform
create host 0x61ca3d0, whose registry find looks up the
"SliceTransform" type node, and whose install wraps the created
object in a _Sp_counted_ptr<const SliceTransform*, _S_atomic>
control block (typeinfo name at 0x97e600). The builder shares the
record field map with the Statistics builder 0x6071520 (open PR
#3685) and the SystemClock builder 0x5fd0180 (open PR #3715) —
same 0xb8-byte record, same type 22, same hook-pair layout — and
shares the SystemClock builder's copy-helper install shape, but
differs from it in cleanup (six explicit manager op-3 destroys
instead of a normal-path record-destructor call). There is exactly
one copy of each window body in the binary: the only qword hits
for the manager/invoker are the .rela.dyn addend fields of their
own GOT slots (file offsets 0x15e428 / 0x15e740), and no RELATIVE
entry points at a window.

## Target

Node #115 binary `work/hl-node-115.bin`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`, `artifacts/node/115/hl-node`).

## Evidence

- `builder-6083a90.objdump.txt`, `manager-607d190.objdump.txt`,
  `invoker-60809e0.objdump.txt`, `host-61ca3d0.objdump.txt`,
  `find-61c9d70.objdump.txt`, `init-61ccfa0.objdump.txt` —
  whole-function objdump excerpts, verbatim as objdump emitted
  them. Generated by `export_excerpts.py` with:
  `objdump -d --start-address=<start> --stop-address=<stop> work/hl-node-115.bin`
  (run from the repository root; GNU objdump 2.42). The mnemonics
  in the excerpts — `endbr64` included — are genuine instructions
  present in the target binary, not placeholders.
- `records.json` — semantic records only: the builder field map,
  the copy helper (by contract), the manager op dispatch, the
  invoker's two paths, the create host's translator/find/create
  dispatch with its three code-4 error arms, the registry find's
  type-node match, entry scan, parent recursion and miss, the
  once initializer, the two installers, the sibling note, the
  control table, the literals and the open unknowns. No
  per-instruction mnemonic list.
- `frames.txt` — the six window FDEs from objdump --dwarf=frames.
- `callers.tsv` — the 97 direct call sites (2 builder, 2 host,
  2 find, 91 copy-helper), each verified as a real call in its
  containing FDE. The manager and invoker have no direct call
  sites (GOT-slot only); the initializer has none (pthread_once
  only).
- `relocations.txt` — the two hook GOT slots, the lambda typeinfo
  relocations, the control-block table relocations, the once/TLS
  relocations, and why no RELATIVE entry points at a window.
- `verify.py`, `census.py`, `export_excerpts.py`, `gen_records.py`
  — the packet's own runnable checks and generators.
- `MANIFEST.sha256` — SHA-256 of every packet file.

## Environment limits

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so the
repo gates (`make verify`, `make test`, `make catalogue-check`)
could not be run here; the packet is validated only by its own
`verify.py` (digest, manifest, excerpt regeneration, byte-for-byte
gate spots, frames, census reproduction, relocations, literals and
the model tests). The model in `tools/optiontypeinfo_slicetransform_115.py`
and its tests in `tests/test_optiontypeinfo_slicetransform_115.py` are
the executable form of the pinned behaviour.

## Open unknowns

See `records.json` "unknowns": the enum spellings for verification
2 / flags 0x1100 and 0 used by the two installing call sites; the
semantic names of the invoker's two string args beyond their
observed roles; the control-table slot +0x00/+0x08 attributions;
the registry structure and the 0x61f8b60 / 0x61cbd50 helper
internals; the translator 0x609e510's stack struct layout and the
second translator 0x609e2d0's contract; the config_options+1
byte's meaning; the create functor's exact signature; whether the
"id" fast path means "reset to default" or "release and return
empty" in the caller's terms; the host's landing-pad stubs and
LSDA call-site tables; whether the second install site's name is
the record's option name (positional association only).
