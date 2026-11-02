# RE-001-node115-lu-qtable-slot8: what the Q table's slot +0x8 calls

- Component ID: RE-001, `base/src/lu.rs` conversion context pointer (Q table).
- Target release and full SHA-256: node #115, 105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: upstream main
  `8fd8db680ec4bfef40996e5616bce3d5156d0b86` (node-115-only migration).
- Claim status: observation for the table record (4 slots, RELATIVE
  addends), the four slot bodies and their hashes, the state/guard/item
  mechanics of the wake and wake-by-ref twins, the clone/drop bodies,
  the GOT resolutions, the park.rs Location and message, and all census
  counts; inference for the `RawWakerVTable` reading of the table (slot
  order plus role-by-role body match, not a symbol name), for the
  wait/notify labels of the guard helpers (call shapes plus park
  context), and for the park-queue role of `0x5bb42e0` (waiter-list
  shape plus xorshift timeout jitter); unresolved for the Rust type/trait
  names, the full decode of `0x5bb42e0` and the guard helpers, the
  finalizer's `0x28` argument reading, and any static slot-`+0x8` call
  site.
- Scope included and excluded: included — table `0x64c6ef8` (32 bytes,
  4 slots), clone `0x5cfdce0..0x5cfdcf4` (20B, 6 instructions), wake
  `0x5cfd8c0..0x5cfd991` (209B, 61 instructions), wake-by-ref
  `0x5cfd600..0x5cfd6a0` (160B, 48 instructions), drop
  `0x5cfd5e0..0x5cfd5fb` (27B, 9 instructions); the park.rs Location and
  message; GOT resolutions; full census counts. Excluded — #183's
  conversion body, #184's helper body, #185's coop callee and proceed
  function, and #186's consumers, vtables, and drops (all cited, not
  re-claimed); the park-queue function `0x5bb42e0`, the wait/notify
  helpers, and the finalizer (context only, observed call facts).

## Reproduce

Working directory: the repository worktree at the base commit above.
Inputs: `artifacts/node/115/hl-node` (digest above). Tools: GNU objdump
(`objdump -d -M intel --start-address=.. --stop-address=..`), Python 3
with `struct`/`re` for the relocation and census scans, and readelf
(`readelf -r`, `readelf --debug-dump=frames`) for relocations and FDE
records. No execution of the node binary, no network, no disassembler
database: all analysis is static byte and disassembly reading.
Deterministic: the verifier `tools/node115_lu_qtable_slot8.py` re-checks
the digest, all four body hashes and pinned hex files, the table record
with all four RELATIVE addends, all 7 GOT resolutions, the park.rs
Location and message, all 11 table `lea` sites, all 4 `E8` census lists
(0/0/2/6), and both proceed call sites, and exits 0. Declared side
effects: none (read-only).

## Evidence

Original addresses are ELF virtual addresses (PIE). `.text` file offset =
VA − 0x1000; `.data.rel.ro`/`.got` file offset = VA − 0x2000; `.rodata`
file offset = VA. Validated boundaries: clone FDE `.eh_frame` offset
`0x003402c8`, CIE `0x00000000`, range `0x5cfdce0..0x5cfdcf4`; wake FDE
offset `0x00398a08`, CIE `0x39672c`, range `0x5cfd8c0..0x5cfd991`,
landing pad `0x5cfd96d..0x5cfd991`; wake-by-ref FDE offset `0x003402a4`,
CIE `0x00000000`, range `0x5cfd600..0x5cfd6a0`; drop FDE offset
`0x0034028c`, CIE `0x00000000`, range `0x5cfd5e0..0x5cfd5fb`. Raw
disassembly and bytes are beside this record (`*.objdump.txt`,
`*.hex`); structured records (table, FDEs, GOT, Location, census) are in
`records.json`. Callers/callees/indirect calls: table 11 `lea` sites
(listed in README, every hit confirmed by objdump); slot direct `E8`
callers 0/0/2/6 (every hit confirmed by objdump; the `0x5a34bc8` hit was
confirmed from the full-FDE dump because a mid-instruction window start
desynchronizes linear disassembly there); proceed `E8` sites
`0x5a34bbc`/`0x5a35859` (from #185, re-observed here); wake-by-ref
fallback sites `0x5a34bc8`/`0x5a358b9` with `rdi` = payload from
`[rsp+0x38]` in both callers.

Table record (`.data.rel.ro`, file slots zero, RELATIVE addends):
`0x64c6ef8` → `0x5cfdce0`, `0x64c6f00` → `0x5cfd8c0`,
`0x64c6f08` → `0x5cfd600`, `0x64c6f10` → `0x5cfd5e0`; next record
`0x64c6f18` → `0x447492` (park.rs file string, not a slot). GOT
resolutions (`.rela.dyn`, RELATIVE): `0x64ec188` → `0x5bb42e0`
(park-queue callee, FDE `0x5bb42e0..0x5bb4663`, 643B),
`0x64e17f8` → `0x5ce9190` (finalizer, FDE `0x5ce9190..0x5ce91ae`,
30B), `0x64e01f8` → `0x5bb59d0` (timeout-wait helper, FDE
`0x5bb59d0..0x5bb606d`), `0x64e0f38` → `0x5bb5650` (notify helper,
FDE `0x5bb5650..0x5bb59c5`), `0x64df6b8` → `0x1680e80` (panic),
`0x64df4c0` → `0x1680cab` (cleanup), `0x64df4a0` → `0x635de30`
(dealloc, called with `esi` = `0x28`). Panic Location record at
`0x64c6f60`: file pointer → `0x447492` (63 bytes:
`/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/park.rs`),
file length `0x3f`, packed line/col `0x12000000bb` (line 187, col 18);
message at `0x94dc34`, length `0x39` (57 bytes, verbatim):
`inconsistent state in unparkassertion failed: !handle.is_`
(the 57 bytes read as two concatenated fragments; reported verbatim,
not split).
