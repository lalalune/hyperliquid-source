# RE-001-node115-lu-acquire-release-callers: census and decode the direct callers of the acquire/release pair

- Component ID: RE-001-node115-lu-acquire-release-callers
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: upstream main `8fd8db680ec4bfef40996e5616bce3d5156d0b86` (node-115-only)
- Claim status: observation
- Scope included and excluded: see README.md Scope section

## Reproduce

Exact commands, tool versions, options, input and output hashes, working directory,
platform, environment requirements, and any declared execution/side effects.

Working directory: the worktree root. Binary: `artifacts/node/115/hl-node`.
Coordinate system: `.text` file offset = VA − 0x1000;
`.data.rel.ro`/`.got` file offset = VA − 0x2000; `.rodata` file offset = VA.
Instruction counts are strict mnemonic-line counts (objdump lines with an
address, a byte field, a tab, and a mnemonic; byte-continuation lines excluded).

```sh
objdump -d -M intel --start-address=0x2ac0f60 --stop-address=0x2ac0fb0 \
  artifacts/node/115/hl-node
objdump -d -M intel --start-address=0x2ace08b --stop-address=0x2ace0ec \
  artifacts/node/115/hl-node
objdump -d -M intel --start-address=0x2aceb52 --stop-address=0x2aceba0 \
  artifacts/node/115/hl-node
python3 tools/node115_lu_acquire_release_callers.py
python3 -m unittest tests.test_node115_lu_acquire_release_callers -v
```

No execution side effects: the node binary was never executed. The verifier
and tests read bytes only. Census scans: whole-`.text` E8/E9/LEA scans for
both targets, absolute-qword scans of `.data.rel.ro`, `.rodata`, `.data`,
`.got`, `.got.plt`, `.gcc_except_table`, `.eh_frame`, `.eh_frame_hdr`,
and a full `.rela.dyn` pass. FDE membership for the 13 GOT sites was
established against the `.eh_frame_hdr` table (135,313 FDE starts,
validated against the known acquire/release/completion FDE starts).

## Evidence

Original addresses and coordinate system (VA/file offset), validated boundaries,
raw disassembly/data, callers/callees/indirect calls, source mapping evidence,
ABI/layout/rounding/overflow observations. Keep raw files beside this record.
State whether analysis was complete, timed out or limited to a range.

GOT slots (RELATIVE relocations, type 8, sym 0, file content zero):
- acquire `0x4fac710` via slot `0x64e7338`
- release `0x4fb52e0` via slot `0x64e7290`
- free target `0x5a8e3c0` via slot `0x64e7278`
- neighboring field drops: slot `0x64e7270` → `0x5a8c9f0`,
  slot `0x64e7208` → `0x5a8c110` (cited, not decoded)

Census (whole-binary, verifier-checked):
- acquire: 0 E8, 0 E9, 0 LEA, 0 absolute refs; 2 GOT call sites
  (`0x2ace0be` in FDE `0x2accee0`, `0x2ad20da` in FDE `0x2ad0db0`)
- release: 0 E8, 0 E9, 0 LEA, 0 absolute refs; 11 GOT call sites
  (`0x2aa5a79`, `0x2aa5c2c` in `0x2aa59f0`; `0x2aa77d9`, `0x2aa798c`
  in `0x2aa7750`; `0x2ac0f70` in `0x2ac0f60`; `0x2aceb7a`,
  `0x2acf336`, `0x2ad06c2` in `0x2accee0`; `0x2ad2b7d`,
  `0x2ad3303`, `0x2ad46cf` in `0x2ad0db0`)
- wrapper `0x2ac0f60`: 12 direct E8 callers, all inside the 4
  caller FDEs above (3 per twin drop FDE, 3 per twin handler)

Acquire call setup (handler A at `0x2ace0b0`, handler B at
`0x2ad20cc`): `rdi` = stack out struct, `rsi` = pcell
`[rbx+0x110]`, `edx` = input dword. NULL check reads out.P
(A `cmp [rsp+0x180],0` at `0x2ace0c4`, `je 0x2ace3c6`;
B `cmp [rsp+0x150],0` at `0x2ad20e0`, `je 0x2ad23e7`).
Success copies the 16-byte pair to the handler slot
(A `rsp+0x160`, B `rsp+0x130`) and sets flag `[rbx+0x163]`
to 1. State byte `[rbx+0x128] == 4` skips the call, zeroes
the pair slot, and also sets flag `[rbx+0x163]` to 1.

Strings (`.rodata`, VA as-is):
- `0x60567b`, 55 bytes: "closing gossip stream because peer is already connected"
  (NULL-path log, call to `0x2d4e9c0` at A `0x2ace421` / B `0x2ad2442`)
- `0x605781`, 44 bytes: "dropping connection after sending abci state"
  (release site-1 context in both handlers)
- `0x6056b2`, 22 bytes: "node_stream_connection"
  (success-path span, call to `0x2e06ac0` at A `0x2ace102` / B `0x2ad211e`)

Release template (all 11 sites): call release through slot
`0x64e7290`, then `lock dec [P]`, then call free through slot
`0x64e7278` if the decremented value is zero. The two
stack-copy sites (handlers, sites 1 and 3) add a P `!= 0`
guard before the call; the field sites (drops, handler
site 2) pass the field address directly. The wrapper adds a
NULL-handle early return and uses a tail jump for the free.

Pair lifecycle (handler A; B mirrors at different frame offsets):
acquire at `0x2ace0be` → copy to `rsp+0x160` → install to
`[rbx+0x278]` at `0x2ace5f0` → teardown drops `rsp+0x160`
via the wrapper at `0x2acffc8` when flag `[rbx+0x163]` is set.
The stored pair field `[rbx+0x1200]` is released on three
handler paths (direct GOT sites) and two wrapper paths, but
never written by either handler.

Analysis was complete for the census (whole binary) and for the
cited windows; it was limited to those windows for the 16 KB
handler FDEs, whose remaining logic is not decoded here.

## Implementation and comparison

Not yet implemented/measured. No Rust reconstruction is included in
this packet; it is an observation packet (evidence + static verifier
+ unit tests). No Cargo build, no two-build comparison, no fixture
identities are claimed.

## Results and limitations

Machine-readable metrics with explicit denominators, what passed/failed, what
remains unknown, and why any requested progress gate covers its entire scope.
If requesting no gate, say so. Finish with a concrete next question.

- Verifier `tools/node115_lu_acquire_release_callers.py`: exit 0
  (binary identity, 3 excerpts, 13 GOT site bytes, 3 RELATIVE
  relocations, 2 negative censuses, 3 strings, 2 NULL branches,
  error-log call, wrapper shape, 12 wrapper callers).
- Unit tests `tests/test_node115_lu_acquire_release_callers.py`: 8/8 pass.
- `make doctor`: analysis_ready true. `make verify`: exit 0
  (29 evidence-packet manifests, 467 entries).
  `make catalogue-check`: exit 0. `make test`: 77 files attempted,
  1 failed — the single failure is the pre-existing
  test_node115_catalogue Errno 18 cross-device-link error,
  unrelated to this packet; this packet's file [36/77] passes 8/8.
- Unknown: state byte `[rbx+0x128] == 4` meaning; installer of
  the `[rbx+0x1200]` stored pair; free target `0x5a8e3c0`
  internals; full handler bodies; delegates `0x51f3e20` /
  `0x57ec1b0`; unwind callee `0x1680cab`. No gate is requested
  for those unknowns.
- No gate is requested by this packet beyond the standard
  verify/catalogue/test suite.
- Next question: decode the free target `0x5a8e3c0` and its
  sibling field drops (`0x5a8c9f0`, `0x5a8c110`): what
  deallocation family frees the pair at refcount zero, and
  what happens to the freed memory?
