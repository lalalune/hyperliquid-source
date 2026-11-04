# RE-001-node115-lu-acquire-release-callers

## Claim status: observation

This packet answers packet #200's explicitly stated next question:
**census and decode the direct callers of the acquire/release pair
(`0x4fac710` / `0x4fb52e0`) — which API operations claim and
release entries, and what do they do with acquire's NULL versus
`{P, input}` result?**

## The answer

**1. Neither helper has a direct caller. Both live behind one
RELATIVE `.got` slot each.** A full-binary static census finds
0 direct E8 calls, 0 E9 tail jumps, 0 rip-relative LEA
address-taken sites, and 0 absolute 8-byte references for both
targets. Acquire is reached through GOT slot `0x64e7338`
(`R_X86_64_RELATIVE`, addend `0x4fac710`); release through GOT
slot `0x64e7290` (addend `0x4fb52e0`). Every static path below
is an `FF 15` call through one of those two slots.

**2. Acquire has exactly 2 call sites, both in twin
node-stream-connection handlers.** FDE `0x2accee0` (A) calls
acquire at `0x2ace0be`; FDE `0x2ad0db0` (B) at `0x2ad20da`.
Both use the same template (frame offsets differ): pcell
`[rbx+0x110]`, input dword (`r15d` in A, `r13d` in B), out
struct on the stack (A `rsp+0x180`, B `rsp+0x150`). The
handlers are mnemonic-level twins (244 differing mnemonic
lines out of ~2900); the strings below pin them to one
operation family.

**3. Acquire's result has three outcomes, not two.**
- State byte `[rbx+0x128] == 4`: acquire is skipped
  entirely. The pair slot is zeroed (A `rsp+0x160`, B
  `rsp+0x130`), flag `[rbx+0x163]` is set to 1, and the
  handler proceeds. Teardown later drops the zeroed slot,
  which the wrapper's NULL check turns into a no-op.
- Acquire returns NULL (`out.P == 0`, count `>= 2`): the
  handler jumps to its error path (A `0x2ace3c6`, B
  `0x2ad23e7`), which logs `"closing gossip stream because
  peer is already connected"` (55 bytes at `0x60567b`) via
  `0x2d4e9c0`, clears flag `[rbx+0x163]` to 0, and tears
  down without ever touching a pair. Claim failure is a
  soft error, not a panic.
- Acquire returns `{P, input}`: flag `[rbx+0x163]` is set
  to 1, the 16-byte pair is copied to the handler's own
  slot, the span `"node_stream_connection"` (22 bytes at
  `0x6056b2`) is logged via `0x2e06ac0`, and the pair is
  installed into the handler struct at `+0x278`
  (A `0x2ace5f0`). At teardown, the flag-guarded wrapper
  call (A `0x2acffc8` on `rsp+0x160`, B `0x2ad3ff0` on
  `rsp+0x130`) drops it.

**4. Release has 11 call sites in 5 FDEs, all following one
template: release, then `lock dec [P]`, then free at zero.**
The free target is GOT slot `0x64e7278` (RELATIVE addend
`0x5a8e3c0`).
- Twin drop FDEs `0x2aa59f0` / `0x2aa7750` (byte-identical
  template, 1216 bytes each): 2 sites each, dropping the
  `+0xe8` handle field on two paths — `lea rdi,[rbx+0xe8]`,
  release, `mov rax,[r15]`, `lock dec [rax]`, free at zero.
- Standalone drop wrapper `0x2ac0f60` (80 bytes, 27
  instructions): 1 site. NULL handle returns immediately;
  otherwise release, `lock dec [r15]`, free at zero via a
  tail jump. This wrapper is itself called directly (E8)
  12 times: 3 per twin drop FDE (unwind paths, `+0xe8`
  field) and 3 per twin handler (2 on the stored `+0x1200`
  field guarded by `[rbx+0x127e]`, 1 on the handler's own
  pair slot guarded by `[rbx+0x163]`).
- Twin handlers: 3 sites each, all on the stored pair
  field `+0x1200` (never written by these handlers, so a
  pre-existing claim from an earlier phase). Site 1 is
  the `"dropping connection after sending abci state"`
  path (44 bytes at `0x605781`): stack copy, P `!= 0`
  guard, release, dec, free. Site 2 is the field
  teardown guarded by `[rbx+0x127e] == 1` and
  `[rbx+0x1200] != 0`, operating on the field directly.
  Site 3 is the final teardown: stack copy, P `!= 0`
  guard, release, dec, free.

**5. The loop closes.** The handlers claim through
acquire, install the pair, and drop it through the
wrapper at teardown; the drops release through the
release helper and free at zero. Acquire's NULL and
`{P, input}` are not two symmetric results: NULL means
"peer already connected" and ends the stream, while a
pair means "claim installed" and is owned until teardown.

## Scope

Included:

- The full wrapper FDE `0x2ac0f60..0x2ac0fb0` (80 bytes;
  19 body instructions through `ret` at `0x2ac0f8f` +
  8 tail instructions).
- The acquire window `0x2ace08b..0x2ace0ec` (97 bytes; 15
  instructions) covering both branches, the call, the
  NULL check, and the pair copy in handler A. Handler B's
  window is the same template at different frame offsets
  (setup and NULL-branch bytes pinned by the verifier).
- The release window `0x2aceb52..0x2aceba0` (78 bytes; 11
  instructions): the stored-pair teardown in handler A.
- The census: 2 acquire + 11 release GOT sites, 12
  wrapper E8 callers, the 3 strings, the RELATIVE
  relocations, and the NULL-branch targets — all checked
  by the verifier.

Excluded:

- The acquire/release FDE internals (claimed by #200 /
  #194; only their GOT slots and call sites are cited).
- The full 16 KB handler FDEs (only the windows above
  and the cited sites are claimed; the handlers' remaining
  logic is not decoded here).
- The internals of the free target `0x5a8e3c0` and the
  neighboring field drops (`0x5a8c9f0`, `0x5a8c110`);
  only their GOT resolutions are cited.
- The delegates `0x51f3e20` / `0x57ec1b0` and the unwind
  callee `0x1680cab` (open from #200, not widened here).
- Any runtime behavior. Analysis is static only; the node
  binary was never executed.

## Reproduce

Worktree base: upstream main `8fd8db680ec4bfef40996e5616bce3d5156d0b86`
(node-115-only). Binary: `artifacts/node/115/hl-node`, 105,896,032 bytes,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
`.text` file offset = VA − 0x1000; `.data.rel.ro`/`.got` file offset =
VA − 0x2000; `.rodata` file offset = VA.
Instruction counts are strict mnemonic-line counts: objdump lines
with an address, a byte field, a tab, and a mnemonic.
Byte-continuation lines (address + bytes only) are excluded.

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

## What this changes about earlier packets

- No corrections. #200's acquire signature, `>= 2` → NULL
  rule, and pair layout all stand; #194's gate-release
  mechanism stands. This packet only adds the callers
  #200 asked for and pins the wrapper that both handler
  teardowns share.

## Limitations

- The handlers' full 16 KB bodies are not decoded; the
  "connection handler" identification rests on the three
  strings and the shared claim/drop template, not on a
  full read of either handler.
- The meaning of state byte `[rbx+0x128] == 4` (skip
  acquire) is not established beyond the branch itself;
  no label is claimed for it.
- The `+0x1200` stored pair's installer is not
  identified; the handlers only release it, never write it.
- The free target `0x5a8e3c0` is characterized by GOT
  resolution only; whether it returns memory to an arena
  or the system allocator is not established.
- No runtime behavior is claimed; the node binary was
  never executed.

## Next question

Decode the free target `0x5a8e3c0` and its sibling field
drops (`0x5a8c9f0`, `0x5a8c110`): what deallocation family
frees the pair at refcount zero, and what happens to the
freed memory? (The delegates `0x51f3e20` / `0x57ec1b0`
and the unwind callee `0x1680cab` from #200 remain open
behind this one.)
