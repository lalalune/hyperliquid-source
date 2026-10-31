# RE-013: which static handoffs precede the visor lifecycle callback?

- Component: `visor`; source base `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Target: captured `artifacts/visor/captured/hl-visor`, 8,305,392 bytes,
  SHA-256 `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
- Status: bounded static byte/relocation observations; interpretations and
  unresolved helper contracts are separated below.
- Scope: ELF entry and four small callable thunks, plus the setup/dispatch
  body at `0x5e34c0..0x5e44b3`. No captured executable is run.
- No Rust reconstruction, body-match result or accepted component gate.

[PR #45](https://github.com/lalalune/hyperliquid-source/pull/45), frozen head
`c8c98b76ccf883fa4aa7aca9c4a4ccc8a8e00692`, already maps update/child behavior
inside the callback at `0x5e44c0..0x5ea1c1`. This packet ends at calls to that
external endpoint and credits that work. It does not repeat its download,
verification, spawn, readiness or termination claims. The earlier visor
compiler/index inventory remains authoritative for its narrower observations.
Separate stopped GPG command-helper research is preserved and not reused here.

## Reproduce

Run from a checkout with authenticated pinned artifacts and imports:

```sh
mkdir -p work/visor-startup
PYTHONDONTWRITEBYTECODE=1 python3 -B tools/visor_startup.py \
  --output work/visor-startup/record.json
cmp research/work-items/RE-013-visor-startup-handoff/record.json \
  work/visor-startup/record.json
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  research/work-items/RE-013-visor-startup-handoff/check_disassembly.py
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests \
  -p test_visor_startup.py -v
```

The producer is standard-library-only and reuses the unchanged project
`elf_index.sections` and `fde_extents.fde_extents` readers. Its public entry
requires the complete size/digest before parsing. A private `_derive` seam
lets tests corrupt actual bytes below that outer authentication gate; it is
not exposed as a CLI re-pin option. The CLI derives a complete record before
exclusive creation of its output, preserving prior results on refusal.

`BOUNDARY-AUDIT.json` records all six exact GNU objdump commands, version
2.44, listing digests and checked extents. For example, its main body command
is:

```sh
objdump -d -M intel --show-raw-insn --insn-width=16 \
  --start-address=0x5e34c0 --stop-address=0x5e44b3 \
  artifacts/visor/captured/hl-visor
```

The retained listings cover 803 linear decoded instruction rows / 4,209 raw
bytes, including the 38-byte ELF-entry prefix and five complete FDE ranges.
Each row was checked against its file bytes and adjacent rows tile each
declared extent. All 15 selected control windows begin/end at decoded
boundaries. This checks linear decoding, not reachability or a full CFG.
The runtime FDE ends at `0x5e44b3`; the later callback starts at `0x5e44c0`.
The intervening alignment is not counted as either body's code.

## Observations

All addresses are linked ELF virtual addresses. `record.json` also gives
file offsets, FDE addresses, range/body hashes, raw control bytes and exact
RELA record offsets. No Ghidra base is guessed.

1. **Entry prepares a callable, rather than directly entering the lifecycle.**
   The ELF entry is `0x2bd180`. At `0x2bd198`, a RIP-relative `lea` supplies
   `0x4e4fb0` in `rdi`; the next call uses GLOB_DAT slot `0x7e4b08`, whose
   actual dynamic symbol is `__libc_start_main`. The call's normal
   fallthrough is a `hlt`. No libc implementation is recovered here.
2. **The thunk packages another callable and descriptor.** The 39-byte FDE
   `0x4e4fb0..0x4e4fd7` supplies the address `0x4e4f90` in a stack slot and
   the descriptor address `0x7c3bf0`; its call uses RELATIVE slot
   `0x7e6ec0 -> 0x684050`. Descriptor slot `0x7c3c08` relocates to
   `0x4e4f80`. That 13-byte FDE loads `[rdi]` and calls the 5-byte FDE
   `0x4e4f70`, whose indirect instruction is `call rdi`. These are concrete
   pointer/call observations. The opaque `0x684050` helper's selection and
   invocation of the supplied callable are not independently proved.
3. **The supplied wrapper initializes one observed context byte.** The
   31-byte FDE `0x4e4f90..0x4e4faf` reserves `0x4c8` stack bytes, stores zero
   at `[rsp+0x1f9]`, passes `rsp` in `rdi` and calls `0x5e34c0`. This is not
   evidence that every context byte is initialized, or that a particular
   private Rust future layout/type has been recovered.
4. **An early numeric result tag has an unwrap-error route.** The driver
   first calls `0x6da910` with `esi=1`, stores word `0x101` at
   `[rsp+0xb7d]`, and calls RELATIVE slot `0x7e57d8 -> 0x6dab20`.
   Comparing dword `[rsp+0xb88]` with 2 at `0x5e3519` sends equality to
   `0x5e35f5`. That block supplies the exact 43-byte literal
   `called Result::unwrap() on an Err value` (with backticks in the actual
   bytes), the returned payload, and Location `0x7d6fd0` to
   `0x7e4be0 -> 0x49abb0`, followed by the shared `ud2` trap route.
   The Location pointer relocates to the actual 17 bytes
   `node/src/utils.rs`, line 66, column 70. It is **not** `node/src/visor.rs`.
   Helper names, complete return types and meanings of all other tags remain
   unproved; the diagnostic supports the caller's error-route interpretation.
5. **The continuing driver has TLS and variant-dependent routes.** It reads
   TLS byte `fs:[-0xd00+0x48]`, compares with 1 and 2, and has additional
   lazy-initialization/diagnostic edges. At `0x5e3648`, a nonzero qword
   `fs:[-0xd00]` branches to `0x5e3d0a`; zero is replaced with `-1` on the
   shown continuation. At `0x5e36eb`, qword `[rsp+0x90] == 1` selects the
   alternate route at `0x5e3f6d`. This packet does not assign private field
   names or equate those tags with specific executor flavors.
6. **Two concrete call sites reach the already studied callback.** The
   RELATIVE `memcpy` slot `0x7e4b68` authenticates the shown `0x4c8` context
   copies, including destination `[rsp+0xb88]` at `0x5e370c` and
   `0x5e4061`. The first callback site `0x5e3b02` follows a call to
   `0x6c7f50`: zero `al` skips the callback via `0x5e3af3 -> 0x5e3b07`;
   nonzero reaches `call 0x5e44c0`. The alternate shown site at `0x5e4106`
   passes the copied-context address in `rdi` and `[rsp+0x50]` in `rsi`
   before calling the same endpoint. These are selected local conditions,
   not a proof that startup reaches either call on every valid invocation.

The label “runtime handoff” is an interpretation of the stack-context,
TLS/admission and repeated-callback structure, consistent with the existing
lifecycle packet. The driver contains parking/wakeup, cleanup and exception
edges beyond these selected checks. No complete state machine, timing,
allocation, signal, environment or command-line policy is reconstructed.

## Controls and limitations

The ten focused tests regenerate the real target record and reject changed
or truncated whole artifacts, context-state and callback-displacement
corruptions, a changed relative relocation, Location/literal changes and a
changed FDE extent. The retained listing audit rechecks its byte and boundary
counts against the target; a re-pinned wrong instruction byte and a false
declared row count are independently rejected. Real CLI controls cover paths with spaces, existing output
preservation, and absent/prior outputs on rejected input. No fake process or
invented runtime implementation substitutes for the target.

There was one author preparation failure: the first reader expected
`node/src/visor.rs` at the Location addend. Checking its actual relocated
17-byte span showed `node/src/utils.rs`; the corrected packet binds those
bytes. No record was published by the failed attempt and no target ran.
The failure is retained in validation metadata as a corrected attribution,
not recast as a captured-program failure.

`record.json` counts **15 selected windows, 17 selected call sites and six
selected branch sites** over five FDE ranges. They are not complete call,
branch, function or matching-window denominators. Passing corruption controls
does not establish full semantic equivalence. There is no reconstructed Rust
implementation, exact-build comparison, target execution, native provider
analysis or gate change. All visor component gates remain false.

Next question: independently establish the opaque callable-dispatch helper
at `0x684050` before claiming a complete proven path from libc entry through
the supplied wrapper, or recover the two setup-result types before assigning
executor flavor names to their numeric tags.
