# RE-001: node94 TLS table slow path, state transitions and thread registration

- Component: `foundation`; bounded static helper closure for the existing TLS-table-index packet.
- Target: node #94, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`, 91,774,280 bytes.
- Source baseline: `e5c9b6436876b2a4a39daef813171f9879317699`.
- Reference source: none used or copied. This is independently authored static research; source names and source-level types remain unknown.
- Included: complete `[0x555a760,0x555aa22)` FDE (706 bytes), its 14 padding bytes, the separate abort cold FDE, the previously established caller edge, selected dynamic bindings and data references.
- Excluded: helper bodies, other incoming references, full allocator reconstruction, node startup integration, Rust reconstruction and behavioral/binary equivalence. No progress gate requested; all component gates remain false.

## Gap resolved and overlap

`foundation-tls-table-index-94/README.md` explicitly excludes its slow-path target `0x555a760`. This packet resolves that target's own control flow, visible writes, TLS-copy extent, pthread registration and failure continuation. The caller is an anchor, not new coverage. The older packet's index arithmetic and all its other 173 caller candidates are outside this contribution.

Live GitHub screening read 555 open PRs through `gh pr list -R lalalune/hyperliquid-source --state open --limit 1000 --json number,title,body` (latest #1910) and found no body mentioning `555a760`, `54f3190`, or `tls-table`. This screening is evidence of selection, not a claim of ownership; recheck before submission.

## Reproduce

Observed platform: macOS 26.4.1 (25E253), Python 3.11.15, Apple LLVM objdump 21.0.0, optimized build. Work from the repository root with the authentic LFS artifact materialized. No captured program, networked node or chain action is executed. Only Python's standard library and the local static disassembler are used.

```sh
python3.11 research/work-items/RE-001-tls-table-slowpath-94/verify.py --negative-controls
```

The retained `verification.json` records the observed result. The verifier authenticates the whole artifact, parses ELF sections independently, rejects duplicate section names, decodes the selected FDEs under their exact supported CIE, resolves the selected dynamic relocations, recomputes call/jump targets and checks every retained instruction line against the artifact bytes. It does not import or execute other repository tools. It checks 218 retained instruction lines across body, caller, cold block and PLT anchors; this is not 218 reconstructed instructions or a whole-program denominator.

Raw exports use the local LLVM objdump (substitute its installed path for `llvm-objdump`):

```sh
llvm-objdump -d --start-address=0x555a760 --stop-address=0x555aa30 artifacts/node/94/hl-node
llvm-objdump -d --start-address=0x54f3190 --stop-address=0x54f31f2 artifacts/node/94/hl-node
llvm-objdump -d --start-address=0x555a757 --stop-address=0x555a75c artifacts/node/94/hl-node
llvm-objdump -d --start-address=0x56602b0 --stop-address=0x56602c0 artifacts/node/94/hl-node
llvm-objdump -d --start-address=0x5660300 --stop-address=0x5660310 artifacts/node/94/hl-node
llvm-objdump --dwarf=frames artifacts/node/94/hl-node
```

The first two outputs are retained as `slowpath.objdump.txt` and `caller.objdump.txt`; the next three are concatenated in `cold-and-plt.objdump.txt`. `frames.txt` retains the three relevant FDE blocks from the last command. `evidence.json` retains section-resolved file offsets, range hashes, raw FDE records, original edge encodings, branch destinations, relocation symbols and selected data bytes. LLVM's nearest-symbol annotations are not recovered function names.

## Observations

All addresses are ELF VAs, without a guessed runtime or Ghidra rebase. The section table maps this body to file offset `0x5559760`; the verifier derives this relationship rather than applying a global subtraction.

### Boundaries and caller

The CIE at `.eh_frame+0` is `zR`, using pcrel signed-32-bit FDE PCs. FDE `.eh_frame+0x2cf8bc` independently decodes to `[0x555a760,0x555aa22)`, agreeing with LLVM's frame dump. Fourteen `int3` bytes follow. The exceptional destination `0x555a757` is not part of this 706-byte body: FDE `.eh_frame+0x2cf8f0` separately covers `[0x555a757,0x555a75c)`, a five-byte call to `abort@plt`.

At `0x54f319b`, the existing caller tests byte `fs:(-0x10a0+0x330)`. A **nonzero** byte branches to the slow path; zero skips it. At `0x54f31e0` it constructs `rdi=fs:0-0x10a0`, clears `esi`, and calls `0x555a760` at `0x54f31eb`, then jumps back to load the table pointer at `0x599a670`. This establishes a real caller protocol, without identifying the table contents or the other call sites.

### Entry state dispatch

The function saves its first argument in `rbx`, loads byte `[rbx+0x330]`, and compares it unsigned. The second argument is tested only through its low byte `sil` on the entry paths below.

| Entry state byte | Entry behavior |
| --- | --- |
| 0, 1, 5, 7..255 | Return the original object pointer in `rax` without an explicit object write in this function |
| 2 | Enter the state-exchange path at `0x555a7ae` |
| 3 | If `sil!=0`, return; otherwise call `0x555a4c0` with second argument 0, decrement byte `[rbx+1]`, exchange/retry, then take common finalization |
| 4 | Call `0x555a4c0` with second argument 5, then take the copy/register path |
| 6 | If `sil!=0`, call `0x555a4c0` with second argument 3 and take the copy/register path. Otherwise return when byte `[0x59b0e58]==0`; when nonzero, call `0x555a4c0` with second argument 0, exchange/retry, copy/register, then common finalization |

These are observed numeric states, not established source enum names. The returned pointer is the original `rbx`, including paths which copy the structure elsewhere.

### Exchange/retry rule

Three memory `xchg` instructions occur at `0x555a798`, `0x555a850`, and `0x555a9d0`, all on byte `[rbx+0x330]`. Memory `xchg` provides the x86 atomic exchange; no source-language memory-order claim is made.

When the most recently loaded state is at most 2, the value offered to the exchange is initially 1. It becomes `(dword[0x59b0dc0]!=0)` only when byte `[0x5787f80]==0`, byte `[rbx]==0` is false, and signed byte `[rbx+1]<=0`. If the loaded state exceeds 2, that loaded byte is offered directly. The exchange returns the old memory byte; old value 2 causes reload/retry, while any other old value proceeds. The initial state-2 route calls `0x5559a90` and returns after a non-2 exchange result. The other two exchange routes call that helper and continue to their finalization paths. These loops must not be simplified to one write based only on the initial state; concurrent changes may alter later loaded and exchanged values.

### TLS copies and pthread registration

Two paths (`0x555a863..0x555a898` and `0x555a8dd..0x555a915`) construct the current-thread destination `fs:0-0x10a0`. If that destination differs from `rbx`, they set `ecx=0x149` and execute `rep movsq` from `rbx`: **329 qwords / 0xa48 bytes**. The usual SysV ABI clear direction flag is assumed for a forward copy; arbitrary overlapping-input semantics are not established. Equal pointers skip the copy.

Both paths then pass `edi=dword[0x59b0e5c]` and `rsi=fs:0-0x10a0` to `0x5660300`. The PLT indirect slot `0x5778ea8` has one `R_X86_64_JUMP_SLOT` relocation naming **pthread_setspecific**. This is symbol-grounded identification, rather than inference from a nearby label. The key's runtime value is unknown: its storage is `.bss`, not initialized file bytes.

The state-4/state-6-nonzero path continues at `0x555a91e`, calls `0x5544700` with `rbx+0x1b0`, stores `rbx` at `[rbx+0x70]`, stores word `0x0100` at `[rbx]`, calls `0x555a0b0` and `0x5521cf0` with `rbx`, and returns.

The shared path at `0x555a9e5` makes the same first call and self-pointer store, then calls `0x555a0b0`, `0x5521cf0`, and additionally `0x55586f0`. It contains no matching explicit word-0x0100 store. Callee writes are unknown and cannot be inferred absent from these paths.

### Failure path and data identity

A nonzero pthread return invokes `0x55294f0` with the exact 31-byte diagnostic `<jemalloc>: Error setting tsd.\n` at `0x7d9118`. If this helper returns, byte `[0x5799c8d]` selects continuation (zero) or a jump to the separate cold FDE (nonzero). That cold FDE calls `0x56602b0`; slot `0x5778e80` has one `R_X86_64_JUMP_SLOT` relocation naming **abort**. Thus pthread failure is not unconditionally fatal in this visible control flow. The diagnostic supports an allocator/TSD attribution, but does not prove an exact jemalloc version, source revision or private fork.

The globals at `0x5799c8d`, `0x59b0dc0`, `0x59b0e58`, and `0x59b0e5c` are `.bss`; `evidence.json` records their section membership and accessed widths, without treating neighboring file bytes as initial runtime values. Byte `0x5787f80` is file-backed `.data` with retained value 1. That file value does not establish its value after initialization.

## Results, controls and limitations

Before this packet the slow-path body was explicitly excluded. The result is one bounded state-machine map with visible writes, 17 direct calls in the main FDE (eight distinct callees), two external cold jumps to one separate abort FDE, and the above TLS-copy/registration protocol. Calls are recorded by actual instruction boundaries and relative displacements. No incoming-reference census or family coverage is claimed.

Observed local verification passes full identity, six retained range hashes, three FDE records, all retained instruction bytes, direct and conditional branch targets, two symbol bindings, and selected data identities. Five mutations are rejected after deliberately bypassing only the full-digest gate: state-immediate byte, FDE extent, caller displacement, pthread relocation and diagnostic string. This demonstrates structural rejection beyond a SHA-only check. `verification.json` records each rejection reason; range mutations can fail their range lock before the narrower edge check.

No Rust implementation, two-build comparison, normalized byte comparison, model-backed execution, behavioral execution, hosted CI or container result is claimed. These remain not implemented/measured. No normalization masks or copied executable reconstruction are used. The raw instruction exports are evidence under the captured artifact's original rights; new prose and checker code are independently authored.

The remaining helper bodies (`0x555a4c0`, `0x5559a90`, `0x5544700`, `0x555a0b0`, `0x5521cf0`, `0x55586f0`, `0x55294f0`) and their effects are unresolved. Numeric state meanings, thread-key creation, global initialization, object lifetime and full allocator ownership/version remain unknown. Full component gates remain false. Next question: recover `0x555a4c0`'s state-setting and list-publication effects, then bind these numeric transitions to licensed upstream source rather than inventing enum names.
