# RE-013 visor lifecycle (second packet)

- Upstream baseline: `1f8c67c63ca4794c9689235471c60297f8a5c985`
- Captured artifact: `artifacts/visor/captured/hl-visor`
- Artifact SHA-256: `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`
- Artifact size: 8,305,392 bytes
- Claim status: bounded static observations plus explicitly labelled inference
- Captured binary executed: **no**

This packet continues, rather than repeats, the compiler/unwind inventory merged
in [PR #3](https://github.com/lalalune/hyperliquid-source/pull/3).  Its scope is
the static download, verification, update, and child-process lifecycle.  It does
not recover source, prove a complete CFG, or claim that an FDE is necessarily a
source-level function.

## Reproduce

From a checkout whose LFS artifact verifies:

```sh
python3 tools/visor_lifecycle.py \
  --binary artifacts/visor/captured/hl-visor \
  --output work/visor-lifecycle

# Optional bounded disassembly exports (the semantic record does not require it):
python3 tools/visor_lifecycle.py \
  --binary artifacts/visor/captured/hl-visor \
  --output work/visor-lifecycle \
  --disassembler llvm-objdump

python3 -m unittest tests.test_visor_lifecycle -v
```

`tools/visor_lifecycle.py` is stdlib-only.  It authenticates the complete file
before parsing it, decodes the ELF/FDE/relocation structures itself, and checks
every cited instruction.  It performs no network access, process spawning, or
captured-code execution.  The tests include synthetic RIP-relative and direct
call fixtures plus a deterministic corrupted-artifact negative control.

## Address coordinate and bounded ranges

Addresses are PIE ELF virtual addresses from the file headers.  The exact FDE
`pc_begin`/`pc_range` values and whole-range hashes are in
[`records/lifecycle.json`](records/lifecycle.json).  Principal ranges are:

| Range | FDE extent | Bounded observation |
| --- | --- | --- |
| Download / artifact verification | `0x4148b0..0x4155a2` | temporary path construction, transport result, GPG command path, digest compare, cleanup/error returns |
| Metadata / artifact selection | `0x415620..0x416cce` | `node_metadata.json` and `visor_metadata.json` descriptors; index, publisher, and hardfork branches |
| Transport adapter | `0x416cd0..0x416e50` | two transport variants and error conversion; protocol details unresolved |
| Quorum / publication | `0x416f30..0x41718a` | quorum flag rejection and two asynchronous filesystem operations |
| GPG failure adapter | `0x4172e0..0x417342` | maps the non-success path to `failed to verify gpg signature` |
| Freeze/readiness policy | `0x5b41b0..0x5b470d` | deferral and one-minute override diagnostics |
| Child termination | `0x5e2d70..0x5e334e` | PID/PIDFD paths, signal 9, error retry, terminal diagnostic |
| Visor/child async state machine | `0x5e44c0..0x5ea1c1` | download failure retention, executable/version construction, spawn, retry, restart |
| Rust process spawn | `0x66f280..0x6718f9` | `pidfd_spawnp` availability branch and `posix_spawnp` fallback |
| Rust exec fallback | `0x671900..0x671d0d` | `execvp` child-side fallback |

The large async FDE contains compiler-generated state for several source
futures (`node/src/visor.rs` and `node/src/child.rs` locations).  It is not
presented as one recovered source function.

## Observed instructions and data flow

The following statements are direct observations checked by the analyzer:

1. The state machine reaches the download/verification range through relative
   function slot `0x7e6550` (`0x5e62d1 -> 0x4148b0`) and subsequently reaches
   the quorum/publication range through slot `0x7e6558`
   (`0x5e63b6 -> 0x416f30`).
2. Selection loads relocated descriptors for `node_metadata.json` at
   `0x7b2670 -> 0x7c0b1` and `visor_metadata.json` at
   `0x7b2680 -> 0x7c0c3`.  The same FDE contains rejection diagnostics for a
   non-increasing index, an unexpected publisher binary, and an incompatible
   state/binary hardfork version.  These show admitted branches, not a complete
   recovered metadata schema.
3. The download range constructs a path containing `/tmp/binary_download_` at
   `0x414ad9`, calls a transport future, and on its success constructs
   `gpg --verify` at `0x414e1c`.  The command/output helper is called directly
   at `0x414e75 -> 0x42a290`.  A non-null result takes
   `0x414ea0 -> 0x4172e0`, whose diagnostic is `failed to verify gpg signature`.
4. The same range calls a helper at `0x396750` through slot `0x7e5e58`.  That
   helper initializes a SHA-256-shaped state, writes exactly 32 output bytes,
   and returns them.  At `0x4150e3..0x415115`, two 32-byte values are compared
   with vector equality; inequality branches to `0x415350`, which constructs
   `binary hash mismatch`.  Thus this call path enforces equality rather than
   merely retaining a hash-related string.  The algorithm name remains an
   inference from the constants/width, not a recovered symbol.
5. Temporary-file cleanup calls resolve through slot `0x7e5610` to
   `0x3a13e0`; that range reaches the imported `unlink` at `0x3a146e`.  Cleanup
   failures are retained as result variants.  Publication uses asynchronous
   filesystem helpers and contains `rename signature failed`, but the complete
   destination-name derivation remains unresolved.
6. At `0x416f47`, the quorum/publication range tests a flag.  The false branch
   reaches `0x41711b` and returns `signature quorum verification failed` before
   the later publication calls.  The flag's producer and quorum membership are
   not recovered here.
7. A freeze/readiness branch logs `new binary detected but not downloading
   until ready after freeze` at `0x5b4573`, sets a false return, and has a
   separate path at `0x5b45c8` for the one-minute override.  The time source
   and the full readiness predicate are not claimed.
8. The child state machine constructs `hl-node` (`0x5e62a0`, `0x5e7627`) and a
   ` --version` command (`0x5e8353`).  Its direct call at
   `0x5e8cf9 -> 0x66f280` reaches the Rust process implementation.  That range
   tests the `pidfd_spawnp` import and calls it at `0x671078`, otherwise calls
   `posix_spawnp` at `0x6710f3`; a child-side fallback reaches `execvp` at
   `0x671c7f`.
9. Spawn failure reaches `failed to spawn child, retrying` at `0x5e965b` and
   writes a `5.0` floating-point state value before returning to the async
   state machine.  Its unit is not established.  Success reaches
   `@@ successfully restarted child @@` at `0x5e986b`.
10. The termination range is reached through slot `0x7e7738`.  It uses signal
    number 9 at imported `kill` calls `0x5e314e` and `0x5e3192`, with an
    errno-dependent retry loop, and has the terminal diagnostic `could not kill
    child process` at `0x5e2fb8`.
11. The download/quorum failure branch reaches `download or verify quorum
    failed, keeping child running` at `0x5e640c`; the observed branch disposes
    the failed result without entering the nearby restart construction.

The graph in [`call-data-graph.dot`](call-data-graph.dot) marks instruction-
and relocation-proven edges as solid.  Dashed edges are inferences or unresolved
effects.  Bounded exports are under [`records/disassembly/`](records/disassembly/).

## Interpretation limits

- A string reference is evidence only where the packet also records the
  reaching branch/call.  Unreferenced strings receive no enforcement claim.
- `gpg --verify` is an observed constructed command reaching a command helper;
  the exact keyring, trust policy, shell quoting, and signature provenance are
  not established.
- The quorum rejection is real, but the producer, signer set, threshold, and
  relationship to GPG verification remain unresolved.
- HTTP/TLS policy, redirects, response limits, and temporary-name entropy are
  below unresolved helpers.  No download was performed.
- Publication and cleanup effects are static call-path observations, not an
  executed filesystem trace.  No child was launched and no process was killed.
- The packet does not prove update atomicity across power loss or races, recover
  all retry limits, or establish complete child supervision semantics.
- Runtime/library fallbacks are compiler/library code retained in this binary;
  this packet does not claim which Linux/glibc branch ran in deployment.

See [`unresolved-edges.md`](unresolved-edges.md) for the bounded follow-up list.
