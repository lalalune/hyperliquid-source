# RE-001: startup log backup selection and helper contracts, node #94

Component: **node-runtime**. Bounded question: which log candidates does
`0x1438630` admit, how does it choose a backup suffix, and what does its move
helper receive? This is static research under RE-001, with no component gate
or independently authored Rust implementation claim.

Target: `artifacts/node/94/hl-node`, node #94, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
Reference pin: can1357-hl `999556f6e0a474b8312db96ec3149e1c44e97c23`.
The reference's `base/production.rs` archive label is an untrusted lead. Its
inferred source is not copied into this packet.

Before: the seed did not establish file eligibility, whitespace handling,
collision semantics, counter overflow or the move request's payload. After:
the bytes bind an **error-then-warn** sequence, a **regular-file** classification,
a **trimmed-content length** gate, a **saturating 64-bit suffix counter**, and a
three-slice request beginning with **`mv`**. These distinctions matter when
reconstructing startup behavior; directory rotation, unconditional movement of
nonempty byte files and an arbitrary free-path search would be inaccurate.

## Exact ranges and evidence denominator

All addresses are linked ELF virtual addresses and all ends are exclusive.

| Body | Range | Bytes | Instructions |
| --- | --- | ---: | ---: |
| Startup backup controller | `0x1438630..0x1438d69` | 1,849 | 379 |
| Regular-file predicate | `0x144a710..0x144a884` | 372 | 100 |
| Content normalization wrapper | `0x144c330..0x144c436` | 262 | 78 |
| Move request wrapper | `0x144cf90..0x144d0c9` | 313 | 76 |
| Metadata-success predicate | `0x144a2f0..0x144a3dc` | 236 | 68 |

These are **5 complete FDE bodies / 3,032 bytes / 701 instructions**, including
their error and unwind-shaped tails. Their full hashes, file offsets, FDE/CIE/
LSDA addresses, and every call site are in `records.json`. GNU readelf agrees
with the independent FDE parser on the five headers. GNU objdump and LLVM
objdump agree on every retained byte and instruction start, with no masks.

Two supporting windows add **83 bytes / 17 instructions**: the incoming call
and its nearby condition/role at `0x2275d02..0x2275d1f`, and the metadata
helper's `stat64` fallback/result-copy window at `0x4edfcc0..0x4edfcf6`.
Each is selected only after both tools decode its complete enclosing FDE.
They are supporting context, not two more completely recovered functions.
These denominators describe authenticated static exports, not compiled Rust
matches, full helper closure or whole-node coverage.

The controller has one RELATIVE incoming slot, `0x576f490`. A whole-`.text`
byte-candidate census finds no E8 direct call, one FF15 call to that slot at
`0x2275d19`, and no FF25 tail jump to it. Both decoders verify that call boundary.
The caller passes pointer `0x3d7680`, length 5: **`infra`**. Its enclosing FDE is
`0x2275a10..0x227a0db`; only the retained call window is interpreted here.
The incoming `cl` / `sil` predicates remain unnamed. Arbitrary indirect callers,
computed pointers and runtime-loaded addresses are outside this census.

## Path requests and level ordering

The controller preserves the incoming pointer/length pair at `rsp+0xb8/+0xc0`.
It performs two sequential, separately emitted paths. The first uses the exact
5-byte literal **`error`** (`0x2194e1`); the second uses the exact 4-byte literal
**`warn`** (`0x209d2c`). There is no additional level iteration in this FDE.

For each level, the byte template at `0x1f4ea6` is:

```text
c0 0a /data/log/ c0 01 / c0 01 / c0 00
```

Its four paired formatting rows contain, in order:

1. Object `0x577b288 + 0x18`, reached through slot `0x576e928`, with callback
   `0x14443e0`.
2. The preserved incoming pointer/length pair, with callback `0x14ddab0`.
3. The current level pointer/length pair, with callback `0x14ddab0`.
4. A 32-bit word returned by `0x151cec0`, with callback `0x1454a00`.

The last word is obtained separately for each level: call
`0x576e8a0 -> 0x151cba0`, pass that output and `edx=0` to
`0x576ea48 -> 0x151cec0`, and reject a zero first dword. No exact date rendering,
calendar consistency between the two calls, or live root path is claimed.
The template therefore requests
`F0(context)/data/log/F1(role)/F2(level)/F3(word)` under ordinary formatter
returns. The resulting path's literal fragments and row order are established;
its complete runtime text depends on those callbacks and values.

Template decoding uses only short literals, tag `0xc0` (next implicit row),
and the zero terminator, as already established by the merged
`RE-001-format-request-controller-94` packet and
`src/node94-format-request-protocol`. The new verifier rejects other tags in
this selected subset. It does not claim to reconstruct the shared formatter,
string display callbacks or numeric/date formatting again.

## Source eligibility and normalized-content gate

The controller calls `0x576e9e8 -> 0x144a710` on the constructed path. A zero
raw `AL` skips the current level. The helper's local contract is explicit:

- Call `0x144a2f0` on the path. That helper calls the shared metadata provider
  `0x4edfb40`, tests its first qword against 2 for the disposal route, and
  finally sets `AL` according to whether that word's **low dword** differs
  from 2. An error carrier is disposed where applicable.
- If that first predicate is false, return zero. Otherwise call the metadata
  provider **again**. A result tag 2 takes an error-disposal/false route.
- On the second success route, set the low return byte to
  `((u32[metadata + 0x38] & 0xf000) == 0x8000)`. No upper-return-bit
  meaning is claimed.

Those constants identify the Linux regular-file mode. The retained metadata
fallback calls the dynamically bound **`stat64`**, copies 0x90 bytes of its
output to metadata `+0x20`, and sets its success tag to zero. The predicate's
`+0x38` then corresponds to the `stat64` mode at `+0x18`. The first predicate
checks metadata success, whereas the second also checks the mode. Errors are
not distinguished from false classification at the controller boundary.

The native metadata helper's alternate fast path, long-path allocation,
symlink handling and race behavior are not closed here. In particular, no
atomic file-existence guarantee is claimed. The two metadata calls and their
local return tests are observations from complete helper bodies.

After a true regular-file result, the controller calls
`0x576e958 -> 0x144c330` with the path and a source Location:

| Record | Source path | Line:column |
| --- | --- | --- |
| `0x566a0d8` | `/home/ubuntu/hl/code_Mainnet/base/src/production.rs` | 141:38 |
| `0x566a0f0` | same | 141:68 |
| `0x566a108` | same | 149:39 |

`0x144c330` first calls `0x576f648 -> 0x4ed9180`. It recognizes the returned
first-word sentinel `0x8000000000000000` and turns that into its own error
sentinel. On its normal route it passes the returned pointer/length through
**`0x1407ac0`**, the whitespace-trim helper already exported and interpreted in
`RE-001-build-mode-94`. It allocates/copies exactly the returned trimmed range,
then writes `(trimmed_length, owned_pointer, trimmed_length)` to its output.
The empty case uses a sentinel pointer 1 and a length-zero copy.

The controller tests the helper's error sentinel with `neg`/overflow and takes
the source-bound panic/formatting route on that sentinel. Otherwise it tests
output `+0x10`, the **trimmed length**, not the original input length. Zero skips
the move; nonzero enters the backup-name loop. Thus whitespace-only valid text
is excluded under the established trim-helper contract. This packet does not
re-prove Unicode classification, UTF-8 admission, file read error semantics,
allocation failure handling or the lower-level reader's full I/O behavior.

## Backup collision loop and counter overflow

For each admitted level independently, the controller initializes a 64-bit
counter to zero. The candidate template at `0x1de8d5` is:

```text
c0 07 _backup c0 00
```

The first row formats the original path with callback `0x14443e0`; the second
formats the counter with the RELATIVE-bound callback `0x1570900`. The complete
numeric renderer is not part of this recovery. The controller passes each
candidate to **the same regular-file predicate `0x144a710`**.

| Path | Format/probe | Counter increment | Move request |
| --- | --- | --- | --- |
| `error` | `0x14387e0..0x143883b` | `0x1438845..0x1438856` | `0x14388b3..0x14388d4` |
| `warn` | `0x1438ad0..0x1438b2b` | `0x1438b35..0x1438b46` | `0x1438ba3..0x1438bc4` |

A nonzero predicate result discards that candidate and retries. The increment
is `inc rax; cmove rax, -1`, with the `-1` register prepared before the loop.
Over the u64 domain it is `min(n + 1, 2^64 - 1)`: maximum minus one advances to
maximum; maximum stays maximum. There is no local exhaustion return or wrap
back to zero. Conditional on repeated true results and ordinary helper returns,
the maximum candidate can be requested repeatedly.

A zero predicate result selects the candidate for the move helper. This admits
anything that the regular-file predicate classifies false, including metadata
failure and non-regular objects; it does not establish that the path is absent.
The controller does not test the selected candidate's contents.

## Move payload and continuation

The controller passes `(source_pointer, source_length, candidate_pointer,
candidate_length)` to `0x576f498 -> 0x144cf90`. That wrapper:

1. Checks source metadata success through `0x144a2f0` again.
2. On success, lays out three borrowed pointer/length pairs:
   **(`mv`, 2), source, candidate**. The exact two-byte literal is at `0x219c6a`.
3. Calls `0x1455c00` with the prepared records and a zero state byte. Existing
   consumer packets bind that helper's body/callers and a single-space delimiter
   store; its full input/output contract stays opaque here. The local move
   wrapper does not directly call the libc `rename` symbol.
4. On a normal returned-buffer route, packages the result with a tag byte 1,
   calls `0x576e8c8 -> 0x13e4e40`, releases the buffer, and forwards that helper's
   result. Other routes call `0x14b5f70` or `0x14b5530`; their full behavior is
   outside this packet.

The controller tests the returned pointer. Zero selects the print request
whose template is **`renamed {source} -> {candidate}\n`** at `0x1e113f`.
Nonzero calls through the first word of the returned object's table instead.
If these calls return normally, both branches release local buffers and
continue: from `error` to `warn`, or from `warn` to the sole controller `ret`.
No automatic retry of the move result is visible in this controller.

The diagnostic is evidence of a selected print branch, **not evidence that an
actual filesystem move succeeded**. The lower-level command consumer, process
status interpretation, quoting, cleanup callback types and external effects
remain unresolved here. No file, directory, command, captured process or live
service was accessed or executed to infer this protocol.

## Prior work, uncertainty and next question

`overlap.json` records searches across all PR states and the committed tree,
plus changed-file/available-patch inspection of every open PR and adjacent closed
work. Related research is credited rather than counted as new recovery:

- #1120 records the regular-file helper as an opaque target for archive-prefix
  preparation; it covers a different controller and does not decode this body.
- #576 records the content helper and its error sentinel in host-IP admission,
  explicitly leaving trimming/I/O unknown. The new packet binds its normal
  trim/copy/output-length path to this backup controller.
- #634/#658/#725 cover the join helper and its callees. The move wrapper appears
  as one caller-range entry, not a recovered three-slice `mv` request.
- #614 supplies the existing trim and compact-template context. #423/#121/#349
  concern daily/hourly writer constructors and rotation, at different addresses.
- #583 is a separate restart-command token filter. #1409 is the production
  600-second poll cycle; its body and wait helper are not part of this packet.

The code retains the error and unwind-shaped tails, every primary call and
source Locations, but **does not decode LSDA call-site tables**. Full exception
ownership, allocator cleanup, once initialization, file/provider internals,
source-level function signatures and ABI names remain gaps. Source labels are
inferences from embedded Locations, literals and use sites. A complete source
reconstruction or safe filesystem API is not claimed.

Next question: close the prepared-record contract of `0x1455c00` and result
contract of `0x13e4e40` before interpreting the zero/nonzero move-helper outcome
as a specific external command status.

## Reproduce and controls

Run from the repository root after materializing the pinned captures. Tools:
Python 3.14.7, GNU binutils 2.47.20260726, LLVM 18.1.4. Put GNU binutils and LLVM
before platform alternatives on `PATH`; both exports use x86-64 Intel syntax.

```sh
python3 research/work-items/RE-001-startup-log-backups-94/export_disassembly.py
python3 research/work-items/RE-001-startup-log-backups-94/verify.py --controls
python3 -m unittest discover -s tests -p test_startup_log_backups.py -v
make doctor verify test catalogue-check reproduce
```

Export regeneration decodes entire owning FDEs before choosing support windows.
`verify.py --write --controls` deliberately regenerates JSON; without `--write`,
it rejects mismatches against retained records. The checker reads captured
bytes and data; it is neither an x86 emulator nor a filesystem behavior mock.

Four focused methods pass. They compare regenerated records from the actual
capture, reject an incorrect whole-image identity, exercise full export-byte
equality on a changed prologue outside semantic obligations, and reject
**70/70** mutations below the whole-image/body-hash and export guards. The
controls cover 30 instruction spans, 15 relative targets, four dynamic-symbol
name/type changes, nine Location pointer/length/line changes, seven literals/
templates and five FDE extents. `controls.json` retains each rejection.

`validation.json` records the required gates, complete official test inventory,
source commit, tool versions, denominators and log hashes. Full-suite modules
run exactly once in isolated worktrees with a fresh interpreter per module,
matching the official `tools/run_tests.py:test_files` inventory. These tooling
results do not establish captured runtime equivalence. No progress/catalogue,
reference pin or byte-coverage registry is changed. New verifier/test code and
documentation are independently authored under the repository MIT license;
imported binary evidence retains its original rights.
