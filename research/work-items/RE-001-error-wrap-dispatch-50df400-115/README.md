# RE-001: node #115 error-wrap dispatch 0x50df400

## Bounded question

The merged loader-checkpoint packet
(RE-017-loader-checkpoint-result-115) named two callers of
the routine at `0x50df400` in its transfers.tsv --
`compact_binary_error_wrap` (site `0x50ddc6a`) and
`expanded_binary_error_wrap` (site `0x50dedca`) -- but left
the callee body itself as a boundary, and the merged
curl-body-helper packet (RE-012-node115-curl-body-helper)
recorded a call to it with "Error/result enum names are
unknown" and no account of what the callee does with the
value it is handed. What does the routine at 0x50df400
actually do: what does it pass to its one unconditional
callee, what does it read from the 24-byte value its second
argument points to, and which payload word, if any, does it
drop on which discriminant?

## Answer, pinned to the target

The routine (FDE `0x50df400..0x50df4b6`, 182 bytes) takes
rdi = an opaque pointer it never dereferences and rsi = a
pointer to a 24-byte value: a tag word at `+0x00` and
payload words at `+0x08` and `+0x10`. It has no loop, and
it writes nothing outside its own stack frame.

**Step 1: descriptor build and the wrap call
(unconditional).** The routine assembles a 32-byte
descriptor in its frame and calls the wrap callee
`0x5101070` (FDE `0x5101070..0x51010aa`, 58 bytes; body by
contract only) once, with rdi = `0x44e417` (a .rodata
address inside the binary's string-fragment table) and
rsi = the descriptor address:

| word | value |
| ---- | ----- |
| `+0x00` | the routine's rdi argument, verbatim |
| `+0x08` | the constant `0x5616320`: a 19-byte thunk (FDE `0x5616320..0x5616333`) that loads a two-word environment from its rdi argument and tail-jumps through GOT slot `0x64df520` (R_X86_64_RELATIVE to `0x1681da0`) |
| `+0x10` | the routine's rsi argument (the value pointer), verbatim |
| `+0x18` | the qword loaded from GOT slot `0x64e0a48`, which its R_X86_64_RELATIVE record resolves to `0x5c3f000` (FDE `0x5c3f000..0x5c3f100`) |

The wrap callee's rax is the value this routine returns on
every non-exception path.

**Step 2: the discriminant.** After the call, the routine
loads the tag word T = `[value +0x00]` and computes an
effective discriminant: `T XOR 0x8000000000000000` when T,
read as a signed qword, is negative (the `cmovs` at
`0x50df455` keys on the tag's own sign), and the constant
4 otherwise.

**Step 3: discriminants 1..3 return at once.** Tested as
`(disc - 1) < 3` unsigned: the routine returns the wrap
result without reading either payload word and without
dropping anything.

**Step 4: discriminant 0 drops the `+0x10` word.**
Discriminant 0 forces T == `0x8000000000000000`. The
routine calls the drop callee `0x50f0580` (FDE
`0x50f0580..0x50f064e`, 206 bytes; body by contract only)
with rdi = the payload word at `+0x10`, passed by value,
then returns the wrap result.

**Step 5: the slow path drops the `+0x08` word, tagged.**
For disc == 4 or disc >= 5: if T == 0 the routine returns
the wrap result untouched (tag 0 reaches this path through
the default discriminant 4, and the explicit zero test at
`0x50df47e` saves it). Otherwise it calls the function
pointer stored in GOT slot `0x64df4a0` -- resolved by its
R_X86_64_RELATIVE record to `0x635de30` (FDE
`0x635de30..0x635ded5`, 165 bytes; body by contract only) --
with rdi = the payload word at `+0x08` (by value),
rsi = T (the tag word, still in rsi from step 2) and
rdx = 0, then returns the wrap result.

**Exception exit.** The block at `0x50df49d..0x50df4b6`
closes the FDE and is the target of no direct branch in
the body; it is the landing pad. It saves the exception
pointer in r14, calls the cleanup callee `0x50f0690`
(FDE `0x50f0690..0x50f06d6`, 70 bytes) on the value
pointer -- that callee opens with the same
tag/discriminant computation as step 2 and is the value's
full destructor -- then calls `_Unwind_Resume` through
the PLT at `0x63f0a50`, and ends with a call through GOT
slot `0x64df4c0` (R_X86_64_RELATIVE to the 20-byte message
stub at `0x1680cab`, FDE `0x1680cab..0x1680cbf`),
reachable only if `_Unwind_Resume` returns. The only call
in the body that can throw is the wrap call (the two drop
calls run on its return path). Exception behaviour is
pinned at this level only; the model and the differential
cover non-throwing runs.

The bytes after the FDE range (`0x50df4b6..0x50df4c0`) are
int3 padding, and the next FDE (`0x50df4c0..0x50df586`) is
a separate routine.

## Consumers (site-only)

The census finds exactly nine direct call sites
file-wide, in nine distinct caller functions, no tail
jumps, no stored qwords and no RELATIVE addends naming
the routine. Caller semantics beyond the sites and FDE
ranges are not claimed:

| site | caller FDE |
| ---- | ---------- |
| `0x50dd97a` | `0x50dd6e0..0x50dd9c4` |
| `0x50ddc6a` | `0x50dd9d0..0x50ddcb4` (the caller RE-017 named `compact_binary_error_wrap`) |
| `0x50ddfa9` | `0x50ddcc0..0x50de008` |
| `0x50de2aa` | `0x50de010..0x50de2f4` |
| `0x50de4e2` | `0x50de300..0x50de518` (the RE-012 curl-body-helper window: on the path pinned there the value is `{0x8000000000000000, 0, 0x2600000003}`, so the discriminant is 0 and the drop callee receives `0x2600000003`) |
| `0x50de9fa` | `0x50de520..0x50deb26` |
| `0x50dedca` | `0x50deb30..0x50dee14` (the caller RE-017 named `expanded_binary_error_wrap`) |
| `0x50df0ba` | `0x50dee20..0x50df104` |
| `0x50df3aa` | `0x50df110..0x50df3f4` |

## NOT claimed

What the 24-byte value, its tag or its two payload words
denote -- the variant names and meanings stay as unknown
as RE-012 recorded them; what the rdi argument points to;
the bodies of the wrap callee `0x5101070`, the drop
callee `0x50f0580`, the GOT-resolved callee `0x635de30`,
the cleanup callee `0x50f0690`, the descriptor thunk
`0x5616320`, its GOT-resolved target `0x1681da0`, or the
function at `0x5c3f000` (all by contract only: this packet
pins only that they are invoked, with the arguments
above, in this order, and how the wrap callee's return
value flows); what the byte content at the descriptor id
`0x44e417` means beyond being passed verbatim; caller
semantics beyond the nine sites and their FDE ranges;
behaviour when the wrap call throws, beyond the
landing-pad level pinned above.

## Evidence

- Artifact: `artifacts/node/115/hl-node`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (provenance/artifacts.json), materialised locally as
  `work/hl-node-115.bin` with the same hash.
- `main.txt`: the whole routine, verbatim, produced by
  `objdump -d --start-address=0x50df400 --stop-address=0x50df4b6 work/hl-node-115.bin`.
  Instruction-level detail lives only in that excerpt
  text, never as a per-instruction list in records.json.
- `records.json`: semantic records only (the descriptor,
  the discriminant rule, the phases, the callee contracts
  as internal call sites, the landing pad, the census,
  the consumers, the closed unknown).
- `frames.txt`: FDE lines for the routine and its nine
  caller functions. `callers.tsv`: the nine direct call
  sites with their smallest enclosing caller FDE ranges.
  `relocations.txt`: the four R_X86_64_RELATIVE records
  the body's own transfers resolve through (the two GOT
  call slots, the descriptor thunk's jump slot, the
  descriptor's fourth-word slot) and the `_Unwind_Resume`
  JUMP_SLOT behind the landing pad's PLT call; no
  relocation record carries the routine itself as addend.
- Census method note: the routine's own control transfers
  are classified from one linear disassembly of the whole
  routine range (true instruction starts only): 4
  internal direct calls (wrap, discriminant-0 drop, and
  the landing pad's cleanup and resume calls), 2 internal
  indirect calls (the GOT-resolved tagged drop and the
  landing pad's closing GOT call), no tail jumps of
  either kind (its only unconditional jump, at
  `0x50df47c`, lands inside the range). The external call
  census uses the exhaustive executable-segment E8/E9
  scan with objdump confirmation per candidate; no
  candidate was rejected.
- `verify.py` re-checks the digest, the manifest, excerpt
  regeneration byte-for-byte against a fresh objdump run,
  every excerpt instruction byte-for-byte against the raw
  binary, spot instructions, the FDE ranges, the
  relocation records, the census, the records, and the
  model tests. `census.py` reproduces the census;
  `export_excerpts.py` regenerates `main.txt`.
- Model: `tools/error_wrap_dispatch_50df400_115.py`,
  tested by `tests/test_error_wrap_dispatch_50df400_115.py`
  (38 checks, including the descriptor word set, the
  discriminant edges -- sign-bit tag, sign|1..5, all-ones,
  largest positive -- both drop paths, the tag-0 save, and
  the value's bytes surviving every path).
- Differential: `differential.py` runs the real 182 bytes
  under Unicorn against the model on 40 cases (the tag
  word's decision edges plus randomised tags, payload
  words and wrap results), with the wrap callee, the
  discriminant-0 drop and the GOT-resolved tagged drop
  answered by the same contract functions the model uses,
  comparing the ordered callee event log (including the
  descriptor's four words read off the native stack), the
  return value, the whole value window byte for byte, and
  the callee-saved registers: 0 mismatches.

## Reproduce

Working directory: the repository root. Tools, all from
this run:

- GNU objdump (GNU Binutils for Ubuntu) 2.42, invoked as
  `objdump -d --start-address=0x50df400 --stop-address=0x50df4b6 work/hl-node-115.bin`
- GNU readelf (GNU Binutils for Ubuntu) 2.42, invoked as
  `readelf --debug-dump=frames work/hl-node-115.bin` and
  `readelf -r work/hl-node-115.bin`
- Python 3.12.3 for `census.py`, `verify.py`,
  `export_excerpts.py`, and the model tests; the Unicorn
  differential additionally needs the `unicorn` package
  (2.1.4 used here).
- Input: `work/hl-node-115.bin`, SHA-256 as above; no
  execution of the target binary (the differential
  emulates the 182 routine bytes only, with the callee
  contracts stubbed), no network, no side effects beyond
  writing the packet files listed in MANIFEST.sha256.

## Verification scope and next step

This packet's own checker (`verify.py`), the model tests
and the Unicorn differential are run before submission
and must print ALL CHECKS PASSED, the model check count
and DIFFERENTIAL PASSED. Repository-wide gates (`make
verify`, `make test`, `make catalogue-check`) are run and
reported separately with the change. The next questions
in this area are the bodies left by contract here -- the
wrap callee `0x5101070` and the two drop callees -- and
what the 24-byte value's variants denote at the nine call
sites.
