# RE-012: node115 poll TLS gate and conditional restoration

- Component: `transport`, with shared runtime context; RE-012, bounded static research.
- Target: Linux x86-64 node **115**, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes).
- Repository/reference base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
  No private or unlicensed inferred source is copied. New analysis code/docs are MIT;
  the captured artifact retains its original provenance and rights.
- Question: when the sender delegates to `0x5ce94c0`, which TLS bytes select its
  wrapped path, and what values does that path restore on return and in its
  encoded unwind cleanup? Prior deadline/core/context packets leave this gate open.
- Claim: address-specific static observations plus conventional LSDA interpretation.
  No Rust implementation, captured execution, CPU emulation, equivalence claim,
  byte-comparison registration, component-gate advancement or current-network claim.

## Evidence and observations

All coordinates below are ELF virtual addresses; ranges are half-open. FDEs are
unwind-described extents, not a claim to have discovered every source function.
`records.json` retains exact FDE/CIE records, mapped file offsets, body hashes,
anchors, unique relocations, dynamic symbol names and parsed call-site entries.
`native/` preserves complete GNU/LLVM exports for four selected FDEs: wrapper
247 bytes, cleanup 85, callback 71 and registration context 255; **658 bytes and
174 logical instructions** in total. Those are observation denominators, not
reconstructed or newly credited bytes. A separate 31-byte sender slice is context.

### Caller and delegation

The sender's full FDE is `0x2b7a290..0x2b7b523`, with its complete body hash in
the record. Only the call-site slice `0x2b7b071..0x2b7b090` is exported/analyzed
here; this is not a new recovery of the sender's complete state machine.
At `0x2b7b077` it copies `r15b` to `edi`, masks `edi` with 1, loads `rsi` from
`[rsp+0x40]`, sets `rdx=r13`, and calls through `0x64e1358` at `0x2b7b086`.
The unique `R_X86_64_RELATIVE` relocation at that slot targets `0x5ce94c0`.
The local source roles/types of these arguments remain unassigned.

The wrapper preserves its incoming `rsi` in `r14`. Its guarded CALL at
`0x5ce953e` and direct tail JMP at `0x5ce9595` both resolve through the unique
relative slot `0x64e0858` to `0x5cf2d30`, passing the old `rsi` as `rdi` and old
`rdx` as `rsi`. The core helper is peer-owned context, not reconstructed here.

### TLS selection and ordinary return

The wrapper sets `r15=-0x1130` and obtains a storage pointer from `fs:0+r15`.
Use **S**, **A**, **B** below only as local labels for the bytes at
`fs:[r15+0x48]`, `fs:[r15+0x44]`, `fs:[r15+0x45]`, respectively:

| Selection | Statically observed route |
| --- | --- |
| Entry S=2 | Direct tail delegation; gate A/B not examined |
| Entry S=1 | Continue to DIL/A/B checks |
| Entry S other | Call registration context, then write S=1 if it returns; continue |
| DIL=0, or A=0, or B nonzero | Direct tail delegation |
| DIL nonzero, A nonzero, B=0 | Write A=0; save stack word `0x0001`; wrapped CALL |

These branch conditions apply when reached, after any registration call. Direct
tail delegation has no wrapper A/B write, but the wrapped core and registration
context are not assumed side-effect-free. Before the wrapped call, the stack
word at `[rsp+0xe]` contains bytes **1,0**, not a copy of arbitrary entry A/B.

After the guarded call returns, the wrapper re-reads S. S=2 skips restoration.
S=1 writes the TLS word at A to `0x0001` (`0x5ce956e`). Other S values first
call registration context, write S=1 if it returns, and then write that word.
The call result in EAX is preserved around that registration call. Thus this
is conditional restoration to canonical bytes **A=1, B=0**, not unconditional
restoration of the previous word. Nothing here establishes the core's TLS writes.

### Unwind table and cleanup

The wrapper FDE links through CIE `zPLR` to LSDA `0x40360c`, using encoded
PC-relative signed 32-bit pointers. Its CIE personality slot `0x64efa28` uniquely
relocates to `0x5cad7b0`; that personality's body is not reconstructed here.
The observed LSDA header omits LPStart, uses type encoding `0x9b`, and gives a
ULEB call-site table of 25 bytes. The parser retains all five intervals:

| Call-site interval | Landing pad | Action |
| --- | --- | --- |
| `0x5ce94c0..0x5ce9538` | none | 0 |
| `0x5ce9538..0x5ce9544` | `0x5ce959b` | 0 |
| `0x5ce9544..0x5ce959e` | none | 0 |
| `0x5ce959e..0x5ce95a9` | `0x5ce95b1` | 1 |
| `0x5ce95a9..0x5ce95b7` | none | 0 |

The guarded CALL's complete instruction lies in the second interval. Under the
conventional non-SjLj LSDA layout, a nonzero landing pad with action 0 is a cleanup;
see the [LLVM libc++abi table layout](https://github.com/llvm/llvm-project/blob/main/libcxxabi/src/cxa_personality.cpp)
and [Itanium unwind ABI](https://itanium-cxx-abi.github.io/cxx-abi/abi-eh.html).
Those are format references, not an assertion that this target uses libc++abi.
The saved raw context is 52 bytes, ending at the next FDE-referenced LSDA address;
**52 is not a proven object extent**. Only the header/call-site table is decoded.
Action/type tables, action 1's meaning and the secondary landing helper stay open.

At landing pad `0x5ce959b`, the wrapper saves the unwind operand, passes
`&[rsp+0xe]` to the cleanup at `0x5cf3190` via unique slot `0x64e13b0`, then
passes the saved operand to `0x63f0a50`. The latter PLT jump resolves through
`R_X86_64_JUMP_SLOT` at `0x64ee178` to dynamic symbol `_Unwind_Resume`.
The cleanup reads the two supplied bytes before testing S. S=2 returns without
writing A/B; S=1 writes them; other values register the callback and set S=1
before writing them if registration returns. For this caller's saved pair, that
means **A=1, B=0** on the restoring route. This closes the static connection
between the wrapped call, encoded cleanup, saved pair and conditional TLS writes.
It is not a runtime guarantee for foreign exceptions, panics or failed cleanup.

### Registration and state-2 store context

Slot `0x64e0510` uniquely relocates to `0x5ca0d20`. The wrapper and cleanup
pass the TLS storage pointer and callback address `0x5cdf410` to it.
When `[0x64ec9b0]` is nonzero, that helper tail-jumps through the slot with
RDI=callback, RSI=storage and RDX=`&0x64fe448`. The slot has one
`R_X86_64_GLOB_DAT` relocation to dynamic symbol `__cxa_thread_atexit_impl`.
This grounds the label *registration context*: it is not evidence that the
callback is invoked to initialize TLS at these call sites. The callback begins
by writing storage byte `+0x48` to 2 before its remaining drop-shaped calls.
Its later calls, refcount ownership, the null-import fallback and the external
destructor API's behavior are not reconstructed. The third operand remains an
address anchor; no recovered source variable name is assigned.

## Reproduce and controls

Run from the repository with authenticated materialized LFS inputs and all six
unchanged pinned source repositories. No target execution or network is needed.
Installed producer tools: Python 3.12.3, GNU objdump 2.42, LLVM objdump 18.1.3;
exact observed strings are in `producer.json`. The collector was run with actual
Capstone 5.0.7 and separately replayed successfully with actual 5.0.6.

```sh
python3 research/work-items/RE-012-poll-tls-gate-115/produce.py
python3 research/work-items/RE-012-poll-tls-gate-115/collect.py --check
python3 -m unittest discover -s tests -p test_poll_tls_gate_115.py -v
python3 -O -m unittest discover -s tests -p test_poll_tls_gate_115.py -v
make doctor verify test catalogue-check reproduce
```

The producer selects `objdump -d -M intel --insn-width=16` and
`llvm-objdump-18 -d --x86-asm-syntax=intel`, with exact start/stop addresses from
`collect.py`; it runs against the relative path `artifacts/node/115/hl-node`.
The collector requires byte-complete coverage, FDE/executable membership and
identical instruction partitions. LLVM splits two LOCK prefixes in the callback;
only those two explicit prefix/continuation joins are permitted, without changing
bytes or operands. The first strict-partition rejection is retained in validation
as an analysis-format negative result, not a target defect. The first full test
run also exposed a stale packet README hash after an editorial change during
testing (76 test files passed, one manifest-coverage test file failed). That
log is preserved as `required-initial-failure.log`; the packet was then frozen,
resealed and the complete required command rerun. This was an author-side
evidence-sealing error, not a pre-existing failure or target behavior.

Ten focused tests check normal evidence and deliberately corrupt restore
operands, sender mask, callback state, relocation uniqueness/target, import name,
FDE/CIE linkage, LSDA landing/action/encoding/bounds, native bytes/completeness and
LOCK continuation. These test evidence rejection, not execution of invented
runtime semantics. Exact commands/results and retained logs are in `validation/`.
No imported evidence, source pins, component gates or byte-window registry change.

## Ownership, limits and next question

Before selecting this question, all 233 then-open PR titles/bodies and exact
address searches were checked. Related work includes sender prefixes (#2068),
reader policy (#2076), core timer (#2125), context/coop helpers (#2137), vtables
(#2158), writer charge (#2166), waker registration (#2179), runtime entry (#2028)
and dependency windows (#2050). Own #2117 covers greeting deadline selection.
These are adjacency references, not proof of their correctness or exhaustive
ownership absence; a fresh submission-time observation is in `validation/`.
Their core, context, source-identity and state-machine claims are not adopted.

Before this packet, this wrapper's registration was opaque and its cleanup route
was not bound in these research records. After it, the caller, both delegation
edges, conditional normal restoration, encoded cleanup path and callback's
state-2 store are grounded in one target-specific record with rejection controls.
The entire sender, timer, TLS source type/identity, fallback registration,
personality/action tables, unwinder and scheduler integration remain unresolved.
Full-scope gates remain **0/92**, whole-ELF equivalence is unproved, and no new
compared implementation bytes are claimed. Next: identify the TLS source/type
from licensed source and validate the personality's interpretation before any
independently authored Rust implementation or runtime behavioral claim.
