# RE-012: gossip lookup word layout and the local comparison-result corridor

- Task/component: RE-012 / `node-runtime`, bounded static research.
- Target: Linux x86-64 node #94, `artifacts/node/94/hl-node`, 91,774,280 bytes,
  SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source base: `e5c9b6436876b2a4a39daef813171f9879317699`.
- Reference gitlink: `999556f6e0a474b8312db96ec3149e1c44e97c23`. No inferred
  reference code, types or tests are copied. New analysis is independently
  authored under the project MIT license; original bytes retain upstream rights.
- Question: after compiled identifier construction, how does the caller find
  its next row and project its words, and is the following comparison return
  byte actually used as a local branch condition?
- Status: instruction/offset observations; tree, row, round and set labels
  are inferences. The directory name is a research allocation, not recovery of
  a source-level round type. No gate is requested or changed.

## Reproduction and validation

From the repository root with the pinned input materialized:

```sh
python3.11 -B research/work-items/RE-012-gossip-round-lookup-94/collect.py
```

Observed: Python 3.11.15, Darwin arm64, Apple LLVM 21.0.0 command-line tools.
The collector reads the authenticated image and invokes only installed static
LLVM objdump/dwarfdump, with exact commands in the retained text files.
Reviewed `elf_index.py` and `fde_extents.py` parser hashes are in `records.json`.
The installed Apple LLVM paths are explicit; another platform needs equivalent
static commands. Only packet outputs are written. No captured executable,
instruction evaluator, networking, signing, real dataset or model call runs.

The owner is `0x4743490..0x4744152`, **3,266 bytes / 584 LLVM instruction
rows**. Actual CIE/FDE and unwind-index decoding and independent LLVM
dwarfdump agree. The complete owner is linearly decoded from its entry with
every byte, boundary and exact end checked against the input. Only
`0x47436a4..0x4743896`, **498 bytes / 91 rows**, is newly interpreted here.
All 13 direct branch destinations in that selected interval are decoded from
their original operands and checked against owner instruction boundaries.
This is not a complete CFG, source-function census or matched-byte denominator.
The rest of this already exported owner is context, not new reconstruction
coverage. All addresses are linked ELF VAs; ends are exclusive. File offsets
are section-resolved. No runtime/Ghidra base is guessed.

Retained text removes surplus trailing newline characters and ends in one
newline; no instruction/data/operand normalization occurs. There was no timeout
or reduced analysis database. `validation.json` records a second byte-identical
generation of all generated outputs. The collector verifies 26 instruction
spans and four direct call boundaries. Thirteen real patched-read controls
alter lookup offsets, unsigned-comparison encoding, value stride, child offset,
matched fields, initialization, a callee displacement, the flags-defining TEST,
local branch and both RAX definitions. Each runs the same local operand
validator below the outer digest check and rejects. These test evidence
admission, not execution semantics or Rust equivalence.

## Lookup observations

The entry copies RSI into R15; identifying the later R15 with that original
input assumes ordinary ABI preservation across the preceding helper calls.
At `0x47436a4` it loads a root-shaped pointer from current `[R15+0x3870]`.
A zero pointer branches to `0x474374b`. Otherwise
it loads the query qword from `+0x3888`, a remaining-depth word from `+0x3878`,
and a node count as u16 from `[node+0x21a]`.

The node's qword comparisons use stride 8: `[node+8*i+8]`. In parallel, a
value offset advances by 40 for each examined key (`0x4743702`). The CMP at
`0x47436f5`, SETA and SBB produce the unsigned comparison classes 1, 0 and
`0xff` for query greater, equal and less. Class 1 continues through keys.
Class 0 reaches the matched path; otherwise the code subtracts one from the
remaining depth and, if it does not borrow, loads a child through
`[node+8*i+0x220]`. Exhausted depth and a zero initial root take the same
missing path. These are observed machine-word widths and addressing rules;
`BTreeMap<u64, ...>` and the validity of a node count/layout remain unproved.

On the matched path, at key index i the selected value qword is at
`node+0x60+40*i`. This follows because the running offset was incremented
before equality is handled; the instruction at `0x4743733` uses offset
`running+0x38`. The next load reads 16 bytes at value `+8`. The final 16 bytes
of the apparent 40-byte row are not projected by this slice.

- If the selected first word W is zero, `0x4743776` zeroes XMM0 and EAX.
- If W is nonzero, the 16 payload bytes are loaded into XMM0 and EAX becomes 1.
- Both paths retain W in RCX and construct a larger stack descriptor from
  EAX, W and those payload bytes before calling `0x3bb3c40` at `0x47437d6`.
  RDI points to stack `+0x18` and RSI to the descriptor at `+0x90`. The caller
  then copies three output words into stack `+0x1e0..+0x1f8`.

This establishes a projection controlled by W, **not** a proven Rust Option,
Vec, container tag, row field name, ownership contract or output schema.
Actual helper/alias effects and normal return remain unclosed assumptions.

The missing path is distinct: it writes scratch word `0x97`, zeroes words at
stack `+0x1e0` and `+0x1f0`, calls `0x3379490` with a scratch pointer, then
joins the following comparison setup. The middle word at `+0x1e8` is not
initialized by these selected stores. This is not a claim of an invalid read:
the called helper and subsequent consumer have their own contracts. No default
value, error variant or helper-side memory preservation is invented here.

## The normal comparison-return corridor

At `0x47437f3`, arguments are RDI = `&stack[0x1e0]` and RSI =
`&stack[0x120]`; the direct call at `0x4743803` targets `0x49a58f0`.
The second pointer names the earlier constructed identifier container. This
callee is existing comparison context in `RE-008-heartbeat-path-94`; its body
is **not** newly recovered here. Direct target and real callee FDE boundaries
are retained as data only, with no claim that a prior model establishes this
call's full effects or the two argument types.

After this call returns normally, the local instructions are:

| VA | Relevant effect |
| --- | --- |
| `0x4743808` | Load RCX from stack `+0x1e0`, without reading AL |
| `0x4743810` | TEST RCX,RCX defines the ZF used below |
| `0x4743813` | Store R12 to a stack slot, without reading AL |
| `0x474381b` | JE `0x474385a`, using that TEST's ZF |
| `0x474381d` | Nonzero path: load RDX from stack `+0x1e8` |
| `0x4743825` | Nonzero path: load all of RAX from stack `+0x1f0` |
| `0x474385a` | Zero path: XOR ECX,ECX |
| `0x474385c` | Zero path: XOR EAX,EAX, defining all of RAX |

Both direct local continuations overwrite AL as part of a full RAX definition
before any local read of that returned byte. The branch consumes the reloaded
candidate first word, **not** AL or the call's prior flags. The collector
checks both byte-supported corridors and their boundaries. This result is
limited to ordinary return at this call site: it does not say the comparison
is globally irrelevant, pure, unreachable or safe to remove. Reads, faults,
panic/exception exits, call-side memory effects and effects on other registers
are not erased by a dead local AL result.

The subsequent descriptor at stack `+0x10` is built from the reloaded candidate
words and drives calls to `0x49478b0` in a local loop. This packet records that
direct helper boundary and the loop's zero-word termination test. Iterator,
drop/ownership behavior and downstream selection after `0x4743896` are unknown.

## Before/after, overlap and remaining work

Before: `gossip-config-inventory-94` provides this owner's Location/byte census;
PR #1941 (`RE-012-gossip-seed-key-selection-94`) resolves the preceding selector
and identifier construction but explicitly excludes downstream lookup. After:
the new packet binds the selected query/row projection, distinct missing path
and two local AL-kill corridors to original bytes. It does not repeat seed
selection or claim previously exported bytes as newly recovered coverage.
Full live open PR bodies were checked for these selected addresses and scope.
No other live work claimed the new interval; helper-only context is credited.

No Rust implementation, source build, behavior comparison, compiled byte
identity, complete lookup invariant, whole-program liveness or acceptance gate
is proposed. The query's producer and meaning, valid node counts, concrete row
types, opaque helper contracts/aliases, exceptional paths and downstream policy
remain open. Source-language labels are inferences, not recovered declarations.

Next question: recover the descriptor/iterator contracts through `0x3bb3c40`
and `0x49478b0`, then the selected-intersection consumer, before assigning a
complete peer-selection rule to these raw layouts.
