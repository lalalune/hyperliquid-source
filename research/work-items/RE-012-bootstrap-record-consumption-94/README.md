# RE-012: node94 bootstrap record consumption and the post-consumption equality gate

- Component: `node-runtime`; bounded static research under RE-012 and RE-001.
- Target: Linux x86-64 node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source base: `e5c9b6436876b2a4a39daef813171f9879317699`.
- Reference gitlink: `999556f6e0a474b8312db96ec3149e1c44e97c23`.
  No inferred reference implementation was copied or executed. New analysis
  code and prose are independently authored under the repository MIT license;
  original capture bytes retain upstream rights.
- Question: how does the selected bootstrap owner iterate returned 32-byte
  records, route a record-consumer result, and decide whether to repeat its
  request window after consumption?
- Claim status: instruction/layout observations below; the labels
  "bootstrap", "record", "height" and "cleanup" are contextual inferences.
  Concrete application types and callback semantics remain unresolved.

## Reproduce

From the repository root, with its pinned node94 artifact materialized:

```sh
python3.11 research/work-items/RE-012-bootstrap-record-consumption-94/reproduce.py
```

Observed: Python 3.11.15, Darwin arm64; Apple LLVM 21.0.0 command-line tools.
The producer uses the reviewed `elf_index.py` and `fde_extents.py` parsers
(source hashes in `records.json`) and the installed LLVM objdump/dwarfdump.
The exact commands and options are retained in the records and transcripts.
Only static file reads and packet-output writes occur. No captured node,
network service, signing operation, real account or runtime fixture is run.
This macOS reproduction selects existing Apple tool paths; other platforms
need equivalent LLVM commands, rather than silently substituting a decoder.

The producer authenticates the complete target first. It decodes actual
CIE/FDE records, checks the unwind-index entry, checks LLVM's independently
decoded FDE, and linearly decodes the entire owner from its entry using LLVM.
Every decoded instruction's original bytes must match the target, with no
gaps, unknown instructions or premature end. The complete owner has **864
instructions / 4,892 bytes**. Only five selected windows (**64 instructions /
368 bytes**) are exported and interpreted here; neither count is whole-node
coverage or an equivalence denominator. There is no operand normalization.
The retained dwarfdump text removes surplus trailing newline characters and
ends in one newline; this text formatting does not alter instructions or metadata.

## Evidence and observations

Coordinates are linked ELF VAs, not a runtime or guessed Ghidra base. File
offsets are resolved from the authenticated section map (these `.text`
coordinates map to file offset VA minus `0x1000`). FDE ends are exclusive.
The owning unwind range is `0x4389070..0x438a38c`, FDE VA `0x123787c`, CIE VA
`0xfbdc2c`. Its original code hash is
`78db20a2c3de64e35135b7730c8b45e77a3b551674136401c6f2de70f4d5f00f`.
An unwind range is not a complete source-level function or reachability proof.

1. At `0x438994e..0x438997f`, the code shifts R15 left by five and adds R13,
   then stores R13 at state `+0x120` and `+0x128`, R12 at `+0x130`, and the
   calculated end at `+0x138`. Equality of cursor and end skips record copying.
   The shift/add operate on raw 64-bit words; no high-level allocation bound
   or overflow rejection is established by this slice.
2. At `0x4389988`, it calculates cursor plus `0x20` and stores that next cursor
   at `+0x128` **before** the record-consumer call. Two 16-byte loads copy the
   current 32-byte record to `+0x140..+0x160`. A zero first qword branches to
   `0x4389ae1`; otherwise another copy supplies a stack argument. This is an
   observed zero test, not proof that zero denotes an absent block or that
   malformed records are accepted.
3. At `0x43899e1`, the call uses RIP-relative slot `0x5776668`. Its original
   slot bytes are zero; the unique `.rela.dyn` `R_X86_64_RELATIVE` record has
   addend `0x4360000`. Both relocation bytes and callee FDE extent are in
   `records.json`. Arguments immediately before the call include the state
   pointer loaded from `+0x88`, the 32-byte stack copy and an output pointer.
   A restored `R14` output word is compared with `0x8000000000000040`.
   Non-equality branches to `0x4389f4d`, saves the remaining returned words,
   calls `0x44c6e70`, then joins the common output path. Equality initializes
   a separate continuation state at `+0xc8`; it does not immediately prove
   that the application state advanced or that the record was valid.
4. The selected resume arm at `0x4389aae` reloads next cursor from `+0x128`
   and end from `+0x138`. If unequal, it returns to `0x4389988`. On equality,
   `0x4389ada` writes a zero first qword at the temporary record and falls
   through to the same direct call at `0x4389ae1`. The helper target is
   `0x44c6e70`; its cleanup role is inferred, and its body is excluded.
5. After intervening diagnostic/helper work, `0x4389c14..0x4389c39` **reloads**
   the target word from state `+0x98` and the current word from
   `[state+0x88]+0x108`. If unequal it branches to `0x43892af`, the existing
   unsigned ahead/window decision. If equal it stores byte 1 at
   `[state+0x88]+0x118`. This check compares current state, not record count,
   requested end or the last record's embedded field. The same completion
   store is also reachable directly from the earlier equality branch at
   `0x43892a9`, so it is **not** uniquely evidence of consuming a batch.

The prior packet `RE-001-bootstrap-window-94` / merged PR #588 establishes
the request-window arithmetic and retains a complete Capstone owner export.
This packet freshly checks its owner hash against the target using LLVM;
it adds the selected consumption/control-flow observations above. Open PR
#1831 reconstructs the earlier window arithmetic and explicitly excludes
callbacks, response verification and state advancement. No prior packet is
modified, and no full async bootstrap claim is made.

## Validation, controls and limitations

`records.json` contains original window bytes, 18 instruction probes, the
callback relocation, independent FDE metadata, parser identities, and six
negative controls. The controls privately change the cursor stride, zero
test immediate, callback displacement, result-tag offset, repeat-branch
displacement and completion-byte value. Each runs the same operand validator
with a patched read view and must fail at the expected probe. These are
static evidence-corruption controls; they do not execute the target or prove
application behavior. `validation.json` records a second exact regeneration.

Before this packet, main had the raw owner export and a bounded request-window
arithmetic interpretation. Afterward it has a reproducible account of these
specific record-consumption and post-consumption branches. No independently
authored Rust, source build, runtime behavior comparison, ABI equivalence,
byte-match credit, helper closure, complete CFG, full async state machine,
component completion or acceptance-gate change is claimed. Callback and
cleanup bodies, allocator invariants, record types, panics, indirect dispatch,
continuation scheduling, and actual application-state writes remain open.

Next question: establish the selected consumer `0x4360000`'s argument/return
layout and state writes, then connect its `0x8000000000000040` result to the
continuation path without assuming source-level `Result`/`Poll` labels.
