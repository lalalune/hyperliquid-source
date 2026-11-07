# RE-012: compression context port provenance on node #115

- Component: `transport`; task RE-012, with RE-001 address/data bindings.
- Sole target: Linux x86-64 node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Status: observed static dataflow with distinct outgoing and listener-side port roles.
- Files owned: this evidence directory only. No implementation, imported input,
  submodule revision, shared tool, catalogue or progress gate is changed.

On the selected initial IPv4 construction path, the word stored at context
`+0x90` is the same host-order u16 that becomes the destination port in the
address passed to the imported `connect`. This resolves a producer/width
unknown left by the compression-selection evidence. The constructor writes
**two bytes**; the sender reads **four bytes**, but its eligibility comparison
uses only the low two bytes. The other two bytes are not initialized by this
constructor and must not be called part of the port value.

This is a bounded path claim, conditional on valid initial states, selected
normal helper returns, the ordinary imported `memcpy` contract, and absence of
unmodeled alias mutation. It is not an assertion about every sender caller,
every context producer, a successful connection, or a completed compressed send.

The [second-caller follow-up](SECOND-CALLER.md) additionally binds a different
initial caller to the same producer and the constant port 4002. Its separate
4,479-byte interval and 12 corruption controls supplement the first-route
metrics below; neither result establishes all caller states.

The [remaining-route follow-up](ROUTE-MAP.md) maps six encoded sender call
sites and five constructor sites. It also traces a selected listener's
requested local bind port 3999 into the same constructor field. Consequently,
`destination_port` is not a valid universal name for this field. The original
outgoing interpretation above remains limited to its selected path.

The [member-lifetime follow-up](MEMBER-LIFETIME.md) now records the selected
24-copy relation in each large caller from its input field to context
`+0x1118`, plus its direct operand and cleanup-call inventory. Intervening
helper mutations and all resumed states remain unclosed.

The [post-copy helper follow-up](HELPER-WRITES.md) resolves the direct write
destinations of `0x2cd0910` and `0x2cd06c0` on selected call-free insertion
paths. Their current-allocation writes miss the tracked `+0xc8` word;
alias/concurrency premises and the other helper branches remain open.

The [poll-prefix follow-up](POLL-PREFIX.md) binds dispatch tables, header/TLS
guards and writes before the two calls into large A. Selected TLS-1/2 paths
have no earlier call and only a header write into the allocation; the TLS
registration branch and scheduler/alias/concurrency premises remain open.

The [TLS write-region join](TLS-WRITES.md) revalidates existing #115 key and
growth evidence and connects it to the tracked field. It exposes the TLS
self-pointer identity, list bounds and imported-runtime contracts required
for the remaining registration path; no new function-body credit is claimed.

The [factory follow-up](FACTORY-JOIN.md) joins the selected accepted-context
field to large caller A's initial input through both executor factories.
It preserves the explicit scheduler/helper premises and does not establish
the initial origin of twin large caller B.

The [accepted-state cleanup join](CLEANUP-JOIN.md) binds the selected acceptor
return to state byte 1 and a 13-instruction cleanup path with no object writes
or nested calls. The intervening copy still requires ordinary imported
behavior, distinct state/stack storage and preservation of the state byte.

The [outer handoff write census](HANDOFF-WRITES.md) accounts for six copies,
state/global/TLS writes and the context helper before both executor calls.
Its selected TLS-1 paths preserve the word conditionally; a nested helper's
12-byte scratch write also limits the older direct-only no-write observation.

The [conditional-result supplement](LOOKUP-RESULT.md) bounds `0x1546570`'s
sentinel/result writes and its classifier's normal-domain division relation.
It preserves the unwritten output-byte gap and distinguishes a sentinel from
the parent returning without later context effects.

The [formatter-output supplement](FORMAT-OUTPUT.md) binds both changed-result
templates to their callbacks, a zero-capacity initial header and a 24-byte
result. It revalidates the dispatcher/append traces and narrows the growth
boundary to `0x141e0e0`; nested callback and allocation effects remain open.

The [allocation-result supplement](ALLOCATION-RESULT.md) bounds that wrapper's
six result paths, its two allocator bindings, and the grow/error consumers.
It preserves the unwritten error word and adds signed-size/doubling limits;
payload preservation and old-allocation ownership remain unclosed.

The [allocator-path supplement](ALLOCATOR-PATHS.md) identifies two call-free
fresh returns with TLS metadata writes, connects existing-buffer delegation
to `0x6365660`, and revalidates shared runtime-table writer bindings. It
preserves unknown table values and allocator ownership rather than assuming
them from file bytes or entry names.

The [reallocation-path supplement](REALLOCATION-PATHS.md) bounds selected
same-pointer, copy and old-pointer cache-insertion routes at `0x6365660`.
It binds memcpy's unsigned size minimum and preserves metadata changes on
same-pointer/null results; general ownership and the caller continuation
remain open.

The [accounting-return supplement](ACCOUNTING-RETURN.md) joins that caller
continuation to its two counter updates, four call-free threshold-helper
leaves and a conditional `0xA5` tail fill. Null results skip these caller
effects but retain preceding metadata changes; mutable globals, imports,
event-triggering branches and general ownership remain open.

The [fresh-fallback supplement](FRESH-FALLBACK.md) bounds small cached returns,
null/error writes and the first refill-call interfaces at `0x6353a70`. It
distinguishes the fast entry's budget and exhausted-slot conditions and
reuses the established mode-one accounting leaves. Refill effects and
general allocation ownership remain unclosed.

The [refill-chain supplement](REFILL-CHAIN.md) follows selected zero/one-item
preparation, metadata/marker helpers, the bitmap worker, the wrapper and the
direct alternative through their caller continuations. It binds the generated
pointer to the cache write/return and preserves the zero-request side effects
and status-versus-null distinction. General loops, provider acquisition,
allocator invariants and outer-field preservation remain unclosed.

## Scope and ownership

The bounded question is the provenance and width of the sender's load at
`0x2b7a2ed`, not another implementation of its framing or codec policy.
[The existing greeting packet](../RE-012-greeting-deadline-115/README.md)
provided the first caller lead. The existing limit-writer labels concern later
states that reuse storage; they are not type evidence for this sender context.
The current catalogue allocates framing/compression to `transport`; its seed
catalogue has no inferred reference-address seeds. No #94 material is used.

[ownership-check.json](ownership-check.json) records bounded live public PR
text searches. Open PRs #2768 and #2789 cover the compression selector/plan;
this packet adds one producer/port binding without modifying their code or
claiming their work. Text search is not an exhaustive ownership census.
No issue claim, PR, review comment, commit or push was published.

## Evidence

All VAs are linked ELF virtual addresses before load bias. The five complete
unwind-described intervals in [native/records.json](native/records.json)
contain **12,000 bytes / 2,312 Capstone instruction rows**. These are exported
context sizes, not a recovered-function denominator or matching-source coverage.
An FDE interval alone is not proof of a source function boundary. Raw GNU and
LLVM exports cover each interval without byte gaps and match Capstone's byte
partitions, apart from explicitly counted standalone LLVM LOCK-prefix rows
joined to the following instruction. There are no byte normalization masks.
This check does not prove mnemonic/operand semantic agreement or complete CFGs.

[anchors.json](anchors.json) retains 21 selected, boundary-checked byte spans.
`collect.py` additionally binds direct calls, RIP-relative indirect call slots,
unique relocations and their dynamic symbol names, and three initial-state
dispatch entries. The important route is:

| Stage | Original evidence | Observed relationship |
| --- | --- | --- |
| Caller input | `0x2b6804e..0x2b68082` | A byte-derived index selects a u16 at `0x607018`; caller stores it at `+0x76`, alongside a zero u16 tag at `+0x70`, and copies the 32-byte input to `+0x1f8`. |
| Producer entry | `0x2b6809e`, `0x2b78313..0x2b78342` | Calls `0x2b782e0`; initial input is retained at producer `+0x20..+0x3f` and copied to its working address storage. The selected word is retained at `+0x26`. |
| Socket input | `0x2b7836d..0x2b7840b`, `0x2b7859f..0x2b78605` | The word passes through `+0x6e`, `+0xce`, `+0x76`, and stack `+0x46`. A call through `0x64e7788` resolves to `0x475b2e0`, receiving the address at stack `+0x40`. |
| Connect argument | `0x475b351..0x475b38b` | For tag zero, load input u16 `+6`, rotate its bytes by 8, store it at stack `+0xe`, and pass address stack `+0xc` with length 16 to `connect`. The family word is 2. |
| Context constructor | `0x2b7876c..0x2b7877d` | Loads producer u16 `+0x26` into ECX; the unique RELATIVE slot `0x64e7540` selects `0x4784d00`. |
| Field store | `0x4784d0a`, `0x4784da7` | ECX is retained in EBP; `mov word [out+0x90], bp` writes that u16. |
| Producer return | `0x2b78793..0x2b787cb` | Two `memcpy` calls of `0x88` bytes carry the constructor tail starting at `+0x10` into the returned tail at `+0x10`; tail offset `+0x80` preserves field `+0x90`. |
| Caller context | `0x2b680a3..0x2b680e7`, `0x2b6828d..0x2b6829f` | Excludes result tag 3, copies `0x98` bytes to caller `+0xb0`; the selected non-2 branch copies that block to caller `+0x148`. |
| Sender argument | `0x2b68496..0x2b684b5` | Stores context pointer `caller+0x148` at caller `+0x230`, initializes sender state zero, and calls `0x2b7a290` with sender base `caller+0x220`. |
| Compression predicate | `0x2b7a2ca..0x2b7a2fe` | Loads context from sender `+0x10`; reads context DWORD `+0x90`, subtracts 4000 with wrapping arithmetic and compares its low WORD unsigned against 65534, conjoined with input length at least 1025. |

The imported names are not guessed from disassembler nearest-symbol labels:
the `socket` and `connect` calls bind to GLOB_DAT slots `0x64e8a10` and
`0x64e14d0`, with dynamic symbol indices 69 and 51. The four selected copies
bind to `memcpy`, slot `0x64df508`, symbol index 7. Each has one relocation and
zero addend. The socket helper's valid-tag-zero address construction agrees
with the Linux IPv4 destination address ABI: a family word followed by a
network-order port word. This is the basis for the semantic port inference;
the numbers 3998/3999 alone would not establish it.
See the primary [Linux IPv4 interface documentation](https://man7.org/linux/man-pages/man7/ip.7.html).

The first seven u16 words observed at `0x607018` are
`4001, 4002, 4003, 4004, 4005, 3998, 3999`. This packet does not establish the
index's valid domain, the full table extent, the enum names or any network role
for those numbers. For these selected input values, only 3998 and 3999 disable
eligibility independently of length; all values still require length >= 1025.
Eligibility does not imply codec success or successful frame delivery.

### Width, padding and decoder caveat

For any u32 `x`,
`low16(x - 4000 mod 2^32) = (low16(x) - 4000) mod 2^16`.
The observed unsigned comparison therefore excludes low words 3998 and 3999
and is independent of the high word. No assumption that `context+0x92/+0x93`
is zero is required. The rest of the original Rust layout, initialized extent,
padding validity and whole-object ownership remain unresolved.

The direct-operand inventory finds the producer's 16-byte store at `0x2b7831e`
overlapping `+0x26`, its later word load at `0x2b7876c`, and the constructor's
word store at `0x4784da7`. It does not close aliases, callees or implicit memory
effects. Capstone 5.0.7 marks the MOVUPS destination as READ; its exported
`decoder_access_flags` are therefore explicitly advisory. The actual pinned
opcode and GNU/LLVM text identify that operand as a store. No write census is
derived from the decoder flags.

## Reproduce and validation

Use Python 3.12 with Capstone 5.0.7, GNU objdump and llvm-objdump on PATH.
Exact host/tool versions and native commands are retained in
[native/versions.json](native/versions.json) and
[native/commands.json](native/commands.json). From the repository root:

```sh
python3 -B research/work-items/RE-012-tcp-context-port-115/collect.py --out work/context-port-recheck
python3 -B research/work-items/RE-012-tcp-context-port-115/verify.py --native work/context-port-recheck --out work/context-port-controls.json
python3 -B -O research/work-items/RE-012-tcp-context-port-115/verify.py --native work/context-port-recheck --out work/context-port-controls-optimized.json
make doctor verify test catalogue-check reproduce
```

The collector requires a fresh output directory. Compare regenerated
`records.json` and raw exports against `native/`; tool version differences may
change native formatting/hashes and must be reviewed rather than normalized
away. Both collection and verification are required: `verify.py` alone does
not revalidate every retained native file or the stored records.

[controls.json](controls.json) records **41 rejected corruption controls**:
21 instruction-span mutations, five table/dispatch mutations, twelve changed
or duplicate relocations, two wrong captures and one truncated native export.
Controls deliberately bypass only the outer digest check in memory to test
actual byte/data bindings. The normal collector always authenticates the full
target. Normal and optimized Python produce identical control reports.

Separate scalar worksheets check all 65,536 u16 byte swaps and 1,048,576
eligibility relations over all u16 values, four upper-word samples and four
lengths. These are arithmetic corroboration plus the general identity above,
not captured execution, CPU emulation, independent behavioral observations or
Rust equivalence tests. No captured executable, socket, key or chain action is
used. Public PR/ABI documentation queries are the only network activity.

Repository-wide results and host limitations are recorded in
[validation.json](validation.json). On this Windows host `make` is absent, so
its recipes are invoked directly with the isolated Python interpreter.
Baseline catalogue checking already reports stale generated README content;
this packet does not edit that unrelated generated output. Do not describe
the repository-wide checks as green unless the recorded results support it.

## Implementation, comparison and remaining work

No Rust implementation or code comparison is added. Source-build identity,
helper/callee behavior, vtables, relocation closure beyond the selected slots,
and whole-ELF identity are unmeasured. All 92 component gates remain false.
An independent static reviewer checked the input/copy/constructor chain,
dynamic symbols and field-width issue; that review is corroboration, not a
substitute for the retained bytes or full-scope acceptance.

The remaining-route follow-up identifies a distinct listener-side source;
the member-lifetime follow-up binds selected large-caller copies to their
initial input word. The factory follow-up supplies a conditional origin for
large caller A; twin B's input, helper mutations and all legal resume paths
still need closure before promoting the observed field
into a shared typed Rust context.
Do not replace the generic selector's u32 input or reconstruct a whole socket
object solely from this one path. Helper errors, unwinding, aliases, current
network compatibility and observable runtime behavior remain open.

New scripts/docs are independently authored MIT work. Target bytes and existing
evidence retain their upstream terms. No unlicensed inferred source is copied.
