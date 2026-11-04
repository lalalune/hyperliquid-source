# RE-005: Node115 GossipRpcRequest prefix-state reconstruction

Component: serialization; RE-012 node-runtime/gossip context. Target Linux
x86-64 node115 SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

## Question and prior work

Recover the three-variant request prefix and all selected logical value/error,
cursor and charge exits. The base has no decoder at the new source path
(`before.json`); this is a bounded reconstruction gap, not an application bug.
Existing PR2300 recovers the u64 reader primitive and selected four-read callers;
we reuse its byte-identical licensed lib from commit
`45e91f8499f1a78460407d235f580c1625f44d1a`. Its standalone probe and tests are
not invoked or counted here. `dependency.json`, the retained MIT LICENSE,
upstream manifest and imports manifest bind all reused bytes. PR2257 is a
size-counting encoder, not this decoder. No dependency on a pending merge or
additional primitive credit is claimed.

## Observations

All addresses are ELF image VAs, not file offsets. `records.json` binds actual
FDE and CIE bytes, body extents, actual RELA records and signed jump tables.
`decoded-closure.json` verifies every byte in six complete GNU disassembly
exports against the authenticated image and records all calls within them.
GNU objdump2.47 used `-d -Mintel --start-address=... --stop-address=...` for each
range; each raw export retains its full command output. No masks, emulation or
captured execution were used. The selected physical closure is1374bytes:

| FDE start | Exclusive end | Meaning |
| --- | --- | --- |
| 0x5aac6a0 | 0x5aac7b7 | Request parent, three variants and invalid-variant context |
| 0x5821150 | 0x5821243 | u32 tag reader / limited precharge |
| 0x5822490 | 0x58225b5 | short u32 reader |
| 0x5821250 | 0x5821335 | reused u64 reader / limited precharge |
| 0x58225c0 | 0x58226fc | reused short u64 reader |
| 0x5822700 | 0x582270e | active invalid-marker error fields |

The parent calls u32 at5aac6b2. Variant0 calls u64 twice at5aac726/5aac73e;
variant1 and2 have no payload; other u32 indices produce tag5/index and the
actual16-byte `GossipRpcRequest` literal at4519b0 plus context456bb0.
Raw output success byte18 and variant/payload fields are observed, but the
safe Rust projection intentionally does not reproduce padding or ABI.

Reader context: DWORD+0 canonical mode1 is limited; qword+8 limit,+16 slice
pointer,+24 remaining length,+32 charged. Limited tag charge is4, each u64
charge8, independent of encoded length. Addition overflow leaves the count
unchanged; otherwise the new count is stored before comparing the limit.
An over-limit result preserves that stored count without consuming input.
Unlimited mode leaves count unchanged. Safe slices represent disjoint storage.

Tag fast route requires remaining>4; payload fast route>8. Short helpers consume
one marker before classifying it, so errors can retain a partially advanced
cursor. Fast invalid markers do not consume it. Inline values are<251; FB/FC
carry u16/u32 little-endian; payload FD carries u64. Tag rejects FD/FE/FF with
raw expected2 and found3/4/12. Payload rejects FE/FF with found4/12 and expected
3 on short routes,2 on fast routes. Empty input needs1byte; truncated marked
payloads report total encoded size minus input size after consuming only their
marker. Nonminimal encodings are accepted. Both wrapper calls force EDX0 at
58211ee/58212f8, excluding the unused generic big-endian branch.

Actual indirect bindings are64e7f70→5822490,64e6c38→58225c0,
64e7f78→5822700; type8 relative relocations prove these edges. Signed table
bases935bcc/935bdc/935c14/935c24 and all four destinations per table are frozen.

## Reconstruction and real comparisons

`tools/gossip_rpc_request.py` authenticates the exact input and checks recorded
native operands, extents, relocation/data closure before regenerating a static
relation. It is hand-authored branch mathematics, not a machine-code emulator
or an execution oracle. `freeze.json` proves12187 expected rows were fixed
before new Rust existed and without executing the imported Reader source.
The static expectation remains a fallible human interpretation of native code.

New Rust decodes the tag and composes the unchanged MIT reader for variant0.
No field units, ordering condition, EOF requirement or network framing is
invented. `comparison.json` records opt0/3:12187rows each, repeat outputs equal,
full repeat rlib bytes equal using the same output basename,4unit tests/profile,
4actually compiled mutants detected, and2target-operand corruption witnesses.
Corrupted target bytes are rejected by production authentication; only the
negative-control relation reads their altered operands. No modified target is
executed. Linux x86_64 rlibs build at both optimization levels and are not run.
Rust1.95.0/LLVM22.1.2, exact compiler/linker hashes and fixture/source hashes are
recorded. Real offline Cargo lock/build/lib-test passes for the two local
packages; no registry dependencies are introduced.

Reproduce with the commands in the component README. Every comparison preserves
input/output and compiler stdout/stderr under the chosen ignored output folder.
`build-setup-observations.json` preserves the initial PATH/preflight and archive
filename failure classifications; they are not presented as initial successes.
Repository-wide checks are reported separately in the PR, including failures.

## Limits and next question

This proves agreement with12187 frozen static expectations, not native dynamic
or machine-code equivalence. Native ABI, inactive error padding/formatting,
arbitrary mode words, aliasing/malformed pointers, network framing, variant
field names/units, message consumers, signatures and full-node integration are
unknown. Reused helper bytes are not new credit. The1374-byte closure is a
selected physical evidence denominator only, not registered reconstructed
implementation bytes. No gate, component percentage, byte-window registry or
whole-program acceptance is advanced. Next: follow the request consumer and
framing to establish field meanings and the surrounding bounded wire contract.
