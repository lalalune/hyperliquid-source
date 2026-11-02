# Visor config-name leaf: conditional low-AL byte contract

Target: separate Visor capture SHA-256
`89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
Native extent `0x4a9ae0..0x4aa3a6`, 2,246 bytes / 564 GNU and LLVM rows.
This is static research, with no Rust implementation, captured execution or target behavior comparator.
It follows the conversion call explicitly left opaque by draft #1516. The
similar node94 recognizer in #1385 targets a different digest, has 76 accepted
values and a different reject byte; its implementation/data was not copied.

## Observable contract and premises

With immutable admitted code/table bytes, a stable valid input byte slice and
the original 64-bit length argument, the low returned AL byte is the code for
one of the 79 exact byte strings frozen in `visor-config-name-map-intake.json`.
Every other byte string returns `0x4f`. Matching does not trim, case-fold,
decode JSON or substitute the application fallback. All listed strings are
ASCII; no valid-UTF-8 premise is needed for this leaf's byte comparisons.
`NvTestnet` is code `0x21`, and rejection is `0x4f`.

This is an AL-value relation, not an original Rust ABI claim. Other return
register bits, invalid pointers, mutable input races and application behavior
are outside the contract. The code-zero return additionally clears EAX, while
the other successful returns only assign AL; do not silently claim identical
full RAX values. No caller/default/file/trim behavior is reconstructed here.

## Guard, table and read extents

Entry assigns AL=0x4f. The unsigned `(length - 2) <= 11` guard at
`0x4a9ae2..0x4a9aea` admits exactly lengths2..13, including the intended
wraparound rejection of lengths0/1. The other edge goes directly to the
default RET at `0x4aa21e` without an input byte read. One 12-entry signed-dword
table at `0x87d20` adds each offset to that same table base before the indirect
jump at `0x4a9afe`. The exact table and destinations are retained in the map.
Lengths5/6 jump directly to the default RET and do not read input.

The static CFG audit follows both conditional edges and the twelve enumerated
indirect edges; it does not run a concrete input through captured instructions.
All 564 instructions are reachable in that conservative graph. It is acyclic,
contains no calls or memory writes, and never changes RDI. Every input read
is based on that unchanged pointer and fits its length group. All 80 RETs are
the 79 frozen value instructions followed by RET, plus the default RET.

| Length | Equality fragments: input offset / width |
| --- | --- |
| 2 | 0/2 |
| 3 | 0/2 and 2/1 |
| 4 | 0/4 |
| 5,6 | no reads; reject |
| 7 | 0/4 and 3/4 |
| 8 | 0/8 |
| 9 | 0/8 and 8/1 |
| 10 | 0/8 and 8/2 |
| 11 | 0/8 and 3/8 |
| 12 | 0/8 and 8/4 |
| 13 | 0/8 and 5/8 |

Thus every retained equality covers the complete admitted slice. The overlapping
loads at lengths7/11/13 remain inside the slice, and their literal bytes agree
on the overlap. No terminator byte, suffix or unqualified allocation padding is
read. The annotated maximum ends and reachable return sites are recorded per
length in `cfg-audit.json`.

## Equality predicates and literal liveness

Single-fragment cases compare the loaded word/dword/qword to the exact literal.
Multiple-fragment cases XOR each loaded fragment with its literal and OR the
differences before the conditional equality edge. OR equals zero iff every
component difference equals zero. Byte/word tails are loaded with zero extension;
the length3 path's 16-bit OR retains all bits of both comparison differences.
The 32-bit and 64-bit forms likewise retain their complete fragments. Fixed
length dispatch and complete fragment coverage rule out prefix/suffix acceptance.

The 79 value sites and 134 logical literal fragments were independently
annotated after the manual candidate table was frozen. The audit reads fixed
immediate operands and annotated constant arithmetic, checks every resulting
little-endian fragment against that earlier table, and checks overlap and
coverage. It is not a register-state machine, branch runner or instruction
evaluator. Register/literal association is the manual obligation below:

- In length9, GaOnchain's RCX literal remains available until its +0x100
  GbOnchain comparison. Every later independent literal is reset explicitly.
  The FBinSpot prefix is reused only on paths that have not changed RCX.
  At `0x4a9ca1`, GaHlPerp becomes the shared RCX base. The FBinPerp2
  predicate uses an RDX result of its +0x220e0ff expression, leaving RCX
  intact; the later Ga/Gb/Gc variants use the same RCX base. The final Gd
  comparison adds0x300 to RCX only after all preceding uses.
- In length10, WebSandbox's RCX base is kept while RDX forms RpcSandbox and
  is reset for RpcMainnet. Its own later XOR is followed by new MOVABS
  literals. NvMainnet2 uses a copied RDX prefix, leaving RCX available for
  NvMainnet3; each later independent prefix is reset explicitly.
- In length11, NodeTestnet's initial comparisons modify RSI/R8, leaving the
  RCX/RDX seed literals for the arithmetic-folded SoloTestnet predicate.
  Afterward RCX is reset to the `nMainnet` suffix and RDX to `JoinMain`.
  SoloMainnet is formed in RSI/R8, and RpcMainnet2/SoloSandbox also use
  RSI/R8. Consequently RCX/RDX still hold the JoinMainnet fragments when
  their own XORs occur. The later FHuobiSpot cases then reset RCX.
- In length8, the FBinSpot RDX base is unchanged while temporary RSI forms
  FCobSpot/FKraSpot, before its +9 OBinSpot comparison. The independent
  RCX GaHlPerp base is kept for Ga/Gb/Gc/Gd/Gs/Ea variants and is changed
  only by the last +0xfe EbHlPerp comparison.
- The other groups reset each literal or use an unchanged directly copied
  seed. Length13's +13 and +4 suffix expressions cover the overlapping last
  eight bytes of LockerTestnet and LockerMainnet respectively.

The map's unique names, unique codes0..78, per-case comparison context and return
site, and complete RET inventory make branch ordering unambiguous: matching a
case reaches its value return; failing every case reaches the still-initialized
default return. No other instruction writes AL on these paths. The code-zero
XOR-EAX result has the same low-byte relation while differing in upper bits.

## Frozen provisional corpus and remaining checks

Before any Rust implementation exists, 263,148 unique synthetic byte inputs
were frozen in a reproducible compressed corpus (digest in FROZEN-CORPUS.json). A dictionary model and
a separately structured byte-fragment-predicate model agree on all cases.
The corpus covers all79 names, all byte substitutions, proper prefixes,
deletions, one-byte prefixes/suffixes, case/padding variants, every byte string
of length0..2 and selected large lengths. Six false source simplifications have
explicit witnesses. This is finite abstract support, not observed target output.

Canonical native regeneration, raw GNU/LLVM partition comparison, lower-level binding corruptions and normal/optimized source-audit receipts are in VALIDATION.json. The manual predicate/liveness argument remains necessary; those checks are not an automatic proof. Frozen intake files retain their original prequalification status as historical snapshots, while this proof states the bounded current claim. Historical intake filenames are provenance labels, not runtime dependencies; portable scripts use the canonical observed export.

No original ABI/full-register equivalence, Rust build, application file/default behavior, captured execution, instruction evaluator, recovered-byte credit or gate completion is claimed. Full make test is not run because flat discovery includes captured-instruction evaluators outside static authorization. All component gates remain unchanged.
