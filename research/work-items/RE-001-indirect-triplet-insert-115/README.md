# RE-001: exact stable insertion with indirect mixed-sign keys

Consensus allocation through actual state.rs caller context, not original
symbol/type recovery. Sole node115 SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
base05bc2de303c05525b71e7e257426e741bc66a390. Merged static #2524 binds
246B74instructions at26d4280..26d4376. This adds actual-instruction
expectations and plans independently authored Rust after sealing; original
packet remains unchanged. No generic dependency or coverage-only claim.

Read CONTRACT.md. Entry guard unsigned(k-1)<n reaches actualUD2 if false;
it touches no memory on that guardtrap. Valid k==n returns before record/key
reads. Remaining paths stably insert suffix[k..n] into the preceding prefix,
using(i32,u32,u32) key order. Records contain payload and an immutable keypointer;
shared pointers and equal-valued distinct pointers preserve their identities.
An unsorted initial prefix is not promised to become fully sorted.

The comparator checks guardUD2 versus normalRET and every final payload and
key-pointer origin. A named keyslot coordinate preserves pointer identity,
not merely equal key values. Key padding/unused keys remain unknown; immutable
key writes reject. NativeRAX scratch is not assigned a source return type.
The evaluator interprets actualUD2 as an explicit guard terminal; no hardware
trap/captured process runs and no imported callback supplies an answer.

Complete body/FDE/CIE, GNU/Capstone bytes, every local branch, actual selected
caller and sourceLocation are authenticated. All236nonpadding bytes/73starts
are visited, including actualUD2. The unvisited10BNOP is unreachable after an
unconditional jump. Full.text exact246-byte encoding census prevents unreported
exact-body aliases. This is not a whole semantic-equivalence/caller census.

```sh
python3 research/work-items/RE-001-indirect-triplet-insert-115/proof.py --objdump /path/to/objdump
python3 -m unittest discover -s tests -p test_indirect_triplet_insert115.py -v
```

Actual-byte controls separately alter guard, earlyreturn, signed/unsigned key
comparisons, stableties, decisionbranches and payload source; stride/keyorigin/
guard-bound corruptions reject. Capture/originalpacket/tools/imports/pins remain
unchanged. All92gates/bytewindows stayfalse. Valid stable disjoint nonwrapping
memory and immutable keys are premises; actual caller passes k1, other k are
leaf states without caller-reachability claims. No original ABI, consensus
admission/state transition, compilerrecipe, Linux execution, target-byte match
or integrated node. No captured ELF/Unicorn/live service/chain/signing. New
source MIT, no unlicensed code. Next: bind caller prefix construction and record
types before composing this local transformation into consensus state.

## Independent source and actual replay

Pre-Rustseal5f27e1e2ebd588189c153c460124c292e5c2e0f8 has no newRust.
Native10988rows include4392actual entryguardUD2 observations;236B73starts
visited,11outputCOW+3negative PASS87.187s. Sevenpretests PASS5.975s.
Independent safe no_std source uses adjacent full-record swaps and preserves
mixed-sign order and equal-key identities. Its Guard is an own adapter for the
observed guardfrontier, not native Rust error handling or panic recovery.

```sh
python3 research/work-items/RE-001-indirect-triplet-insert-115/verify-rust.py \
  --rustc /path/to/rustc --out /fresh/owned/output
```

Original opt0/3/repeat match all10988 outputs; same-path opt3 rlib bytes repeat.
The221case clientfixture selects only unchanged sealed rows. Twelve compiled
wrong sources emit complete streams and fail ordinary assertions101. The first
CPU-limited run hit its480s wallcap (NOT a full pass); continuation reused only
hash-verified completed subprocess stdout/stderr/exit receipts and executed all
unfinished commands in87.391s. No native-evaluator result is cached/substituted.
Continuation metadata and archived historical driver/logs preserve this split;
normal reproduction uses the fresh replay command above, not historical cache.
Source/fixture/inputs stayed unchanged through continuation. The original opt3
repeat check completed in the uninterrupted prefix, not newly proved by reuse.

Exact fullreceipts/15streams/152stdout-stderr logs and fixture are losslessly
gzip archived; only owned path prefixes in command output are projected.
The published replay only adds SHA-checked fixture rehydration to the same
original build/compare functions; temporary historical continuation adds a
receipt-cache guard around run, documented separately. See VALIDATION.md for
all command scopes and limitations. No acceptance gate advances.
