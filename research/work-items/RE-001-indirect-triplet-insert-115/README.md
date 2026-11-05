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
