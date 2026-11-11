# RE-012: subaccount label length and transformed duplicate guard

Merged #2287 establishes the creation caller's admission and append order but
leaves `0x366b350` opaque. This packet resolves that helper's byte-length gate,
transformed-view comparison, raw result tags and cleanup ordering. A label/name
interpretation comes from the subaccount caller and pointer/length use; original
source type names and the transformation's full text policy remain unclosed.

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base: `05bc2de303c05525b71e7e257426e741bc66a390`. Task RE-012, vaults/subaccounts
input validation. Private FDE `0x366b350..0x366b4f9` is 425 bytes. Credited caller
`0x366a620..0x366ac91` adds 1,649 bytes. The caller's actual Location at
`0x6468aa8` binds `l1/src/sub_account.rs:75:13`. ELF VAs, unique file offsets,
body hashes, full unwind/LSDA records and actual call relocations are retained.

## Local control and output

RDI is the result pointer, RSI the owner, RDX a retained lookup key, and RCX/R8
supply input pointer/length. Before either helper call, unsigned
`(length - 17) mod 2^64 > 2^64 - 17` admits exactly lengths **1 through 16**.
Zero and all larger raw u64 lengths write WORD `0xe8` and return. This is an
original byte-length test, not Unicode character counting or a post-transform
length bound. It does not read the input bytes on this rejection path.

On admission, slot `0x64df650` transforms the input into a stack descriptor,
then `0x4716880` looks up the owner/key. Null lookup or zero record count writes
WORD `0x1a2`. Otherwise the code traverses 64-byte records and sends each
record's pointer/length at `+8/+0x10` through the same transformation slot.
That slot's actual RELATIVE target is `0x141cc40`. Its full case conversion,
Unicode/version behavior, allocation and failure contract are not reconstructed
or replaced by a mock.

The transformed candidate and transformed current input are compared by length
first. Unequal lengths skip byte comparison and proceed after temporary cleanup.
Equal lengths call the actual `bcmp` import at `0x64df9f8` with that length.
The code uses only zero/nonzero EAX, never its sign. On ordinary import semantics
and valid storage, zero identifies byte equality. The temporary descriptor's
allocation is disposed **before** testing the retained comparison result for
the duplicate return. A duplicate writes WORD `0xe6`; exhaustion writes WORD
`0x1a2`. The record producer, uniqueness beyond the measured list, valid source
variants, state stability and full account creation remain unknown.

The local final result-tag write precedes disposal of the input's transformed
descriptor. Only a nonzero capacity-like word requests deallocation. This order
also applies to duplicate return; the cleanup does not supply the tag. Local
result stores write two bytes only, without zeroing inactive payload or padding.
Valid disjoint native storage and ABI-preserving ordinary returns are premises.
Helpers may have side effects or unwind, so no atomicity, rollback, lifetime
guarantee or whole transformed-string equivalence is proved. Unwind cleanup is
exported and preserved as context.

## Reproduce and limits

```sh
python3 research/work-items/RE-012-subaccount-label-guard-115/collect.py --output work/subaccount-label-replay --check
python3 research/work-items/RE-012-subaccount-label-guard-115/analysis.py
python3 -m unittest discover -s tests -p test_subaccount_label_guard115.py -v
```

The whole digest is authenticated before native tools/output. Python/readelf
full unwind and relocation readers and GNU/Capstone complete instruction
partitions must agree. Private direct branches must target actual instruction
starts in their FDE; runtime-indirect calls remain explicit. A private read-only
copy is disassembled, never executed. Exact tools, commands, counts and raw
results accompany the evidence. Selected real-byte corruptions are checked
below the whole-image identity guard. Length-partition examples are mathematics,
not captured runtime vectors or supplied transformation/lookup results.

This is independently authored static research, with project-authored collector
scaffolding credited. No Rust reconstruction, executed helper, captured process,
instruction evaluation, complete Unicode policy, public ABI or compiled identity
is claimed. All 92 acceptance gates and registered windows remain unchanged.
Original #2287 evidence, imports, tools, captures and pins are preserved. New
code is MIT. Next close the transformation/record producer and ownership
contracts before implementing a faithful label-validation interface.

Catalogue generation/check alone uses the existing #2655 snapshot-read fix for
the measured repeated-read blocker; baseline is restored before actual reproduce
and final audit. This qualified local check is not an unmodified-head full-suite
or hosted CI pass. New-head full repository CI remains pending.

Fresh collection passed in 50.663 seconds: 425 bytes / 114 instructions of new private guard plus 1,649 bytes / 333 instructions of credited caller context, total 2,074 bytes / 447 instructions. Twenty-six structural controls passed in 4.142 seconds, and seven focused tests passed in 6.441 seconds. Forty-one length illustrations are local mathematical checks, not runtime observations.

Integration passed in 374.247 seconds: six generated files byte-exact, 12 packet-integrity tests, doctor, verify, catalogue/check and actual reproduce. Baseline tooling was restored before reproduce. New-head full hosted CI remains pending.

Final audit passed in 2.856 seconds: 26 manifest entries at audit time, six regenerated files, original packet/tools/imports/captures preservation and three catalogue scope tests. Archiving this receipt adds one manifest entry.
