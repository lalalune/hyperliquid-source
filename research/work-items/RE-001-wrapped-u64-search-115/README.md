# RE-001: reconstruct u64 ring-search status and exact duplicate position

Foundation allocation, node115 SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
base05bc2de303c05525b71e7e257426e741bc66a390. Two complete call-free bodies:
2ee0640..2ee0761 (289B92instructions/stride32) and4551810..455192b
(283B89instructions/stride56). Physical total572B181starts, all visited.
Merged static #2593/#2594 are credited and preserved; their layouts are one
semantic family here. Open #2716/#2750 and prior #2957 concern different
32/20-byte full keys or u32 tier lookup, not these u64-key bodies.

Read CONTRACT.md. Exact output is rawRAX/RDX:0match/1miss and logical index
(or insertiongap). Normal span search chooses the last equal key. Wrapped
input with query equal to physicalslot0 immediately returns that seam's
logical position, including duplicates on either side. Uniform first-equal
or last-equal search would therefore change observed output. The rawhead is
normalized by at most one capacity subtraction, under explicit valid geometry.
No original map ABI, signature policy or caller validity is inferred.

The evaluator materializes logical sorted keys in their actual32/56-byte
physical records. Only live key qwords are initialized: unused capacity and
all payload bytes remain unknown, and no input store is allowed. Empty search
must not read query or keys. RealRET and restored stack are required. Expectations
come from actual instructions, with no callbacks, substituted helper results
or interior-state composition. Full FDE/CIE/body, GNU/Capstone agreement,
local branch closure and actual selected caller/sourceLocations are checked.
Source association is context, not recovery of original names/ownership.

```sh
python3 research/work-items/RE-001-wrapped-u64-search-115/proof.py --objdump /path/to/objdump
python3 -m unittest discover -s tests -p test_wrapped_u64_search115.py -v
```

Actual-byte COWs separately change each body's pivot comparison, equality,
span search/status and wrap boundary; independent normalization/stride
corruptions must reject undeclared storage. Valid sorted geometry is a premise,
not proof native code rejects malformed objects. Native/contract/expectations
must be Git-sealed before independent Rust. No captured executable, Unicorn,
original compiler recipe, Linux execution, original ABI, production signature
tracking, target-byte equivalence or whole-component gate is claimed. All92
gates and byte registrations unchanged; imports/tools/oldpackets/captures
preserved. New source MIT, no unlicensed code. Next: bind construction and
invariants of these descriptors at actual callers before integrated use.
