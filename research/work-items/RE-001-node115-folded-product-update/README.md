# RE-001: bind the node #115 folded-product update

- Component: function map / arithmetic state update; ownership unresolved.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source revision: `05bc2de303c05525b71e7e257426e741bc66a390`. This is an independently authored static model, not recovered source.
- Question: given a 20-byte input and a state containing two words, a key pointer, an accumulator and a count byte, what complete state update does the function compute?

On valid, disjoint readable/writable input and state memory and a readable key word, the function combines the input with the two state words according to the count byte, multiplies two 64-bit operands as an unsigned 128-bit product, and stores the XOR of the high and low halves as the new accumulator. Counts 1 through 64 use one multiplication and leave the second input word and final 32-bit input in the first two state words; count 0 uses one multiplication and leaves the final 32-bit input and zero there. Counts above 64 first fold the old state into the accumulator, then perform the count-0-shaped update. The count output is 96 on the 1..64 path and 32 otherwise. The key pointer is unchanged. This describes the machine-level relation, not an identified hash algorithm or original Rust type.

## Evidence and rule

The complete unwind-described window is `0x1452020..0x14520cb` (171 bytes), original ELF virtual addresses; file offset `0x1451020`. Body SHA-256 is `25284b67050c3005c1a8984afde7cc6e9a1b1b0779a6920db014d1ea9b830d60`. FDE file offset/VA `0xcaa498` refers to CIE file offset/VA `0xca6ed8` (`zR`, no LSDA); original frame bytes are in `records.json`. 5 `cc` bytes follow the FDE. The decoded control flow stays inside the range and all paths return. There are **58 instructions**, **0 callees**, and **2 rel32 candidates** in the JSON. No indirect transfer occurs. This FDE, full branch walk and returning endpoints support the bounded function extent; unwind metadata alone would not.

Let input qwords `x`, `y` and final dword `z` be little-endian at input offsets 0, 8 and 16. Let `a`, `b`, `k`, `h`, `n` be state qwords at offsets 0, 8, the dereferenced pointer at 16, 24, and the byte at 32 respectively. For 64-bit values define `F(u,v) = low64(u*v) XOR high64(u*v)`. All shifts and ORs below operate on unsigned 64-bit words.

- For `n=0`, let `L = x OR a`, `H = b`.
- For `1 <= n < 64`, let `L = (x << n modulo 2^64) OR a`, `H = (x >> (64-n)) OR b`.
- For `n=64`, let `L = a`, `H = x OR b`.
- For `n>64`, replace `h` by `F(h XOR a, b XOR k)`, and let `L=x`, `H=0`.

For `1 <= n <= 64` the output at state offsets 0, 8, 24 and 32 is `(y, zero_extend(z), F(h XOR L, k XOR H), 96)`. Otherwise it is `(zero_extend(z), 0, F(h XOR L, k XOR (y OR H)), 32)`. The load of `z` is a dword load; its high bits are zero, not input bytes 20..23. The n=64 case uses the hardware-masked shift count and the bit-6 conditional moves, so it is not a 64-bit shift in the model.

The instruction-by-instruction byte walk is in `records.json`; `decode` recognizes each complete encoding and independently derives short-branch targets. Key points: `0x1452037` branches at unsigned count 65; `0x145205e..0x1452075` forms the shifted pair and ORs the old words; `0x1452087..0x1452096` performs the normal fold; `0x14520a3..0x14520b7` performs the alternate fold; and `0x14520bf..0x14520ca` writes the output and returns. `MUL` gives the full 128-bit unsigned product and the following XOR reduces its halves. The initial fold for counts above 64 is at `0x145203c..0x1452048`. There are no normalized bytes or masks.

The full `.text` scan checks every byte offset for `e8` and `e9` with signed rel32 targeting the entry. It finds `e8` at `0x1451621` and `0x1451ed5`; focused static disassembly confirms both are call instruction starts. The scan is deliberately an over-approximation: bytes in immediates can look like calls, and indirect calls, other executable sections, dynamic dispatch and reachability are outside its census. These two callers initialize state and subsequently consume its fields, but their complete semantics and source attribution are not established. No first-party source association is claimed.

## Reproduce, novelty and controls

Python 3.10+ standard library, static ELF parsing; the recorded local validation used Python 3.13.5 and GNU objdump 2.44 for independent exploratory disassembly. The generator and verifier do not invoke objdump. From the repository root:

```sh
python3 tools/node115_folded_product_update.py --out research/work-items/RE-001-node115-folded-product-update/
python3 -m unittest tests.test_node115_folded_product_update -v
python3 research/work-items/RE-001-node115-folded-product-update/verify.py
make verify
make catalogue-check
```

Before creating this packet or investing in the bind, the search below returned no matches (exit 1):

```sh
rg -in '1452020|21307424' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

There are no callees to check for novelty. The public generator checks the full input digest before parsing or creating output. Tests exercise all count cases and 64-bit product boundaries, byte-identical regeneration, wrong-digest rejection before output, every body-byte mutation, shifted FDE and altered direct-call opcode controls, and README/JSON count agreement. Because the bound body has no callee, there is no callee target to redirect; the call-opcode corruption instead checks that an injected transfer is rejected. The model is independent arithmetic, not execution of target instructions.

No captured executable was run. This is a static local result, not a Rust reconstruction, complete caller proof, source/component ownership, full hash algorithm identification, binary equivalence or a progress-gate claim. The object layout, aliasing behavior outside the stated disjoint-memory precondition, error handling and overall algorithm are unresolved. There is no source build or binary comparison. Next: bind the two callers' initialization and finalization and identify the key's provenance before assigning algorithm or component meaning.
