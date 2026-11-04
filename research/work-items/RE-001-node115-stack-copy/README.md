# RE-001: bounded 32-byte stack copy at 0x2995ab0

- Component: RE-001 function map; potential RE-011 execution-adapter lead.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base revision: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; no reference source used.
- Bounded question: what does this entire previously unbound function do to its length and 32-byte elements, and what happens at its bounds?

**Answer (inference from the complete instructions):** Let `n` be the unsigned 64-bit word at `[rdi+0x30]`, and let `[rdi+0x28]` point to an array of 32-byte elements. If `2 <= n <= 1023`, it copies element `n-2` into element `n`, stores `n+1` at `[rdi+0x30]`, and returns AL=0. Otherwise it returns AL=0x2d without accessing the array or writing the length. The rejection arm only writes AL; the upper return-register bits are not specified as a return value. Valid object, readable source and writable destination memory are preconditions for the success arm.

## Evidence and coordinates

All addresses are original ELF virtual addresses; the window `0x2995ab0..0x2995aea` is 58 bytes, at file offset `0x2994ab0`. Its SHA-256 is `b4397d5b09239add74b760338497bd4a84d0703975daf03592d823afd15271f4`. The FDE starts at file offset `0xd73a50` (section offset `0xccb78`), names CIE file offset `0xca6ed8` (section offset `0x0`), and describes exactly the window with no LSDA. The six bytes after the described body are `cc` padding. The FDE alone does not prove a function; the entry, complete decoded control flow and two dynamic relative relocation references support this particular boundary. The CIE and FDE bytes are in records.json.

The complete instruction walk (16 instructions) and bytes are in records.json. `lea rcx,[rax-2]` wraps modulo 2^64; unsigned `cmp rcx,0x3fd` / `ja` therefore accepts exactly 2 through 1023, inclusive. On success, shifting the original `n` by five forms the 32-byte stride. The two 16-byte loads happen before either store, from `32*n-64` and `32*n-48`; stores target `32*n` and `32*n+16`. The length update follows both stores. No calls, indirect transfers, or external data references occur in the body: callee count 0.

A complete bytewise `.text` scan for every `e8` and `e9` with an in-section four-byte rel32 operand found 0 candidate direct transfers to the entry. This is a raw opcode-byte census, not instruction-boundary disassembly and not a census of indirect callers. The `.rela.dyn` scan found 2 `R_X86_64_RELATIVE` records whose addend is the entry, at the slots listed in records.json. They establish address references, not execution or the identities of any callers.

## Novelty and reproduction

Before analysis, these searches returned no matches (exit 1) in the specified corpus:

```sh
rg -i '2995ab0|43604656' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

The producer authenticates the entire input before any output, checks ELF sections, exact instruction forms and branch target, CIE/FDE and padding, and records the full raw transfer scan and relocation records. From the repository root, Python 3.10+ standard library only:

```sh
python3 tools/node115_stack_copy.py --out research/work-items/RE-001-node115-stack-copy/
python3 -m unittest tests.test_node115_stack_copy -v
python3 research/work-items/RE-001-node115-stack-copy/verify.py
make verify
make catalogue-check
```

Static inspection only; no captured executable, network or external state is used. Reproduction requires the authenticated artifact at `artifacts/node/115/hl-node`. Results, instruction bytes and hashes are deterministic; no disassembler is required. The producer and verifier are independently authored under the repository MIT terms.

## Limits and next step

The names “array” and “length” describe observed memory operations, not recovered Rust types. Neither a specific EVM opcode nor the meaning of status 0x2d is proven. No direct or indirect caller semantics, runtime behavior, invalid-pointer behavior, Rust reconstruction, compiled-byte comparison, normalization masks, whole-ELF equivalence, component completion or acceptance gate is claimed. The Python model tests this local rule only; it is not a differential execution of the node. Next, trace both relocation slots and their consumers to establish dispatch context and the original operation identity.
