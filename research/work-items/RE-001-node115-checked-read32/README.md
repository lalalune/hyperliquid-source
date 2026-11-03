# RE-001: node #115 checked 32-byte read

- Component: RE-001 function map; serialization is a possible use, not established ownership.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; 105896032 bytes.
- Source/base revision: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; no source implementation is claimed.
- Bounded question: what state and output does the function at `0x5821430` produce when asked to read its fixed-width value?
- Scope: valid, nonoverlapping state, output, and readable input memory; arithmetic and memory writes of this one leaf only.

The function reads 32 bytes or writes an error. If the low 32-bit mode is 1, it checks whether adding 32 to the u64 counter at state +0x20 would overflow; overflow returns tag 1/error 2 without updating the counter. Otherwise it stores the incremented counter and returns tag 1/error 2 if it exceeds the u64 limit at +8. Next, for any mode, fewer than 32 bytes at the u64 length at +0x18 returns tag 1/error 0 and the missing count at output +0x10. This short-input return retains any counter increment already made. With at least 32 bytes, it advances the pointer at state +0x10 by 32, reduces the length by 32, copies the original 32 bytes to output +1, and writes tag 0. The return register is the original output pointer. Output bytes not explicitly written are unspecified by this function.

## Evidence and instruction walk

All addresses are original ELF virtual addresses; `.text` file offset differs by 0x1000. The complete window is `0x5821430..0x58214a3`, 115 bytes, file offset `0x5820430`, SHA-256 `14f7a11f50bba370abd61ae08c76346b828217584ce9a296bcce3df0040cd7a5`. The FDE at `0xf9c4a4` points to CIE `0xca6ed8` (zR, pcrel sdata4), has no LSDA, and covers exactly the window. The nearest FDEs end 11 bytes before and begin 13 bytes after; both intervening regions consist solely of INT3. Every path in the instruction walk below returns within the FDE. There are 0 callees and no indirect transfers. The 37 instructions and all branch operands are decoded by exact encoding; the signed branch targets must land on listed instruction boundaries.

- `0x5821430` `4889f8`: `mov rax,rdi`
- `0x5821433` `833e01`: `cmp dword [rsi],1`
- `0x5821436` `7524`: `jne 0x582145c`
- `0x5821438` `488b4e20`: `mov rcx,[rsi+0x20]`
- `0x582143c` `4883f9df`: `cmp rcx,-33 (unsigned)`
- `0x5821440` `7711`: `ja 0x5821453`
- `0x5821442` `488b5608`: `mov rdx,[rsi+8]`
- `0x5821446` `4883c120`: `add rcx,32`
- `0x582144a` `48894e20`: `mov [rsi+0x20],rcx`
- `0x582144e` `4839d1`: `cmp rcx,rdx`
- `0x5821451` `7609`: `jbe 0x582145c`
- `0x5821453` `c6400802`: `mov byte [rax+8],2`
- `0x5821457` `b101`: `mov cl,1`
- `0x5821459` `8808`: `mov byte [rax],cl`
- `0x582145b` `c3`: `ret`
- `0x582145c` `488b4e18`: `mov rcx,[rsi+0x18]`
- `0x5821460` `4883f91f`: `cmp rcx,31`
- `0x5821464` `7715`: `ja 0x582147b`
- `0x5821466` `ba20000000`: `mov edx,32`
- `0x582146b` `4829ca`: `sub rdx,rcx`
- `0x582146e` `c6400800`: `mov byte [rax+8],0`
- `0x5821472` `48895010`: `mov [rax+0x10],rdx`
- `0x5821476` `b101`: `mov cl,1`
- `0x5821478` `8808`: `mov byte [rax],cl`
- `0x582147a` `c3`: `ret`
- `0x582147b` `488b5610`: `mov rdx,[rsi+0x10]`
- `0x582147f` `488d7a20`: `lea rdi,[rdx+32]`
- `0x5821483` `4883c1e0`: `add rcx,-32`
- `0x5821487` `48897e10`: `mov [rsi+0x10],rdi`
- `0x582148b` `48894e18`: `mov [rsi+0x18],rcx`
- `0x582148f` `0f1002`: `movups xmm0,[rdx]`
- `0x5821492` `0f104a10`: `movups xmm1,[rdx+0x10]`
- `0x5821496` `0f114811`: `movups [rax+0x11],xmm1`
- `0x582149a` `0f114001`: `movups [rax+1],xmm0`
- `0x582149e` `31c9`: `xor ecx,ecx`
- `0x58214a0` `8808`: `mov byte [rax],cl`
- `0x58214a2` `c3`: `ret`

The complete `.text` bytewise scan for E8/E9 signed rel32 encodings targeting the entry yields 5 matches: `0x4e04ea7`, `0x4e182ed`, `0x5434b3d`, `0x5968dd8`, `0x5ad0abc`. All are E8 call encodings; focused disassembly shows these are call instructions in their surrounding functions. A bytewise scan can include false positives embedded in other instructions; it does not find indirect calls, other entry points, or prove a complete call graph. No external call or tail jump is in the bound body.

## Reproduction and novelty

Python 3.10+ standard library; ELF and unwind parsers in the repository; no captured executable is run. From repository root:

```sh
python3 tools/node115_checked_read32.py --out research/work-items/RE-001-node115-checked-read32/
python3 -m unittest tests.test_node115_checked_read32 -v
python3 research/work-items/RE-001-node115-checked-read32/verify.py
```

Before analysis, `rg -in '5821430|92410928' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt` returned no matches. There are no callee addresses requiring a separate novelty check. After adding this packet the same search naturally finds this work. No normalizations or byte masks are used.

## Limits and next step

This is an instruction-derived static theorem, not execution, a Rust reconstruction, an original source name, field identity, a protocol definition, or a full decoder. The proof assumes native pointers are valid and nonoverlapping; faults, wrapping pointer arithmetic, unwind behavior and aliasing are outside the model. The actual caller roles, initialization invariants, indirect references and whether this belongs to first-party code are unknown. No build, source comparison, whole-ELF equivalence, component gate, or progress change is claimed. Next, bind a caller's input construction and error handling to determine the format and provenance of the 32-byte field. New tool, model and prose are independently authored under the repository MIT license.
