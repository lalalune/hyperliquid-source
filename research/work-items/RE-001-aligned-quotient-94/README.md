# RE-001: aligned quotient leaf (node #94)

Task: RE-001; component ownership unresolved. Bounded question: what does the
function at `0x538c990` compute from `rsi` and the dword at `[rdi+0x120]`?

The function sets the numerator to zero when the unsigned `rsi` is at most
4; otherwise it subtracts 5, caps the result at
`0xffffffc0`, rounds it down to a multiple of 64, and
multiplies by 8000. It divides that numerator unsigned by the
64-bit sign extension of the dword at `[rdi+0x120]`, returning the
quotient in `rax`. A zero divisor raises the x86 divide exception even when
the numerator is zero. A negative signed dword becomes a large unsigned divisor;
it is not signed division. No source-level unit or type is established.

## Identity and bounds

Node #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`; `91774280` bytes,
identity from `provenance/artifacts.json`. ELF virtual addresses are used.
The FDE range is `0x538c990..0x538c9c4` (52 bytes),
file offset `0x538b990`, `.eh_frame+0x2b3880` (FDE length
`0x10`), CIE section offset `0x0`.
The body SHA-256 is `bf507d29b9abe8a1dbce28d0f25ad3dbc7534d14bb11d866fa087ed217553c1b`. It ends in `ret`, followed by
12 `cc` bytes to the next FDE at `0x538c9d0`.
The branch stays within the range and both paths reach the return or the
processor's divide exception. These facts support the bound, without claiming
all possible entries are known. The baseline repository revision is `e5c9b643`;
the reference tree is not used for a semantic claim.

## Instruction walk

The decoder rejects any different instruction encoding, resolves the branch,
and checks the immediate values and field offset. Every instruction in the
FDE is shown (14 instructions):

| VA | Bytes | Instruction |
| --- | --- | --- |
| `0x538c990` | `f30f1efa` | `endbr64` |
| `0x538c994` | `31c0` | `xor eax, eax` |
| `0x538c996` | `4883fe04` | `cmp rsi, 4` |
| `0x538c99a` | `761b` | `jbe 0x538c9b7` |
| `0x538c99c` | `b8c0ffffff` | `mov eax, 0xffffffc0` |
| `0x538c9a1` | `4883ee05` | `sub rsi, 5` |
| `0x538c9a5` | `4839c6` | `cmp rsi, rax` |
| `0x538c9a8` | `480f47f0` | `cmova rsi, rax` |
| `0x538c9ac` | `4883e6c0` | `and rsi, -64` |
| `0x538c9b0` | `4869c6401f0000` | `imul rax, rsi, 8000` |
| `0x538c9b7` | `48638f20010000` | `movsxd rcx, dword [rdi+0x120]` |
| `0x538c9be` | `31d2` | `xor edx, edx` |
| `0x538c9c0` | `48f7f1` | `div rcx` |
| `0x538c9c3` | `c3` | `ret` |

`mov eax` zero-extends the cap into `rax`; `cmova` uses an unsigned comparison.
The largest numerator fits in 64 bits. `xor edx, edx` makes the dividend
`0:rax`; for a nonzero divisor the quotient fits in `rax`. Memory validity
and an operational exception handler are assumptions outside this packet.

## Calls and scope

The function contains 0 calls or tail jumps: there are no callee
identities or extents to bind. A complete `.text` byte-pattern scan for `e8`
and `e9` rel32 operands targeting the entry finds 0
sites: none. The scan includes possible false positives from instruction
interiors; indirect calls, other opcodes, relocations and data references are
not covered. No direct site does not establish that the function is unused.

## Novelty check

Before building this packet, both commands below returned no matches (exit 1):

```sh
rg -i '538c990|87607696' research/
rg -i '538c990|87607696' ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

There are no callees whose behavior is bound. The nearby arithmetic function
at the next FDE is not bound here. The address and behavior have no claimed
first-party attribution; the nearest dynamic symbol is not evidence of ownership.

## Reproduce and limits

From the repository root, with Python 3.10+ and the authenticated binary:

```sh
python3 tools/aligned_quotient_94.py --out research/work-items/RE-001-aligned-quotient-94/
python3 -m unittest tests.test_aligned_quotient_94 -v
python3 research/work-items/RE-001-aligned-quotient-94/verify.py
make verify
make catalogue-check
```

The generator parses the ELF sections and FDE, decodes the complete window,
scans all of `.text`, and emits deterministic records and this README. It
never executes the target or invokes an external disassembler. The Python
model checks consequences of the instructions, not observed target execution.
No Rust build, binary equivalence, wire format, global ownership, data or
whole-component completion is claimed; no progress gate changes. Next, trace
indirect references and examine the adjacent function's relationship to this
quotient before assigning units or a source-level name.
