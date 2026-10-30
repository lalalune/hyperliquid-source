# RE-004: static validation of node #94's unsigned 128-bit division helper

- Component: quantities/rounding, one dependency of the existing
  `RE-004-spot-wei-scale-family-94` packet.
- Target: node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Reference pin: can1357/hl `999556f6e0a474b8312db96ec3149e1c44e97c23`.
  No inferred reference implementation was read or copied for this packet.
- Claim: target instructions support a two-limb unsigned quotient interface,
  corroborated by finite static evaluation against Python integer division.
- Included: the complete 198-byte helper window, its relocated call slot, one
  bounded incoming caller, all four returns, and instruction corruption controls.
- Excluded: native execution, an all-input proof, Rust reconstruction, node #115,
  caller reachability in real application state, and compiler/library attribution.

## Why this question

The existing spot-wei-scale packet models slot `0x576e1a8` as unsigned 128-bit
division but explicitly leaves its target body unvalidated. Its twelve conversion
helper comparisons therefore rely on that assumption. This packet inspects the
actual callee rather than adding more tests of the assumed operation. The prior
packet and its limitations remain unchanged; this is finite corroboration of one
dependency, not retroactive proof of all its comparisons or component completion.

## Reproduce

Use the authenticated artifacts and pinned submodules described in CONTRIBUTING.
All addresses are linked ELF virtual addresses. Commands run at repository root:

```sh
make doctor
make verify test catalogue-check
make reproduce
python3 tools/u128_division.py --objdump llvm-objdump --out work/u128-llvm
python3 tools/u128_division.py --objdump objdump --out work/u128-gnu
cmp work/u128-llvm/evidence.json work/u128-gnu/evidence.json
cmp work/u128-llvm/evidence.json research/work-items/RE-004-u128-division-94/evidence.json
python3 -m unittest discover -s tests -p test_u128_division.py -v
```

The producer recognizes GNU and LLVM from their version output, supplies their
respective Intel-syntax option, authenticates the ELF, checks the FDE and relocation,
and binds every listing byte to the complete window before evaluating it. It does
not execute a captured instruction or launch a captured service. The evaluator is
independently authored Python integer logic for the observed register-only subset.
It tracks defined register bits (including AL/CL and 32-bit zero extension), CF/ZF,
the saved RBX value and the private push/pop balance. Unknown operands, flags,
instructions, out-of-window control flow and excessive steps stop the evaluation.

In the recorded run, use these executable paths on macOS arm64:

```sh
export PATH=/opt/homebrew/opt/binutils/bin:/private/tmp/slop-git-lfs/bin:$PATH
export LLVM_OBJDUMP=/Library/Developer/CommandLineTools/usr/bin/llvm-objdump
python3 tools/u128_division.py --objdump "$LLVM_OBJDUMP" --out work/u128-llvm
python3 tools/u128_division.py --objdump /opt/homebrew/opt/binutils/bin/objdump --out work/u128-gnu
```

Raw exports can be independently regenerated with:

```sh
llvm-objdump -d --x86-asm-syntax=intel --start-address=0x565f5a0 --stop-address=0x565f666 artifacts/node/94/hl-node
objdump -d -M intel --insn-width=16 --start-address=0x333e310 --stop-address=0x333e441 artifacts/node/94/hl-node
readelf --debug-dump=frames artifacts/node/94/hl-node
```

`helper.frames.txt` retains the exact helper FDE block from the last command.
`helper.*-objdump.txt` and `caller.gnu-objdump.txt` retain decoder output. The labels
printed from the nearest unrelated dynamic symbol are **not recovered function
names**. Only addresses, bytes and decoded operations are used here.

## Observations

The independent GNU frame dump agrees with the existing binary FDE parser:
`[0x565f5a0, 0x565f666)`, 198 bytes, FDE VA `0xfbdaa0`. Both decoders give
71 contiguous instructions. The full window SHA-256 is
`45f632dd0c1fc0915e680ad7ad98cabda1fcf34ba7835c2e73e3569b570a288d`.
No helper calls, global loads or stores occur in this window; its only memory
operations are the conditional RBX push/pop. This is a boundary corroboration,
not a global function census.

The relocation maps slot `0x576e1a8` to the helper entry. In the complete
`[0x333e310, 0x333e441)` caller listing, the call at `0x333e361` addresses that
slot. The preceding MUL product is moved into RDI (low) and RSI (high); RBX
is moved into RDX and RCX is zeroed. After the call, RAX/RDX are saved and
multiplied/subtracted as a two-limb quantity. This corroborates one real use;
the caller's full application contract and upstream inputs are not closed.

For the helper, write `N = RDI + 2^64*RSI` and `D = RDX + 2^64*RCX` at entry.
The observed output is `RAX + 2^64*RDX`:

| Entry condition | Observed instruction path |
| --- | --- |
| `D_hi != 0` | Normalize using BSR and double shifts, estimate a one-limb quotient, subtract its full product, then correct once using the full-width remainder comparison. Return at `0x565f61d`. |
| `D_hi == 0`, `N_hi < D_lo` | One 64-bit hardware DIV, zero high quotient. Return at `0x565f631`. |
| `D_hi == 0`, `N_hi >= D_lo`, `(N_hi OR D_lo) >> 32 != 0` | Two 64-bit DIVs, carrying the first remainder into the second; preserve the high quotient. Return at `0x565f652`. |
| Remaining one-limb-denominator case | First DIV is 32-bit, second is 64-bit. Return at `0x565f665`. |

The high-denominator estimate subtracts one with a zero clamp. The final
`SBB RAX,-1` implements the one-step correction. The two-limb remainder
subtraction must propagate borrow: changing that SBB to SUB makes the tested
`2^65 / (2^64+1)` result `2` instead of `1`.

## Measurements and controls

Both independent listings produce identical `evidence.json`:

- 159,431 nonzero-denominator **cases**, zero quotient mismatches. Cases include
  power-of-two neighbours at every bit position, quotient/remainder boundaries,
  and 8,192 fixed-seed random pairs (full-width and one-limb denominators).
  This count includes repeated pairs; it is not a count of distinct inputs.
- All 71 instructions visited; both outcomes of all five conditional branch/move
  sites reached; all four return paths reached (counts in the JSON).
- Six zero-divisor controls stop at hardware divide faults, exercising both the
  32-bit and 64-bit first-DIV routes. No native signal was triggered.
- Six actual instruction-byte mutations are written only to owned temporary
  ELF copies, freshly disassembled, and evaluated at retained counterexamples.
  These deliberately bypass only the global identity check to test sensitivity
  to denominator source, DIV width, estimate decrement, remainder borrow,
  correction carry, and high-quotient preservation. Each is also rejected by
  the ordinary identity gate. Exact changes and outcomes are retained in
  `corruption-controls.json`.
- Listing-hole, byte-binding, interior-branch, unknown-register/flag and
  unsupported-instruction controls fail explicitly.

The vector/result stream SHA-256 is
`3c830d08cd836da43ed56369a3cac2834dc67b4ce2aae53d82d4c7a5faf8b80e`.
No binary normalization mask is used. The only disassembly text canonicalization
equates an implicit shift-by-one with explicit one, and equivalent immediate and
branch-address spellings. It changes no input byte or evaluated integer.

## Results and limitations

Exact executed tool versions and repository checks are retained in `validation.txt`.
The GNU-equipped baseline passed 431 existing tests before adding the new tests.
Earlier local attempts exposed missing GNU tools and Apple/GNU output differences;
no repository checks were weakened to resolve those environment failures.

Rust implementation, pinned component build, two-build comparison, raw or normalized
source-build equality, native behavioral execution, hosted CI and whole-node
equivalence are **not yet implemented/measured**. The decoder and evaluator remain
trusted analysis tools. Finite agreement and complete instruction/path visits do
not establish correctness over all 2^256 input pairs. The generic compiler-runtime
name `__udivti3` remains an inference, not a recovered symbol or ownership claim.
Original binary/disassembly material retains upstream rights; new code is MIT.
No progress gate is requested; all incomplete component gates stay false.

Next question: can the normalized high-denominator estimate and single correction
be proved correct over the entire unsigned 128-bit domain, independently of this
finite evaluator?
