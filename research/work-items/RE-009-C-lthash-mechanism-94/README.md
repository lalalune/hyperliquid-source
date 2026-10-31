# RE-009-C — LtHash-style lattice accumulator mechanism (node #94)

## Component ID
RE-009-C `lthash-mechanism-94`. Related: #262 (field identities). Nothing is imported from #262.

## Target release
`hl-node` #94, 91,774,280 bytes, sha256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

## Source commit
This packet was built off main `1f8c67c63ca4794c9689235471c60297f8a5c985`.

## Claim status
**Mechanism: verified from instructions.** The name "LtHash" is used because it fits the evidence. The identity is not proven.

## Scope
**Included:** three leaf functions. Each one does the following:
1. Hashes an entry with blake3 and reads 0x800 bytes of XOF output.
2. Adds the result into a 0x800-byte lattice of 1024 **big-endian** u16 words. The add wraps mod 2^16.
3. Saturating-adds two u64 counters in a 0x810-byte state (at +0x800 and +0x808).
4. Merges states with the same word-wise add.

It also covers the complete reference closure above each leaf. The scan covers four reference kinds across all of `.text`: e8 call, e9 jmp, RIP-relative lea, and R_X86_64_RELATIVE addends.

**Excluded:**
- The field identities (accounts, contracts, storage). These are a Location-supported inference, consistent with #262.
- Hash input serialisation.
- Any comparison with a reference LtHash implementation.
- What the writer 0x32699c0 does, beyond its pinned callers.
- Register-computed indirect calls through non-relocated data.

## Reproduce
```
python3 -O -B tools/lthash_mechanism.py > out.json      # sha256 fd44957c759ec48f8499ac966e89cfab7c92a5405ab3087a1476df3897b9339e
python3 -O -B research/work-items/RE-009-C-lthash-mechanism-94/verify.py
python3 -O -B research/work-items/RE-009-C-lthash-mechanism-94/independent_verify.py
python3 -B -m unittest tests.test_lthash_mechanism        # 21 tests
```
Tool versions: Python 3.13.5 and GNU objdump 2.44 (Debian), used only for bounded extents. The output is byte-identical under PYTHONHASHSEED 0, 7 and 99.

## Evidence
All coordinates are virtual addresses (VAs). The pinned per-leaf VAs, calls, loop bounds and block sha256s are in `lthash-mechanism.json`.
- **Byte order:** each lane is `movzx` WORD load → `rol r16,0x8` (`66 c1 cX 08`) → 32-bit add → `rol r16,0x8` → `mov` WORD store. These are big-endian words. There is no movbe or bswap.
- **Entry loop:** rax = 1..0x401 step 2, 2 lanes per iteration. That is 512 × 2 = 1024 words (0x800 bytes). 0x401 is the loop bound, not the word count. The merge loop runs 0..0x400 step 2, which is also 1024 words.
- **Counters:** add, then `mov rcx,-1` with cmovb/cmovae, which saturates at 2^64−1.
- **XOF:** each leaf makes three blake3 calls, with XOF length 0x800. They go through GOT slots 0x57700c0, 0x57700c8 and 0x57700b0. Each slot is filled by a single R_X86_64_RELATIVE entry, and both the tool and the independent verifier resolve those entries. The names are stripped, so each label comes from the target's bytes:
  - 0x57700c0 → 0x14fa220 is a **platform-detect** slot. The target tests the CPU feature word (`test eax,0x80000`) and returns a SIMD level (`mov al,0x4`). The hasher constructor is inlined at the call site.
  - 0x57700c8 → 0x14f93e0 is **update**. It works on a 0x400-byte chunk buffer (`cmp rax,0x401`, `mov r14d,0x400`).
  - 0x57700b0 → 0x14f7e40 is **XOF fill**. It is called with a buffer and a length, sets the ROOT flag (`or al,0x8`), and writes 64-byte output blocks (`and rax,-0x40`, `shr rcx,6`). There is a wide-SIMD path through slot 0x57700b8. All links are direct rel32 calls; there is no vtable.
- **Reference closure:** the full `.text` scan pins 53 reference sites to 32 targets, each with an exact site, kind and owner function. The owner is checked against the `.eh_frame_hdr` FDE ranges.
  - Each leaf's backward closure has exactly 11 functions and 16 edges.
  - The only entry from outside the closure is one call from the top function 0x3269ae0.
  - Inside the closure, the rayon helper and join functions (0x381f310, 0x3828b20, 0x3830a40) recurse into each other. Their job functions are reached only by lea.
- **Writer 0x32699c0:** exactly 3 callers: 0x326a2e0 (in top 0x3269ae0), 0x326aff3 (in 0x326aec0), and 0x32fc267 (in 0x32fc190). The writer is not exclusive to the top function.
- **Top 0x3269ae0:** exactly 2 callers: 0x326e4bb (in 0x326e460) and 0x32fc41f (in 0x32fc190).
  - 0x326aec0, 0x326e460 and 0x32fc190 are referenced only through RELATIVE relocations, at 0x5775058, 0x5775580 and 0x5775720.

## Implementation and comparison
Not yet implemented.

## Results and limitations
- 3/3 leaves decoded.
- 6/6 loops (3 entry, 3 merge), all 1024 words, big-endian.
- 3/3 count blocks saturating.
- `independent_verify.py` checks 46 items, including 37 key VAs and 9 block hashes, with errors=0.
- Tamper tests cover all 37 key VAs, for both the tool and the independent verifier.

Limitations:
- Reference closure: 3/3 leaves closed, with 11/11/11 functions and 16/16/16 edges.
  - 53/53 pinned sites over 32/32 targets.
  - Writer: 3 callers. Top function: 2 callers.
  - Any new reference site fails both checkers, and so does any removed one. Tests inject e8 and e9 calls, and remove a call.
- Completeness applies only to the four scanned reference kinds. Register-computed indirect calls through non-relocated data are not covered.

Next question: do the writer's other callers write the same `/lt_hashes` format? Those callers are 0x326aec0 and 0x32fc190, and both are reached only through relocations. A related question is what the relocation-only entry functions 0x326e460, 0x326aec0 and 0x32fc190 are.

## What this does not claim
- It does not claim this is a specific published LtHash. "LtHash" is only a fitting name.
- It does not claim the accounts/contracts/storage identities. Those are inference, consistent with #262.
- It does not claim what bytes are hashed, or that this is a security property.
- It does not claim callers reached through register-computed indirect calls outside the four scanned reference kinds.
