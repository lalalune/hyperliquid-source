# RE-001: node #115 hash-long with-seed body 0x61c2cb0

## Bounded question

The merged hash packet for the parent dispatch
(RE-001-hash-callee-61c3530-115, PR #3486) pinned the
877-byte hash function at `0x61c3530` for lengths 0..128
and left its two delegation targets by contract only,
naming this one first among them for the long lengths:
when the length is 241 or more, the parent restores the
argument registers and tail-jumps to `0x61c2cb0`. What
does that body compute: what does it do when the seed is
zero, what secret does it build when the seed is nonzero,
how does it accumulate the input, and what exactly does
it hand to its one callee at the end?

## Answer, pinned to the target

The routine (FDE `0x61c2cb0..0x61c3221`, 1393 bytes) takes
the parent's own arguments: rdi = the input pointer
(read, never written), rsi = the length, rdx = the seed.
Its only entry is the parent's tail jump at `0x61c3808`;
the census finds no direct call site, no stored qword and
no RELATIVE addend naming it anywhere in the binary. Its
only writes are to its own 0x118-byte stack frame. The
RE-002 vendor census registers this body as
librocksdb-sys 0.11.0+8.1.1 `XXPH3_hashLong_64b_withSeed`;
that identity is cited, not re-asserted -- what follows is
pinned from this binary's instructions.

**Seed 0 delegates.** Tested before any other work
(`0x61c2cd0..0x61c2cd3`): the routine re-checks the stack
canary, restores rsp and tail-jumps to the seedless body
at `0x61c2890` (FDE `0x61c2890..0x61c2cad`, 1053 bytes;
body by contract only) with rdi/rsi/rdx untouched -- the
prologue only ever copied rdi to r9 and rsi to r8.

**The custom secret (seed != 0).** The routine builds a
192-byte secret at frame +0x40 from the 192-byte default
secret: even qwords get +seed, odd qwords get -seed (mod
2^64). The default secret is not stored contiguously: the
compiler deinterleaved it into an even-qword constant set
and an odd-qword constant set, and each 16-byte stack
chunk interleaves one +seed qword from the even set with
one -seed qword from the odd set. records.json pins all
24 (source address, sign, default qword) triples; the
first two default qwords are `0xbe4ba423396cfeb8` and
`0x1cad21f72c81017c`.

**Accumulator init.** Eight qwords, loaded from four
.rodata chunks (`0x455960`, `0x455950`, `0x453a30`,
`0x4525e0`), held in xmm3/xmm9/xmm2/xmm1 through the
loops and also stored at frame +0x00..+0x40:
`0xc2b2ae3d`, `0x9e3779b185ebca87`, `0xc2b2ae3d27d4eb4f`,
`0x165667b19e3779f9`, `0x85ebca77c2b2ae63`, `0x85ebca77`,
`0x27d4eb2f165667c5`, `0x9e3779b1`.

**The accumulate step** is one instruction pattern used
by all three loops. Per 16-byte lane pair j of a 64-byte
stripe, with secret byte offset o = stripe offset + 16*j:

    key_lo = data64[2j]   XOR secret64[o]
    key_hi = data64[2j+1] XOR secret64[o + 8]
    acc[2j]   += data64[2j]   + lo32(key_lo) * hi32(key_lo)
    acc[2j+1] += data64[2j+1] + lo32(key_hi) * hi32(key_hi)

(all mod 2^64; the products are the pshufd $0x31 /
pmuludq pair in the excerpt).

**Block loop.** `length >> 10` blocks of 1024 bytes;
stripe s of a block reads its secret at byte offset 8*s.
Each block closes with one **scramble**:
`acc[i] = (acc[i] XOR secret64[128 + 8*i] XOR (acc[i] >> 47)) * 0x9e3779b1`
for i = 0..7, against the custom secret's last 64 bytes.

**Remaining stripes.** `(length >> 6) & 0xf` stripes from
`data + (length & ~1023)`, at the same secret offsets.

**Last stripe.** Only when `length & 63 != 0`: one stripe
from the input's last 64 bytes (`data + length - 64`)
against the secret at byte offset 121 (= 192 - 64 - 7).
That offset is not qword-aligned -- the body loads the
secret bytes with movdqu at frame +0xb9/+0xc9/+0xd9/+0xe9,
so the key words straddle the secret's qwords.

**Merge hand-off.** The routine calls the merge callee
`0x61c27f0` (FDE `0x61c27f0..0x61c2888`, 152 bytes; body
by contract only) once, at `0x61c31fc`, with rdi = the
accumulator array (frame +0x00), rsi = the custom secret
+ 11 bytes, and rdx = `length * 0x9e3779b185ebca87`
(mod 2^64), and returns its rax after re-checking the
canary. Canary failure on either exit calls
`__stack_chk_fail` through the PLT at `0x63f0d70` (the
body's only other internal call).

## Consumers (site-only)

The census finds exactly one entry, a tail jump inside
the parent hash callee; there are no direct call sites.
Caller semantics beyond the site and the FDE range are
not claimed:

| site | caller FDE | kind |
| ---- | ---------- | ---- |
| `0x61c3808` | `0x61c3530..0x61c389d` (the parent hash callee of PR #3486, itself called directly from 108 sites) | tail jump |

## NOT claimed

The bodies of the seedless delegate `0x61c2890` and the
merge callee `0x61c27f0` (both by contract only: this
packet pins only that the first is entered by tail jump
with the arguments unchanged, and that the second is
called once with the arguments above and its rax
returned); the exact source spelling of the routine
beyond the RE-002 census identity cited above; what the
parent's 108 callers pass as seeds or what they do with
the result; behaviour when the input pointer is invalid
for the length given.

## Evidence

- Artifact: `artifacts/node/115/hl-node`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (provenance/artifacts.json), materialised locally as
  `work/hl-node-115.bin` with the same hash.
- `main.txt`: the whole routine, verbatim, produced by
  `objdump -d --start-address=0x61c2cb0 --stop-address=0x61c3221 work/hl-node-115.bin`.
  Instruction-level detail lives only in that excerpt
  text, never as a per-instruction list in records.json.
- `records.json`: semantic records only (the delegation,
  the custom-secret wiring with all 24 sources, the
  accumulator init, the accumulate/scramble rules, the
  merge hand-off, the census, the consumer).
- `frames.txt`: FDE lines for the routine, its sole
  caller, and the two contract callees. `callers.tsv`:
  the one tail-jump site with its enclosing caller FDE.
  `relocations.txt`: the `__stack_chk_fail` JUMP_SLOT
  behind the canary-failure call; no relocation record
  carries the routine itself as addend.
- Census method note: the routine's own control transfers
  are classified from one linear disassembly of the whole
  routine range (true instruction starts only): 2 internal
  direct calls (the merge call and the stack-check failure
  call), 1 internal direct tail jump (the seed==0
  delegation), no indirect calls or tail jumps. The
  external census uses the exhaustive executable-segment
  E8/E9 scan with objdump confirmation per candidate; no
  candidate was rejected.
- `verify.py` re-checks the digest, the manifest, excerpt
  regeneration byte-for-byte against a fresh objdump run,
  every excerpt instruction byte-for-byte against the raw
  binary, spot instructions, the FDE ranges, the
  relocation record, the census, the records, and the
  model tests. `census.py` reproduces the census;
  `export_excerpts.py` regenerates `main.txt`.
- Model: `tools/hash_long_seed_61c2cb0_115.py`, tested by
  `tests/test_hash_long_seed_61c2cb0_115.py` (46 checks,
  including the custom-secret parity wiring, accumulator
  vectors observed from the real bytes at the merge
  hand-off for lengths 241/1024/1025/2048, the unaligned
  last-stripe secret read, the seed==0 delegation, and
  the input window surviving every path).
- Differential: `differential.py` runs the real 1393
  bytes under Unicorn against the model on 164 cases (the
  length decision edges from 241 to 5000 crossed with
  seed variety and data patterns, plus a random sweep),
  with the merge callee and the seedless delegate answered
  by the same contract functions the model uses, comparing
  the ordered callee event log, the return value, the
  whole native stack frame (accumulator array and custom
  secret) byte for byte, the input window byte for byte,
  and the callee-saved registers: 0 mismatches.

## Reproduce

Working directory: the repository root. Tools, all from
this run:

- GNU objdump (GNU Binutils for Ubuntu) 2.42, invoked as
  `objdump -d --start-address=0x61c2cb0 --stop-address=0x61c3221 work/hl-node-115.bin`
- GNU readelf (GNU Binutils for Ubuntu) 2.42, invoked as
  `readelf --debug-dump=frames work/hl-node-115.bin` and
  `readelf -r work/hl-node-115.bin`
- Python 3.12.3 for `census.py`, `verify.py`,
  `export_excerpts.py`, and the model tests; the Unicorn
  differential additionally needs the `unicorn` package
  (2.1.4 used here).
- Input: `work/hl-node-115.bin`, SHA-256 as above; no
  execution of the target binary (the differential
  emulates the 1393 routine bytes only, with the two
  callee contracts stubbed), no network, no side effects
  beyond writing the packet files listed in MANIFEST.sha256.

## Verification scope and next step

This packet's own checker (`verify.py`), the model tests
and the Unicorn differential are run before submission
and must print ALL CHECKS PASSED, the model check count
and DIFFERENTIAL PASSED. Repository-wide gates (`make
verify`, `make test`, `make catalogue-check`) are run and
reported separately with the change. The next questions
in this area are the two bodies left by contract here --
the seedless delegate `0x61c2890` and the merge callee
`0x61c27f0` -- and the sibling delegation target
`0x61c3230` (lengths 129..240) left open by the parent
packet.
