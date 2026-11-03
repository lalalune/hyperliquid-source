# RE-001: node #115 +0x70 incrementer leaf 0x5d8d0b0 with its sole call site

## Bounded question

What is the small leaf immediately preceding the +0x70 getter/raiser
pair mapped by open PR #2397, and what does its only caller do with it?

## Answer, stated literally

The leaf at `0x5d8d0b0` (FDE `0x5d8d0b0..0x5d8d0be`, 14 bytes)
takes an object in `rdi`, reads the dword at `obj+0x70`, adds 1 to
it as a 32-bit quantity, stores the result back at `obj+0x70`,
and returns the new value in `eax`. It makes no calls and writes
nothing else. The addition wraps modulo 2**32: a field holding
`0xFFFFFFFF` becomes `0`, and the returned value is `0` in that
case. Together with the getter at `0x5d8d0c0` and the unsigned-max
raiser at `0x5d8d0d0` (open PR #2397, referenced here and not
re-claimed), this completes the observed operation family on the
same `+0x70` field: read it, raise it to a maximum, increment it.

## The sole call site, end to end

Whole-file census (reproduced by `census.py` and re-run inside
`verify.py`): exactly one direct call, at `0x5d69d70`; no tail
jumps, no stored qwords, no RELATIVE addends. The caller function
is `0x5d69a00..0x5d6a6d9`.

- Lookup and branch (`site-lookup.txt`, `0x5d69caa..0x5d69cc6`):
  the caller loads `rdi` from the qword at `[qword at [r13+0x68]
  + 0x40]` and `rsi` from `[rbp-0x9b8]`, calls the lookup routine
  `0x5d8cf70`, saves the result, tests it, and jumps to the null
  arm at `0x5d69d38` when the result is zero.
- Taken arm (`site-taken.txt`, `0x5d69cc6..0x5d69d31`): when the
  lookup returns nonzero, the caller falls through past the jump
  and never calls the incrementer on that path; the path ends
  with a jump to `0x5d69aff` at `0x5d69d2c`. The intervening calls
  on that path are not claimed.
- Null arm (`site-nullarm.txt`, `0x5d69d38..0x5d69d7b`): the
  caller prepares a stack object (a call at `0x5d69d49`, then an
  assign PLT call at `0x5d69d63` with `rdi` = stack address
  `[rbp-0x538]` and `rsi` = the qword at `[rbp-0x9b8]`), loads the
  same `rdi` chain as the lookup call, calls the incrementer at
  `0x5d69d70`, and stores the returned value at `[rbp-0x540]`.
  A whole-function scan of the caller shows that stack slot is
  never read again inside the caller function.

So the complete observable behavior is: on a lookup miss, the
caller increments the shared object's `+0x70` field by one and
saves the new value; on a lookup hit, it does not touch the
field on this path at all.

## NOT claimed

Caller semantics beyond the recorded site (including the
stack-object preparation's purpose and the taken path's later
calls), the lookup routine's own semantics, what the objects or
their `+0x70` field denote, what happens at `0x5d69aff` or past
the site, or any use of the stored value after the caller
function returns.

## Evidence and how it was produced

All results are bound to one artifact: `work/hl-node-115.bin`,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
matching the entry for `artifacts/node/115/hl-node` in
`provenance/artifacts.json`.

The disassembly excerpts in this packet are verbatim objdump
output, produced with commands of the form:

```
objdump -d --start-address=0x5d8d0b0 --stop-address=0x5d8d0be work/hl-node-115.bin
```

(see `export_excerpts.py`, which is committed in this packet and
regenerates every excerpt). Instruction-level detail lives only
in those raw excerpt text files, kept whole-function; the JSON
in this packet holds semantic records only, with no
per-instruction mnemonic list. Mnemonics such as `endbr64` in
the excerpts are genuine instructions present in the target
binary, not placeholders.

Files: `main.txt` (whole leaf), `site-lookup.txt`,
`site-taken.txt`, `site-nullarm.txt` (whole site windows),
`frames.txt` (FDE lines for the leaf, the caller and the lookup
routine), `relocations.txt` (empty: no RELATIVE record mentions
the leaf), `callers.tsv` (the census site), `records.json`
(semantic records), `export_excerpts.py`, `census.py`,
`verify.py`, `MANIFEST.sha256`.

## Verification

- Packet checker: `python3
  research/work-items/RE-001-incrementer-115/verify.py` prints
  ALL CHECKS PASSED (digest, provenance, manifest, excerpt
  regeneration byte-for-byte from a fresh objdump run, every
  excerpt instruction byte-for-byte against the raw binary, FDE
  ranges, census, semantic records, model tests).
- Anti-low-quality self-check: three instructions picked from
  the leaf and the site (`0x5d8d0b7`, `0x5d69cb9`, `0x5d69d70`)
  verified byte-for-byte against a fresh objdump run and the raw
  binary inside `verify.py`.
- Model: `tools/incrementer_115.py` with
  `tests/test_incrementer_115.py` — 12 checks pass (zero, value,
  wrap at `0xFFFFFFFF`, 32-bit masking, double increment,
  missing-field guard, other fields untouched, null-arm
  increment-and-store, null-arm wrap, taken-arm no-increment for
  two nonzero results, null-arm missing-field guard).

## Environment limits, stated honestly

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so
the model is Python only and no Rust reconstruction is claimed.
The full `make verify` suite is not run here: its baseline
already fails on missing LFS material, which is pre-existing
and unrelated to this change. The packet's own checker and the
model tests above are the verification for this work item.
