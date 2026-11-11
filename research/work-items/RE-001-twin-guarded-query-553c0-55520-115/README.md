# RE-001: map node #115 twin guarded queries 0x5d553c0 / 0x5d55520

- Component ID: RE-001
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (bound via `provenance/artifacts.json`; local copy `work/hl-node-115.bin`
  hashes to the same value).
- Source commit / reference commit: upstream main `05bc2de30` (advanced
  from `8fd8db68` during this cycle by a mass integration of late
  node115 PRs, including merges of #2643, #2642, #2640, #2638 and
  #2636; the twin routines are not covered by that integration).
- Claim status: observations, inferred semantics and unknowns are kept
  separate below; `records.json` holds semantic records only.
- Scope included and excluded: the two twin routines in full, their
  exception-cleanup fragments, and their two single call sites. The
  1352-byte inner queries (0x61b21f0, 0x61b2760) are described by call
  shape only and are NOT pinned. Caller bodies beyond the call setups
  and the post-call free are NOT pinned.

## Bounded question

What do the twin routines at 0x5d553c0 and 0x5d55520 do to their holder
and output record, and which code calls them?

## Reproduce

Working directory: the repository root. Tool versions on this VM:
`objdump`/`readelf` from GNU binutils (versions recorded by the command
output itself; rerun `objdump --version` for the exact build). Commands:

```
objdump -d --start-address=0x5d553c0 --stop-address=0x5d554e4 work/hl-node-115.bin
objdump -d --start-address=0x5d55520 --stop-address=0x5d55644 work/hl-node-115.bin
objdump -d --start-address=0x5d5538e --stop-address=0x5d553c0 work/hl-node-115.bin
objdump -d --start-address=0x5d554e4 --stop-address=0x5d55516 work/hl-node-115.bin
readelf --debug-dump=frames work/hl-node-115.bin
python3 research/work-items/RE-001-twin-guarded-query-553c0-55520-115/census.py
python3 research/work-items/RE-001-twin-guarded-query-553c0-55520-115/verify.py
python3 tests/test_twin_guarded_query_553c0_55520_115.py
```

Virtual addresses are objdump's addresses; file offset = virtual
address - 0x1000 within the executable LOAD segment (file offset
0x1418300, vaddr 0x1419300). No execution, no network, no side effects
beyond reading the binary.

Note on instruction mnemonics: tokens such as `endbr64` in the excerpts
are genuine instructions present in the target binary, not placeholders;
the excerpts are verbatim objdump output (only the binary path in the
header is normalized to the bare binary name) and `verify.py` checks
every excerpt instruction line byte-for-byte against the raw binary.

## Evidence

The two routine bodies are instruction-identical except for their
branch/call target addresses and the inner query callee (0x61b21f0 vs
0x61b2760); each routine's landing pads jump to its own cleanup
fragment. Both inner queries are 1352 bytes. The pair reads as two
instantiations of one guarded-query template.

Pinned semantics (signature: rdi = output record, rsi = holder,
rdx = key_struct, rcx = caller_arg, r8 = key16 pointer, plus a 16-byte
stack argument forwarded unchanged to the inner query; returns the
output pointer):

1. The output record (int32 +0x00, uint16 +0x04, pointer +0x08) is
   zeroed at entry, unconditionally, before the flag check. An incoming
   pointer in the output slot is overwritten, not freed.
2. Holder +0x650 null -> return the zeroed output at once: no mutex
   operation, no inner query call.
3. Otherwise acquire the mutex at holder +0x658 via 0x606ca40, then
   re-read holder +0x650; a null re-read releases the mutex via
   0x60d52f0 and returns the zeroed output.
4. Otherwise call the inner query with (stack temp record, re-read flag
   value, key_struct, caller_arg, key16, pair16 stack argument).
5. Move the temp record into the output (int and tag copied, pointer
   moved; temp slots cleared). The code then tests the pre-move output
   pointer for a conditional operator delete[] free, but that slot was
   zeroed at entry, so the free never fires on the normal path.
6. Release the mutex via 0x60d52f0 and return the output pointer. The
   returned pointer is disposed of by the caller, not by the twin.
7. Exception path: each twin's landing-pad fragment tests the output
   pointer for a conditional delete[] free and rethrows via
   _Unwind_Resume; the fragment reached from the post-acquire region
   additionally releases the mutex first. Because the output was zeroed
   at entry, the cleanup free likewise cannot fire with a non-null
   pointer; the fragment's observable effects are the mutex release
   (post-acquire region) and the rethrow. Both routines check the stack
   canary and call __stack_chk_fail on mismatch.

Callers (census: executable-LOAD-segment exhaustive E8/E9 scan with
objdump confirmation, reproduced by `census.py`): each twin has exactly
1 direct call and 0 tail jumps, 0 stored qwords in data segments, and
0 RELATIVE relocations mentioning its address — reached only by code,
never by data. Twin A is called at 0x5ea300a (caller FDE
0x5ea2e40..0x5ea3c83); twin B at 0x5ea877a (caller FDE
0x5ea85b0..0x5ea93f1). Both callers build byte-identical setups: the
holder is the object at caller rbx +0x2e0 (null-gated), the key_struct
is seeded from the first dword of the object at caller rbx +0x2e8
(null-gated), key16 comes from the object at caller rbx +0x1d8 (or the
default whose first qword points at the path string at 0x4376fd,
`/home/ubuntu/hl/code_Mainnet/z_vendor/futures-channel/src/oneshot.rs`),
and the stack pair comes from the object at caller rbx +0x1e0 (or the
same default). After the call each caller frees the output pointer
field when non-null (operator delete[]) and does not read the int/tag
fields in the observed block — a probe-style use, where the inner
query's side effect on the holder under the mutex is the observable
effect and the returned triple is discarded.

## Implementation and comparison

Model: `tools/twin_guarded_query_553c0_55520_115.py` with
`tests/test_twin_guarded_query_553c0_55520_115.py` (12 tests: flag-zero
path, entry zeroing without free, happy-path move with mutex ordering,
temp clearing, re-read-null path, inner-exception release + rethrow,
both twins sharing wrapper behavior, u16 boundary, probe-call free
cases, pointer-move identity). The inner query is a test input in every
case; the model pins the twin wrapper only. No Rust reconstruction: this
VM has no cargo/rustc, and the inner queries are not pinned.

## Results and limitations

`verify.py` reports ALL CHECKS PASSED (digest, provenance, manifest,
excerpt regeneration byte-for-byte from fresh objdump runs, every
excerpt instruction line byte-for-byte against the raw binary, FDE
ranges, both censuses with exact site lists, empty relocation record,
semantic-only records, model spot checks). Three extra spot
instructions were additionally checked byte-for-byte against a fresh
objdump run and the raw binary: the mutex-acquire call at 0x5d55422,
the twin-B inner call at 0x5d555b1, and the cleanup unlock call at
0x5d55391.

Unknowns, not pinned: what either 1352-byte inner query computes; the
identity/type of the holder object and of the object at holder +0x650;
what the key_struct, caller_arg, key16 and pair16 arguments mean to the
inner query; caller bodies beyond the call setups and the post-call
free; the exact LSDA protected-range assignment of each twin's two
landing pads.

Environment limits: this VM has no cargo/rustc, git-lfs or Ghidra/Java
(`make doctor` fails on missing native tools); the work is static
disassembly plus a Python model only, verified against the materialized
node #115 binary above.

Next question: what do the twin inner queries (0x61b21f0, 0x61b2760)
compute from the flag object and the caller-built key arguments?
