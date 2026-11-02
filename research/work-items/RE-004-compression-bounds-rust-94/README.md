# RE-004: independently authored Rust for both node #94 compression bounds

- Component: `foundation`; bounded arithmetic reconstruction under RE-004,
  using the earlier RE-001-style byte/FDE evidence. Both leaves belong to one
  compression capacity contract; this packet implements them together.
- Target: node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
- Reference: the project-authored
  [static packet](../foundation-compression-bounds-94/README.md), whose tool
  and evidence hashes are recorded in `target-binding.json`. No can1357
  implementation or external compression source was read or copied.
- Before: the static packet expressly excluded Rust reconstruction. After:
  both established value contracts have a safe, buildable Rust implementation
  and separate native checks against frozen exact expectations.
- Claim: complete value rules under normal return conditions for the two
  selected leaves. Library names remain inferences. Original ABI, compiler,
  rebuilt bytes, complete callers and full component gates remain unresolved.

On 2026-11-02 KST, live GitHub inspection found 33 open PRs and no open issues.
No PR title/body matched either address or compression-bound terms; source
search found the separate Rust `lz4_flex` transport implementation, which is
outside these leaves. The coordinating agent reserved this scope. No issue,
claim or external message was created by this worker.

## Actual bytes, boundaries and data

Addresses are linked ELF virtual addresses, not runtime relocated addresses.
`target-binding.json` is regenerated from the authenticated ELF on every
qualification run. It uses the existing full-byte checker plus the separate
`fde_extents.eh_frame_records` decoder, not merely the prior packet's prose.
The complete decoded FDE list contains exactly one record for each start,
with the expected end and no LSDA. Both bodies end at `ret`; the following
padding and successor FDE records are also locked.

| Leaf | Extent / bytes | File offset | Body SHA-256 |
| --- | --- | --- | --- |
| A | `[0x546af50, 0x546af6b)` / 27 | `0x5469f50` | `8c23296a82e969ac0537190fdcbae87527ac42aeca3e225608500d55620463f2` |
| B | `[0x546e280, 0x546e2ad)` / 45 | `0x546d280` | `2faf91e85036c759201857f0ee15f1c7418a0c1d9f46dcd83eed1c1edd60e23f` |

`snappy.objdump.txt` and `lz4.objdump.txt` are fresh GNU objdump exports,
including the five and three `int3` padding bytes respectively. The displayed
nearest symbol plus offset is an objdump label, not a recovered function name.
Exact export commands, from repository root:

```sh
/opt/homebrew/opt/binutils/bin/objdump -d --insn-width=16 --start-address=0x546af50 --stop-address=0x546af70 artifacts/node/94/hl-node
/opt/homebrew/opt/binutils/bin/objdump -d --insn-width=16 --start-address=0x546e280 --stop-address=0x546e2b0 artifacts/node/94/hl-node
```

Every body instruction is decoded. A has no branch except `ret`; B has one
`ja` targeting its common `ret` at `0x546e2ac`. There are no calls or tail calls,
external memory operands, tables, vtables or helper functions in these bodies.
`lea` performs integer arithmetic, not a memory read. All constants are inline
instruction operands. `ret` requires a valid return-address stack.

The verifier checks every ELF `SHT_RELA` section for relocations patching these
bodies; there are none. The prior checker separately revalidates the shared
CIE, both selected and successor FDE bytes, no `.rela.dyn` addend naming either
entry, and the direct `e8` call candidates. These are not an indirect-caller
census. Caller semantics and original C/C++ type names are unchanged in scope.

## Exact value proof from those bytes

For A, let `n` be raw RDI and `M = 0xaaaaaaaaaaaaaaab`.
The unsigned `mul` high half followed by `shr 2` gives
`floor(n*M / 2^66)`. Since `6*M = 2^66 + 2`, write `n = 6*q + r`:

```text
n*M / 2^66 = q + r/6 + n/(3*2^66)
0 <= r <= 5, 0 <= n < 2^64
0 <= r/6 + n/(3*2^66) < 5/6 + 1/12 < 1
```

Thus the quotient is exactly `floor(n/6)` for every `u64`. The final 64-bit
`lea` adds `n + quotient + 32` modulo `2^64`. No overflow branch exists.
The independent oracle combines the arithmetic into
`floor((7*n + 192)/6) mod 2^64` using Python arbitrary-precision integers.
The first wrapped input is 15,811,494,920,322,472,787; its predecessor returns
`0xffffffffffffffff`, it returns zero, and its successor returns two.

For B, the `cmp`/`ja` is an unsigned comparison of EDI against `0x7e000000`.
The rejected arm returns the initial EAX zero. This rejects every raw input
with bit 31 set, so the admitted arm always has nonnegative `n` and its sign
correction in EDX is zero. Let `M = 0x80808081`. The signed multiplication
uses `M - 2^32`; extracting its high half and adding `n` modulo `2^32`
produces `floor(n*M/2^32)`. This is below `2^31` throughout the admitted
domain, so the following arithmetic right shift by seven is the unsigned
floor `floor(n*M/2^39)` as well.

```text
255*M = 2^39 + 127
n = 255*q + r, 0 <= r <= 254
n*M / 2^39 = q + r/255 + 127*n/(255*2^39)
127*0x7e000000 < 2^39
0 <= r/255 + 127*n/(255*2^39) < 1
```

The quotient is therefore `floor(n/255)`. The final 32-bit `lea` adds
`n + quotient + 16`, with maximum `0x7e7e7e8e`, below `2^31`; no admitted
result overflows. The oracle independently combines the numerator into
`floor((256*n + 4080)/255)`, after applying the exact unsigned guard.
The derivation is mathematical; no instruction emulator or captured code ran.

## Implementation and test separation

[`src/node94-compression-bounds`](../../../src/node94-compression-bounds/README.md)
contains two safe `const fn` value APIs, using ordinary Rust division and
explicit wrapping only where the target wraps. The library is `no_std`,
forbids unsafe code, has no dependencies and needs no Cargo manifest/lockfile.
The direct rustc build is the actual documented build scope.

`snappy_bound(u64)` represents raw RDI and returns the observed RAX value.
`lz4_bound(u32)` represents raw EDI and returns the observed EAX value; EAX
writes also clear the target's upper RAX bits. High input RDI bits are ignored
by B's result, since its guard and effective final arithmetic are 32-bit.
Rust ABI, host instruction selection, register clobbers, flags, faults, CET,
unwind behavior and invalid return state are not reproduced. The APIs do not
promise that a wrapped result is an adequate compression allocation.

The independently written client reads only stimuli from stdin and calls the
compiled rlib. It has no expected-answer file argument, embedded fixture or
alternate formula. The Python parent supplies input bytes, compares complete
output rows and rejects missing/reordered/malformed records. This is data-flow
separation, not an operating-system sandbox.

`inputs.txt`, `expected.txt`, `coverage.json` and `target-binding.json` are
frozen and regenerated for comparison before compilation. The expected file
comes from the two rational-floor forms above, never from the new Rust output.
The manifest binds those files, the checker and the Rust sources. Coverage is
finite and is reported separately from the proof over all inputs:

- 1,162 A inputs, including all six residues, division edges, 64 KiB, 32-bit
  and sign boundaries, the exact first overflow and `u64::MAX`; 162 wrap.
- 2,502 B inputs, including all 255 admitted residues at several quotient
  anchors, the exact guard boundary, sign boundary and `u32::MAX`; 822 reject.
- Both families also include deterministic random bit patterns.

## Reproduce

From repository root, with the captured inputs already materialized:

```sh
PATH="/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH" make doctor
python3 tools/foundation_compression_bounds.py \
  --check research/work-items/foundation-compression-bounds-94/evidence.json
python3 -m unittest tests.test_foundation_compression_bounds -v
RUSTC_BIN=$(/opt/homebrew/opt/rustup/bin/rustup which --toolchain 1.94.1 rustc)
python3 research/work-items/RE-004-compression-bounds-rust-94/verify.py \
  --out work/compression-bounds-review --rustc "$RUSTC_BIN"
shasum -a 256 -c research/work-items/RE-004-compression-bounds-rust-94/MANIFEST.sha256
```

`--freeze` was used once to create the new frozen files; it refuses to overwrite
them. Ordinary qualification only compares them with regenerated expectations.
Use a fresh output directory so prior failures cannot be overwritten.

Recorded tools: Python 3.14.3; GNU objdump 2.47.20260726; rustc 1.94.1,
commit `e408947bfd200af42db322daf0fadfe7e26d3bd1`, LLVM 21.1.8,
host `aarch64-apple-darwin`; Apple clang 17.0.0 (`clang-1700.0.13.5`);
macOS 27.0.1, build 26A434. Actual rustc executable SHA-256:
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`.
The verifier rejects a different executable. These are research tools, not
recovered target build provenance. The record includes the linker executable
hash and full versions; it does not pin every OS SDK or compiler shared library.

The retained streams can be independently checked without compiling:

```sh
python3 - <<'PY'
import base64, gzip, hashlib, json
from pathlib import Path
p = Path('research/work-items/RE-004-compression-bounds-rust-94/native')
archive = json.loads(gzip.decompress((p / 'raw-streams.json.gz').read_bytes()))
for call in json.loads((p / 'calls.json').read_text()):
    for log in call['logs'].values():
        raw = base64.b64decode(archive['payloads'][archive['streams'][log['path']]], validate=True)
        assert len(raw) == log['bytes']
        assert hashlib.sha256(raw).hexdigest() == log['sha256']
print('All retained stream hashes match')
PY
```

Every Rust compilation uses edition 2021, target `aarch64-apple-darwin`,
`-Dwarnings`, one codegen unit, `-Copt-level=0` or `3`, overflow checks on,
the explicit `/usr/bin/cc` linker, and repository path remapping to
`/reconstruction`. Library metadata is `compression_bounds94`.
`native/calls.json` records every actual command, exit status, stdin and raw
stdout/stderr hash. Only the repository and actual compiler paths are replaced
by `<repo>` and `<rustc>` to avoid publishing home-directory information.

## Observed native results

Both optimization levels passed all 3,664 input-only comparisons with zero
mismatches and passed three Rust unit tests. The common stdout SHA-256 is
`76faa8c308bc0e02a5178648bc82b2ed944ade269aa848349f8a0b2f16ee8810`.
Repeated builds at each level produced identical rlibs and linked clients:
four raw-equal own-artifact comparisons, no normalization. This says nothing
about equality to the original x86-64 bytes.

Each deliberate wrong implementation was compiled and executed under both
optimization levels, exited normally, and differed from the same frozen oracle:

| Wrong implementation | Mismatches per level |
| --- | ---: |
| A divides by seven | 1,144 |
| A saturates instead of wrapping | 162 |
| A narrows its input addend to 32 bits | 1,100 |
| A adds 31 | 1,162 |
| B rejects the inclusive limit | 1 |
| B uses a signed guard | 678 |
| B divides by 256 | 1,171 |
| B adds 15 | 1,680 |

The wrong signed guard uses wrapping additions only in that mutant so rejected
high-bit values produce wrong values without aborting on overflow. A changed
output answer, a missing row and reordered rows also exercised the comparator.
`native/results.json` records counts, source hashes and the first witness for
each of the 16 native mutation controls. `native/raw-streams.json.gz` retains
all raw stdout/stderr streams losslessly, including empty streams. The
deterministic archive maps each log filename to its SHA-256 and stores each
distinct payload once as base64. Every decompressed payload was checked against
the byte count and hash in `native/calls.json` after packaging.

The earlier static checker and all 18 existing focused tests passed, with no
skips. Those tests retain wrong-byte, FDE, guard, constant and padding controls.
Repository-wide validation is recorded separately in `checks.txt`; a full
test-suite or hosted CI result is not inferred from these focused checks.

## Limits

No captured node/visor execution, networked service, instruction emulator,
external compression source, instruction-byte transplantation or chain action
was used. Two selected leaf value contracts are implemented; complete storage,
compression algorithm behavior, original symbols/library versions, indirect
callers, caller allocation policy and the Rust `lz4_flex` path are outside scope.
No compiled target byte comparison was performed and no byte-window registry,
component acceptance gate or imported evidence was changed.

Remaining question: which real callers can reach A's wrapping range, and how
do their allocation/error paths constrain its mathematical input domain?

Execution provenance: OpenAI via Codex. The exact model identifier was not
available to this worker and is not guessed.
