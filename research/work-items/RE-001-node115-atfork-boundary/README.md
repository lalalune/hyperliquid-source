# RE-001: node #115 atfork registration boundary

- Component: foundation / native initialization; selected caller only.
- Target: `artifacts/node/115/hl-node`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Status: bounded static observation, not reconstructed implementation.

## Observation

At VA `0x634f351`, within unwind FDE `[0x634f0b0,0x634f8d5)`,
three preceding RIP-relative LEAs supply `rdi=0x634f910`,
`rsi=0x634fd90`, `rdx=0x634ffd0`. Each value is an exact FDE entry;
the corresponding exclusive ends are `0x634fd81`, `0x634ffca`,
`0x635020a`. These are argument coordinates, not reconstructed callback bodies.

The direct call reaches `0x63f09f0`, whose 16-byte stub loads `rcx`
from `0x64efa20` and jumps to PLT `0x63f1b90`. The PLT's indirect
jump uses slot `0x64eea18`, resolved by an actual
`R_X86_64_JUMP_SLOT` relocation to `__register_atfork@GLIBC_2.3.2`.
This closure does not rely on misleading objdump nearest-symbol annotations.
Interpreting these registers as callback arguments and a DSO-handle argument
uses the x86-64 SysV ABI and the imported function's interface; the loaded
handle value and dynamic loader's runtime resolution remain untested.

Immediately after the call, `test eax,eax; jne 0x634f5c0` splits the result.
Zero falls through at `0x634f35e` to a direct call to `0x6369dc0`.
Nonzero reaches code that loads string VA `0x95ac10` and calls
`0x63be670`; the target string is `<jemalloc>: Error in pthread_atfork()\n`.
This supports a jemalloc-associated registration boundary, not a claim about
node-specific callback semantics, fatal errors or runtime registration success.
The nonzero excerpt also shows subsequent conditional flow: the diagnostic
helper's behavior and whether it returns are not established here.

## Reproduce

From repository root, with Python 3 and GNU binutils 2.40:

```sh
python3 research/work-items/RE-001-node115-atfork-boundary/replay.py
python3 -m unittest discover -s tests -p test_node115_atfork_boundary.py -v
```

`--write` regenerates the packet for explicit review; ordinary replay compares
against committed records. The collector authenticates the complete ELF digest,
uses file-backed PT_LOAD VA-to-file mappings, checks exact FDEs with
`readelf -wf`, binds the relocation with `readelf -Wr`, and saves four
instruction-aligned `objdump -d -M intel` windows. Exact argv and version
queries are in `replay.py`; raw bounded outputs, file offsets and hex are in
`records.json`. No normalization masks are used. The full frame/relocation
streams are consumed in memory and not saved as large dumps.

## Implementation and controls

The independently authored Python collector is task-local evidence replay,
not a new general-purpose disassembler. The instruction decoder accepts only
specific observed forms and validates each relevant relative operand.
Corruption tests change actual authenticated target bytes in memory after
extraction, exercising callback coordinates, call/branch opcodes and targets,
stub operands, PLT/GOT linkage, diagnostic operands and truncation separately.
The positive replay reads the real pinned ELF; no captured binary is executed.

## Results and limits

The explicit denominator is one selected caller, three supplied callback
coordinates, five exact FDEs, and 109 code bytes in four bounded windows.
This is not a census of all callers or callbacks. It adds the registering
caller, import linkage, callback FDE coordinates and return split beyond the
previous vendor-census stub identification (merged PR #2050).

`local-checks.json` is a historical local-only capture, before independent
validation. Its "not run" fields describe that capture stage, not the latest
publication state. Subsequent independent commands, tree identity, results and
global-suite limits belong to the trusted PR validation receipt. This packet
does not assert a global-suite or hosted-CI pass.
No component/progress gate changes are requested. No Rust reconstruction,
source equivalence, whole-function CFG coverage, callback effects, successful
fork behavior, or runtime target execution is established. Imported byte
excerpts retain their original upstream rights; new collector/tests/prose are
independently authored, without copying inferred reference source.

Next question: validate this packet independently, then determine whether a
separately bounded callback-body analysis would establish useful semantics.
