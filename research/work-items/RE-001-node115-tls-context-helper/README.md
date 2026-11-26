# RE-001: resolve the node #115 TLS-context helper target

- Target: Linux x86-64 `hl-node` #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Question: which native body is reached by the two indirect helper calls that
  precede the `rsp+0xa0`/`rsp+0xa8` copies in the TLS-context producer?
- Scope: static relocation and entry-window binding only; no execution or ABI
  reconstruction.

## Observations

Both producer calls at `0x15d7026` and `0x15d70c2` use GOT slot `0x64e1760`.
The authenticated `R_X86_64_RELATIVE` entry for that slot has addend
`0x5cf9600`, so both calls resolve to the same native FDE body beginning at
`0x5cf9600`. That body receives the producer's destination in `rdi` and source
in `rsi`; its selected entry window establishes the destination construction
and its later window loads the constructed pair at `rsp+0x400/+0x408`.

This resolves the indirect target and preserves the observed data-flow edge,
but does not assign source names, prove the callee ABI beyond the observed
register/stack relation, or claim that all helper outputs are understood.
The callee's deeper branches and runtime reachability remain outside scope.

## Reproduction and limits

`verify.py` authenticates the full ELF, checks the five exact instruction
windows, verifies the native FDE for the three code regions, and parses the
ELF64 `.rela.dyn` table for the slot/addend pair. The captured binary is not
executed or emulated.

