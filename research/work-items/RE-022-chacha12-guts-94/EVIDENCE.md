# RE-022 evidence notes

## Binary

- Node #94 `artifacts/node/94/hl-node`
- sha256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`

## Function

- VA `0x4e13780` .. ret `0x4e13e59` (carved len 1754, sha256 `1bea6b14e546e8037c041345946203e3994be41e7b83d5c75eca60d40da59eae`)
- SSE only (`movdqa`/`paddd`/`pshufd`); Unicorn-capable
- `test esi,esi` / `je 0x4e13d25` rounds==0 path; round loop `dec esi` / `jne 0x4e13880`
- rip-load of `"expand 32-byte k"` at `0x204670`

## Wrapper + wiring

- Wrapper `0x4e14560`; RELA `R_X86_64_RELATIVE` at GOT `0x576e900` addend `0x4e14560`
- Loads a word via `[0x576e350]` (rip at `0x4e1456d`) and tests bits `0x4000` / `0x400`; one branch tail-jumps (`e9` @ `0x4e14db7`) to FN. Other wrapper paths not examined.
- **21** `ff15` callers of the GOT slot; exemplar `0x13c9ed2`:
  - `lea rdi,[r14+0x120]` state
  - `add rcx,-0x100` / store remaining at `[r14+0x158]`
  - `mov esi,6` ChaCha12 double-rounds
  - `mov rdx,rax` out buffer
  - `call [0x576e900]`

## Source pin

- VA `0x1e6959`, len 95, sha256 `79cee213bb7bba7155a035070bbc1abed8bd176a9839bdb674df8816801602b7`
- suffix (endswith): `rand_chacha-0.3.1/src/guts.rs`
- Crate link = this string pin + code shape; no pinned xref from FN or wrapper to `0x1e6959`.

## Emulation vectors (32-byte material `00..1f`, ctr0=0, nonce=0)

| name | ndr | output sha256 |
|------|-----|---------------|
| chacha20 | 10 | `ec79b7a536038d2e8602bb95c785efe8f3a8a762c676a98cd20ab28af4824f10` |
| chacha12 | 6 | `d842f70da3bf07003b911bf8360e23abab0176922865303b07a5c55bb8656479` |
| chacha8 | 4 | `293c4d57eb663356d1e34a624e10313d3a045214e489e2a263257670578559b0` |

Counter after each run: 4.
