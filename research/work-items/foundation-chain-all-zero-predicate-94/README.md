# foundation-chain-all-zero-predicate-94: what does the 72-byte window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 72-byte FDE window, its 8 int3 padding bytes, the chain all-zero predicate rule, the one confirmed caller, the no-naming-relocation scan, and the one-direct-caller scan.
- Excluded: the meaning of the struct fields, the meaning of the flag byte, the caller's behavior beyond the call itself, other predicates, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: a flag-gated chain walk that only reads, with a rule fully determined by one flag byte, one chain head, one link step, and one per-node field test. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x51a5d60`, no open pull request title mentions it or chain-all-zero-predicate, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, or later foundation packets.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_chain_all_zero_predicate.py --check research/work-items/foundation-chain-all-zero-predicate-94/evidence.json
python3 -m unittest tests.test_foundation_chain_all_zero_predicate -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x51a5d60 --stop-address=0x51a5db0 artifacts/node/94/hl-node
objdump -d --start-address=0x51fd4c0 --stop-address=0x51fe69d artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

## Observations

### Window identity

- FDE `[0x51a5d60, 0x51a5da8)`, 72 bytes, `.eh_frame+0x29f430`, CIE at offset 0, `zR` pcrel sdata4, confirmed with GNU `--dwarf=frames`. The next FDE starts exactly at `0x51a5db0` (`[0x51a5db0, 0x51a5f09)`), so the 8 int3 bytes between the body end and the next FDE start are padding, not body. The checker locks the body and the padding separately.
- Body SHA-256: `80708970d69bcb62f58f3ae6811f4f5b13f4834362ff3c4308100775c8ff80c4`.
- Retained disassembly (`window.objdump.txt`):

```text
51a5d60: endbr64
51a5d64: mov (%rdi),%rax
51a5d67: movzbl 0x70(%rax),%edx
51a5d6b: test %dl,%dl
51a5d6d: jne 51a5d98
51a5d6f: mov 0x48(%rax),%rax
51a5d73: test %rax,%rax
51a5d76: jne 51a5d88
51a5d78: jmp 51a5da0
51a5d7a: nopw 0x0(%rax,%rax,1)
51a5d80: mov (%rax),%rax
51a5d83: test %rax,%rax
51a5d86: je 51a5da0
51a5d88: cmpq $0x0,0x10(%rax)
51a5d8d: je 51a5d80
51a5d8f: mov %edx,%eax
51a5d91: ret
51a5d92: nopw 0x0(%rax,%rax,1)
51a5d98: xor %edx,%edx
51a5d9a: mov %edx,%eax
51a5d9c: ret
51a5d9d: nopl (%rax)
51a5da0: mov $0x1,%edx
51a5da5: mov %edx,%eax
51a5da7: ret
```

### Decoded rule

- `p = [rdi]`, then the flag byte is `[p+0x70]`, loaded with movzbl into edx.
- Flag nonzero → `jne 0x51a5d98`: `xor %edx,%edx; mov %edx,%eax; ret`, so eax = 0. The flag test short-circuits the walk: a set flag returns 0 without touching the chain.
- Flag clear → edx is already 0 (movzbl of zero), and the chain head is `node = [p+0x48]`.
- Head null → `jmp 0x51a5da0`: `mov $0x1,%edx; mov %edx,%eax; ret`, so eax = 1. An empty chain counts as all-zero.
- Head nonnull → `cmpq $0x0,0x10(%rax)`: if `[node+0x10] == 0`, `je 0x51a5d80` advances with `node = [node]`; if the next link is null, `je 0x51a5da0` returns 1; otherwise the field test repeats.
- If any visited node's `[node+0x10]` is nonzero, control falls to `mov %edx,%eax; ret` with edx still 0, so eax = 0.
- Return rule: `eax = 1` exactly when `[p+0x70] == 0` and every node on the chain starting at `[p+0x48]`, linked by `[node]`, has `[node+0x10] == 0`, including the empty chain; else eax = 0. All three return paths write a full edx then `mov %edx,%eax`, so eax is exactly 0 or 1 on every path.
- No field is written anywhere in the window: every mov is a load or a register-to-register move, and the only stores in the usual sense are absent — the body contains no store-form instruction. The checker pins all 72 body bytes, so this property follows from the locked instruction list, not from a separate scan.
- Branch targets, all exact: `jne` at offset `0x0d` (2 bytes, disp `0x29`) lands on the flag-set return at offset `0x38`; `jne` at offset `0x16` (2 bytes, disp `0x10`) lands on the node check at offset `0x28`; `jmp` at offset `0x18` (2 bytes, disp `0x26`) lands on the one-return at offset `0x40`; `je` at offset `0x26` (2 bytes, disp `0x18`) lands on the same one-return; `je` at offset `0x2d` (2 bytes, disp `0xf1` = -15) lands on the link load at offset `0x20`. Four forward branches, one loop-back branch, no calls inside.
- The two `nopw` groups (offsets `0x1a` and `0x32`) and the `nopl` at offset `0x3d` are alignment padding inside the body, not separate logic.

### Call and data edges

- Incoming calls: the `.text` byte-pattern scan (70,370,352 bytes) finds exactly one direct `e8` site landing on the window start: `0x51fd9e5` (bytes `e8 76 83 fa ff`), confirmed as an instruction start by linear disassembly from its caller FDE start. This is explicitly not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope for the scan.
- Caller FDE: `[0x51fd4c0, 0x51fe69d)`, retained in full in `caller.objdump.txt`. Setup immediately before the call: `mov 0x10(%rax),%rax; mov (%rax),%rdi` (preceded by `mov (%r12),%esi; mov %r13,%rdi; call 0x51fccf0`). The caller's purpose is not claimed; the caller tests `%al` right after the call (`test %al,%al` at `0x51fd9ea`), which is consistent with the byte result but is caller behavior, not window behavior.
- Relocations: no record of any type in any `.rela.*` section names this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries).
- Nearest claimed window: binary search over 16-byte entries `0x51cb570` (packet #76), `0x25810` away.
- Symbol hint, explicitly disclaimed: objdump annotates the address with a nearest ctype `do_widen` label about 2 MB below; at that distance it proves nothing, and no stdlib or private provenance is claimed either way.

## Inferences

- The "chain all-zero predicate" label is an inference from the instruction shape: one flag gate, one chain head, one link step, and one per-node zero test feeding a 0/1 return. It is kept separate from the observed rule above.
- The struct types, the meaning of the `+0x48` head hop, the `+0x70` flag byte, and the `+0x10` node field are not identified by the bytes, so no such claim is made.

## Distinction from packet #88

Packet #88 (`0x50e69f0`, pointer-mark walk) walks entry chains and *stamps* a mark byte when a node's field equals a mask sentinel: it writes. This window walks one chain and only *reads*: it compares each node's `+0x10` field against zero and returns a byte. A predicate vs a stamping walk, one chain vs entry-selected chains, no store vs a store: the mechanisms differ even though both windows walk chains. No shared primitive is claimed, and no census of chain walks was built.

## Unknowns

- The struct types, the meaning of the `+0x48` head hop, the `+0x70` flag byte, and the `+0x10` node field, and the caller's purpose.
- Whether indirect callers or tail jumps reach this window (outside the byte-pattern scan's scope).
- Whether the result is consumed as a boolean or as one byte of a wider value (all return paths write full edx then move it to eax, so eax is exactly 0 or 1, but consumption is not observed).

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94.
