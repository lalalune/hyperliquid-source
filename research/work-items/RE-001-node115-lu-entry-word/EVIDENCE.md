# RE-001-node115-lu-entry-word: the entry-word lifecycle

- Component ID: `base/src/lu.rs` conversion context, hash-bucket entry word.
- Target release and full SHA-256: node #115, 105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit:
  `8fd8db680ec4bfef40996e5616bce3d5156d0b86` (upstream main, node-115-only
  migration).
- Claim status: observation for the helper body, the word transitions, the
  waiter-node layout, and the census; inference for the "FIFO drain" reading
  of the cleanup walk (the walk, the back-link fixup, and the wake order are
  observed instructions; the FIFO label is the behavior summary); unresolved
  for the `[rsp] = 1` stack slot, the family functions' individual roles, and
  the wake-site `rdx` setup.
- Scope included: helper body `0x5bb6790..0x5bb68d9` (329B, 104
  instructions), the word state machine, the waiter-chain push/wait/drain,
  and the call-site census.
- Scope excluded: the lookup, park, and cleanup bodies (packet #188's
  claims, cited by address only); the table-creation helper and resize path;
  the Rust type names; any progress gate.

## Reproduce

Working directory: repository root at the base commit above. Toolchain:
system GNU objdump (disassembly) and Python 3 (verifier, byte scans).
Commands, all offline, none executing the node binary:

```sh
sha256sum artifacts/node/115/hl-node
objdump -d -M intel --start-address=0x5bb6790 --stop-address=0x5bb68d9 \
  artifacts/node/115/hl-node
python3 tools/node115_lu_entry_word.py
python3 -m unittest tests.test_node115_lu_entry_word
make doctor && make verify && make catalogue-check
```

Input hash: node SHA-256 above. Output hashes: helper body SHA-256
`a94378e14e8639339101729a199bd051e7795fc54c0ca9f2ff528bffcf902be8`.
No execution of captured binaries, no network, no side effects beyond
reading the binary and the packet files.

## Evidence

Original addresses and coordinate system: ELF virtual addresses (PIE);
`.text` file offset = VA − 0x1000, `.got` file offset = VA − 0x2000.
Validated boundaries: helper FDE `0x5bb6790..0x5bb68d9` (CIE `0x00000000`,
`.eh_frame` offset `0x00330574`), single `ret` at `0x5bb68d8`, `int3`
padding after. Raw disassembly is in `helper.objdump.txt`; raw bytes in
`helper.hex`. Callers/callees: the helper is reached only through GOT
`0x64ec160` (13 call sites, all counted in `records.json`); it calls
`sched_yield` (GOT `0x64e1558`) and `syscall` (GOT `0x64e06b8`) and no other
function. Source mapping evidence: none — no `lu.rs` line is cited for the
helper; the packet claims machine behavior only. Analysis was complete for
the helper body (linear disassembly, 104 instructions, every branch
followed); the family functions were census-scanned, not decoded.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is claimed, so there is
no independent build, no Cargo lockfile, and no raw/normalized comparison.
Fixture identities: the node binary itself (digest above) is the only
fixture. Boundary/error cases: the verifier's corruption controls mutate
the helper hex (prologue, push `cmpxchg`, futex nr) and the records byte
count, each requiring verifier failure. The census byte scan covers all of
`.text` (135,313 FDEs in the binary; the scan is address-exact, not a
substring search).

## Results and limitations

Metrics with explicit denominators: helper 329 bytes / 104 instructions, one
complete FDE; census over all of `.text`: 2 direct `E8` lookup callers, 3
GOT park sites, 13 GOT helper sites, 44 GOT cleanup sites, 12 table-variable
loads. What passed: verifier exit 0, unit tests 7/7, `make doctor`
`analysis_ready` true, `make verify` exit 0, `make catalogue-check` exit 0.
What remains unknown: the `[rsp] = 1` slot's role, the family functions'
individual roles, and the wake-site `rdx` setup (see README). No gate is
requested: this packet covers one helper and its protocol, not a component.
Next question: decode one family function end to end (the 4525-byte FDE
`0x5bb2440`, with three helper call sites, is the largest candidate) to see
the word-chain pop path from the inserter side, or find the vtable dispatch
site that would settle the wake-site `rdx` question.
