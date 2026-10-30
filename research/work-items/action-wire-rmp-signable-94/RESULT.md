# action-wire rmp_signable evidence result — node #94

Target `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The bounded component-map task is related to RE-005 and requests no progress gate.
The packet is in `research/work-items/action-wire-rmp-signable-94/`.

## Observations

- Three first-party `l1/src/action/rmp_signable.rs` Location-shaped records,
  each at line 14, column 55, are addressed by instructions in FDEs
  `[0x333f240,0x333f686)`, `[0x37eb2d0,0x37eb702)`, and
  `[0x3984fe0,0x39853ec)`. The packet lists the slot and instruction VAs.
- In the first FDE, an eight-byte context value is reversed and appended, then
  a conditional zero/one byte is written; the one path copies 20 bytes. Another
  conditional path writes zero and a second reversed eight-byte value. It also
  selects byte `0x61` when an input byte equals 3, otherwise `0x62`, and stores
  `0x539`. The first FDE references a generic unwrap diagnostic. The raw ELF
  contains no contiguous `connectionId` string.
- The suffixed buffer reaches an indirect call through slot `0x576e1d8`; a
  subsequent indirect call through `0x576e1e0` receives an output length of 32.
  Their RELATIVE relocation targets are retained in the packet.

## Inferences

The first FDE's byte stores and scoped Location match the reference lead's
nonce, optional vault, and optional expiry suffix shape. The names and the
purpose of the selected source byte and `1337` field are inferred. These
observations are static and limited to this digest and FDE.

## Unresolved

The helper algorithms and connection-id identity are not proven; neither are
full serialization, a signing-domain schema, all callers or monomorphs,
runtime behavior, source function names, or component-wide coverage. Absence
of the contiguous literal does not establish absence of its field or behavior.
No Rust implementation, binary comparison, or gate change is claimed. This
checkout has no Git metadata, and the imported `visor.dis.txt` is missing.

## Commands and exits

From repository root:

- `make doctor`: 0.
- `make verify`: 0; artifact hashes/signatures and import verification with pinned LFS inputs.
- `make reproduce`: 0.
- `make catalogue-check`: 0.
- `python3 tools/rmp_signable_path.py --out research/work-items/action-wire-rmp-signable-94/`: 0.
- `python3 -m unittest tests.test_rmp_signable_path -v`: 0, nine tests.
- `python3 research/work-items/action-wire-rmp-signable-94/verify.py`: 0.
- `python3 -O research/work-items/action-wire-rmp-signable-94/verify.py`: 0.
- `make test`: 0 (full offline suite after packet integration).
