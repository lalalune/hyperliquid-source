# RE-007 — node #94 clearinghouse oracle inventory

This static-only packet addresses the oracle slice of `l1/clearinghouse/*`.
See [RESULT.md](RESULT.md) for observations, inferences and explicit gaps.
The target is `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`;
repository revision when examined: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
The separate #115 node and visor are not inputs. No executable is run.

## Reproduce from repository root

Requires Python 3 stdlib and the pinned target. The generator uses existing
`tools/info_request_path.py` ELF primitives, whose digest is pinned by the
verifier. No reference checkout or installed disassembler is needed to
regenerate JSON and byte excerpts.

```sh
python3 tools/clearinghouse_oracle_inventory.py --out research/work-items/clearinghouse-oracle-inventory-94/
python3 -m unittest tests.test_clearinghouse_oracle_inventory -v
python3 research/work-items/clearinghouse-oracle-inventory-94/verify.py
# Optional: GNU objdump 2.44, separately check all 72 instruction boundaries:
python3 research/work-items/clearinghouse-oracle-inventory-94/check_objdump.py > work/oracle-location-objdump.txt
cmp work/oracle-location-objdump.txt research/work-items/clearinghouse-oracle-inventory-94/location-objdump.txt
```

Capture environment: Linux x86-64, Python 3.13.5, GNU binutils objdump 2.44.
The recorded disassembly is a supplemental independent decoding, generated
with `objdump -d` on the authenticated ELF, for FDE
`0x3261290..0x326151a` and the three instruction-aligned windows
`0x26f7912..0x26f7932`, `0x26f7be6..0x26f7bf6`, and
`0x26efa7a..0x26efa87` via `--start-address`/`--stop-address`. All 67
Location-bearing FDEs were separately decoded from their FDE starts to check
the 72 candidate LEA instruction boundaries. `location-objdump.txt` retains every checked instruction, grouped by FDE;
`check_objdump.py` reproduces them with the exact decoder options and checks
the decoded target and bytes. Those checks are scoped to the candidate sites; they do not constitute full CFG validation.

## Method and limits

The generator checks the complete SHA-256 before parsing. It reads ELF64
little-endian file-backed load segments, `.rela.dyn` `R_X86_64_RELATIVE`
relocations to `.data.rel.ro`, and Location-shaped length/line/column records
whose path starts `/home/ubuntu/hl/code_Mainnet/`. It selects only
`l1` Rust paths containing consecutive `clearinghouse/oracle` path segments,
including relocated shapes and descendants. It scans `.text` for the
specified seven-byte RIP-relative REX.W LEA encodings, associates them with
FDE bounds from `.eh_frame_hdr` and checks the two literal pairs and direct
call. This is a restricted pattern census, not a general instruction/xref or
function census; absent source paths, alternate address materializations,
non-RELATIVE records, non-file-backed data and other forms are out of scope.
Potential raw-byte LEAs were individually checked with objdump as described
above. FDE ranges are unwind metadata, not independently complete function
boundaries; ownership means containment only. No operands are normalized.

`oracle-inventory.json` retains the census, positive and negative diagnostic
candidates, and edge. `byte-excerpts.txt` regenerates byte-for-byte;
`objdump-excerpts.txt` preserves human-readable disassembly;
`location-objdump.txt` preserves the 72 independently decoded xrefs. `MANIFEST.sha256`
contains a strict whitelist of packet files excluding itself. `verify.py`
checks that whitelist, packet hashes, generator and shared parser hashes,
identity, regeneration, and pinned results; corruptions are exercised by tests.
The artifact signature and hash passed `make verify`, but that command then
failed because the pinned reference checkout is absent; no setup or install
was performed. `make reproduce` stops on the same missing reference;
`make catalogue-check` reports a stale retained catalogue in this checkout.
The final `make test` ran 379 tests and reported 20 errors in existing tests
that require the absent can1357 checkout; the packet tests passed.
No catalogue, progress or gate is changed.
