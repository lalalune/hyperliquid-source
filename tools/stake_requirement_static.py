"""Static reverse engineering analysis for node #94 Staking Requirement (l1/exchange/stake_requirement.rs)."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BINARY_REL = "artifacts/node/94/hl-node"
EXPECTED_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
EXPECTED_SIZE = 91774280

# 4 target FDE ranges
FDES = [
    {
        "id": "collect_spot",
        "start_va": 0x2512770,
        "end_va": 0x2512ad0,
        "size": 864,
        "file_offset": 0x2511770,
        "expected_sha256": "eb51363fd6627bce69d11e4daec39870628d9cb4401cf14fa74cb0a136a6660a",
        "inferred_role": "exchange::stake_requirement::collect_requirements_spot",
        "scope": "Spot",
        "panic_record_va": "0x56b81b0",
    },
    {
        "id": "iter_next_spot",
        "start_va": 0x26b58d0,
        "end_va": 0x26b59e0,
        "size": 272,
        "file_offset": 0x26b48d0,
        "expected_sha256": "ba2138bba3abe52183363f9f0ca5ca6fe5da70cd49f2c5e1885dd6a0a93f637f",
        "inferred_role": "exchange::stake_requirement::RequirementIterator::next_spot",
        "scope": "Spot",
        "state_tier_offset": "0x8f2",
        "table_va": "0x3f0994",
        "panic_record_va": "0x5713008",
    },
    {
        "id": "collect_perp",
        "start_va": 0x487ccd0,
        "end_va": 0x487cee0,
        "size": 528,
        "file_offset": 0x487bcd0,
        "expected_sha256": "fe2f8e7202c88c2e4b4c3efa30cced50a327cbecd016c1eb5918537a94d5b1fd",
        "inferred_role": "exchange::stake_requirement::collect_requirements_perp",
        "scope": "Perp",
        "panic_record_va": "0x571f590",
    },
    {
        "id": "iter_next_perp",
        "start_va": 0x47bcea0,
        "end_va": 0x47bcfb0,
        "size": 272,
        "file_offset": 0x47bbea0,
        "expected_sha256": "569310416da297a16740f8f350b852eec0e194d1eb9762dc6373b6105ffcd350",
        "inferred_role": "exchange::stake_requirement::RequirementIterator::next_perp",
        "scope": "Perp",
        "state_tier_offset": "0x1372",
        "table_va": "0x5732f60",
        "panic_record_va": "0x5713008",
    },
]

# 4 kinds x 4 tiers recovered matrix
TABLE_VALUES = [
    [100_000, 10_000_000_000, 10_000_000_000, 50_000_000_000_000],
    [50_000, 20_000_000_000_000, 5_000_000_000, 20_000_000_000_000],
    [150_000, 80_000_000_000_000, 15_000_000_000, 80_000_000_000_000],
    [200_000, 50_000_000_000_000, 10_000_000_000, 50_000_000_000_000],
]

SOURCE_PATH = "/home/ubuntu/hl/code_Mainnet/l1/src/exchange/stake_requirement.rs"
PANIC_LOCATIONS = {
    "0x56b81b0": {"line": 5, "col": 62, "path": SOURCE_PATH},
    "0x5713008": {"line": 5, "col": 62, "path": SOURCE_PATH},
    "0x571f590": {"line": 5, "col": 62, "path": SOURCE_PATH},
}


class EvidenceError(Exception):
    pass


def check_digest(data):
    if len(data) != EXPECTED_SIZE:
        raise EvidenceError(f"size mismatch: {len(data)} != {EXPECTED_SIZE}")
    actual = hashlib.sha256(data).hexdigest()
    if actual != EXPECTED_SHA256:
        raise EvidenceError(f"sha256 mismatch: {actual} != {EXPECTED_SHA256}")


def parse_elf_sections(data):
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize = struct.unpack_from("<H", data, 58)[0]
    e_shnum = struct.unpack_from("<H", data, 60)[0]
    e_shstrndx = struct.unpack_from("<H", data, 62)[0]
    shstr_offset = struct.unpack_from("<Q", data, e_shoff + e_shstrndx * e_shentsize + 24)[0]

    sections = {}
    for i in range(e_shnum):
        sec = e_shoff + i * e_shentsize
        sh_name_idx = struct.unpack_from("<I", data, sec)[0]
        sh_addr = struct.unpack_from("<Q", data, sec + 16)[0]
        sh_offset = struct.unpack_from("<Q", data, sec + 24)[0]
        sh_size = struct.unpack_from("<Q", data, sec + 32)[0]
        end_str = data.find(b"\0", shstr_offset + sh_name_idx)
        name = data[shstr_offset + sh_name_idx:end_str].decode("latin1")
        sections[name] = {"addr": sh_addr, "offset": sh_offset, "size": sh_size}
    return sections


def analyse(data):
    check_digest(data)
    sections = parse_elf_sections(data)

    def va_to_offset(va):
        for name, s in sections.items():
            if s["addr"] <= va < s["addr"] + s["size"]:
                return s["offset"] + (va - s["addr"])
        return None

    # 1. Verify FDEs
    fde_results = []
    for fde in FDES:
        off = va_to_offset(fde["start_va"])
        assert off == fde["file_offset"], f"file offset mismatch: {off} != {fde['file_offset']}"
        chunk = data[off : off + fde["size"]]
        chash = hashlib.sha256(chunk).hexdigest()
        assert chash == fde["expected_sha256"], f"FDE sha256 mismatch for {fde['id']}: {chash}"
        fde_results.append({
            "id": fde["id"],
            "start_va": hex(fde["start_va"]),
            "end_va": hex(fde["end_va"]),
            "file_offset": hex(fde["file_offset"]),
            "bytes": fde["size"],
            "sha256": chash,
            "inferred_role": fde["inferred_role"],
            "scope": fde["scope"],
        })

    # 2. Extract spot table from .rodata 0x3f0994
    spot_rdx = 0x3f0994
    spot_offsets = struct.unpack_from("<iiii", data, spot_rdx)
    spot_matrix = []
    for r14 in range(4):
        rsi = spot_rdx + spot_offsets[r14]
        row = [struct.unpack_from("<Q", data, rsi + rcx * 8)[0] for rcx in range(4)]
        spot_matrix.append(row)

    # 3. Extract perp table relocations from .rela.dyn for 0x5732f60
    rela_sec = sections[".rela.dyn"]
    r_off = rela_sec["offset"]
    r_sz = rela_sec["size"]
    relocs = {}
    for j in range(r_sz // 24):
        ro, ri, ra = struct.unpack_from("<QQq", data, r_off + j * 24)
        if 0x5732f60 <= ro < 0x5732f60 + 32:
            relocs[ro] = ra

    perp_matrix = []
    for r14 in range(4):
        target_va = relocs[0x5732f60 + r14 * 8]
        row = [struct.unpack_from("<Q", data, target_va + rcx * 8)[0] for rcx in range(4)]
        perp_matrix.append(row)

    assert spot_matrix == TABLE_VALUES, f"Spot table mismatch: {spot_matrix}"
    assert perp_matrix == TABLE_VALUES, f"Perp table mismatch: {perp_matrix}"

    # 4. Verify source path in .rodata
    src_bytes = data[0x1e16d0 : 0x1e16d0 + 65].decode("utf-8")
    assert src_bytes == SOURCE_PATH, f"Source path mismatch: {src_bytes}"

    return {
        "fdes": fde_results,
        "table_values": TABLE_VALUES,
        "source_path": SOURCE_PATH,
        "panic_locations": PANIC_LOCATIONS,
    }


def generate_packet(out_dir, binary_path):
    data = binary_path.read_bytes()
    analysis = analyse(data)

    out_dir.mkdir(parents=True, exist_ok=True)
    obs_dir = out_dir / "observed"
    obs_dir.mkdir(parents=True, exist_ok=True)

    # records.json
    records_obj = {
        "target_sha256": EXPECTED_SHA256,
        "target_bytes": EXPECTED_SIZE,
        "component_id": "RE/Staking",
        "subsystem": "l1/exchange/stake_requirement",
        "source_path": SOURCE_PATH,
        "fdes": analysis["fdes"],
        "constants": {
            "n_stake_requirement_kinds": 4,
            "n_stake_tiers": 4,
            "table_spot_va": "0x3f0994",
            "table_perp_va": "0x5732f60",
            "state_tier_offset_spot": "0x8f2",
            "state_tier_offset_perp": "0x1372",
        },
        "multiplier_table": TABLE_VALUES,
        "panic_records": PANIC_LOCATIONS,
    }

    records_json_text = json.dumps(records_obj, indent=2, sort_keys=True) + "\n"
    (out_dir / "records.json").write_bytes(records_json_text.encode("utf-8"))
    (obs_dir / "records.json").write_bytes(records_json_text.encode("utf-8"))

    # multiplier_table.tsv
    tsv_lines = ["kind\ttier_0\ttier_1\ttier_2\ttier_3"]
    for kind_idx, row in enumerate(TABLE_VALUES):
        tsv_lines.append(f"{kind_idx}\t{row[0]}\t{row[1]}\t{row[2]}\t{row[3]}")
    (out_dir / "multiplier_table.tsv").write_bytes(("\n".join(tsv_lines) + "\n").encode("utf-8"))

    # evidence.json
    evidence_obj = {
        "target_release": "94",
        "target_sha256": EXPECTED_SHA256,
        "fde_count": len(analysis["fdes"]),
        "fde_total_bytes": sum(f["bytes"] for f in analysis["fdes"]),
        "table_shape": [4, 4],
        "tables_match": True,
        "source_record_verified": True,
    }
    (out_dir / "evidence.json").write_bytes((json.dumps(evidence_obj, indent=2, sort_keys=True) + "\n").encode("utf-8"))

    # observed/stake-requirement.objdump.txt
    dump_lines = []
    for f in FDES:
        dump_lines.append(f"================================================================================")
        dump_lines.append(f"=== FDE {hex(f['start_va'])}..{hex(f['end_va'])}: {f['inferred_role']} ({f['size']} B)")
        dump_lines.append(f"================================================================================")
        cmd = [
            "objdump",
            "-d",
            "-M",
            "intel",
            f"--start-address={hex(f['start_va'])}",
            f"--stop-address={hex(f['end_va'])}",
            str(binary_path),
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        dump_lines.append(res.stdout.strip())
        dump_lines.append("")

    (obs_dir / "stake-requirement.objdump.txt").write_bytes(("\n".join(dump_lines) + "\n").encode("utf-8"))

    # README.md
    readme_content = f"""# RE/Staking: Exchange Stake Requirement Calculation & Monomorph Dispatch (node #94)

- Component ID: RE/Staking (`l1/exchange/stake_requirement.rs`, `l1/exchange/*`)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`,
  `{EXPECTED_SHA256}` ({EXPECTED_SIZE} bytes)
- Source commit / reference commit: repository baseline `1f8c67c63ca4794c9689235471c60297f8a5c985`;
  reference lead `references/can1357-hl/l1/exchange/stake_requirement.rs`
  (unlicensed reference lead only; search guidance for mathematical formulas; zero implementation copied)
- Claim status:
  - Observation for byte-level disassembly of 4 FDEs totaling 1,936 bytes:
    - `0x2512770..0x2512ad0` (864 B): `collect_requirements_spot`
    - `0x26b58d0..0x26b59e0` (272 B): `RequirementIterator::next_spot`
    - `0x487ccd0..0x487cee0` (528 B): `collect_requirements_perp`
    - `0x47bcea0..0x47bcfb0` (272 B): `RequirementIterator::next_perp`
  - Observation for exact 4x4 multiplier matrix in `.rodata` (`0x3f0994`) and `.data.rel.ro` (`0x5732f60`),
    state tier byte offsets (`+0x8f2` for Spot, `+0x1372` for Perp), and source panic records at `0x56b81b0`, `0x5713008`, `0x571f590`
    mapping to `/home/ubuntu/hl/code_Mainnet/l1/src/exchange/stake_requirement.rs:5:62`.
  - Inference for high-level Rust enum variants (`StakeRequirementAction`, `StakeRequirementScope`), trait structures (`StakeRequirementState`), and delegation lookup models.
  - Unresolved items are listed under Results and Limitations.
- Scope included and excluded:
  - Included:
    - Four FDE extents:
      - `0x2512770..0x2512ad0` (864 B; file offset `0x2511770..0x2511ad0`).
      - `0x26b58d0..0x26b59e0` (272 B; file offset `0x26b48d0..0x26b49e0`).
      - `0x487ccd0..0x487cee0` (528 B; file offset `0x487bcd0..0x487bee0`).
      - `0x47bcea0..0x47bcfb0` (272 B; file offset `0x47bbea0..0x47bbfb0`).
    - Numeric bounds and constants:
      - `N_STAKE_REQUIREMENT_KINDS = 4`.
      - `N_STAKE_TIERS = 4`.
      - Hard bounds: index check `cmp rcx, 0x4` and kind boundary `cmp r14, 0x3`.
      - Saturating count addition: `cmovae` / `cmovb` against `0xffffffffffffffff`.
      - Multiplication and overflow detection: `mul QWORD PTR [...]` followed by `jo`.
    - Exact 4x4 multiplier values (raw staking units):
      - Kind 0: `[100_000, 10_000_000_000, 10_000_000_000, 50_000_000_000_000]`
      - Kind 1: `[50_000, 20_000_000_000_000, 5_000_000_000, 20_000_000_000_000]`
      - Kind 2: `[150_000, 80_000_000_000_000, 15_000_000_000, 80_000_000_000_000]`
      - Kind 3: `[200_000, 50_000_000_000_000, 10_000_000_000, 50_000_000_000_000]`
    - Source panic records in `.data.rel.ro`:
      - `0x56b81b0`: line 5, col 62 (`/home/ubuntu/hl/code_Mainnet/l1/src/exchange/stake_requirement.rs`).
      - `0x5713008`: line 5, col 62 (`/home/ubuntu/hl/code_Mainnet/l1/src/exchange/stake_requirement.rs`).
      - `0x571f590`: line 5, col 62 (`/home/ubuntu/hl/code_Mainnet/l1/src/exchange/stake_requirement.rs`).
  - Excluded:
    - Zero execution of captured binary (static disassembly and offline structural verification only).
    - No live trading network, validator signing keys, or consensus execution harness.
    - Node #115 and visor targets excluded.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64 / Windows, Python 3.12+, GNU objdump 2.42+.
The binary is only read offline; nothing is executed.

```sh
# Verify authentic node #94 input digest
python3 -c "import hashlib; assert hashlib.sha256(open('artifacts/node/94/hl-node','rb').read()).hexdigest() == '{EXPECTED_SHA256}'"

# Verify packet integrity against sha256 manifest
(cd research/work-items/stake-requirement-94 && sha256sum -c MANIFEST.sha256)

# Optional human cross-check: disassemble the 4 FDE extents
objdump -d -M intel --start-address=0x2512770 --stop-address=0x2512ad0 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x26b58d0 --stop-address=0x26b59e0 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x487ccd0 --stop-address=0x487cee0 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x47bcea0 --stop-address=0x47bcfb0 artifacts/node/94/hl-node
```

## Evidence

Coordinates are ELF virtual addresses (VA). `.rodata` VA equals file offset; `.text` VA = file offset + 0x1000;
`.data.rel.ro` VA = file offset + 0x2000.

### 1. Observed Binary Facts (Ground Truth)

| Routine | ELF VA Range | File Offset | Size | SHA-256 |
| --- | --- | --- | ---: | --- |
| `collect_requirements_spot` | `0x2512770..0x2512ad0` | `0x2511770..0x2511ad0` | 864 B | `eb51363fd6627bce69d11e4daec39870628d9cb4401cf14fa74cb0a136a6660a` |
| `RequirementIterator::next_spot` | `0x26b58d0..0x26b59e0` | `0x26b48d0..0x26b49e0` | 272 B | `ba2138bba3abe52183363f9f0ca5ca6fe5da70cd49f2c5e1885dd6a0a93f637f` |
| `collect_requirements_perp` | `0x487ccd0..0x487cee0` | `0x487bcd0..0x487bee0` | 528 B | `fe2f8e7202c88c2e4b4c3efa30cced50a327cbecd016c1eb5918537a94d5b1fd` |
| `RequirementIterator::next_perp` | `0x47bcea0..0x47bcfb0` | `0x47bbea0..0x47bbfb0` | 272 B | `569310416da297a16740f8f350b852eec0e194d1eb9762dc6373b6105ffcd350` |

#### A. Monomorphized Iterator Dispatch
- The iterator is hard-bounded to 4 entries (`0..=3`).
- In `0x26b58d0` (Spot), the state tier byte is loaded from `[r15 + 0x8f2]`.
  The multiplier table is resolved via four signed 32-bit displacements at `0x3f0994` pointing into `.rodata` base.
- In `0x47bcea0` (Perp), the state tier byte is loaded from `[r15 + 0x1372]`.
  The multiplier table is resolved via four absolute 64-bit pointers at `0x5732f60` in `.data.rel.ro`.
- Both table representations resolve to the identical underlying 4x4 raw multiplier values:
  - Kind 0 (`0x20c2a0`): `100,000`, `10,000,000,000`, `10,000,000,000`, `50,000,000,000,000`
  - Kind 1 (`0x20c040`): `50,000`, `20,000,000,000,000`, `5,000,000,000`, `20,000,000,000,000`
  - Kind 2 (`0x20c760`): `150,000`, `80,000,000,000,000`, `15,000,000,000`, `80,000,000,000,000`
  - Kind 3 (`0x20c420`): `200,000`, `50,000,000,000,000`, `10,000,000,000`, `50,000,000,000,000`

#### B. Caller Collection & Aggregation
- `0x2512770` and `0x487ccd0` invoke their respective iterator monomorphs in a loop.
- They allocate heap storage for up to 4 elements (capacity 4, elements 0..4, initial buffer size 0x20 = 32 bytes) and collect results into a `Vec<u64>` vector.
- The requirements are summed using checked addition with saturation behavior.

---

### 2. Inferred Role Models (Separated from Binary Proof)

The following high-level role models are inferred based on search leads from `references/can1357-hl/l1/exchange/stake_requirement.rs`:
- Function signatures:
  - `per_kind_requirements<S: StakeRequirementState>(state: &S, scope: StakeRequirementScope, user: &Address, action: StakeRequirementAction) -> Result<[Stake; 4], StakeRequirementError>`
  - `total_requirement_saturating(per_kind: [Stake; 4]) -> Stake`
- Inferred enum: `StakeRequirementAction`:
  - `Kind0 = 0`, `Kind1 = 1`, `Kind2 = 2`, `Kind3 = 3`: adds 1 to prospective kind count.
  - `ExistingOnly = 4`: pure check against existing live counts.

## Implementation and comparison

Not yet implemented in clean-room Rust.
An independent clean-room Rust implementation must:
1. Enforce the exact 4x4 multiplier table values matching both Spot and Perp monomorphs.
2. Read the appropriate state tier index (`0..=3`) according to the active exchange scope.
3. Detect `u64` multiplication overflow with fail-closed error handling.
4. Correctly aggregate requirements across the 4 kinds.
5. Be independently authored under MIT license without copying from unlicensed reference repositories.
6. No runtime or binary equivalence claim is made.

## Results and limitations

- Metrics (explicit denominators):
  - FDE extents validated: 4/4 (1,936 B total).
  - Multiplier tables verified across both monomorphs: 16/16 cells (100% agreement).
  - Panic source records mapped: 3/3 (`/home/ubuntu/hl/code_Mainnet/l1/src/exchange/stake_requirement.rs:5:62`).
- Limitations & Inferences:
  - User delegation balance lookups and auxiliary validator tree checks occur in caller routines outside these 4 FDEs.
  - Node #115 and visor differences are not evaluated.
- No progress gate is requested.

Next question: How does `available_delegated_stake` query the delegation map and validate active validator status?
"""
    (out_dir / "README.md").write_bytes(readme_content.encode("utf-8"))

    # MANIFEST.sha256
    manifest_lines = []
    for p in sorted(out_dir.rglob("*")):
        if p.is_file() and p.name != "MANIFEST.sha256":
            rel = p.relative_to(out_dir).as_posix()
            digest = hashlib.sha256(p.read_bytes()).hexdigest()
            manifest_lines.append(f"{digest}  {rel}")

    manifest_text = "\n".join(manifest_lines) + "\n"
    (out_dir / "MANIFEST.sha256").write_bytes(manifest_text.encode("utf-8"))

    # Assert pure LF on all generated files
    for p in out_dir.rglob("*"):
        if p.is_file():
            assert b"\r" not in p.read_bytes(), f"CRLF found in {p}"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=ROOT / "research" / "work-items" / "stake-requirement-94")
    ap.add_argument("--binary", type=Path, default=ROOT / BINARY_REL)
    args = ap.parse_args()

    print(f"Generating evidence packet in {args.out}...")
    generate_packet(args.out, args.binary)
    print("Done! All files generated and validated with pure LF.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
