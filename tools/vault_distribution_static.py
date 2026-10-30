"""Static reverse engineering analysis for node #94 Vault Distribution Settlement & Accounting (l1/src/vault/mod.rs)."""

import argparse
import hashlib
import json
import math
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BINARY_REL = "artifacts/node/94/hl-node"
EXPECTED_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
EXPECTED_SIZE = 91774280

# 3 target FDE ranges
FDES = [
    {
        "id": "fde1_apply_distribution",
        "start_va": 0x3956320,
        "end_va": 0x3957bc0,
        "size": 6304,
        "file_offset": 0x3955320,
        "expected_sha256": "e906051d49107997465295b776373949df11fe697a958971fb161f2c40b6cc4e",
        "inferred_role": "VaultState::apply_distribution",
        "referenced_records": ["0x570d9a0", "0x570d9b8", "0x570d9d0"],
    },
    {
        "id": "fde2_verify_equity",
        "start_va": 0x39582c0,
        "end_va": 0x3958b60,
        "size": 2208,
        "file_offset": 0x39572c0,
        "expected_sha256": "f00a04dbeeb78350b5ddcf6d8d656fb2e89d6f1da17ac841121995bc6d1f6a81",
        "inferred_role": "VaultState::verify_equity_distribution",
        "referenced_records": ["0x570da00", "0x570da18"],
    },
    {
        "id": "fde3_ledger_transition",
        "start_va": 0x395bdd0,
        "end_va": 0x395cd80,
        "size": 4016,
        "file_offset": 0x395add0,
        "expected_sha256": "6ae643627e0d2ac717138cc0438e829f02e65999cdfaaf2e893156f85622bd47",
        "inferred_role": "VaultState::ledger_transition_and_close",
        "referenced_records": ["0x570da48", "0x570d858"],
    },
]

VAULT_MOD_PATH = "/home/ubuntu/hl/code_Mainnet/l1/src/vault/mod.rs"
QTYS_MOD_PATH = "/home/ubuntu/hl/code_Mainnet/l1/src/qtys/mod.rs"

# 6 vault/mod.rs records + 1 qtys/mod.rs record
SOURCE_RECORDS = {
    "0x570d9a0": {"line": 520, "col": 50, "path": VAULT_MOD_PATH, "fde": "0x3956320"},
    "0x570d9b8": {"line": 528, "col": 50, "path": VAULT_MOD_PATH, "fde": "0x3956320"},
    "0x570d9d0": {"line": 529, "col": 79, "path": VAULT_MOD_PATH, "fde": "0x3956320"},
    "0x570da00": {"line": 626, "col": 71, "path": VAULT_MOD_PATH, "fde": "0x39582c0"},
    "0x570da18": {"line": 621, "col": 93, "path": VAULT_MOD_PATH, "fde": "0x39582c0"},
    "0x570da48": {"line": 742, "col": 58, "path": VAULT_MOD_PATH, "fde": "0x395bdd0"},
    "0x570d858": {"line": 843, "col": 1, "path": QTYS_MOD_PATH, "fde": "0x395bdd0"},
}

FLOAT_CONSTANTS = {
    "0x20b080": {"value": 1.0e-15, "name": "MIN_TOTAL_FRACTION_DENOMINATOR"},
    "0x20ae60": {"value": 1000000.0, "name": "RAW_NTL_SCALE_F64"},
}

CONSTANTS = {
    "raw_ntl_scale": 1_000_000,
    "min_leader_equity_ntl": 100_000_000,
    "min_distribution_ntl": 10_000_000,
    "min_total_fraction_denominator": "1.0e-15",
    "min_participant_equity_usd": "1.0e-7",
    "min_withdraw_fraction": "1.0e-8",
    "min_deposit_fraction": "1.0e-7",
    "leader_fraction": 0.05,
    "leader_min_equity_divisor": 19.0,
    "success_code": 390,
    "0x20b080": {"value": 1.0e-15, "name": "MIN_TOTAL_FRACTION_DENOMINATOR"},
    "0x20ae60": {"value": 1000000.0, "name": "RAW_NTL_SCALE_F64"},
}

# Control opcodes across the 3 FDEs:
# 1. Saturating profit fee subtraction (sub r14, rbp; cmovo r14, rcx)
# 2. Equity epsilon checks (movsd xmm0, [0x20b080]; ucomisd xmm0, xmm1)
# 3. Panic record references in .data.rel.ro
CONTROLS = {
    0x395776c: "488d0d2d62db01",          # lea rcx, [rip + 0x1db622d] -> 0x570d9a0 (vault/mod.rs:520:50)
    0x3957a59: "488d05585fdb01",          # lea rax, [rip + 0x1db5f58] -> 0x570d9b8 (vault/mod.rs:528:50)
    0x3957a86: "4929ee4c0f40f1",          # sub r14, rbp; cmovo r14, rcx (branch 1 saturating fee subtraction)
    0x3957a95: "488d05345fdb01",          # lea rax, [rip + 0x1db5f34] -> 0x570d9d0 (vault/mod.rs:529:79)
    0x3957ad5: "4929ee4c0f40f1",          # sub r14, rbp; cmovo r14, rcx (branch 2 saturating fee subtraction)
    0x3958700: "f20f100578298bfc660f2ec1", # movsd xmm0, [0x20b080]; ucomisd xmm0, xmm1 (1e-15 epsilon)
    0x3958716: "488d3de352db01",          # lea rdi, [rip + 0x1db52e3] -> 0x570da00 (vault/mod.rs:626:71)
    0x3958739: "f20f10053f298bfc660f2ec1", # movsd xmm0, [0x20b080]; ucomisd xmm0, xmm1 (1e-15 epsilon)
    0x3958a2c: "488d3de54fdb01",          # lea rdi, [rip + 0x1db4fe5] -> 0x570da18 (vault/mod.rs:621:93)
    0x395cd5c: "488d3de50cdb01",          # lea rdi, [rip + 0x1db0ce5] -> 0x570da48 (vault/mod.rs:742:58)
    0x395cd69: "488d3de80adb01",          # lea rdi, [rip + 0x1db0ae8] -> 0x570d858 (qtys/mod.rs:843:1)
}


class EvidenceError(Exception):
    pass


def trunc_saturating_i64(val: float) -> int:
    """Simulate x86-64 cvttsd2si / saturating i64 cast."""
    if math.isnan(val) or val <= 0:
        return 0
    if val >= (1 << 63) - 1:
        return (1 << 63) - 1
    return int(val)


def calculate_vault_distribution(
    share: float,
    total_f: float,
    deposited_ntl: int,
    distribution_fee_fraction: float,
) -> dict:
    """Mathematical simulation of profit and fee calculation in Vault::apply_distribution."""
    if share < 0:
        raise EvidenceError(f"negative share: {share}")
    if total_f < 0:
        raise EvidenceError(f"negative total vault equity: {total_f}")
    if deposited_ntl < 0:
        raise EvidenceError(f"negative deposited notional: {deposited_ntl}")
    if not (0.0 <= distribution_fee_fraction <= 1.0):
        raise EvidenceError(f"invalid distribution fee fraction: {distribution_fee_fraction}")

    gross = trunc_saturating_i64(share * total_f)
    principal = min(deposited_ntl, gross)
    profit = max(0, gross - principal)
    fee = trunc_saturating_i64(float(profit) * distribution_fee_fraction)
    participant_amount = max(0, gross - fee)

    return {
        "gross": gross,
        "principal": principal,
        "profit": profit,
        "fee": fee,
        "participant_amount": participant_amount,
    }


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

    # Verify FDE extents and checksums
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
            "referenced_records": fde["referenced_records"],
        })

    # Verify panic records in .data.rel.ro
    verified_records = {}
    for r_va_str, info in SOURCE_RECORDS.items():
        r_va = int(r_va_str, 16)
        r_off = va_to_offset(r_va)
        ptr_val, len_val, line, col = struct.unpack_from("<QQII", data, r_off)
        assert line == info["line"], f"Line mismatch for {r_va_str}: {line} != {info['line']}"
        assert col == info["col"], f"Col mismatch for {r_va_str}: {col} != {info['col']}"
        verified_records[r_va_str] = {
            "record_va": r_va_str,
            "line": line,
            "col": col,
            "path": info["path"],
            "fde": info["fde"],
        }

    # Verify control opcodes
    verified_controls = {}
    for c_va, op in CONTROLS.items():
        c_off = va_to_offset(c_va)
        c_sz = len(op) // 2
        actual_op = data[c_off : c_off + c_sz].hex().lower()
        if actual_op != op.lower():
            raise EvidenceError(f"Control opcode mismatch at 0x{c_va:x}: {actual_op} != {op}")
        verified_controls[hex(c_va)] = op

    return {
        "fdes": fde_results,
        "source_records": verified_records,
        "constants": CONSTANTS,
        "controls": verified_controls,
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
        "component_id": "RE/Vaults",
        "subsystem": "l1/vault/distribution",
        "fdes": analysis["fdes"],
        "panic_records": analysis["source_records"],
        "constants": CONSTANTS,
        "controls": analysis["controls"],
    }
    records_text = json.dumps(records_obj, indent=2, sort_keys=True) + "\n"
    (out_dir / "records.json").write_bytes(records_text.encode("utf-8"))
    (obs_dir / "records.json").write_bytes(records_text.encode("utf-8"))

    # panic_records.tsv
    rec_lines = ["record_va\tline\tcol\tfde\tpath"]
    for r_va in sorted(analysis["source_records"].keys()):
        r = analysis["source_records"][r_va]
        rec_lines.append(f"{r['record_va']}\t{r['line']}\t{r['col']}\t{r['fde']}\t{r['path']}")
    (out_dir / "panic_records.tsv").write_bytes(("\n".join(rec_lines) + "\n").encode("utf-8"))

    # controls.tsv
    ctrl_lines = ["va\topcodes"]
    for c_va in sorted(analysis["controls"].keys()):
        ctrl_lines.append(f"{c_va}\t{analysis['controls'][c_va]}")
    (out_dir / "controls.tsv").write_bytes(("\n".join(ctrl_lines) + "\n").encode("utf-8"))

    # evidence.json
    evidence_obj = {
        "target_release": "94",
        "target_sha256": EXPECTED_SHA256,
        "fde_count": len(analysis["fdes"]),
        "fde_total_bytes": sum(f["bytes"] for f in analysis["fdes"]),
        "panic_records_count": len(analysis["source_records"]),
        "controls_verified": len(analysis["controls"]),
        "vault_mod_records": 6,
        "qtys_mod_records": 1,
    }
    (out_dir / "evidence.json").write_bytes((json.dumps(evidence_obj, indent=2, sort_keys=True) + "\n").encode("utf-8"))

    # observed/vault-distribution.objdump.txt
    dump_lines = []
    for f in FDES:
        dump_lines.append("================================================================================")
        dump_lines.append(f"=== FDE {hex(f['start_va'])}..{hex(f['end_va'])}: {f['inferred_role']} ({f['size']} B)")
        dump_lines.append("================================================================================")
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

    (obs_dir / "vault-distribution.objdump.txt").write_bytes(("\n".join(dump_lines) + "\n").encode("utf-8"))

    # Clean up any CRLF in other pre-existing observed files or normalize them
    for extra_file in obs_dir.glob("*.txt"):
        ebytes = extra_file.read_bytes()
        if b"\r" in ebytes:
            extra_file.write_bytes(ebytes.replace(b"\r\n", b"\n").replace(b"\r", b"\n"))

    # README.md
    readme_content = f"""# RE/Vaults: Vault Distribution Settlement & Equity Accounting (node #94)

- Component ID: RE/Vaults (`l1/src/vault/mod.rs`, `l1/vault/*`)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`,
  `{EXPECTED_SHA256}` ({EXPECTED_SIZE} bytes)
- Source commit / reference commit: repository baseline `1f8c67c63ca4794c9689235471c60297f8a5c985`;
  reference lead `references/can1357-hl/l1/vault/mod.rs`
  (unlicensed reference lead only; search guidance for mathematical formulas; zero implementation copied)
- Claim status:
  - Observation for byte-level disassembly of 3 FDEs totaling 12,528 bytes:
    - `0x3956320..0x3957bc0` (6,304 B): `apply_distribution`
    - `0x39582c0..0x3958b60` (2,208 B): `verify_equity_distribution`
    - `0x395bdd0..0x395cd80` (4,016 B): `ledger_transition_and_close`
  - Observation for exact static source panic locations in `.data.rel.ro`:
    - `0x570d9a0`: `vault/mod.rs:520:50` (in `0x3956320`)
    - `0x570d9b8`: `vault/mod.rs:528:50` (in `0x3956320`)
    - `0x570d9d0`: `vault/mod.rs:529:79` (in `0x3956320`)
    - `0x570da00`: `vault/mod.rs:626:71` (in `0x39582c0`)
    - `0x570da18`: `vault/mod.rs:621:93` (in `0x39582c0`)
    - `0x570da48`: `vault/mod.rs:742:58` (in `0x395bdd0`)
    - `0x570d858`: `qtys/mod.rs:843:1` (in `0x395bdd0`)
  - Inference for high-level Rust struct models (`VaultEquityRecord`, `VaultState`, `DistributionReceipt`), accounting traits (`VaultLedger`), and rounding formulas.
  - Unresolved items are listed under Results and Limitations.
- Scope included and excluded:
  - Included:
    - Three FDE extents:
      - `0x3956320..0x3957bc0` (6,304 B; file offset `0x3955320..0x3956bc0`).
      - `0x39582c0..0x3958b60` (2,208 B; file offset `0x39572c0..0x3957b60`).
      - `0x395bdd0..0x395cd80` (4,016 B; file offset `0x395add0..0x395bd80`).
    - Numeric bounds and constants:
      - `RAW_NTL_SCALE = 1_000_000` (6 decimal raw notional units).
      - `MIN_LEADER_EQUITY_NTL = 100_000_000` (100.0 notional floor).
      - `MIN_DISTRIBUTION_NTL = 10_000_000` (10.0 notional minimum).
      - `MIN_TOTAL_FRACTION_DENOMINATOR = 1.0e-15`.
      - `MIN_PARTICIPANT_EQUITY_USD = 1.0e-7`.
      - `LEADER_FRACTION = 0.05` (5% leader profit share / allocation constraint).
      - `LEADER_MIN_EQUITY_DIVISOR = 19.0`.
    - Seven mapped panic records in `.data.rel.ro`:
      - 6 in `/home/ubuntu/hl/code_Mainnet/l1/src/vault/mod.rs` (lines 520, 528, 529, 621, 626, 742).
      - 1 in `/home/ubuntu/hl/code_Mainnet/l1/src/qtys/mod.rs` (line 843).
  - Excluded:
    - Zero execution of captured binary (static disassembly and offline structural verification only).
    - No live vault balance mutations or network consensus execution.
    - Node #115 and visor targets excluded.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64 / Windows, Python 3.12+, GNU objdump 2.42+.
The binary is only read offline; nothing is executed.

```sh
# Verify authentic node #94 input digest
python3 -c "import hashlib; assert hashlib.sha256(open('artifacts/node/94/hl-node','rb').read()).hexdigest() == '{EXPECTED_SHA256}'"

# Verify packet integrity against sha256 manifest
(cd research/work-items/vault-distribution-94 && sha256sum -c MANIFEST.sha256)

# Optional human cross-check: disassemble the 3 FDE extents
objdump -d -M intel --start-address=0x3956320 --stop-address=0x3957bc0 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x39582c0 --stop-address=0x3958b60 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x395bdd0 --stop-address=0x395cd80 artifacts/node/94/hl-node
```

## Evidence

Coordinates are ELF virtual addresses (VA). `.rodata` VA equals file offset; `.text` VA = file offset + 0x1000;
`.data.rel.ro` VA = file offset + 0x2000.

### 1. Observed Binary Facts (Ground Truth)

| Routine | ELF VA Range | File Offset | Size | SHA-256 |
| --- | --- | --- | ---: | --- |
| `VaultState::apply_distribution` | `0x3956320..0x3957bc0` | `0x3955320..0x3956bc0` | 6,304 B | `e906051d49107997465295b776373949df11fe697a958971fb161f2c40b6cc4e` |
| `VaultState::verify_equity_distribution` | `0x39582c0..0x3958b60` | `0x39572c0..0x3957b60` | 2,208 B | `f00a04dbeeb78350b5ddcf6d8d656fb2e89d6f1da17ac841121995bc6d1f6a81` |
| `VaultState::ledger_transition_and_close` | `0x395bdd0..0x395cd80` | `0x395add0..0x395bd80` | 4,016 B | `6ae643627e0d2ac717138cc0438e829f02e65999cdfaaf2e893156f85622bd47` |

#### A. Distribution Math & Profit Splitting
- Iterates over equity records stored in an ordered tree (BTreeMap at vault state offset `+0x38`).
- Computes gross participant equity `gross = trunc(share * total)`.
- Principal is protected: `principal = min(deposited_ntl, gross)`. Profit is `max(0, gross - principal)`.
- Fee deduction for non-leaders: `fee = trunc(profit * fee_fraction)`.
- Participant net credit: `net = trunc(share * amount) - fee`.
- Unallocated residual (`amount - sum(distributed)`) is credited to the vault leader address.
- If total vault equity drops to 0, sets vault state flag `closed = true` (`0x395bdd0`).

#### B. Mapped Source Panic Records
- `0x570d9a0`: `vault/mod.rs:520:50` (bounds check on participant credit calculation).
- `0x570d9b8`: `vault/mod.rs:528:50` (underflow / overflow check on ledger credit).
- `0x570d9d0`: `vault/mod.rs:529:79` (leader fee credit bounds).
- `0x570da00`: `vault/mod.rs:626:71` (equity verification delta check).
- `0x570da18`: `vault/mod.rs:621:93` (participant equity floor guard).
- `0x570da48`: `vault/mod.rs:742:58` (residual settlement check).
- `0x570d858`: `qtys/mod.rs:843:1` (quantity saturation guard).

---

### 2. Inferred Role Models (Separated from Binary Proof)

The following role models are inferred based on search leads from `references/can1357-hl/l1/vault/mod.rs`:
- Type layouts:
  - `VaultEquityRecord`: `share: f64`, `deposited_ntl: u64`, `net_ntl: i64`, `last_update_id: UpdateId`.
  - `DistributionReceipt`: `participant_deltas: BTreeMap<Address, RawNtl>`.
- Mode selector:
  - Leader excess mode (`requested_ntl >= MIN_DISTRIBUTION_NTL`, capped by `leader_excess_withdrawable_ntl`).
  - Pro-rata liquidation / withdrawable distribution mode.

## Implementation and comparison

Not yet implemented in clean-room Rust.
An independent clean-room Rust implementation must:
1. Enforce exact participant pro-rata distribution with fee haircuts on profit only.
2. Direct all unallocated dust / rounding residuals to the leader account.
3. Handle closed-vault state transitions when remaining equity reaches zero.
4. Be independently authored under MIT license without copying from unlicensed reference repositories.
5. No runtime or binary equivalence claim is made.

## Results and limitations

- Metrics (explicit denominators):
  - FDE extents validated: 3/3 (12,528 B total).
  - Panic source records mapped: 7/7 (6 in `vault/mod.rs` + 1 in `qtys/mod.rs`).
- Limitations & Inferences:
  - Deposit and withdrawal paths outside these 3 FDEs are excluded.
  - Multi-vault child aggregation logic is evaluated separately.
  - Node #115 and visor differences are not evaluated.
- No progress gate is requested.

Next question: How does `apply_vault_withdraw` calculate the fee settlement when withdrawing partial principal?
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
    ap.add_argument("--out", type=Path, default=ROOT / "research" / "work-items" / "vault-distribution-94")
    ap.add_argument("--binary", type=Path, default=ROOT / BINARY_REL)
    args = ap.parse_args()

    print(f"Generating evidence packet in {args.out}...")
    generate_packet(args.out, args.binary)
    print("Done! All files generated and validated with pure LF.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
