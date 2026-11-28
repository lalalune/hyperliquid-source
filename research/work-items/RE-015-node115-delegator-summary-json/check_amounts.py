#!/usr/bin/env python3
"""Compare the public Rust writer with independent fixed-place Decimal rounding."""
from decimal import Decimal, ROUND_HALF_EVEN, localcontext
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
DRIVER = """
use info_api::response::DelegatorSummary;
use std::io::{self, BufRead, Write};
fn main() {
    let mut out = io::BufWriter::new(io::stdout().lock());
    for (i, row) in io::stdin().lock().lines().enumerate() {
        let field = u64::from_str_radix(&row.unwrap(), 16).unwrap();
        let amount = f64::from_bits(field);
        DelegatorSummary {
            delegated: amount, undelegated: -amount, total_pending_withdrawal: 0.0,
            n_pending_withdrawals: i as u64,
        }.write_json(&mut out).unwrap();
        writeln!(out).unwrap();
    }
}
"""


def amount(value):
    with localcontext() as ctx:
        ctx.prec = 340
        rounded = Decimal.from_float(value).quantize(Decimal("1e-10"), rounding=ROUND_HALF_EVEN)
    if not rounded:
        return "0.0"
    text = format(rounded, "f").rstrip("0")
    return text + "0" if text.endswith(".") else text


def main():
    rng = random.Random(115)
    fields = [0, 1, 0x8000000000000000, 0x7fefffffffffffff, 0x0010000000000000]
    for i in range(1, 32, 2):
        mid, = struct.unpack(">Q", struct.pack(">d", i / 2048))
        fields.extend((mid - 1, mid, mid + 1))
    while len(fields) < 4096:
        bits = rng.getrandbits(64)
        if (bits >> 52) & 0x7ff != 0x7ff:
            fields.append(bits)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        (work / "src").mkdir()
        (work / "src/main.rs").write_text(DRIVER)
        crate = json.dumps(str(ROOT / "src/info-api"))
        (work / "Cargo.toml").write_text('[package]\nname="compare-staking"\nversion="0.0.0"\nedition="2021"\n'
                                        + '[dependencies]\ninfo-api={path=' + crate + '}\n')
        # Cargo writes the ephemeral probe's lockfile inside its temporary project.
        environment = dict(os.environ, CARGO_TARGET_DIR=str(work / "target"))
        result = subprocess.run(["cargo", "run", "--quiet", "--offline"], cwd=work, env=environment,
                                text=True, input="".join(f"{b:016x}\n" for b in fields),
                                capture_output=True, check=True)
    rows = result.stdout.splitlines()
    if len(rows) != len(fields):
        raise ValueError("wrong response count")
    for i, (bits, row) in enumerate(zip(fields, rows)):
        value, = struct.unpack(">d", struct.pack(">Q", bits))
        expected = dict(delegated=amount(value), undelegated=amount(-value),
                        totalPendingWithdrawal="0.0", nPendingWithdrawals=i)
        if row != json.dumps(expected, separators=(",", ":")):
            raise ValueError(f"response mismatch for binary64 {bits:016x}")
    print(f"{len(rows)} compact JSON responses matched the independent Decimal oracle")


if __name__ == "__main__":
    main()
