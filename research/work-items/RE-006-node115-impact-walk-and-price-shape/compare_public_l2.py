"""Replay the public order-book server's L2 bucketing function on ordinary raw quotes."""

import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
SERVER = ROOT / "upstream/order_book_server"
REVISION = "8b4f237904f683aca2dba21a07d87e831ead2a97"


def upstream_file(name):
    path = f"server/src/order_book/{name}.rs"
    return subprocess.check_output(
        ["git", "-C", str(SERVER), "show", f"{REVISION}:{path}"], text=True
    )


def main():
    # Compile the actual private functions from the pinned source in a small
    # local harness. A full server, database and network connection are unnecessary.
    levels = upstream_file("levels")
    start = levels.index("fn bucket(")
    bucket = levels[start:levels.index("\n}", start) + 2]
    types = upstream_file("types")
    start = types.index("    pub(crate) fn num_digits(")
    num_digits = types[start:types.index("\n    }", start) + 6]
    with tempfile.TemporaryDirectory(prefix="public-l2-check-") as tmp:
        crate = Path(tmp)
        (crate / "src").mkdir()
        manifest = ['[package]', 'name = "public-l2-check"', 'version = "0.0.0"',
                    'edition = "2024"', '[dependencies]']
        for dep in ("node115-assets", "node115-orderbook"):
            path = json.dumps(str(ROOT / "src" / dep))
            manifest.append(f"{dep} = {{ path = {path} }}")
        (crate / "Cargo.toml").write_text("\n".join(manifest) + "\n")
        source = """
use node115_assets::{Px as LocalPx, Side as LocalSide};
use node115_orderbook::bucket_l2_px;
#[derive(Clone, Copy)] struct Px(u64);
impl Px {
    fn new(value: u64) -> Self { Self(value) }
    fn value(self) -> u64 { self.0 }
""" + num_digits + "\n}\n" + """
#[derive(Clone, Copy, Debug)] enum Side { Bid, Ask }
""" + bucket + """
fn main() {
    let mut checked = 0;
    for raw in 1..=100_000 {
        for (local_side, side) in [(LocalSide::Bid, Side::Bid), (LocalSide::Ask, Side::Ask)] {
            for mantissa in [None, Some(2), Some(5)] {
                let expected = bucket(Px(raw), side, Some(5), mantissa).value();
                let actual = bucket_l2_px(LocalPx(raw), local_side, 5, mantissa).raw();
                assert_eq!(actual, expected, "price {raw} side {side:?} mantissa {mantissa:?}");
                checked += 1;
            }
        }
    }
    println!("{checked} public order-book bucket comparisons passed");
}
"""
        (crate / "src/main.rs").write_text(source)
        subprocess.run(["cargo", "run", "--offline", "--quiet", "--manifest-path",
                        str(crate / "Cargo.toml")], cwd=ROOT, check=True)


if __name__ == "__main__":
    main()
