"""Verify direct native inputs and the adjacent-height root comparison."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory

from transition import compare_manifest, encoded, load_tree_codec, transition

sys.path.insert(0, str(Path.cwd() / "tools"))
from freeze_snapshot_115 import read_va

PACKET = Path(__file__).resolve().parent
TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def verify_native():
    data = Path("artifacts/node/115/hl-node").read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET
    compact = read_va(data, 0x548388A, 0x54838F5 - 0x548388A)
    assert compact == read_va(data, 0x5483F8A, len(compact))
    for address, raw in {
        0x5483890: "0f9ec2", 0x548389D: "0f96c2", 0x54838AA: "7706",
        0x54838B7: "41895574", 0x54838BF: "4989556c",
        0x54838C6: "49891424", 0x54838CE: "4189542408",
        0x54838E5: "49895528", 0x54838F1: "49894d30",
        0x43037FB: "488d4f28", 0x430381A: "488d4f30",
        0x4303832: "488d4f60", 0x430384D: "488d576c",
        0x141B296: "4889040a", 0x141B2BA: "892c01",
    }.items():
        code = bytes.fromhex(raw)
        assert read_va(data, address, len(code)) == code
    print(f"PASS: node #115 SHA-256 {TARGET}", flush=True)
    print("PASS: identical compact/expanded clock, height and round store windows", flush=True)
    subprocess.run([sys.executable, "-B", "tools/height_advance_115.py", "--check"], check=True)


def clock(seconds, nanos):
    return {"unix_seconds": seconds, "subsec_nanos": nanos}


def controls():
    previous = {"height": 42, "round": 300, "time": clock(-1, 999),
                "prev_time": clock(-2, 500)}
    header = {"height": 43, "round": 900, "time": clock(0, 4)}
    expected_old = (42, 300, (-1, 999), (-2, 500))
    expected_new = (43, 900, (0, 4), (-1, 999))
    assert transition(previous, header) == (expected_old, expected_new, True)
    for incoming in (clock(-1, 999), clock(-1, 998), clock(-3, 999_999_999)):
        result = transition(previous, header | {"time": incoming})
        assert result[1:] == ((43, 900, (-1, 999), (-2, 500)), False)
    assert encoded(expected_old)["time"].hex() == "ffffffffffffffffe7030000"
    assert encoded(expected_new)["time"].hex() == "000000000000000004000000"
    for invalid in ({"height": 42}, {"height": 44}, {"height": True}):
        try:
            transition(previous, header | invalid)
        except ValueError:
            pass
        else:
            raise AssertionError(invalid)
    print("PASS: distinct incoming round/height, newer/equal/older clocks and ordinary clock preimages")
    return previous, header


def full_comparison(root_packet, rustc, previous, header):
    with TemporaryDirectory() as tempdir:
        directory = Path(tempdir)
        codec_file = root_packet / "isolate.py"
        codec = load_tree_codec(codec_file)
        lib = directory / "libnode115_abci_blake3.rlib"
        helper = directory / "hash_tree"
        subprocess.run([rustc, "--edition=2024", "--crate-name", "node115_abci_blake3",
                        "--crate-type", "rlib", "src/node115-abci-blake3/src/lib.rs",
                        "-o", lib], check=True)
        subprocess.run([rustc, "--edition=2024", root_packet / "hash_tree.rs",
                        "--extern", f"node115_abci_blake3={lib}", "-o", helper], check=True)

        def write(name, obj):
            path = directory / name
            data = (json.dumps(obj) + "\n").encode()
            path.write_bytes(data)
            return {"path": name, "sha256": hashlib.sha256(data).hexdigest()}

        def raw(h, round_, time, prev):
            scope = []
            for index, leaf in (
                (2, struct.pack("<Q", h)), (4, struct.pack("<Q", round_)),
                (5, struct.pack("<qI", *time)), (6, struct.pack("<qI", *prev)),
            ):
                hashed = subprocess.check_output([helper], input=leaf).decode("ascii").strip()
                scope.append([index, hashed])
            context = [[0, [[0, scope]]], [58, "0x" + f"{h:02x}" * 32]]
            return {"height": h, "exchange_abci_hash": context,
                    "abci_digest": codec.digest(helper, codec.decode_tree(context))}

        first = raw(42, 300, (-1, 999), (-2, 500))
        second = raw(43, 900, (0, 4), (-1, 999))
        roles = {
            "restored_context": write("context.json", previous),
            "successor_header": write("successor.json", header),
            "reference_h": write("h.jsonl", first),
            "reference_h_plus_one": write("h1.jsonl", second),
        }
        manifest = write("manifest.json", roles)
        base = [sys.executable, "-B", PACKET / "transition.py", codec_file, helper]
        result = json.loads(subprocess.check_output(
            base + [directory / manifest["path"], manifest["sha256"]], text=True))
        assert result["clock_rotated"]
        assert all(result["h_context"]["matched"].values())
        assert all(result["h_plus_one_begin_projection"]["matched"].values())

        wrong_previous = raw(43, 900, (0, 4), (-2, 500))
        roles["reference_h_plus_one"] = write("h1-set.jsonl", wrong_previous)
        manifest = write("manifest.json", roles)
        result = subprocess.run(base + [directory / manifest["path"], manifest["sha256"]],
                                capture_output=True, text=True)
        assert result.returncode == 1
        report = json.loads(result.stdout)
        assert report["h_plus_one_begin_projection"]["matched"] == {
            "height": True, "round": True, "time": True, "prev_time": False,
        }

        wrong_previous["abci_digest"] = "0x" + "00" * 32
        roles["reference_h_plus_one"] = write("stale.jsonl", wrong_previous)
        manifest = write("manifest.json", roles)
        result = subprocess.run(base + [directory / manifest["path"], manifest["sha256"]],
                                capture_output=True, text=True)
        assert result.returncode == 2 and "disagrees with its recorded raw digest" in result.stderr
    print("PASS: paired complete synthetic raw roots; stale reference rejection and isolated H+1 clock mismatch")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root-packet", type=Path)
    parser.add_argument("--rustc", default="rustc")
    args = parser.parse_args()
    verify_native()
    previous, header = controls()
    if args.root_packet:
        full_comparison(args.root_packet.resolve(), args.rustc, previous, header)


if __name__ == "__main__":
    main()
