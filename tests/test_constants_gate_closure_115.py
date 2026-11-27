"""Tests for RE-015-node115-constants-gate-closure."""

from __future__ import annotations

import importlib.util
import json
import os
import pwd
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKET_DIR = (
    REPO_ROOT
    / "research"
    / "work-items"
    / "RE-015-node115-constants-gate-closure"
)
BINARY_PATH = REPO_ROOT / "artifacts" / "node" / "115" / "hl-node"
BYTE_WINDOWS_PATH = REPO_ROOT / "research" / "byte-windows.json"
STREAM_F_RECORDS_PATH = (
    REPO_ROOT
    / "research"
    / "work-items"
    / "RE-015-node115-stream-f-byte-matches"
    / "records.json"
)


def _load_verify():
    spec = importlib.util.spec_from_file_location(
        "re015_constants_gate_closure_verify", PACKET_DIR / "verify.py"
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@unittest.skipUnless(BINARY_PATH.exists(), "node #115 binary required")
class ConstantsGateClosure115Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_verify()
        cls.data = BINARY_PATH.read_bytes()
        cls.records = json.loads((PACKET_DIR / "records.json").read_text(encoding="utf-8"))

    def test_committed_records_rebuild_and_match_node115(self) -> None:
        self.mod.verify_records(self.records, self.data, rebuild=True)
        s = self.records["summary"]
        self.assertEqual(s["cgu_total_fdes"], 40)
        self.assertEqual(s["cgu_total_bytes"], 23050)
        self.assertEqual(s["windows"], 12)
        self.assertEqual(s["total_bytes"], 5031)
        self.assertEqual(s["relocation_qualified_windows"], 12)
        self.assertEqual(s["raw_equal_bytes"], 4305)

    def test_windows_disjoint_from_dependencies_and_peer_packets(self) -> None:
        ours = [(int(w["start"], 16), int(w["end"], 16)) for w in self.records["windows"]]
        # Internal disjointness
        ours_sorted = sorted(ours)
        for (s1, e1), (s2, e2) in zip(ours_sorted, ours_sorted[1:]):
            self.assertLessEqual(e1, s2, f"internal overlap: {hex(s1)}..{hex(e1)} vs {hex(s2)}..{hex(e2)}")

        # Disjoint from dependency windows and no partial overlap with first-party windows in byte-windows.json
        if BYTE_WINDOWS_PATH.exists():
            bw = json.loads(BYTE_WINDOWS_PATH.read_text(encoding="utf-8"))
            for w in bw.get("windows", []):
                ws = int(w["start"], 16) if isinstance(w["start"], str) else int(w["start"])
                we = int(w["end"], 16) if isinstance(w["end"], str) else int(w["end"])
                is_dep = "dependency" in w
                for os_, oe_ in ours:
                    if os_ < we and ws < oe_:
                        if is_dep or (os_, oe_) != (ws, we):
                            self.fail(
                                f"overlap with byte-windows.json ({'dep' if is_dep else 'partial fp'}): "
                                f"{hex(os_)}..{hex(oe_)} vs {hex(ws)}..{hex(we)}"
                            )

        # Strictly disjoint from RE-015-node115-stream-f-byte-matches
        if STREAM_F_RECORDS_PATH.exists():
            sf = json.loads(STREAM_F_RECORDS_PATH.read_text(encoding="utf-8"))
            for w in sf.get("windows", []):
                ws = int(w["start"], 16)
                we = int(w["end"], 16)
                for os_, oe_ in ours:
                    self.assertFalse(
                        os_ < we and ws < oe_,
                        f"overlap with stream-f-byte-matches: {hex(os_)}..{hex(oe_)} vs {hex(ws)}..{hex(we)}",
                    )

    def test_all_four_negative_controls_are_rejected(self) -> None:
        rejected = self.mod.run_negative_controls(self.records, self.data)
        self.assertEqual(rejected, 4)

    def test_home_dir_getpwuid_r_fallback_when_home_unset(self) -> None:
        expected_home = pwd.getpwuid(os.getuid()).pw_dir
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            src = td_path / "check_home.rs"
            exe = td_path / "check_home"
            src.write_text(
                'fn main() {\n'
                '    #[allow(deprecated)]\n'
                '    let h = std::env::home_dir()\n'
                '        .and_then(|p| p.to_str().map(str::to_owned))\n'
                '        .unwrap_or_default();\n'
                '    print!("{h}");\n'
                '}\n',
                encoding="utf-8",
            )
            subprocess.run(
                ["rustc", "+1.95.0", "--edition=2021", str(src), "-o", str(exe)],
                check=True,
            )
            env_clean = {k: v for k, v in os.environ.items() if k != "HOME"}
            out = subprocess.check_output([str(exe)], env=env_clean, text=True)
            self.assertEqual(out, expected_home)


if __name__ == "__main__":
    unittest.main()
