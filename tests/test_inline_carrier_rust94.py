"""Native identity, independent width equations and retained real Rust streams."""
import base64
import importlib.util
import io
import json
from pathlib import Path
import struct
import tarfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT/"research/work-items/RE-001-inline-carrier-rust-94"
SPEC = importlib.util.spec_from_file_location("inline_carrier94", PACKET/"verify.py")
v = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(v)


class InlineCarrierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = v.NODE.read_bytes()
        cls.secs = v.sections(cls.data)
        cls.cases = v.vectors()

    def mutate(self, address, byte):
        sec = next(s for s in self.secs if s["type"] != 8
                   and s["address"] <= address < s["address"]+s["size"])
        changed = bytearray(self.data)
        changed[sec["offset"]+address-sec["address"]] = byte
        return changed

    def test_complete_constructor_packer_slot_and_selected_guards(self):
        v.authenticate(self.data)
        record = json.loads((PACKET/"native.json").read_text())
        self.assertEqual([r["bytes"] for r in record["owners"]], [1417, 89])
        self.assertEqual(len(record["owners"][0]["explicit_prefix_row_differences"]), 8)
        self.assertEqual(record["owners"][1]["gnu_rows"], 25)
        self.assertEqual(record["owners"][1]["llvm_rows"], 25)
        self.assertEqual(record["slot_binding"]["addend"], "0x144a010")

    def test_all_frozen_native_halves_match_independent_integer_and_byte_views(self):
        native = [r for r in self.cases if r["partition"] == "native"]
        self.assertEqual(len(native), 156)
        for row in native:
            low, high = v.equations(row["input"])
            raw = struct.pack("<QQ", low, high)
            self.assertEqual((low, high), row["expected"], row["name"])
            self.assertEqual(raw, row["input"].ljust(16, b"\0"), row["name"])
        for bit in range(128):
            row = next(r for r in native if r["name"] == f"bit-{bit}")
            self.assertEqual(row["expected"], ((1 << bit) & v.MASK, (1 << bit) >> 64))

    def test_native_boundaries_and_chosen_api_refusals_are_separate(self):
        for length in (0, 1, 8, 15, 16):
            row = next(r for r in self.cases if r["name"] == f"length-{length}")
            self.assertIsNotNone(v.equations(row["input"]))
        api = [r for r in self.cases if r["partition"] == "api"]
        self.assertEqual([len(r["input"]) for r in api], [17, 32])
        self.assertTrue(all(r["expected"] is None for r in api))
        self.assertEqual(v.equations(b"A"), v.equations(b"A\0"))
        self.assertEqual(v.equations(bytes([255])*16), (v.MASK, v.MASK))

    def test_all_five_inert_native_controls_have_equation_witnesses(self):
        actual = v.native_controls(self.data, self.secs, self.cases)
        self.assertEqual(v.json_bytes(actual), (PACKET/"native-controls.json").read_bytes())
        self.assertEqual(len(actual), 5)
        self.assertTrue(all(r["different_native_cases"] > 0 for r in actual))

    def test_identity_and_undeclared_native_changes_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "identity"):
            v.authenticate(self.data[:-1])
        with self.assertRaisesRegex(ValueError, "identity"):
            v.authenticate(self.mutate(0x144A040, 7))
        with self.assertRaisesRegex(ValueError, "grammar"):
            v.native_fields(self.mutate(0x144A010, 0x90), self.secs)
        with self.assertRaisesRegex(ValueError, "unsupported"):
            v.native_fields(self.mutate(0x144A040, 9), self.secs)

    def test_native_exports_reject_missing_duplicate_or_corrupted_bytes(self):
        owners = json.loads((PACKET/"native.json").read_text())["owners"]
        text = (PACKET/"native-gnu.txt").read_text()
        row = next(s for s in text.splitlines() if s.lstrip().startswith("144a010:"))
        for changed in (text.replace(row, ""), text.replace(row, row+"\n"+row),
                        text.replace("144a010:\t53", "144a010:\t90")):
            with self.assertRaises(ValueError):
                v.check_listing(changed, self.data, self.secs, owners)

    def test_actual_output_comparator_rejects_wrong_halves_and_framing(self):
        inputs, expected = v.streams(self.cases, "native")
        self.assertEqual(v.compare(expected, expected), [])
        changed = bytearray(expected)
        changed[10] ^= 1
        self.assertEqual(len(v.compare(changed, expected)), 1)
        for malformed in (expected[:-1], b"x"+expected[1:], expected+b"x"):
            with self.assertRaises(ValueError):
                v.compare(malformed, expected)
        changed = bytearray(expected)
        changed[7] ^= 1
        with self.assertRaisesRegex(ValueError, "framing"):
            v.compare(changed, expected)
        # Parse the input stream independently: no expected status/half words.
        at = 7
        for row in (r for r in self.cases if r["partition"] == "native"):
            _, length = struct.unpack_from("<HB", inputs, at)
            at += 3
            self.assertEqual(inputs[at:at+length], row["input"])
            at += length
        self.assertEqual(at, len(inputs))

    def test_retained_live_rust_streams_and_all_semantic_source_controls(self):
        receipt = json.loads((PACKET/"comparison.json").read_text())
        self.assertEqual(receipt["source_input_pins"], v.source_pins())
        self.assertEqual(receipt["runner_sha256"], v.sha((PACKET/"verify.py").read_bytes()))
        self.assertEqual(len(receipt["builds"]), 15)
        self.assertTrue(receipt["repeat_library_equal"] and receipt["repeat_executable_equal"])
        self.assertFalse(receipt["captured_execution"])
        bundle = json.loads((PACKET/"raw-streams.json").read_text())
        payload = base64.b64decode(bundle["payload_base64"], validate=True)
        self.assertEqual(len(payload), bundle["payload_bytes"])
        self.assertEqual(v.sha(payload), bundle["payload_sha256"])
        self.assertEqual(v.sha((PACKET/"comparison.json").read_bytes()), bundle["comparison_json_sha256"])
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as tar:
            members = tar.getmembers()
            self.assertTrue(all(m.isfile() and not m.name.startswith("/") and ".." not in Path(m.name).parts for m in members))
            self.assertEqual(len(members), len({m.name for m in members}))
            raw = {m.name: tar.extractfile(m).read() for m in members}
        self.assertEqual(set(raw), set(bundle["files"]))
        self.assertFalse(any(n.endswith((".rs", ".rlib", ".o", ".so")) or n.endswith(("/native.json", "/PLAN.json")) for n in raw))
        allowed_snapshot = {"snapshot/SNAPSHOT.json", "snapshot/recipes.json",
                            "snapshot/native.inputs.bin", "snapshot/native.expected.bin",
                            "snapshot/api.inputs.bin", "snapshot/api.expected.bin"}
        self.assertTrue(all(n in allowed_snapshot or not n.startswith("snapshot/")
                            and n.endswith((".stdout", ".stderr", ".d", ".actual.bin")) for n in raw))
        for partition in ("native", "api"):
            inputs, expected = v.streams(self.cases, partition)
            self.assertEqual(raw[f"snapshot/{partition}.inputs.bin"], inputs)
            self.assertEqual(raw[f"snapshot/{partition}.expected.bin"], expected)
        for name, record in bundle["files"].items():
            self.assertEqual(len(raw[name]), record["bytes"])
            self.assertEqual(v.sha(raw[name]), record["sha256"])
        snapshot = json.loads(raw["snapshot/SNAPSHOT.json"])
        self.assertEqual(v.sha(raw["snapshot/SNAPSHOT.json"]), receipt["snapshot_sha256"])
        for name, record in snapshot.items():
            if name in bundle["omitted_snapshot_files_bound_to_current_text"]:
                content = (ROOT/bundle["omitted_snapshot_files_bound_to_current_text"][name]).read_bytes()
            else:
                content = raw["snapshot/"+name]
            self.assertEqual(len(content), record["bytes"])
            self.assertEqual(v.sha(content), record["sha256"])
        baseline = (v.COMPONENT/"src/lib.rs").read_text()
        recipes = {r[0]: r for r in v.RECIPES}
        for build in receipt["builds"]:
            directory = f"{build['variant']}-opt{build['opt']}-repeat{build['repeat']}"
            expected_source = baseline
            if build["variant"] != "baseline":
                _, _, old, new = recipes[build["variant"]]
                self.assertEqual(baseline.count(old), 1)
                expected_source = baseline.replace(old, new)
            self.assertEqual(v.sha(expected_source.encode()), build["source_sha256"])
            for group in build["groups"]:
                part = group["partition"]
                actual = raw[directory+"/"+part+".actual.bin"]
                expected = raw["snapshot/"+part+".expected.bin"]
                differences = v.compare(actual, expected)
                self.assertEqual(len(differences), group["different_cases"])
                self.assertEqual(v.sha(actual), group["stdout_sha256"])
                self.assertEqual(bool(differences), build["partition"] == part)
                self.assertEqual(differences[0] if differences else None, group["first_witness"])
            for i, command in enumerate(build["commands"]):
                self.assertEqual(command["exit"], 0)
                self.assertEqual(raw[directory+f"/compile-{i}.stderr"], b"")
                self.assertEqual(v.sha(raw[directory+f"/compile-{i}.stdout"]), command["stdout_sha256"])

    def test_file_backing_and_packet_manifest(self):
        fake = [{"type": 1, "address": 0x1000, "offset": 0, "size": 4}]
        self.assertEqual(v.span(b"abcd", fake, 0x1001, 2), b"bc")
        for sections in ([], fake+fake, [{**fake[0], "type": 8}]):
            with self.assertRaises(ValueError):
                v.span(b"abcd", sections, 0x1000, 1)
        for address, size in ((True, 1), (0x1000, True), (-1, 1), (0x1000, 0)):
            with self.assertRaises(ValueError):
                v.span(b"abcd", fake, address, size)
        with self.assertRaisesRegex(ValueError, "exceeds"):
            v.span(b"a", fake, 0x1000, 2)
        v.manifest_check()


if __name__ == "__main__":
    unittest.main()
