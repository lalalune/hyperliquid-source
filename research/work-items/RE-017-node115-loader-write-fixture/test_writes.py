"""Test selected store boundaries with ordinary offline compact fixture bytes."""

from hashlib import sha256
from pathlib import Path
from struct import pack_into, unpack_from
import subprocess
import sys
import tempfile
import unittest

from apply_writes import COMPACT_SIZE, STAGES, U64_MAX, apply

sys.path.insert(0, str(Path.cwd() / "tools"))
from re16_state_load_chain115 import BUILDER_FRAME_FILL, all_cases, model as load_model
from re16_state_materialize115 import model as materialize_model

HEIGHT = 1196590000


def sample(version=109, round_number=777):
    image = bytearray(b"\x7b" * COMPACT_SIZE)
    pack_into("<Q", image, 0x18, version)
    pack_into("<Q", image, 0x28, HEIGHT)
    pack_into("<Q", image, 0x30, round_number)
    return image


def run(stage, image):
    return apply(image, sha256(image).hexdigest(), HEIGHT, stage)


class LoaderWriteFixtureTests(unittest.TestCase):
    def test_entry_copies_requested_height_and_preserves_freeze_payload(self):
        for version, next_version in ((109, 110), (U64_MAX, U64_MAX)):
            original = sample(version)
            expected = original.copy()
            for offset, value in ((0x10, HEIGHT), (0x18, next_version),
                                  (0x20, 777), (0xDF0, 777), (0x10E8, 0)):
                expected[offset:offset + 8] = value.to_bytes(8, "little")
            self.assertEqual(run("entry", original), expected)
            self.assertEqual(unpack_from("<Q", original, 0x18)[0], version)

    def test_post_c_staking_reloads_the_fixture_round(self):
        midway = bytearray(run("entry", sample()))
        pack_into("<Q", midway, 0x30, 888)
        expected = midway.copy()
        expected[0xEF8:0xF00] = (888).to_bytes(8, "little")
        actual = run("after-c-staking", midway)
        self.assertEqual(actual, expected)
        self.assertEqual(unpack_from("<Q", actual, 0xDF0)[0], 777)

    def test_late_flags_do_not_clear_adjacent_payloads(self):
        original = sample()
        expected = original.copy()
        expected[0x39B0] = 2
        expected[0x3E28:0x3E2A] = b"\0\0"
        expected[0x3EE0:0x3EE2] = b"\0\0"
        self.assertEqual(run("after-action-delayer", original), expected)

    def test_all_stage_stores_match_loader_model_with_inert_helpers(self):
        count = 0
        for case in all_cases(72):
            _, terminal, _, expected, _ = load_model(case)
            if terminal is not None:
                continue
            state = materialize_model({
                "in": case["in"], "out": BUILDER_FRAME_FILL,
                "composed": case["composed"], "consumed": case["consumed"],
                "a": case["a"], "b": case["b_arg"],
            })["out"][:COMPACT_SIZE]
            for stage in STAGES:
                state = apply(state, sha256(state).hexdigest(), case["w"][3], stage)
            self.assertEqual(state, expected[:COMPACT_SIZE])
            count += 1
        self.assertEqual(count, 40)

    def test_identity_coordinates_and_invalid_stage(self):
        image = sample()
        digest = sha256(image).hexdigest()
        with self.assertRaisesRegex(ValueError, "0x42c8"):
            apply(image[:-1], digest, HEIGHT, "entry")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            apply(image, "0" * 64, HEIGHT, "entry")
        with self.assertRaisesRegex(ValueError, "height"):
            apply(image, digest, HEIGHT + 1, "entry")
        with self.assertRaisesRegex(ValueError, "boundary"):
            apply(image, digest, HEIGHT, "all")

    def test_cli_applies_one_stage_to_a_local_file(self):
        image = sample()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "compact.bin"
            path.write_bytes(image)
            result = subprocess.run([
                sys.executable, "-B", str(Path(__file__).with_name("apply_writes.py")),
                str(path), "--sha256", sha256(image).hexdigest(), "--height", str(HEIGHT),
                "--stage", "after-action-delayer",
            ], check=True, capture_output=True)
            self.assertEqual(result.stdout, run("after-action-delayer", image))
            self.assertEqual(path.read_bytes(), image)


if __name__ == "__main__":
    unittest.main(verbosity=2)
