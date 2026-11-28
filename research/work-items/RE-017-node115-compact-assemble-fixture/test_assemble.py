"""Check composition against existing pure Python layout models and real local files."""

from hashlib import sha256, shake_256
from pathlib import Path
from struct import pack_into
import subprocess
import sys
import tempfile
import unittest

from assemble import DECODED_SIZE, EVM_BLOCK_SIZE, assemble

sys.path.insert(0, str(Path.cwd() / "tools"))
from re16_state_compose115 import model as compose_model
from re16_state_materialize115 import model as materialize_model

H = 1196590000
COMPOSER_TAIL = bytes.fromhex("a1b2c3d4")
COMPACT_TAIL = bytes.fromhex("e54657")


def fixture(seed):
    pool = shake_256(seed).digest(DECODED_SIZE + EVM_BLOCK_SIZE)
    decoded = bytearray(pool[:DECODED_SIZE])
    pack_into("<Q", decoded, 0x28, H)
    return bytes(decoded), pool[DECODED_SIZE:]


def model(decoded, evm_block):
    composed = compose_model({
        "in": decoded[0x1108:0x1CC0], "block": evm_block,
        "out": bytes(0x26D4) + COMPOSER_TAIL,
        "cap": 0, "ptr": 0, "ctx": 0, "h": 0,
    })["out"]
    return materialize_model({
        "in": decoded, "out": bytes(0x42C5) + COMPACT_TAIL,
        "composed": composed, "consumed": bytes(0xBB8), "a": 0, "b": 0,
    })["out"]


def project(decoded, block):
    return assemble(decoded, block, sha256(decoded).hexdigest(), sha256(block).hexdigest(),
                    H, COMPOSER_TAIL, COMPACT_TAIL)


class CompactAssemblyTests(unittest.TestCase):
    def test_entire_image_matches_both_pure_models(self):
        for seed in range(48):
            decoded, block = fixture(bytes([seed]))
            with self.subTest(seed=seed):
                self.assertEqual(project(decoded, block), model(decoded, block))

    def test_pads_and_reordered_historical_member(self):
        decoded, block = fixture(b"order")
        state = project(decoded, block)
        self.assertEqual(state[0x1108:0x2C28], block)
        self.assertEqual(state[0x2C28:0x2C48], decoded[0x1C40:0x1C60])
        self.assertEqual(state[0x37DC:0x37E0], COMPOSER_TAIL)
        self.assertEqual(state[0x42C5:0x42C8], COMPACT_TAIL)

    def test_digest_length_height_and_pad_controls(self):
        decoded, block = fixture(b"checks")
        dsha, esha = sha256(decoded).hexdigest(), sha256(block).hexdigest()
        good = [decoded, block, dsha, esha, H, COMPOSER_TAIL, COMPACT_TAIL]
        for pos, replacement in ((0, decoded[:-1]), (1, block + b"\x00"),
                                 (2, "0" * 64), (3, "0" * 64), (4, H + 1),
                                 (5, bytes(3)), (6, bytes(4))):
            args = good.copy()
            args[pos] = replacement
            with self.subTest(pos=pos), self.assertRaises(ValueError):
                assemble(*args)

    def test_cli_reads_both_real_local_fixture_files(self):
        decoded, block = fixture(b"cli")
        with tempfile.TemporaryDirectory() as temporary:
            input_file = Path(temporary) / "decoded.bin"
            block_file = Path(temporary) / "block.bin"
            input_file.write_bytes(decoded)
            block_file.write_bytes(block)
            result = subprocess.run([
                sys.executable, "-B", str(Path(__file__).with_name("assemble.py")),
                str(input_file), str(block_file),
                "--decoded-sha256", sha256(decoded).hexdigest(),
                "--evm-sha256", sha256(block).hexdigest(), "--height", str(H),
                "--composer-tail", COMPOSER_TAIL.hex(), "--compact-tail", COMPACT_TAIL.hex(),
            ], check=True, capture_output=True)
            self.assertEqual(result.stdout, model(decoded, block))


if __name__ == "__main__":
    unittest.main(verbosity=2)
