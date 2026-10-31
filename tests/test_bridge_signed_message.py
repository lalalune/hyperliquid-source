"""Tests for tools/bridge_signed_message.py: static pins, the specification on real bytes, and negative controls."""

import hashlib
import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("bridge_signed_message", ROOT / "tools" / "bridge_signed_message.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
FOLDER = ROOT / "research" / "work-items" / "bridge-signed-message-94"
ACCOUNT = bytes(range(1, 21))
TARGET = bytes(range(0x21, 0x35))
WITHDRAWAL = {"arm": 5, "account": ACCOUNT, "destination": TARGET, "amount": 123456, "nonce": 77}


def rows(count):
    return [{"power": 100 + index, "hot": bytes([0x40 + index]) * 20, "cold": bytes([0x80 + index]) * 20} for index in range(count)]


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = tool.load_image()
        cls.harness = tool.make_harness(cls.image)
        cls.harness.fast(True)

    def setUp(self):
        self.harness.book = dict(self.harness.book_base)

    def request(self, payload, chain=3):
        return tool.run_case(self.harness, payload, chain)

    def expected(self, payload, chain=3):
        return tool.expected_messages(payload, chain, self.harness.book_base)

    def poke(self, va, value):
        machine = self.harness.machine
        machine.patches = {va: value}
        machine.cache.clear()

    def tearDown(self):
        self.harness.machine.patches = {}
        self.harness.machine.cache.clear()


class Input(unittest.TestCase):
    def test_wrong_digest_is_refused(self):
        with self.assertRaisesRegex(tool.EvidenceError, "SHA-256"):
            tool.load_image(expected="0" * 64)

    def test_other_file_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "blob"
            path.write_bytes(b"not an elf")
            with self.assertRaises(tool.EvidenceError):
                tool.load_image(path=path)


class Hashes(unittest.TestCase):
    def test_keccak_known_answers(self):
        self.assertEqual(tool.keccak(b"").hex(), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        self.assertEqual(tool.keccak(b"transfer(address,uint256)")[:4].hex(), "a9059cbb")

    def test_rate_boundary_takes_a_second_block(self):
        self.assertNotEqual(tool.keccak(bytes(135)), tool.keccak(bytes(136)))

    def test_abi_dynamic_head_points_past_the_head(self):
        data = tool.abi_encode([("string", b"ab"), ("uint", 5)])
        self.assertEqual(int.from_bytes(data[:32], "big"), 64)
        self.assertEqual(int.from_bytes(data[32:64], "big"), 5)
        self.assertEqual(int.from_bytes(data[64:96], "big"), 2)
        self.assertEqual(data[96:98], b"ab")


class Static(Base):
    def test_arms(self):
        arms = tool.arm_rows(self.image)
        self.assertEqual([row["action"] for row in arms][5:7], ["requestWithdrawal", "unlock"])
        self.assertEqual(arms[6]["entry"], "0x358e57a")
        self.assertEqual(len(arms), 8)

    def test_only_two_callers_and_their_tags(self):
        self.assertEqual([row["tag"] for row in tool.caller_rows(self.image)], [4, 5])

    def test_templates(self):
        self.assertEqual([row["text"] for row in tool.text_rows(self.image)], ["Bridge2", "modify"])

    def test_book_texts(self):
        rows_ = tool.book_text_rows(self.image)
        self.assertEqual({row["name"]: row["value"][2:].lower() for row in rows_}, {name: value for namespace in tool.SPEC_BOOK.values() for name, value in namespace})

    def test_namespace_rule_pin(self):
        self.assertIn("namespace 2", tool.chain_rule_bytes(self.image)["rule"])

    def test_outside_lea_is_refused(self):
        with self.assertRaisesRegex(tool.EvidenceError, "no rip lea"):
            tool.lea_target(self.image, tool.BUILD)

    def test_out_of_file_address_is_refused(self):
        with self.assertRaises(tool.EvidenceError):
            self.image.offset(1 << 40)


class Messages(Base):
    def test_withdrawal_words(self):
        got = self.request(WITHDRAWAL)
        data = got["absorbed"][0]
        self.assertEqual(len(data), 7 * 32)
        self.assertEqual(int.from_bytes(data[:32], "big"), 0xA0)
        self.assertEqual(data[44:64], ACCOUNT)
        self.assertEqual(data[76:96], TARGET)
        self.assertEqual(data[192:209], b"requestWithdrawal")

    def test_every_arm_on_both_chains(self):
        payloads = [{"arm": 0, "role": 1, "active": False, "validator": ACCOUNT, "nonce": 9}, {"arm": 1, "value": 5, "nonce": 6}, {"arm": 2, "value": 5, "nonce": 6}, {"arm": 3, "value": 5, "nonce": 6},
                    {"arm": 4, "epoch": 7, "rows": rows(3)}, WITHDRAWAL, {"arm": 6, "epoch": 7, "rows": rows(3), "nonce": 8}, {"arm": 7, "ids": [b"\x11" * 32], "nonce": 4}]
        for payload in payloads:
            for chain in (2, 3):
                with self.subTest(arm=payload["arm"], chain=chain):
                    got, expected = self.request(payload, chain), self.expected(payload, chain)
                    self.assertEqual(got["absorbed"], tool.message_list(expected))
                    self.assertEqual(got["digest"], expected["digest"])
                    self.assertEqual(got["chain_id"], 42161 if chain == 3 else 421614)

    def test_rows_come_out_last_first(self):
        got = self.request({"arm": 4, "epoch": 1, "rows": rows(2)})
        data = got["absorbed"][0]
        self.assertEqual(data[8 * 32 + 12:8 * 32 + 32], bytes([0x41]) * 20)

    def test_forward_row_order_is_not_what_runs(self):
        payload = {"arm": 4, "epoch": 1, "rows": rows(2)}
        forward = tool.abi_encode(tool.payload_tokens({"arm": 4, "epoch": 1, "rows": rows(2)[::-1]}))
        self.assertNotEqual(self.request(payload)["absorbed"][0], forward)

    def test_two_level_set_walks_every_row(self):
        got = self.request({"arm": 4, "epoch": 1, "rows": rows(13)})
        self.assertEqual(got["absorbed"][0], self.expected({"arm": 4, "epoch": 1, "rows": rows(13)})["payload_input"])

    def test_digest_takes_high_chain_words(self):
        connection = b"\x07" * 32
        got = tool.run_digest(self.harness, b"b", connection, 1, 3)
        self.assertEqual(got["digest"], tool.expected_digest(b"b", connection, 1 | 3 << 192)["digest"])
        self.assertNotEqual(got["digest"], tool.expected_digest(b"b", connection, 1)["digest"])

    def test_book_namespaces_and_files(self):
        book = tool.run_book(self.harness)
        self.assertEqual(len(book["files"]), 11)
        self.assertTrue(book["files"][3].endswith("/ArbitrumTestnet.json"))
        self.assertEqual({row[0] for row in book["rows"]}, {2, 3})

    def test_local_chain_has_no_row(self):
        with self.assertRaises(tool.Panicked):
            self.request(WITHDRAWAL, 0)


class Negative(Base):
    def case(self, label):
        return next(case for case in tool.all_cases() if case.label == label)

    def test_control_passes(self):
        self.assertIsNone(tool.compare_run(self.harness, self.case("chain 3 withdrawal")))

    def test_source_byte_change_is_seen(self):
        self.poke(0x358EC71, 0x62)
        self.assertIsNotNone(tool.compare_run(self.harness, self.case("chain 3 withdrawal")))

    def test_mainnet_id_change_is_seen(self):
        self.poke(0x358EC73, 0xB2)
        self.assertIsNotNone(tool.compare_run(self.harness, self.case("chain 3 withdrawal")))

    def test_namespace_rule_change_is_seen(self):
        self.poke(0x358EAFD, 0x02)
        self.assertIsNotNone(tool.compare_run(self.harness, self.case("chain 3 withdrawal")))

    def test_domain_name_change_is_seen(self):
        self.poke(0x38EFF5F, 0x46)
        self.assertIsNotNone(tool.compare_run(self.harness, self.case("chain 3 withdrawal")))

    def test_wrong_contract_is_seen(self):
        changed = dict(self.harness.book_base)
        changed[(2, b"Bridge2Mainnet\0\0")] = bytes(20)
        self.assertNotEqual(tool.expected_messages(WITHDRAWAL, 3, changed)["digest"], self.request(WITHDRAWAL)["digest"])


class Files(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = tool.render(tool.analyse(tool.load_image(), full=False))

    def test_case_files_match(self):
        for name in ("cases.tsv", "vectors.tsv", "worked_words.tsv"):
            self.assertEqual((FOLDER / name).read_text(encoding="ascii"), self.files[name], name)

    def test_manifest(self):
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest, name)

    def test_generated_files_carry_no_absolute_path(self):
        for name, text in self.files.items():
            self.assertNotIn("/" + "mnt/", text, name)
            self.assertNotIn("\x40", text, name)


if __name__ == "__main__":
    unittest.main()
