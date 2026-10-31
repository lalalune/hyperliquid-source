"""Tests for tools/staking_delegate_entry.py: real node #94 bytes with corruption controls."""

import copy
import hashlib
import importlib.util
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLDER = ROOT / "research" / "work-items" / "staking-delegate-entry-94"
spec_ = importlib.util.spec_from_file_location("staking_delegate_entry", ROOT / "tools" / "staking_delegate_entry.py")
tool = importlib.util.module_from_spec(spec_)
sys.modules["staking_delegate_entry"] = tool
spec_.loader.exec_module(tool)

IMAGE = None
HARNESS = None
RESULT = None
A, B = tool.A, tool.B
NOW = tool.NOW
OLD = (0x3FFFFF00, 5, 6)


def setUpModule():
    global IMAGE, HARNESS, RESULT
    IMAGE = tool.load_image()
    HARNESS = tool.Harness(IMAGE)
    RESULT = tool.analyse(IMAGE, mutate=False, vectors=60)


def run(name="t", **fields):
    case = tool.Case(name, **fields)
    got = HARNESS.run(case)
    assert got == tool.spec_run(case), case.__dict__
    return got


def token(**fields):
    return run(kind="token", **fields)


def host(**fields):
    base = dict(kind="host", users=tool.RICH)
    base.update(fields)
    return run(**base)


def self_exit(**fields):
    base = dict(user=A, validator=A, mode=1, states=((A, OLD),))
    base.update(fields)
    return token(**base)


def events(got, kind):
    return [event for event in got[1] if event[0] == kind]


def changed(patch, **fields):
    harness = tool.Harness(IMAGE, patch)
    return tool.first_failure(harness, [tool.Case("t", **fields)]) is not None


class Identity(unittest.TestCase):
    def test_digest_is_the_target(self):
        self.assertEqual(hashlib.sha256(IMAGE.blob).hexdigest(), tool.SHA256)

    def test_wrong_digest_fails(self):
        with self.assertRaises(tool.EvidenceError):
            tool.load_image(expected="0" * 64)

    def test_address_outside_every_fde_fails(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.fde(0x10)

    def test_exact_bounds(self):
        self.assertEqual(IMAGE.exact_fde(tool.GATE_A), (0x2757FE0, 0x2757FE0 + 842))
        self.assertEqual(IMAGE.exact_fde(tool.GATE_C), (0x4D80BC0, 0x4D80BC0 + 1007))
        self.assertEqual(IMAGE.exact_fde(tool.HOST_A), (0x2768FF0, 0x2768FF0 + 985))

    def test_inside_address_is_not_an_entry(self):
        with self.assertRaises(tool.EvidenceError):
            IMAGE.exact_fde(tool.GATE_A + 1)

    def test_status_text(self):
        rows = {row[0]: row[2] for row in RESULT["statuses"]}
        self.assertEqual(rows["0x130"], "Self delegation insufficient")
        self.assertEqual(rows["0x8e"], "Action disabled on this chain.")
        self.assertEqual(rows["0xff"], "Cannot undelegate during lockup period after delegating or voting.")


class Lists(unittest.TestCase):
    def test_chain_arms(self):
        rows = RESULT["chains"]
        self.assertEqual(rows[0][4], "invalid chain")
        self.assertEqual([row[3] for row in rows[1:]], ["0x57861d8", "0x57861f8", "0x5786218"])

    def test_counts(self):
        rows = RESULT["lists"]
        names = [row[0] for row in rows]
        self.assertEqual([names.count(name) for name in ("sandbox_self_signers", "testnet_self_signers", "mainnet_self_signers", "mainnet_foundation_signers", "mainnet_foundation_validators")], [4, 4, 4, 5, 1])

    def test_extra_key_is_copied_from_the_mainnet_cell(self):
        row = [row for row in RESULT["lists"] if row[0] == "mainnet_foundation_validators"][0]
        self.assertEqual((row[3], row[4]), ("0x5786218", tool.EXTRA_VALIDATOR))

    def test_signer_set_has_the_other_key(self):
        keys = [row[4] for row in RESULT["lists"] if row[0] == "mainnet_foundation_signers"]
        self.assertIn(tool.EXTRA_SIGNER, keys)
        self.assertNotIn(tool.EXTRA_VALIDATOR, keys)

    def test_a_changed_key_is_refused(self):
        saved = tool.LISTS[1]
        tool.LISTS[1] = (saved[0], saved[1], ("00" * 20,) + saved[2][1:])
        try:
            with self.assertRaises(tool.EvidenceError):
                tool.list_rows(IMAGE)
        finally:
            tool.LISTS[1] = saved

    def test_list_entry_points(self):
        self.assertEqual(run(kind="list", chain=3, mode=0)[0], ("list", 0x5786218))
        self.assertEqual(run(kind="list", chain=3, mode=1)[0], ("list", 0x5786238))
        self.assertEqual(run(kind="list", chain=2, mode=1)[0], ("list", 0x57861F8))
        self.assertEqual(run(kind="list", chain=0, mode=1)[0], ("panic", "invalid chain"))

    def test_lazy_word(self):
        self.assertEqual(run(kind="list", chain=3, mode=1, lazy=True)[1], (("once_word", 0x5786250),))


class TokenGate(unittest.TestCase):
    def test_delegate_row(self):
        got = token()
        self.assertEqual(got[0], ("applied",))
        self.assertEqual(events(got, "core")[0][1:4], (2, 0, 100))

    def test_guard_is_first(self):
        self.assertEqual(token(wei=tool.GUARD, tag=0)[0], ("failed", 0x13F, tool.GUARD))
        self.assertEqual(token(wei=tool.GUARD - 1)[0], ("applied",))

    def test_tag_before_zero(self):
        self.assertEqual(token(tag=0, wei=0)[0], ("failed", 0xFB))
        self.assertEqual(token(wei=0)[0], ("failed", 0x32))

    def test_tag_is_a_dword(self):
        self.assertEqual(token(tag=0x101)[0], ("failed", 0xFB))
        self.assertEqual(token(tag=0x100000001)[0], ("applied",))

    def test_other_validator_has_no_floor(self):
        self.assertEqual(events(token(mode=1), "core")[0][1:3], (0, 0))

    def test_mode_above_one(self):
        self.assertEqual(events(token(mode=7), "core")[0][1:3], (1, 7))

    def test_self_without_row(self):
        self.assertEqual(token(user=A, validator=A, mode=1)[0], ("failed", 0x91))

    def test_lock_running_keeps_floor(self):
        got = self_exit(lock=(NOW[0] + 1, 0, 0))
        self.assertEqual(events(got, "core")[0][1:3], (0, 1000))
        self.assertEqual(events(got, "add_year"), [("add_year", OLD)])

    def test_lock_equal_keeps_floor(self):
        self.assertEqual(events(self_exit(lock=NOW), "core")[0][2], 1000)

    def test_lock_over_clears_floor(self):
        self.assertEqual(events(self_exit(lock=(NOW[0], NOW[1], NOW[2] - 1)), "core")[0][2], 0)

    def test_date_is_signed(self):
        self.assertEqual(events(self_exit(lock=(0xC0000000, 0, 0)), "core")[0][2], 0)

    def test_foundation_keeps_floor_without_time_add(self):
        key = tool.members(3)[1]
        got = token(user=key, validator=key, mode=1, states=((key, OLD),), lock=(1, 0, 0))
        self.assertEqual(events(got, "core")[0][2], 1000)
        self.assertEqual(events(got, "add_year"), [])

    def test_mainnet_extra_validator_is_a_member(self):
        key = bytes.fromhex(tool.EXTRA_VALIDATOR)
        self.assertEqual(events(token(user=key, validator=key, mode=1, states=((key, OLD),), lock=(1, 0, 0)), "add_year"), [])

    def test_signer_key_is_not_a_member(self):
        key = bytes.fromhex(tool.EXTRA_SIGNER)
        self.assertEqual(len(events(token(user=key, validator=key, mode=1, states=((key, OLD),)), "add_year")), 1)

    def test_local_chain_panics(self):
        self.assertEqual(self_exit(chain=0)[0], ("panic", "invalid chain"))

    def test_core_failure_is_copied(self):
        got = token(core=0xFE)
        self.assertEqual(got[0], ("failed", 0xFE, tool.payload(0xFE)))


class Host(unittest.TestCase):
    def test_unregister_first(self):
        self.assertEqual(host(word0=tool.UNREGISTER, allow_all=0)[0], ("status", 0x8E))

    def test_allow_list(self):
        self.assertEqual(host(allow_all=0)[0], ("status", 0x94))
        self.assertEqual(host(allow_all=0, allowed=(A,), wei=1000)[0], ("status", tool.OK))

    def test_ip_tag_rule(self):
        self.assertEqual(host(ip_tag=1, wei=1000)[0], ("status", 0x8E))
        self.assertEqual(host(ip_tag=1, chain=0, wei=1000)[0], ("status", tool.OK))
        self.assertEqual(host(ip_tag=0, chain=0)[0], ("status", 0x8E))

    def test_change_patch(self):
        self.assertEqual(host(word0=tool.CHANGE, patch=1)[0], ("status", 0x8E))
        self.assertEqual(host(word0=tool.CHANGE, patch=2, ip_tag=1)[0], ("status", tool.OK))

    def test_floor_order(self):
        self.assertEqual(host(wei=1, disabled=1)[0], ("status", 0xFD))
        self.assertEqual(host(wei=1, tag=0)[0], ("status", 0xFB))
        self.assertEqual(host(wei=999)[0], ("status", 0x130))
        self.assertEqual(host(wei=2000, users=((A, 1999),))[0], ("status", 0xFC))

    def test_zero_zero_skips_gates(self):
        self.assertEqual(host(wei=0, required=0, disabled=1, tag=0)[0], ("status", tool.OK))

    def test_failed_self_delegate_is_swallowed(self):
        for copy in range(3):
            got = host(copy=copy, wei=1000, core=0xFE)
            self.assertEqual(got[0], ("status", tool.OK))
            self.assertEqual(got[1][-1], ("drop", 0xFE))

    def test_tag_width_gap(self):
        got = host(wei=1000, tag=0x101)
        self.assertEqual(got[0], ("status", tool.OK))
        self.assertEqual(events(got, "core"), [])

    def test_profile_failure_is_copied(self):
        self.assertEqual(host(profile=0x121, wei=1000)[0], ("status", 0x121, tool.payload(0x121)))

    def test_change_never_delegates(self):
        self.assertEqual(events(host(word0=tool.CHANGE, wei=5000), "core"), [])


class Event(unittest.TestCase):
    def test_only_copy_c(self):
        self.assertEqual(events(token(copy=0), "sink"), [])
        self.assertEqual(events(token(copy=1), "sink"), [])
        self.assertEqual(len(events(token(copy=2), "sink")), 1)

    def test_amount_and_flag(self):
        row = events(token(copy=2, wei=150000000, mode=1), "sink")[0]
        self.assertEqual((row[2], row[5]), (tool.to_bits(1.5), 1))

    def test_off_word(self):
        self.assertEqual(events(token(copy=2, sink_off=True), "clock"), [])

    def test_no_event_on_core_failure(self):
        self.assertEqual(events(token(copy=2, core=0xFE), "sink"), [])

    def test_token_bound(self):
        self.assertEqual(token(copy=2, token=200, count=200)[0], ("panic", "unwrap"))

    def test_register_event_in_copy_c(self):
        self.assertEqual(len(events(host(copy=2, wei=1000), "sink")), 1)
        self.assertEqual(len(events(host(copy=0, wei=1000), "sink")), 0)


class Stamp(unittest.TestCase):
    def stamp(self, **fields):
        base = dict(kind="stamp", user=A, users=((A, 77),), lock=(0x40000100, 11, 22))
        base.update(fields)
        return run(**base)

    def test_seconds(self):
        for chain, seconds in ((0, tool.YEAR), (1, tool.SHORT), (2, tool.SHORT), (3, tool.YEAR)):
            self.assertEqual(events(self.stamp(chain=chain), "add_seconds")[0][1], tool.to_bits(seconds))

    def test_flag_clear(self):
        self.assertEqual(self.stamp(flag=0)[0], ("stamp", None, None))

    def test_existing_and_new_row(self):
        self.assertEqual(self.stamp()[0], ("stamp", True, (0x40000100, 11, 22)))
        self.assertEqual(self.stamp(users=())[0], ("stamp", False, (0x40000100, 11, 22)))


class Controls(unittest.TestCase):
    def test_flipped_condition_is_seen(self):
        data = bytes(IMAGE.blob[IMAGE.offset(0x1E5FA9B):IMAGE.offset(0x1E5FA9B) + 2])
        self.assertTrue(changed({0x1E5FA9B: data[0] ^ 1}, kind="token"))

    def test_wrong_rule_is_seen(self):
        case = tool.Case("t", user=A, validator=A, mode=1, states=((A, OLD),), lock=(1, 0, 0))
        got = HARNESS.run(case)
        wrong = tool.Case("t", user=A, validator=A, mode=1, states=((A, OLD),), lock=(0x7FFFFFFF, 0, 0))
        self.assertNotEqual(got, tool.spec_run(wrong))

    def test_wrong_key_length_stub(self):
        with self.assertRaises(tool.EvidenceError):
            tool.Case("t", nothing=1)

    def spoiled(self, va):
        other = copy.copy(IMAGE)
        at = IMAGE.offset(va)
        other.blob = IMAGE.blob[:at] + bytes([IMAGE.blob[at] ^ 1]) + IMAGE.blob[at + 1:]
        return other

    def test_changed_year_is_seen(self):
        with self.assertRaises(tool.EvidenceError):
            tool.constant_rows(self.spoiled(0x20A4D0))

    def test_changed_immediate_is_seen(self):
        with self.assertRaises(tool.EvidenceError):
            tool.constant_rows(self.spoiled(0x2769009))

    def test_changed_list_byte_is_seen(self):
        with self.assertRaises(tool.EvidenceError):
            tool.list_rows(self.spoiled(0x58EF27))

    def test_tree_key_is_checked(self):
        patch = {0x27581E9 + 1: 0x13}
        self.assertTrue(changed(patch, user=A, validator=A, mode=1, states=((A, OLD),)))


class Rendered(unittest.TestCase):
    def test_tables_equal_the_folder(self):
        files = tool.render(RESULT)
        for name, text in files.items():
            if name in ("evidence.json", "outcomes.tsv"):
                continue
            self.assertEqual((FOLDER / name).read_text(encoding="ascii"), text, name)

    def test_manifest(self):
        for line in (FOLDER / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((FOLDER / name).read_bytes()).hexdigest(), digest)

    def test_no_absolute_paths(self):
        for path in FOLDER.iterdir():
            text = path.read_text(encoding="utf-8")
            for word in ("\x2ftmp", "\x2fhome", "\x2fsrv", "\x2fmnt"):
                self.assertNotIn(word, text, path.name)

    def test_summary_counts(self):
        data = json.loads((FOLDER / "evidence.json").read_text())
        self.assertEqual(data["sha256"], tool.SHA256)
        self.assertEqual(data["named_cases"], len(RESULT["cases"]))
        self.assertEqual(len(data["functions"]), len(tool.TARGETS))


if __name__ == "__main__":
    unittest.main()
