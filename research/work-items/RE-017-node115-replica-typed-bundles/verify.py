"""Authenticate the selected #115 scalar writers and verify fixture projection offline."""

from argparse import ArgumentParser
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import struct
import sys

from project import U64_MAX, project


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_target(repo):
    sys.path.insert(0, str(repo / "tools"))
    from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

    image = (repo / TARGET).read_bytes()
    require(hashlib.sha256(image).hexdigest() == TARGET_SHA256, "wrong target image")
    sections = {item["name"]: item for item in parse_sections(image)}

    def read(name, va, length):
        entry = sections[name]
        relative = va - entry["va"]
        require(0 <= relative <= relative + length <= entry["size"], "out-of-section anchor")
        return image[entry["offset"] + relative:entry["offset"] + relative + length]

    eh = sections[".eh_frame"]
    _, fdes = walk_eh_frame(read(".eh_frame", eh["va"], eh["size"]), eh["va"])
    ends = {row["entry"]: row["end"] for row in fdes}
    anchors = {
        0x53CAF10: {
            0x53CAF74: "488d3583a255fb", 0x53CAF85: "e8c621caff",
            0x53CAF9A: "488d3568a255fb", 0x53CAFAE: "e82defcaff",
        },
        0x5923350: {
            0x59233CA: "488d35c34c01fb", 0x59233DB: "e870f874ff",
            0x5923426: "488d35734c01fb", 0x5923437: "e8846875ff",
            0x5923453: "488d35294601fb", 0x5923464: "e8776a75ff",
            0x5923480: "e8bb400b00",
        },
        0x506D150: {
            0x506D20D: "be2a000000", 0x506D212: "b914000000", 0x506D21D: "e82ef0daff",
        },
        0x5072C50: {
            0x5072D15: "be2a000000", 0x5072D1A: "b914000000", 0x5072D25: "e82695daff",
        },
        0x5075DB0: {0x5075EC6: "b920000000", 0x5075ED1: "e87a63daff"},
        0x4E1C250: {0x4E1C25D: "4531c0", 0x4E1C260: "ff15a28a6c01"},
        0x2EABB50: {0x2EABB62: "66c7073078", 0x2EABB89: "488d05b0a15afd"},
        0x5079CC0: {
            0x5079D6C: "40f6c501", 0x5079D8A: "c7043074727565",
            0x5079DAF: "c644300465", 0x5079DB4: "c7043066616c73",
        },
        0x5079EE0: {0x5079F8C: "488b3b", 0x5079F92: "e86944d8ff"},
        0x4DFE400: {0x4DFE401: "b814000000", 0x4DFE406: "4881ff10270000", 0x4DFE40D: "0f82aa000000"},
        0x59D7540: {0x59D7548: "488d355b0bf6fa", 0x59D7554: "e947216aff"},
        0x50796A0: {0x5079751: "488b7b08", 0x5079758: "e8530c8e00"},
        0x595A3B0: {0x595A3B1: "b814000000", 0x595A3B6: "4881ff10270000", 0x595A3BD: "0f82aa000000"},
        0x53D6FD0: {0x53D701B: "e8d034cbff", 0x53D7045: "e8a634cbff", 0x53D706E: "e86df8c9ff"},
    }
    spans = {}
    for start, witnesses in anchors.items():
        for address, encoding in witnesses.items():
            raw = bytes.fromhex(encoding)
            require(start <= address < address + len(raw) <= ends[start], "invalid FDE anchor")
            require(read(".text", address, len(raw)) == raw, f"changed instruction {address:#x}")
            spans[address] = raw
            print(f"FDE={start:#x} VA={address:#x} instruction={encoding}")

    def relative_target(address):
        raw = spans[address]
        return address + len(raw) + struct.unpack("<i", raw[-4:])[0]

    for site, field in {
        0x53CAF74: b"broadcaster", 0x53CAF9A: b"broadcaster_nonce",
        0x59233CA: b"vaultAddress", 0x5923426: b"isFrontend",
        0x5923453: b"nonce", 0x59D7548: b"expiresAfter",
        0x2EABB89: b"0123456789abcdef",
    }.items():
        require(read(".rodata", relative_target(site), len(field)) == field, f"changed literal {field!r}")
    for site, target in {
        0x53CAF85: 0x506D150, 0x53CAFAE: 0x5079EE0,
        0x59233DB: 0x5072C50, 0x5923437: 0x5079CC0, 0x5923464: 0x5079EE0,
        0x5923480: 0x59D7540, 0x59D7554: 0x50796A0, 0x5079758: 0x595A3B0,
        0x5079F92: 0x4DFE400, 0x506D21D: 0x4E1C250, 0x5072D25: 0x4E1C250,
        0x5075ED1: 0x4E1C250,
        0x53D701B: 0x508A4F0, 0x53D7045: 0x508A4F0, 0x53D706E: 0x50768E0,
    }.items():
        require(relative_target(site) == target, f"changed edge at {site:#x}")
    rela = sections[".rela.dyn"]
    relocations = {slot: (info, addend) for slot, info, addend in struct.iter_unpack(
        "<QQq", read(".rela.dyn", rela["va"], rela["size"])
    )}
    require(relocations.get(relative_target(0x4E1C260)) == (8, 0x2EABB50), "changed hex writer slot")
    print(f"Verified #115 SHA-256 {TARGET_SHA256}; {len(spans)} scalar and enclosing-format anchors")


def fixture():
    return {"abci_block": {"signed_action_bundles": [
        ["0x" + "00" * 31 + "01", {
            "broadcaster": "0x" + "00" * 19 + "02", "broadcaster_nonce": U64_MAX,
            "signed_actions": [
                {"signature": {"r": "0x0", "s": "0x1", "v": 255},
                 "action": {"type": "fixture", "price": "PRECISION"}, "nonce": 0,
                 "vaultAddress": "0x" + "00" * 19 + "03", "isFrontend": False, "expiresAfter": 0},
                {"signature": {"r": "0x" + "f" * 64, "s": "0xfed", "v": 0},
                 "action": {"type": "fixture2"}, "nonce": U64_MAX},
            ],
        }],
        ["0x" + "00" * 31 + "02", {
            "broadcaster": "0x" + "00" * 20, "broadcaster_nonce": 0, "signed_actions": [],
        }],
    ]}, "resps": None}


def verify_fixture():
    def encode(record):
        return json.dumps(record, separators=(",", ":")).encode().replace(
            b'"PRECISION"', b"0.123456789012345678901234567890"
        ) + b"\n"

    encoded = encode(fixture())
    first, second = project(encoded)
    early, late = first.signed_actions
    require([first.key, second.key] == [bytes(31) + b"\x01", bytes(31) + b"\x02"], "bundle order/key")
    require(first.broadcaster == bytes(19) + b"\x02" and first.broadcaster_nonce == U64_MAX, "broadcaster")
    require(second.signed_actions == () and second.broadcaster_nonce == 0, "empty bundle")
    require(early.action["price"] == Decimal("0.123456789012345678901234567890")
            and late.action == {"type": "fixture2"}, "opaque action values/order")
    require((early.nonce, late.nonce) == (0, U64_MAX), "action nonce endpoints")
    require(early.signature.r == bytes(32) and early.signature.s == bytes(31) + b"\x01"
            and early.signature.v == 255, "zero/narrow limbs")
    require(late.signature.r == b"\xff" * 32 and late.signature.s == bytes(30) + b"\x0f\xed"
            and late.signature.v == 0, "full-width and odd-digit limbs")
    require(early.vault_address == bytes(19) + b"\x03" and early.is_frontend is False
            and early.expires_after == 0, "present false and zero optionals")
    require((late.vault_address, late.is_frontend, late.expires_after) == (None, None, None),
            "optional absence")
    require(project(b'{"abci_block":{"signed_action_bundles":[]}}\n') == (), "empty outer array")
    print(f"Projected ordered synthetic row SHA-256 {hashlib.sha256(encoded).hexdigest()}")

    for label, a, b, expected in (
        ("nonce boolean", b'"nonce":0', b'"nonce":false', "nonce must be an unsigned integer"),
        ("nonce overflow", b'"nonce":0', b'"nonce":18446744073709551616', "nonce must be an unsigned integer"),
        ("padded scalar limb", b'"0x1"', b'"0x01"', "signature.s must be a compact"),
        ("signature byte overflow", b'"v":255', b'"v":256', "signature.v must be an unsigned integer"),
        ("frontend integer", b'"isFrontend":false', b'"isFrontend":0', "isFrontend must be a boolean"),
        ("explicit expiry null", b'"expiresAfter":0', b'"expiresAfter":null', "expiresAfter must be an unsigned"),
        ("short address", b'"0x' + b"00" * 19 + b'03"', b'"0x03"', "vaultAddress must be a fixed 20-byte"),
        ("duplicate nonce", b'"nonce":0', b'"nonce":0,"nonce":0', "duplicate JSON key nonce"),
        ("truncated row", b',"resps":null}', b',"resps":null', "Expecting"),
    ):
        require(a in encoded, f"unusable control {label}")
        try:
            project(encoded.replace(a, b, 1))
        except ValueError as error:
            require(expected in str(error), f"{label}: unexpected error {error}")
        else:
            raise ValueError(f"{label} was accepted")
        print(f"Rejected control: {label}")


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[3])
    args = parser.parse_args()
    verify_target(args.repo.resolve())
    verify_fixture()


if __name__ == "__main__":
    main()
