"""Check the captured #115 rotation/record anchors and the source-specific selector."""

from argparse import ArgumentParser
import hashlib
from pathlib import Path
import sys

from extract import MAX_U64, successor

PACKET = Path(__file__).resolve().parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_target(repo):
    sys.path.insert(0, str(repo / "tools"))
    from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

    image = (repo / TARGET).read_bytes()
    require(hashlib.sha256(image).hexdigest() == TARGET_SHA256, "wrong #115 image")
    sections = {section["name"]: section for section in parse_sections(image)}

    def read(name, va, length):
        entry = sections[name]
        relative = va - entry["va"]
        require(0 <= relative <= relative + length <= entry["size"], "out-of-section anchor")
        return image[entry["offset"] + relative:entry["offset"] + relative + length]

    eh = sections[".eh_frame"]
    _, fdes = walk_eh_frame(read(".eh_frame", eh["va"], eh["size"]), eh["va"])
    ends = {row["entry"]: row["end"] for row in fdes}
    anchors = {
        0x595A6B0: {
            0x595A6D9: "4883fe01",
            0x595A6DD: "4883d6ff",
            0x595A6F5: "4c69f210270000",
            0x595A715: "4c89742458",
            0x595A775: "488d442458",
        },
        0x50E2F80: {
            0x50E307B: "c604030a",
        },
    }
    for start, witnesses in anchors.items():
        for address, encoding in witnesses.items():
            raw = bytes.fromhex(encoding)
            require(start <= address < address + len(raw) <= ends[start], "wrong FDE anchor")
            require(read(".text", address, len(raw)) == raw, f"changed instruction {address:#x}")
            print(f"FDE={start:#x} VA={address:#x} instruction={raw.hex()}")
    print(f"Verified #115 SHA-256 {TARGET_SHA256}; native rotation stem and line framing")


def verify_selector():
    first = b'{"abci_block":{"round":7,"parent_round":4,"signed_action_bundles":[]},"resps":null}\n'
    second = b'{"height":10002,"abci_block":{"round":12,"parent_round":7,"signed_action_bundles":[[]]},"resps":[]}\n'
    blank = b"\n"
    chunk = [first, second]

    def digest(lines):
        return hashlib.sha256(b"".join(lines)).hexdigest()

    require(successor(chunk, 10000, 10000, digest(chunk)) == first, "first row lost")
    require(successor(chunk, 10000, 10001, digest(chunk)) == second, "second row lost")
    for label, lines, start, height, checksum, expected in (
        ("wrong shard pin", chunk, 10000, 10000, "0" * 64, "SHA-256 mismatch"),
        ("wrong explicit height", chunk, 10001, 10001, digest(chunk), "explicit height conflicts"),
        ("duplicate height", [second.replace(b'"height":', b'"height":10002,"height":')],
         10001, 10001, digest([second]), "duplicate JSON key"),
        ("truncated line", [first[:-1]], 10000, 10000, digest([first[:-1]]), "row boundary"),
        ("blank line", [blank, first], 10000, 10000, digest([blank, first]), "Expecting value"),
        ("wrong checkpoint", chunk, 10000, 10002, digest(chunk), "successor is absent"),
        ("coordinate overflow", chunk, MAX_U64, MAX_U64, digest(chunk), "outside the shard"),
    ):
        try:
            successor(lines, start, height, checksum)
        except ValueError as error:
            require(expected in str(error), f"{label}: unexpected result {error}")
        else:
            raise ValueError(f"{label} was accepted")
        print(f"Rejected control: {label}")
    print(f"Selected synthetic record SHA-256 {hashlib.sha256(first).hexdigest()} (original line bytes)")


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=PACKET.parents[2])
    args = parser.parse_args()
    verify_target(args.repo.resolve())
    verify_selector()


if __name__ == "__main__":
    main()
