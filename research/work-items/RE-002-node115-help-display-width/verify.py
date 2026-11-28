#!/usr/bin/env python3
"""Rebuild three public unicode-width versions and compare the #115 linked width policy."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import urllib.request

from capture import HERE, capture, digest, require

PINS = {
    "0.1.12": "68f5e5f3158ecfd4b8ff6fe086db7c8467a2dfdac97fe420f2b7c4aa97af66d6",
    "0.1.13": "0336d538f7abc86d282a4189614dfaa90810dfc2c6f6427eaf88e16311dd225d",
    "0.1.14": "7dd6e30e90baa6f72411720665d41d89b9a3d039dc45b8faea1ddd07f617f6af",
}
REFERENCE = "0.1.13"
EMOJI = {0: 0, 8: 1, 9: 2, 10: 3, 124: 4, 125: 5}
TEXT = {8: 0, 9: 1, 10: 1, 124: 2, 125: 3}
EXAMPLES = {
    "Greek small alpha": "α", "middle dot": "·", "Korean Hangul": "한글", "CRLF": "\r\n",
    "Latin combining acute": "e\u0301", "less-than overlay": "<\u0338",
    "copyright emoji style": "©\ufe0f", "watch text style": "⌚\ufe0e",
    "woman technologist": "👩\u200d💻", "Korean flag": "🇰🇷", "Lisu tone pair": "\ua4f8\ua4fc",
}


def packages(cache, fetch):
    result = {}
    for version, checksum in PINS.items():
        filename = f"unicode-width-{version}.crate"
        archive = cache / filename
        if fetch:
            cache.mkdir(parents=True, exist_ok=True)
            if not archive.is_file() or digest(archive.read_bytes()) != checksum:
                url = "https://static.crates.io/crates/unicode-width/" + filename
                with urllib.request.urlopen(url, timeout=30) as response:
                    data = response.read()
                require(digest(data) == checksum, "registry checksum differs: " + version)
                with tempfile.NamedTemporaryFile(dir=cache, delete=False) as temp:
                    temp.write(data)
                Path(temp.name).replace(archive)
        require(archive.is_file() and digest(archive.read_bytes()) == checksum,
                "missing or changed cached package: " + filename)
        result[version] = archive
    return result


def leaf_bit(table, groups, cp):
    group = groups.get(cp >> 10)
    return group is not None and bool(table[group * 128 + ((cp >> 3) & 127)] & (1 << (cp & 7)))


def expected_stream(tables):
    root, middle, widths = (tables[f"TABLES_{i}"] for i in range(3))
    emoji = tables["EMOJI_PRESENTATION_LEAVES"]
    text = tables["TEXT_PRESENTATION_LEAVES"]
    result = bytearray()
    for cp in range(0x110000):
        if 0xd800 <= cp <= 0xdfff:
            continue
        block = root[cp >> 13]
        leaf = middle[block * 128 + ((cp >> 6) & 127)]
        code = (widths[leaf * 16 + ((cp >> 2) & 15)] >> (2 * (cp & 3))) & 3
        if cp <= 0xa0:
            narrow = cjk = 1  # Single-scalar string path, including ASCII control characters.
        else:
            narrow, cjk = (1, 2) if code == 3 else (code, code)
        text_width = 1 if leaf_bit(text, TEXT, cp) else narrow
        emoji_form = leaf_bit(emoji, EMOJI, cp)
        result.extend((narrow, cjk, text_width, cjk, 2 if emoji_form else narrow, 2 if emoji_form else cjk))
    return bytes(result)


def build_release(version, src, work, rustc):
    library = work / "libunicode_width.rlib"
    # 0.1.14 makes the public CJK method conditional on a default feature.
    flags = ["--cfg", 'feature="cjk"'] if version == "0.1.14" else []
    subprocess.run([rustc, "--crate-name", "unicode_width", "--crate-type", "rlib", "--edition=2021",
                    "-C", "opt-level=3", *flags, src / "src/lib.rs", "-o", library], check=True)
    binary = work / "widths"
    subprocess.run([rustc, "--edition=2021", "-C", "opt-level=3", "--extern", f"unicode_width={library}",
                    HERE / "widths.rs", "-o", binary], check=True)
    stream = subprocess.check_output([binary])
    inputs = "".join(" ".join(format(ord(c), "x") for c in s) + "\n" for s in EXAMPLES.values())
    examples = subprocess.check_output([binary, "--sequences"], input=inputs.encode("ascii"))
    require(len(examples) == len(EXAMPLES) * 2, "wrong example count")
    return stream, {name: list(examples[2 * i:2 * i + 2]) for i, name in enumerate(EXAMPLES)}


def analyze(archives, tmp):
    rustc = subprocess.check_output(["rustup", "which", "--toolchain", "1.95.0", "rustc"], text=True).strip()
    sources = {}
    for version, archive in archives.items():
        with tarfile.open(archive, "r:gz") as tar:
            tar.extractall(tmp, filter="data")
        sources[version] = tmp / f"unicode-width-{version}"
    tables, binding = capture((sources[REFERENCE] / "src/tables.rs").read_text())
    expected = expected_stream(tables)
    require(len(expected) == (0x110000 - 0x800) * 6, "wrong scalar corpus")
    releases = {}
    for version, source in sources.items():
        unicode_version = re.search(
            r"pub const UNICODE_VERSION:[^=]*=\s*\((\d+),\s*(\d+),\s*(\d+)\)",
            (source / "src/tables.rs").read_text())
        require(unicode_version is not None, "missing generated Unicode version: " + version)
        work = tmp / version
        work.mkdir()
        stream, samples = build_release(version, source, work, rustc)
        require(len(stream) == len(expected), "wrong public output length")
        mismatch = [sum(a != b for a, b in zip(stream[i::6], expected[i::6])) for i in range(6)]
        require((not any(mismatch)) == (version == REFERENCE), "width-version control failed: " + version)
        releases[version] = {"crate_sha256": PINS[version], "corpus_sha256": digest(stream),
                             "unicode_version": ".".join(unicode_version.groups()),
                             "different_widths_per_column": mismatch, "examples": samples}
    return {"binding": binding, "scalar_count": len(expected) // 6,
            "linked_table_widths_sha256": digest(expected), "releases": releases}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--fetch", action="store_true", help="only provision the checksum-pinned public archives")
    parser.add_argument("--record", action="store_true")
    args = parser.parse_args()
    archives = packages(args.cache, args.fetch)
    if args.fetch:
        print("Verified three public crate archives.")
        return
    with tempfile.TemporaryDirectory(prefix="unicode-width-") as tmp:
        report = analyze(archives, Path(tmp))
    if args.record:
        print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        require(report == json.loads((HERE / "results.json").read_text()), "recorded results changed")
        print("Verified 19 narrow-width calls, five data tables and six widths per Unicode scalar.")


if __name__ == "__main__":
    main()
