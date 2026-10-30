#!/usr/bin/env python3
"""Verify the RE-012 packet: manifest, regenerated evidence, and pinned facts."""
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
OUT_SHA256 = "4edf26203f2a9f2ddd307b728d54aba77ac493a158462e40e331e4a494893baa"
SCOPED = {
    "info_server/src/abci_state_info_handler.rs": 17,
    "info_server/src/f_types/position.rs": 1,
    "info_server/src/handle_request.rs": 3,
    "info_server/src/handler.rs": 1,
    "info_server/src/request.rs": 2,
    "info_server/src/router.rs": 1,
    "info_server/src/user_ip.rs": 1,
}


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def check(cond, msg):
    if not cond:
        fail(msg)


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"tools/{name}.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


PACKET_FILES = frozenset({
    "README.md", "independent_verify.py", "info-request-path.json",
    "objdump-excerpts.txt", "verify.py",
})


def main():
    listed = set()
    for line in (HERE / "MANIFEST.sha256").read_text().splitlines():
        digest, name = line.split("  ", 1)
        got = hashlib.sha256((HERE / name).read_bytes()).hexdigest()
        check(got == digest, f"manifest mismatch for {name}")
        listed.add(name)
    # The manifest pins every packet file except itself (README). Comparing
    # it only against the directory is not enough: a file deleted together
    # with its manifest row leaves the two sets equal. So the listed set
    # must also equal the packet's pinned file set, and the directory must
    # not hold unlisted files.
    check(listed == PACKET_FILES, f"manifest file set differs from the pinned packet files: "
          f"missing rows {sorted(PACKET_FILES - listed)}, unexpected rows {sorted(listed - PACKET_FILES)}")
    present = {p.name for p in HERE.iterdir() if p.is_file()} - {"MANIFEST.sha256"}
    check(listed == present, f"manifest file set differs from packet contents: "
          f"unlisted {sorted(present - listed)}, missing {sorted(listed - present)}")
    binary = (ROOT / "artifacts/node/94/hl-node").read_bytes()
    check(hashlib.sha256(binary).hexdigest() == BIN_SHA256, "binary sha256")
    irp = load("info_request_path")
    r = irp.build(binary)
    text = irp.render(r)
    check(hashlib.sha256(text).hexdigest() == OUT_SHA256, "regenerated JSON hash")
    check((HERE / "info-request-path.json").read_bytes() == text, "JSON differs from tool")
    d = json.loads(text)
    check(d["fde_count"] == 121299, "fde_count")
    check(d["first_party_location_count"] == 1186, "first_party_location_count")
    check(d["scoped_location_counts"] == SCOPED, "scoped_location_counts")
    check(sum(SCOPED.values()) == 26, "scoped total")
    check(len(d["functions"]) == 113, "function count")
    check(d["tag_count"] == 56, "tag_count")
    check(len(d["tags"]) == 56, "tags len")
    check(d["hub"]["start"] == "0x24af210", "hub start")
    check(d["hub"]["to_deserializer"] == {
        "kind": "rel32", "site": "0x24aff82", "slot": None, "to": "0x28c7c80",
    }, "hub→deser")
    check(d["deserializer"]["start"] == "0x28c7c80", "deser start")
    check(d["deserializer"]["tag_owner_count"] == 52, "deser tag owners")
    locs = d["hub"]["locations"]
    check(set(locs) == {
        "info_server/src/handle_request.rs",
        "info_server/src/handler.rs",
        "info_server/src/router.rs",
        "info_server/src/user_ip.rs",
    }, "hub location files")
    check(locs["info_server/src/handle_request.rs"] == [30, 49, 120], "handle_request lines")
    markers = {s["marker"] for s in d["side_effects"]}
    check("fileSnapshot" in markers and "outPath" in markers, "write tags")
    tpl = next(s for s in d["side_effects"] if s["kind"] == "template")
    check(tpl["gate_function"] == "0x27e91d0", "snapshot gate")
    check("0x27e91d0" in tpl["functions"], "gate owns template")
    check(any(t["text"] == "meta" for t in d["tags"]), "meta tag")
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
