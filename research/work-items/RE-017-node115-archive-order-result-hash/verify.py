"""Check exact static boundaries and selected order result Hash bytes offline."""

from argparse import ArgumentParser
from importlib.util import module_from_spec, spec_from_file_location
import csv
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from order_hash import compare, encode_rows, require

BASE = "2da45cb0a761cff6b478e40421699857d87a94df"
HASH_PACKET = "e9b66e50091a757067e2e64ade1e3682cce5197f"
HASH_PATH = "research/work-items/RE-017-node115-archive-response-hash-compare"
ORDER_PATH = "research/work-items/RE-001-node115-order-status-nested-fields"
TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def source(repo, commit, name):
    return subprocess.check_output(["git", "show", f"{commit}:{name}"], cwd=repo)


def module(path, name):
    spec = spec_from_file_location(name, path)
    result = module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


def prepare(repo, scratch):
    for filename in ("compare.py", "verify.py", "anchors.tsv", "reference.rs"):
        (scratch / filename).write_bytes(source(repo, HASH_PACKET, f"{HASH_PATH}/{filename}"))
    sys.path.insert(0, str(repo / "tools"))
    module(scratch / "verify.py", "existing_response_hash_evidence").verify_native(repo)
    prior = module(scratch / "compare.py", "existing_response_hash_fixture")
    image = (repo / "artifacts/node/115/hl-node").read_bytes()
    require(hashlib.sha256(image).hexdigest() == TARGET, "wrong #115 image")
    records = json.loads(source(repo, BASE, f"{ORDER_PATH}/records.json"))
    require(records["target_sha256"] == TARGET, "wrong prior nested-result evidence")
    for body in records["bodies"]:
        offset = int(body["file_offset"], 16)
        raw = image[offset:offset + body["bytes"]]
        digest = hashlib.sha256(raw).hexdigest()
        require(digest == body["sha256"], f"changed selected body {body['role']}")
        print(body["role"], body["start"], body["end"], digest)
    names = {b"filled", b"resting", b"totalSz", b"avgPx", b"oid", b"cloid"}
    for item in records["literals"]:
        value = bytes.fromhex(item["bytes"])
        if value in names:
            offset = int(item["file_offset"], 16)
            require(image[offset:offset + item["length"]] == value, "wrong named field literal")
            names.remove(value)
            print(item["va"], item["role"], item["bytes"])
    require(not names, "missing selected field literals")
    literals = source(repo, BASE, "research/work-items/RE-017-abci-res-variants-115/literals.tsv")
    states = {"order", "statuses"}
    for item in csv.DictReader(literals.decode().splitlines(), delimiter="\t"):
        label = item["text"]
        if label in states:
            offset, length = int(item["literal_file_offset"], 16), int(item["length"])
            require(image[offset:offset + length] == label.encode("ascii"), "wrong status literal")
            states.remove(label)
            print(item["literal_va"], label, item["bytes"])
    require(not states, "missing selected status literals")
    table = source(repo, BASE, "research/work-items/RE-017-abci-res-variants-115/order-statuses.tsv")
    for item in csv.DictReader(table.decode().splitlines(), delimiter="\t"):
        offset, length = int(item["literal_file_offset"], 16), int(item["length"])
        target = int(item["table_file_offset"], 16)
        raw = image[target:target + 4]
        require(raw.hex() == item["table_bytes"] and image[offset:offset + length].hex() == item["bytes"],
                "wrong tagged order arm")
        print(item["tag"], item["entry_va"], item["text"], raw.hex())
    return prior


def fixtures(repo, scratch, prior):
    cloid = "0x" + "00" * 15 + "01"
    digest = "0x" + "ab" * 32
    states = [
        {"filled": {"oid": 128, "avgPx": "12.5", "cloid": cloid, "totalSz": "0.0"}},
        {"resting": {"oid": 18446744073709551615}},
        "waitingForFill", "waitingForTrigger", {"error": "price"},
    ]
    order = {"user": None, "res": {"status": "ok", "response": {
        "type": "order", "data": {"statuses": states},
    }}}
    default = {"user": None, "res": {"status": "ok", "response": {"type": "default"}}}
    full = {"height": 43, "resps": {"Full": [[digest, [order, default]]]}}
    known = (b"\x91\x92\xd9\x42" + digest.encode("ascii")
             + b"\x92\x82\xa4user\xc0\xa3res\x82\xa6status\xa2ok\xa8response"
             + b"\x82\xa4type\xa5order\xa4data\x81\xa8statuses\x95"
             + b"\x81\xa6filled\x84\xa7totalSz\xa30.0\xa5avgPx\xa412.5"
             + b"\xa3oid\xcc\x80\xa5cloid\xd9\x22" + cloid.encode("ascii")
             + b"\x81\xa7resting\x81\xa3oid\xcf" + b"\xff" * 8
             + b"\xaewaitingForFill\xb1waitingForTrigger\x81\xa5error\xa5price"
             + b"\x82\xa4user\xc0\xa3res\x82\xa6status\xa2ok\xa8response\x81\xa4type\xa7default")
    encoded, count = encode_rows(full["resps"]["Full"], prior)
    require(known == encoded and count == 2, f"wrong named order preimage: {encoded.hex()}")
    (scratch / "utils.rs").write_bytes(source(repo, BASE, "src/l1-shared/src/utils.rs"))
    flags = ["rustc", "--edition", "2021"]
    library = scratch / "libreference_hash.rlib"
    subprocess.run([*flags, "--crate-type", "lib", "--crate-name", "reference_hash",
                    scratch / "utils.rs", "-o", library], check=True)
    compiled = scratch / "rust-keccak"
    subprocess.run([*flags, "--extern", f"reference_hash={library}", scratch / "reference.rs",
                    "-o", compiled], check=True)
    digest = subprocess.check_output([compiled], input=known).decode("ascii").strip()
    archive = {"height": 43, "resps": {"Hash": "0x" + digest}}
    matched = compare(archive, full, prior)
    require(matched.matches, "selected Full did not match independent Rust hash")
    print(f"matched {len(known)} handcrafted bytes and independent Rust Keccak {matched.actual}")

    states[2], states[3] = states[3], states[2]
    require(not compare(archive, full, prior).matches, "waiting status order was discarded")
    states[2], states[3] = states[3], states[2]
    cloidless = states[0]["filled"].pop("cloid")
    require(not compare(archive, full, prior).matches, "optional cloid was discarded")
    states[0]["filled"]["cloid"] = cloidless
    states[0]["filled"]["totalSz"] = 0.0
    try:
        compare(archive, full, prior)
    except ValueError as error:
        require("group 0, position 0: totalSz must be normalized" in str(error), str(error))
        print(f"rejected float input: {error}")
    else:
        raise ValueError("accepted float in native string field")
    full["height"] = 44
    try:
        compare(archive, full, prior)
    except ValueError as error:
        require("same exact height" in str(error), str(error))
        print(f"rejected incompatible Full height: {error}")
    else:
        raise ValueError("compared two heights")
    print("verified five order statuses, omitted optional cloid, fixed field order, and mixed result encoding")


if __name__ == "__main__":
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--full", type=Path)
    args = parser.parse_args()
    if bool(args.archive) != bool(args.full):
        parser.error("--archive and --full must be specified together")
    with TemporaryDirectory() as folder:
        scratch = Path(folder)
        repo = args.repo.resolve()
        prior = prepare(repo, scratch)
        if args.archive:
            def read(path):
                return json.loads(path.read_bytes(), object_pairs_hook=prior.unique_object)
            result = compare(read(args.archive), read(args.full), prior)
            print(json.dumps({**vars(result), "matches": result.matches}))
            raise SystemExit(0 if result.matches else 1)
        fixtures(repo, scratch, prior)
