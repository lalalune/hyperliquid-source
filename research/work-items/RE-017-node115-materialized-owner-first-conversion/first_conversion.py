"""Use observed prepared owners while keeping the replay wire unchanged."""

import hashlib
from pathlib import Path
import subprocess


def require(condition, message):
    if not condition:
        raise ValueError(message)


def artifact(folder, entry):
    require(type(entry) is dict and set(entry) == {"path", "sha256"}, "wrong artifact declaration")
    path = (folder / entry["path"]).resolve()
    require(hashlib.sha256(path.read_bytes()).hexdigest() == entry["sha256"],
            f"wrong SHA-256 for {path.name}")
    return path


def run(manifest, digest, scratch, prefilter_ops, lookup, lookup_ops):
    attachment, _, convert, wire_case, kit, *cursor_ops = prefilter_ops
    pinned_json = kit["begin"].pinned_json
    data = pinned_json(manifest, digest)
    roles = wire_case.ROLES - {"wire"}
    controls = {"height", "restored_round", "ordered_pair"}
    require(set(data) == controls | roles | {"records", "successful_rows"}, "wrong replay fixture roles")
    require(isinstance(data["records"], list) and data["records"], "empty fixture sequence")

    scoped = {key: data[key] for key in controls}
    for role in roles:
        scoped[role] = {**data[role], "path": str(artifact(manifest.parent, data[role]))}
    prepared, traces = [], []
    for index, row in enumerate(data["records"]):
        require(type(row) is dict and set(row) in ({"wire"}, {"wire", "materialization"}),
                f"wrong source declaration at row {index}")
        wire = artifact(manifest.parent, row["wire"])
        if "materialization" in row:
            case = artifact(manifest.parent, row["materialization"])
            selected = lookup(case, row["materialization"]["sha256"], scratch,
                              scratch / f"owner-bodies-{index}", *lookup_ops)
            custody = selected["body_custody"]
            require(custody is not None, f"unresolved attachment owner at row {index}")
            require(custody["source_wire_sha256"] == row["wire"]["sha256"],
                    f"materialized owner belongs to another wire at row {index}")
            keys = [entry["content_key"] for entry in custody["derived_rows"]]
            traces.append({"source": selected["store_kind"], "body_custody": custody, "keys": keys})
        else:
            keys = subprocess.check_output([attachment.resolve()], input=wire.read_bytes()).decode("ascii").splitlines()
            traces.append({"source": "wire", "keys": keys})
        prepared.append({"path": str(wire), "sha256": row["wire"]["sha256"], "prepared_count": len(keys)})

    scoped["records"] = prepared
    sequence = wire_case.save_json(scratch, "materialized-owner-sequence.json", scoped)
    replay = convert(scratch / sequence["path"], sequence["sha256"], scratch, wire_case, kit, *cursor_ops)
    index = replay["cursor"][-1]["index"]
    selected = traces[index]
    keys = selected["keys"]
    success = data["successful_rows"]
    require(type(success) is list and all(type(i) is int and 0 <= i < len(keys) for i in success),
            "success position lies outside selected prepared owner")
    require(all(left < right for left, right in zip(success, success[1:])),
            "success positions must retain prepared-owner order")
    archive = pinned_json(Path(scoped["archive"]["path"]), scoped["archive"]["sha256"])
    require(archive["height"] == replay["selected_wire_header"]["height"], "wrong archive height")
    rows = archive["abci_block"]["signed_action_bundles"]
    require(type(rows) is list and all(type(row) is list and len(row) == 2 for row in rows),
            "wrong archive bundle rows")
    expected, observed = [keys[i] for i in success], [row[0] for row in rows]
    return {"prepared_owners": traces, "before_filter": len(keys), "successful_rows": success,
            "expected_archive_keys": expected, "archive_keys": observed, "archive_matches": expected == observed,
            **replay}
