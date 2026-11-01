"""Identity and downstream static controls; no captured execution."""
import json
import struct
import oracle


def check():
    original = oracle.prior.TARGET.read_bytes()
    facts = oracle.admit()
    frozen = json.loads((oracle.PACKET / "frozen/ORACLE-FREEZE.json").read_text())
    oracle.require(facts == frozen["static_facts"], "Frozen static facts changed")
    secs, offset = oracle.mapping(original)
    eh = next(s for s in secs if s["name"] == ".eh_frame")["address"]
    relocation = next(s for s in secs if s["name"] == ".rela.dyn")["address"]
    cases = {
        "first_load_offset": (0x5632d93, None),
        "first_swap": (0x5632d94, None),
        "first_store": (0x5632d97, None),
        "second_load_offset": (0x5632d9d, None),
        "second_store_offset": (0x5632da4, None),
        "third_load_offset": (0x5632da8, None),
        "third_store_offset": (0x5632daf, None),
        "last_load": (0x5632db0, None),
        "last_swap": (0x5632db3, None),
        "last_store_offset": (0x5632db9, None),
        "return": (0x5632dba, None),
        "padding": (0x5632dbb, None),
        "preceding_gap": (0x5632d8f, None),
        "fde_extent": (eh + 0x2d81c8 + 12, None),
        "cie": (eh + 17, None),
        "unexpected_naming_relocation": (relocation + 16, struct.pack("<q", oracle.prior.START)),
    }
    for index, site in enumerate(oracle.prior.CALLERS):
        cases[f"caller_{index + 1}_edge"] = site + 1, None
    controls = {}
    for label, (address, replacement) in cases.items():
        changed = bytearray(original)
        if replacement is None:
            changed[offset(address, 1)] ^= 1
        else:
            begin = offset(address, len(replacement))
            changed[begin:begin + len(replacement)] = replacement
        try:
            oracle.structure(changed)
        except ValueError as error:
            controls[label] = {"va": hex(address), "rejected": str(error)}
        else:
            raise ValueError(f"Structural corruption accepted: {label}")
    return {"target_sha256": oracle.prior.SHA256, "leaf_instructions": len(facts["leaf"]),
            "caller_instructions": [len(rows) for rows in facts["callers"]],
            "structural_controls": controls, "captured_execution": False}


if __name__ == "__main__":
    print(json.dumps(check(), indent=2))
