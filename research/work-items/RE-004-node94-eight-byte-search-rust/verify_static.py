"""Full identity and downstream structural corruptions, with no execution."""
import hashlib
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
    reloc = next(s for s in secs if s["name"] == ".rela.dyn")["address"]
    cases = {
        "limit_equality_branch": (0x52ca98c, None),
        "span_count_width": (0x52ca984, None),
        "unsigned_entry_comparison": (0x52ca9ad, None),
        "midpoint_scale": (0x52ca9a9, None),
        "right_step": (0x52ca9b5, None),
        "final_index_shift": (0x52ca9c5, None),
        "last_return": (0x52ca9e2, None),
        "padding": (0x52ca9e3, None),
        "fde_extent": (eh + 0x2ac1ec + 12, None),
        "cie_encoding": (eh + 17, None),
        "caller_edge": (0x52cab18, None),
        "caller_descriptor": (0x52cab0b, None),
        "unexpected_naming_relocation": (reloc + 16, struct.pack("<q", oracle.prior.START)),
    }
    controls = {}
    for label, (address, replacement) in cases.items():
        changed = bytearray(original)
        if replacement is None:
            changed[offset(address, 1)] ^= 1
        else:
            begin = offset(address, len(replacement))
            changed[begin:begin + len(replacement)] = replacement
        try:
            oracle.structure(changed)  # Skip only whole-file identity.
        except ValueError as error:
            controls[label] = {"va": hex(address), "rejected": str(error)}
        else:
            raise ValueError(f"Structural corruption accepted: {label}")
    changed = bytearray(original)
    changed[-1] ^= 1
    oracle.require(hashlib.sha256(changed).hexdigest() != oracle.prior.SHA256, "Identity control failed")
    return {"target_sha256": oracle.prior.SHA256, "leaf_instructions": len(facts["leaf"]),
            "caller_instructions": len(facts["caller"]), "structural_controls": controls,
            "identity_digest_changed": True, "captured_execution": False}


if __name__ == "__main__":
    print(json.dumps(check(), indent=2))
