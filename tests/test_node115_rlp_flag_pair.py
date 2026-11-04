"""Physical Node115 evidence controls; never runs captured code."""
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
import node115_rlp_flag_pair as evidence

class RlpFlagEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(ROOT/"artifacts/node/115/hl-node").read_bytes()
    def test_original_complete_evidence(self):
        result=evidence.verify(self.data)
        self.assertEqual(result["rootAndScalarBytes"],1387)
        self.assertEqual(result["callerContextBytes"],4592)
        self.assertEqual(result["functions"],6)
        self.assertFalse(result["capturedCodeExecuted"])
    def test_capstone_row_corruptions(self):
        for mode in ["missing","duplicate","address","byte","mnemonic","zero"]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as td:
                packet=Path(td)/"packet";shutil.copytree(evidence.PACKET,packet)
                path=packet/"flag-pair.capstone.json"
                rows=json.loads(path.read_text())
                if mode=="missing":rows.pop()
                elif mode=="duplicate":rows.insert(1,dict(rows[0]))
                elif mode=="address":rows[0]["address"]="0x298f161"
                elif mode=="byte":rows[0]["bytes"]="90"
                elif mode=="mnemonic":rows[0]["mnemonic"]="ret"
                else:rows[0]["bytes"]=""
                path.write_text(json.dumps(rows))
                with self.assertRaises(ValueError):evidence.verify(self.data,packet)
    def test_gnu_partition_corruptions(self):
        for mode in ["truncate","duplicate"]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as td:
                packet=Path(td)/"packet";shutil.copytree(evidence.PACKET,packet)
                path=packet/"word256.objdump"
                lines=path.read_text().splitlines()
                if mode=="truncate":lines=lines[:len(lines)//2]
                else:
                    row=next(line for line in lines if "\t" in line and ":" in line)
                    lines.append(row)
                path.write_text("\n".join(lines)+"\n")
                with self.assertRaises(ValueError):evidence.verify(self.data,packet)
    def test_identity_and_recorded_closure(self):
        with self.assertRaises(ValueError):evidence.verify(self.data[:-1])
        for field,value in [
            ("targetSha256","0"*64),("relocations",{}),("directCalls",[]),
            ("sourceBase","0"*40),("normalizationMasks",["anything"]),
            ("capturedCodeExecuted",True)]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as td:
                packet=Path(td)/"packet";shutil.copytree(evidence.PACKET,packet)
                path=packet/"records.json";record=json.loads(path.read_text())
                record[field]=value;path.write_text(json.dumps(record))
                with self.assertRaises(ValueError):evidence.verify(self.data,packet)
    def test_frozen_prediction_binding(self):
        import hashlib
        path=evidence.PACKET/"frozen-predictions.json"
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),
                         "e0f3bdbb8f2a29504a210734861804cff7b9f1abdaa81ae978161e9adad87073")
        cases=json.loads(path.read_text())["cases"]
        expected=[]
        for c in cases:
            value=c.get("value")
            expected.append("\t".join([
                c["name"],c["input"],str(c.get("error","-")),str(c["consumed"]),
                str(value["flag"]).lower() if value else "-",
                ",".join(value["first"]) if value else "-",
                ",".join(value["second"]) if value else "-"]))
        actual=[s for s in (evidence.PACKET/"predictions.tsv").read_text().splitlines()
                if s and not s.startswith("#")]
        self.assertEqual(actual,expected)
        self.assertEqual(len(cases),20)
if __name__=="__main__":unittest.main()
