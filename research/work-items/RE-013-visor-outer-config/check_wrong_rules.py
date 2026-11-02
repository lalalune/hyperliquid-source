"""Witnesses against five plausible wrong abstract grammar rules; no native execution."""
from pathlib import Path
import hashlib, importlib.util, json, math, sys
sys.dont_write_bytecode=True
B=Path(__file__).resolve().parent
source=B/'check_language.py'
spec=importlib.util.spec_from_file_location('outer_relation_intake',source)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class StrictDiscarded(m.Relation):
    def string(self, strict_unicode):
        return super().string(True)
class PermissiveKeys(m.Relation):
    def string(self, strict_unicode):
        return super().string(False)
class FiniteNumbers(m.Relation):
    def ignored(self):
        self.whitespace()
        match=m.NUMBER.match(self.s,self.i)
        if match is not None and not math.isfinite(float(match.group())):
            raise m.Invalid('Wrong finite-number restriction')
        return super().ignored()
class ConstantDefault(m.Relation):
    def default_value(self):
        self.calls+=1
        return 21
class WideWhitespace(m.Relation):
    def whitespace(self):
        while self.i<len(self.s) and self.s[self.i].isspace():
            self.i+=1

def result(cls,raw,default):
    p=cls(raw,default)
    try:
        return 0,p.outer(),p.calls
    except m.Invalid:
        return 1,None,p.calls

cases=[
    ('strict-discarded-surrogate',StrictDiscarded,b'{"u":"\\uD800","aws_name":"Ec"}',21,(0,0,0)),
    ('permissive-decoded-outer-key',PermissiveKeys,b'{"\\uD800":0}',21,(1,None,0)),
    ('finite-discarded-number',FiniteNumbers,b'{"u":1e999999,"aws_name":"Ec"}',21,(0,0,0)),
    ('constant-default-code',ConstantDefault,b'{}',78,(0,78,1)),
    ('wide-whitespace',WideWhitespace,'{}\u00a0'.encode(),21,(1,None,1)),
]
rows=[]
for name,cls,raw,default,expected in cases:
    observed=result(m.Relation,raw,default)
    wrong=result(cls,raw,default)
    if observed!=expected or wrong==expected:
        raise ValueError('Witness does not discriminate: '+name)
    rows.append({'rule':name,'inputHex':raw.hex(),'defaultCode':default,'expected':expected,'abstractRelation':observed,'wrongRule':wrong})
out=Path(sys.argv[1])
if out.exists():
    raise ValueError('Preserve earlier witness audit')
receipt={'state':'abstract-wrong-rule-witnesses-intake-unqualified','wrongRules':len(rows),'witnesses':rows,
         'modelSha256':hashlib.sha256(source.read_bytes()).hexdigest(),
         'capturedExecution':False,'instructionEvaluation':False,'nativeSemanticQualification':False,
         'limits':'These witnesses discriminate high-level syntax hypotheses; they do not evaluate original code or close native bindings/helper premises.'}
out.write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n',encoding='utf-8',newline='\n')
print(json.dumps({'wrongRules':len(rows),'nativeSemanticQualification':False}))
