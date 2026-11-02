"""Check bound lookup data against a decimal/ASCII specification, without CPU evaluation."""
from pathlib import Path
import json,hashlib,itertools,datetime
b=Path(__file__).resolve().parent
from native_view import SUMMARY,data
import struct
src=b/'observed/summary.json'
q={'targetSha256':SUMMARY['targetSha256'],'tables':[]}
for slot,va in [(0x7e7a48,0xbbe10),(0x7e7a50,0xbbc10)]:
    row=data(va);q['tables'].append(dict(row,slot=hex(slot),words=list(struct.unpack('<256h',bytes.fromhex(row['bytes'])))))
by_slot={t['slot']:t for t in q['tables']}
digits={ord(c):int(c,16) for c in '0123456789abcdefABCDEF'}
for slot,shift in [('0x7e7a48',4),('0x7e7a50',0)]:
    table=by_slot[slot]
    expected=[digits[v]<<shift if v in digits else -1 for v in range(256)]
    if table['words']!=expected:raise ValueError('Whole native table differs from independent ASCII specification')
    if hashlib.sha256(bytes.fromhex(table['bytes'])).hexdigest()!=table['sha256']:raise ValueError('Table digest mismatch')
# Pure abstract arithmetic consistency, not native instruction evaluation.
# The manual proof must separately bind these nibble positions to the original code.
h=hashlib.sha256();count=0
for byte_tuple in itertools.product(sorted(digits),repeat=4):
    text=bytes(byte_tuple)
    expected=int(text.decode('ascii'),16)
    positional=sum(digits[v]<<(12-4*i) for i,v in enumerate(byte_tuple))
    if positional!=expected:raise ValueError('Independent positional formula disagrees')
    h.update(text+b'\t'+str(expected).encode()+b'\n');count+=1
result={
 'state':'static-hex-data-and-abstract-arithmetic-intake-unqualified',

 'targetSha256':q['targetSha256'],'sourceSha256':hashlib.sha256(src.read_bytes()).hexdigest(),
 'tableWordChecks':512,'validInputBytes':22,'nonHexByteValues':234,
 'abstractMixedCaseFourDigitCases':count,'abstractCorpusSha256':h.hexdigest(),
 'nativeRelationDraft':'With four available bytes and stable valid storage, the lookup/sign-propagation corridor computes a tag0 u16 for four ASCII hex digits and routes every other four-byte tuple to its error-constructor call. Error-constructor output tag and payload remain unqualified.',
 'limits':['Native instruction semantics are justified only by an outstanding addressed manual proof; this program is not a CPU evaluator or target comparator.',
   'Abstract case digest is not captured runtime evidence or a complete JSON/Unicode corpus. No implementation or publication has been created.'],
 'capturedExecution':False,'instructionEvaluation':False,'semanticQualification':False,
}
dest=Path(__import__('sys').argv[1])
if dest.exists():raise ValueError('Preserve previous audit')
dest.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
print(json.dumps({k:result[k] for k in ['tableWordChecks','validInputBytes','abstractMixedCaseFourDigitCases','abstractCorpusSha256','semanticQualification']}))
