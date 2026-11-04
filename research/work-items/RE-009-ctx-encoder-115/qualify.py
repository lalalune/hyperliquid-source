"""Qualify static calendar, wire anchors and formatting data; no target execution."""
from pathlib import Path
import argparse,hashlib,json
SHA="a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
def qualify(contexts,witness):
 digest=contexts["targetSha256"]
 assert digest==SHA
 frames={r["start"]:r for r in contexts["records"]}
 rows={r["va"]:r for f in frames.values() for r in f["instructions"]}
 anchors={
 "0x4d9305e":"ba0d000000","0x4d93094":"ba0d000000",
 "0x1628bd3":"41c1fd0d","0x1628bdf":"81e3ff030000","0x1628be5":"81fbdd020000",
 "0x162a773":"bb89888888","0x162a7a1":"41bec5b3a291",
 "0x162a8dd":"4169cf3961c268","0x162a8e7":"81f9c6100000",
 "0x162a8ef":"4169cfd578e926","0x162a8f9":"81f937894100",
 "0x57d00be":"4881fa00010000","0x57d0109":"4881fa00000100",
 "0x57d0139":"48c1e820","0x57d053a":"c60401cd",
 "0x57d077a":"c60401ce","0x57d090b":"c60401cf"}
 for va,raw in anchors.items(): assert rows[va]["bytes"]==raw,(va,rows[va])
 key_sites={"0x4d930b4":"hardfork_height","0x4e0bdd9":"hardfork","0x4e0be4e":"version","0x4e0be87":"round","0x4d9311c":"height","0x4d93160":"tx_index","0x4d931fa":"round","0x4d9323c":"time","0x4d93264":"prev_time","0x4d9328c":"next_oid","0x4d932b4":"next_lid","0x4d932dc":"next_twap_id","0x4d93318":"use_system_nonce","0x4d9333c":"mac"}
 for va,key in key_sites.items():
  assert bytes.fromhex(rows[va]["ripReferences"][0]["raw32"]).startswith(key.encode()),(va,key)
 for frame in frames.values():
  raw=bytes.fromhex("".join(x["bytes"] for x in frame["instructions"]))
  assert len(raw)==frame["size"] and hashlib.sha256(raw).hexdigest()==frame["sha256"]
 table=bytes.fromhex(next(x["rawHex"] for x in contexts["data"] if x["label"]=="ordinal-month-delta"))
 off=int(next(x["fileOffset"] for x in contexts["data"] if x["label"]=="ordinal-month-delta"),16)
 digits=bytes.fromhex(next(x["rawHex"] for x in contexts["data"] if x["label"]=="decimal-digit-pairs"))
 assert digits=="".join(f"{i:02}" for i in range(100)).encode()
 expected=bytearray(733);logical=[]
 for common in (0,1):
  lengths=[31,28+(not common),31,30,31,30,31,31,30,31,30,31];ordinal=0
  for month,length in enumerate(lengths,1):
   for day in range(1,length+1):
    ordinal+=1;index=2*ordinal+common;md=(month<<6)|(day<<1)|common
    expected[index]=md-index
    logical.append((index,month,day,ordinal,common))
 assert bytes(expected)==table
 assert len(logical)==731 and len({x[0] for x in logical})==731
 mut=bytearray(table);mut[120]^=1
 assert mut!=expected
 # Sufficient all-n proof for floor(n*m/2**s)==floor(n/d) on 0<=n<=N:
 # n=q*d+r; m*d=2**s+e; 0<=q*e+r*m<=qmax*e+(d-1)*m<2**s.
 division=[]
 for label,d,m,s,N in [
  ("seconds_to_minutes",60,0x88888889,37,86399),
  ("seconds_to_hours",3600,0x91a2b3c5,43,86399),
  ("minutes_to_hours",60,0x8888889,33,1439),
  ("reduced_year_to_century",25,0x147b,17,2499),
  ("decimal_tens",10,205,11,99),
  ("milliseconds",1000000,0x431bde83,50,999999999),
  ("microseconds",1000,0x10624dd3,38,999999999),
  ("decimal_four_digit_chunks",10000,0xd1b71759,45,(1<<32)-1),
  ("decimal_pair_hundreds",100,0x147b,19,9999)]:
  e=m*d-(1<<s);bound=(N//d)*e+(d-1)*m
  assert 0<=e and bound<(1<<s),(label,e,bound,1<<s)
  division.append(dict(label=label,denominator=d,multiplier=hex(m),shift=s,maxInput=N,error=e,sufficientUpperBound=bound,powerOfTwo=1<<s,proved=True))
 divisibility=[]
 for d,k,inv,threshold in [(1000000,6,0x68c26139,0x10c6),(1000,3,0x26e978d5,0x418937)]:
  odd=d>>k;assert d==odd*(1<<k) and odd%2
  assert (odd*inv)%(1<<32)==1 and threshold==((1<<32)-1)//d
  assert threshold<(1<<(32-k)) and d*threshold<(1<<32)
  divisibility.append(dict(denominator=d,oddPart=odd,inverse=hex(inv),rotation=k,threshold=hex(threshold),proved=True))
 for year in range(10000):
  h=((year>>2)*0x147b)>>17
  assert h==year//100 and ((h*205)&65535)>>11==h//10
  assert (((year-h*100)*205)&65535)>>11==(year%100)//10
 w=witness
 assert w["allControlsPassed"] and len(w["cases"])==7
 result={"targetSha256":digest,"anchors":anchors,"dateLut":{"va":"0x46bfcb","fileOffset":hex(off),"size":733,"sha256":hashlib.sha256(table).hexdigest(),"rawHex":table.hex(),"calendarCellsCompared":731,"paddingCellsCompared":2,"allEqual":True,"singleCellMutationRejected":True,"interpretation":"index=2*ordinal+commonYearBit; zero padding at0/1; ordinal366 only fits leap bit0. Gregorian table independently regenerated, not copied as implementation data."},"divisionProofs":division,"divisibilityProofs":divisibility,"proofText":["For division n=q*d+r, multiplier*d=2**shift+e. The saved upper bound on q*e+r*multiplier is strictly less than2**shift, so the quotient is exact throughout the stated domain.","For divisibility d=odd*2**k and odd*inverse=1 mod2**32. Rotate-right(n*inverse mod2**32,k)<=floor((2**32-1)/d) iff n=d*t: on the bounded t interval rotation-left does not wrap, nor does d*t. This is an integer bijection argument, not execution or emulation of captured instructions."],"yearDigitInputsExhaustivelyCompared":10000,"decimalDigitPairsCompared":100,"formatDescriptorControls":7,"capturedCodeExecuted":False,"capturedCodeEmulated":False,"qualificationOnly":True,"limits":["Success wire semantics on canonical mode/Option/bool and the declared raw timestamp profile; original allocator, panic/unwind and compiler ABI equivalence are not proved.","Date source path proves a chrono path attribution only, not vendor revision or unmodified upstream identity.","No progress gate or compiled-code byte-equivalence credit."]}
 return result

if __name__=="__main__":
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument("--input-dir",type=Path,required=True)
 parser.add_argument("--out",type=Path,required=True)
 args=parser.parse_args()
 d=json.loads((args.input_dir/"contexts.json").read_text(encoding="utf-8"))
 w=json.loads((args.input_dir/"format-descriptor-witness.json").read_text(encoding="utf-8"))
 args.out.write_text(json.dumps(qualify(d,w),indent=2)+"\n",encoding="utf-8",newline="\n")
 print("qualified29 FDE contexts,731calendar cells+2padding,100decimal pairs,9quotient and2divisibility proofs")
