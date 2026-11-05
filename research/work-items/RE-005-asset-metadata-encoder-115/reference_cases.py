from pathlib import Path
import argparse,datetime,hashlib,itertools,json,struct
def fee(bits):
 sign=bits>>63;exponent=(bits>>52)&2047;mantissa=bits&((1<<52)-1)
 if exponent==2047:
  return "NaN" if mantissa else ("-" if sign else "")+"inf"
 if exponent:mantissa|=1<<52;power=exponent-1023-52
 else:power=-1074
 numerator=mantissa*10**10;denominator=1
 if power>=0:numerator<<=power
 else:denominator<<=-power
 q,remainder=divmod(numerator,denominator)
 if remainder*2>denominator or remainder*2==denominator and q%2:q+=1
 whole,fraction=divmod(q,10**10)
 value=("-" if sign else "")+str(whole)+"."+str(fraction).zfill(10)
 while value.endswith("0") and not value.endswith(".0"):value=value[:-1]
 return "0.0" if value=="-0.0" else value
def timestamp(t):
 date=t["packed_date"];index=(date>>3)&1023
 assert date!=0 and index<733 and 0<=t["seconds"]<86400 and 0<=t["nanos"]<2_000_000_000
 ordinal,common=divmod(index,2);year=date>>13
 if ordinal:
  d=datetime.date(2001 if common else 2000,1,1)+datetime.timedelta(days=ordinal-1);month,day=d.month,d.day
 else:month,day=0,0
 yt=str(year).zfill(4) if 0<=year<10000 else ("+" if year>=0 else "-")+str(abs(year)).zfill(4)
 hour,rem=divmod(t["seconds"],3600);minute,second=divmod(rem,60)
 carry,fraction=divmod(t["nanos"],1_000_000_000);second+=carry
 suffix=""
 if fraction:
  digits=3 if fraction%1_000_000==0 else 6 if fraction%1000==0 else 9
  divisor={3:1_000_000,6:1000,9:1}[digits];suffix="."+str(fraction//divisor).zfill(digits)
 return f"{yt}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}"+suffix
def encode(m):
 pairs=[("szDecimals",m["sz_decimals"]),("name",m["name"]),("maxLeverage",m["max_leverage"]),("marginTableId",m["margin_table_id"])]
 if m["only_isolated"]:pairs.append(("onlyIsolated",True))
 if m["is_delisted"]:pairs.append(("isDelisted",True))
 if m["margin_mode"]!=0:pairs.append(("marginMode",["normal","noCross","strictIsolated"][m["margin_mode"]]))
 if m["growth_mode"]!=1:pairs.append(("growthMode",["enabled","disabled","blocked"][m["growth_mode"]]))
 if m["last_fee_time"] is not None:pairs.append(("lastFeeScaleChangeTime",timestamp(m["last_fee_time"])))
 if m["fee_bits"] is not None:pairs.append(("deployerFeeScale",fee(int(m["fee_bits"],16))))
 return json.dumps(dict(pairs),ensure_ascii=False,separators=(",",":"))
def date(year,ordinal,common,seconds=0,nanos=0):
 return {"packed_date":(year<<13)|(ordinal<<4)|(common<<3)|1,"seconds":seconds,"nanos":nanos}
base={"sz_decimals":6,"name":"XYZ","max_leverage":50,"margin_table_id":56,"only_isolated":False,"is_delisted":False,"margin_mode":0,"growth_mode":1,"last_fee_time":None,"fee_bits":None}
cases=[]
def add(case_id,**changes):
 m=base|changes;expected=encode(m);cases.append({"id":case_id,"input":m,"expectedUtf8Hex":expected.encode().hex(),"expectedJson":expected})
for only,listed,margin,growth,has_date,has_fee in itertools.product(range(2),range(2),range(3),range(3),range(2),range(2)):
 add(f"policy_{only}{listed}_{margin}{growth}_{has_date}{has_fee}",only_isolated=bool(only),is_delisted=bool(listed),margin_mode=margin,growth_mode=growth,last_fee_time=date(2026,309,1,45045,123456000) if has_date else None,fee_bits="3ff0000000000000" if has_fee else None)
bits=[0,1,0x000fffffffffffff,0x0010000000000000,0x3fb999999999999a,0x3fd3333333333333,0x3ff0000000000000,0x4000000000000000,0x7fefffffffffffff,0x7ff0000000000000,0x7ff8000000000000,0x7ff0000000000001]
for value in [1/2048,3/2048,5/2048,1e-10,5e-11]:
 x=struct.unpack("<Q",struct.pack("<d",value))[0];bits.extend([x-1,x,x+1])
for bits_value in sorted(set(bits)):
 for sign in [0,1]:
  b=bits_value|(sign<<63);add(f"fee_{b:016x}",fee_bits=f"{b:016x}")
for j,name in enumerate(["",'a"b\\c/',"".join(chr(x) for x in range(32)),"자산 α","e\u0301","🙂\u2028\u2029",chr(127)+chr(128),"A"*1024]):
 add("name_"+str(j),name=name)
for j,n in enumerate([0,9,10,99,100,255]):
 add("integer_"+str(j),sz_decimals=n,max_leverage=255-n,margin_table_id=[0,1,255,65536,2**31,2**32-1][j])
dates=[date(-1,1,1),date(0,60,0),date(9999,365,1,86399),date(10000,1,0),date(-262144,1,0),date(262143,365,1),date(2024,60,0,59,1_000_000_000),date(2024,366,0,86399,1_999_999_999),date(2026,1,1,1,1),date(2026,1,1,1,1000),date(2026,1,1,1,1_000_000)]
for j,t in enumerate(dates):add("timestamp_"+str(j),last_fee_time=t)
p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);args=p.parse_args()
reference=json.loads((Path(__file__).resolve().parent/"frozen-cases.json").read_text(encoding="utf-8"))
assert reference["cases"]==cases,"independent expectations differ"
args.output.write_text(json.dumps(reference,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps({"cases":len(cases),"equal":True,"sha256":hashlib.sha256(args.output.read_bytes()).hexdigest()}))
