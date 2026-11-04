# RE-012: node115 curl body-helper path routing and local buffers

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (105,896,032 bytes). Base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. Component: node-runtime/networking support. This partial static packet closes the local control/data flow of helper `0x50de300..0x50de518`, explicitly excluded from the retained curl-options packet. It does not recover a curl subprocess or establish actual filesystem behavior. Full component gates remain false.

The complete unwind-described owner has **536 bytes, 133 contiguous decoded instructions, one FDE**. `evidence.json` retains exact raw body, FDE/CIE bytes, original file offsets, six RELATIVE bindings and the three-byte `rmp` literal. `owner.objdump.txt` is the complete LLVM decode; `owner.frames.txt` independently confirms the PC range using GNU readelf. An unwind extent is not proof of every possible incoming edge, source-level function identity or exception closure. No comparison masks are used. Text paths are normalized to the repository-relative target and only surplus terminal newlines are removed; instructions and frame metadata are unchanged.

## Observed routing

Under ordinary x86-64 calling convention, incoming RSI/RDX are retained as a pointer/length pair in R15/R14; RCX is retained in RBX. Original source types, input validity and caller reachability are not recovered. The retained curl-options packet establishes a call to this address; its broader command builder is context, not new coverage here.

At `0x50de324..345`, length must equal nine, the first eight bytes must equal `/dev/nul`, and byte eight must equal `l`. Only this exact `/dev/null` comparison zeroes EBX and jumps directly to the common RAX=RBX return. This path makes no helper call in this owner. It is not an OS device-resolution or general path-policy theorem.

Otherwise, an empty length sets AL=0; a nonempty input sets AL from whether its first byte is `/`. The pair and numeric tag6 are stored at RSP+0x10/+0x18/+0x20, word `0x0201` at +0x48, and that AL at +0x4a. The descriptor is passed to relocated helper `0x5cab560` with output at RSP+0x60. Its interpretation and memory effects remain opaque.

Only returned byte tag9 enters the suffix scan; returned +0x68/+0x70 supply a second pointer/length pair. Exact length2 and bytes `..` bypass scanning. Otherwise the owner scans backward, comparing bytes to `.`. No dot, or a dot at the first byte, goes to the default buffer path. For a dot with at least one byte before it, the following suffix pointer and suffix length are passed alongside literal `rmp` and length3 to direct helper `0x159fca0`. The owner tests only returned AL. Thus suffix extraction and the three-byte argument are observed; equality semantics, accepted encodings and the helper's full behavior are not proved. The label “rmp-like” is an inference only.

## Buffer and opaque consumer handoff

The default path requests numeric size128 through slot `0x64df480 -> 0x6355830`, checks returned RAX for null, writes four bytes `null` to a nonnull result, and retains pointer/length/capacity-like values R13/RBP/R12 = result/4/128. These names describe local use, not a recovered Vec/String ABI.

A nonzero AL from the suffix helper instead passes numeric arguments `(out,0,1,8,1,1)` to `0x5963650`. If returned output dword is not1, it reads the pointer at output+8, writes byte `0xc0`, and uses local values pointer/1/8. If the dword is1, it builds three words `0x8000000000000000`, `0`, `0x2600000003`, passes the saved original pointer/length storage and this descriptor to `0x50df400`, saves returned RAX and joins the common return. Error/result enum names are unknown.

Both local-buffer routes call slot `0x64e0028 -> 0x15020f0` with original pointer/length. Only a zero RAX invokes slot `0x64e09e8 -> 0x15024a0`, with `(buffer,local_length,original_pointer,original_length,saved_incoming_RCX)`. The first helper's nonzero result or the second helper's result is saved in RBX. The owner then calls `0x64df4a0 -> 0x635de30` with `(buffer,local_capacity,0)` before RAX=RBX return. This is an observed ownership/cleanup-like handoff, not proof of deallocation, successful writing, JSON/MessagePack validity, escaping or I/O side effects. All these helper bodies remain unresolved.

The allocation-null arm calls `0x64df498 -> 0x141e264` with `(1,128)`. Separate tail code saves RAX, calls the cleanup-like slot and invokes `_Unwind_Resume`; the raw decode is retained. Reachability of that cleanup fragment, nonreturn contracts, LSDA actions, exceptions and helper behavior are not closed. The common return statement applies only to paths that reach its normal return.

## Reproduce and limitations

From repository root, with Python3.11 and native tools already installed, choose a new output directory:

```sh
python3.11 -B research/work-items/RE-012-node115-curl-body-helper/collect.py \
  --output work/curl-body-fresh --objdump "$OBJDUMP" --readelf "$READELF"
```

Observed platform: macOS arm64. Observed tools: Python3.11.15, Apple LLVM21.0.0, GNU readelf2.45 (exact banners in `validation.json`). The producer verifies the complete target digest before native tools/output, checks each decoded byte and continuous coverage against the authenticated input, independently reads the native FDE range, and validates six actual relocation records. Native tools only read the capture. Capture file changes between reads are not atomically prevented; decoded byte comparison detects changed owner bytes, not arbitrary concurrent changes elsewhere in the file.

Actual run: **22 below-hash negative controls passed**: 19 distinct instruction-pin corruptions, suffix-data corruption, FDE-range corruption and relocation-addend corruption. These invoke `analyze` on mutated real images, bypassing only the public digest gate. They are obligation controls, not a claim to reject every possible byte change. Two captures generated all four outputs byte-for-byte identically. Wrong-input public-gate checks and cross-review results are recorded separately in the work log. No target instruction evaluator, captured execution, helper invocation, curl command or actual target filesystem/network action is performed.

New main's required doctor/verify/catalogue-check/reproduce passed before this packet. Default `make test` was not run: some current tests invoke Python evaluation of captured instructions, outside this task's static-only authorization. This is an unmet required verification gate, not a full-suite PASS. The contribution is a draft for review; a maintainer must arrange compliant full validation or obtain additional authorization before it can be considered ready. No hosted CI, independent Rust implementation, exact ABI, whole returned-command or full-node equivalence is claimed.

Next bounded question: close `0x15020f0` and one normal-return caller handoff before attributing filesystem effects or implementing a body writer. Independent Rust and implementation comparison are not yet implemented/measured.
