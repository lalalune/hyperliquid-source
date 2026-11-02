"""Static specialization of the captured vector verifier to its nine-byte needle.

No target instructions execute. Pins below bind the proof to concrete operands.
"""
PINS = {
 0x158ef30: '85c9740331c0c3',  # nonzero prior-match class returns zero
 0x158ef37: '488b074c8b47104801c648ffc6488b7f18',  # haystack+window+1, needle ptr/len
 0x158ef48: '4883ff04731beb70',
 0x158ef50: '8b00413b4438fc0f84c0000000',  # final four bytes versus needle[len-4:]
 0x158ef5d: '66b8feff66d3c06621c274cb',  # remove selected candidate; zero mask returns false
 0x158ef69: 'f30fbcca4c8d0c0e4a8d040f4883c0fc4939c173d2',
 0x158ef90: '458b19453b1a75c54983c1044983c2044939c172ebeba9',
 0x158f01d: 'b001c3',
 0x158e9b7: '4c89e74c89ee31c9e86c050000',
 0x158ed7e: '498d77e7400fb6ed488d7c242889e9e89e010000',
}


def check(read):
 for va, raw in PINS.items():
  wanted=bytes.fromhex(raw)
  if read(va,len(wanted))!=wanted:raise ValueError(f'vector verifier operand changed at {va:#x}')


def prove(data):
 from evm_amount_scale import Image
 image=Image(data);check(image.read)
 rejected=0
 for va,raw in PINS.items():
  def patched(at,n):
   value=bytearray(image.read(at,n))
   if at<=va<at+n:value[va-at]^=1
   return bytes(value)
  try:check(patched)
  except ValueError:rejected+=1
  else:raise ValueError('undetected selected-operand corruption')
 # Algebra on 16-bit candidate masks: ROL16(0xfffe, lowest_set_bit)
 # equals the complement of exactly that bit. No CPU instruction is interpreted.
 for mask in range(1,65536):
  bit=(mask & -mask).bit_length()-1
  rotated=((0xfffe<<bit)|(0xfffe>>(16-bit)))&65535
  next_mask=mask & rotated
  assert rotated==(65535^(1<<bit)) and next_mask==mask-(1<<bit)
 assert set(range(0,4))|set(range(4,8))|set(range(5,9))==set(range(9))
 return {
  'pins':{hex(k):v for k,v in PINS.items()},
  'below_identity_operand_corruptions_rejected':rejected,
  'nonzero_masks_checked':65535,
  'specialization':'Supplied constructor descriptor: haystack base, needle heckpoint, length 9; caller mask bit j means c at window+j and t at window+j+9.',
  'nine_byte_comparison_ranges':[[0,4],[4,8],[5,9]],
  'proof':['ECX nonzero returns zero; caller OR preserves the already-found flag.',
           'For length 9 the dword loop compares offsets [0,4) then [4,8); final dword compares [5,9). These cover exactly nine needle bytes, overlaps require the same bytes.',
           'On mismatch the chosen lowest bit is removed. Every nonzero 16-bit mask decreases; zero returns false, a full nine-byte match returns true.',
           'Mask bit j already proves the first c and last t. Verifier proves the following heckpoint. Thus any successful candidate equals checkpoint, with no candidate lost by mask clearing.'],
  'limits':'Conditional on valid live regions, captured descriptor/argument transfers and ordinary execution. Coverage of the outer loop remains finite 0..512 plus supplied corpus lengths; no general allocation/alias/SIMD-fault/process behavior or all-usize bound is established.',
 }
