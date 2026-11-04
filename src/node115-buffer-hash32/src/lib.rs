#![no_std]

const P1: u32 = 0x9e3779b1;
const P2: u32 = 0x85ebca77;
const P3: u32 = 0xc2b2ae3d;
const P4: u32 = 0x27d4eb2f;
const P5: u32 = 0x165667b1;

#[inline(always)]
fn finish(mut value: u32) -> u32 {
    value ^= value >> 15;
    value = value.wrapping_mul(P2);
    value ^= value >> 13;
    value = value.wrapping_mul(P3);
    value ^ (value >> 16)
}

#[inline(always)]
fn lane(previous: u32, word: u32) -> u32 {
    previous.wrapping_add(word.wrapping_mul(P2)).rotate_left(13).wrapping_mul(P1)
}

#[inline(always)]
unsafe fn word(input: *const u8, offset: usize) -> u32 {
    u32::from_le(unsafe { core::ptr::read_unaligned(input.add(offset).cast::<u32>()) })
}

/// Raw byte-buffer checksum relation of node115 FDE61da8b0..61daa52.
/// This explicitly chosen C boundary reflects observed integer registers;
/// original source provenance, source types and caller ownership remain open.
///
/// # Safety
/// A nonnull input must identify len initialized bytes in one valid allocation,
/// with len <= isize::MAX and no address wrap. Alignment is unrestricted.
/// A null input ignores len and hashes the empty input with the supplied seed,
/// as observed before any native length addition or buffer load.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn node115_buffer_hash32(input: *const u8, len: usize, seed: u32) -> u32 {
    if input.is_null() { return finish(seed.wrapping_add(P5)); }
    let mut offset = 0usize;
    let mut value;
    if len >= 16 {
        let mut a = seed.wrapping_add(P1).wrapping_add(P2);
        let mut b = seed.wrapping_add(P2);
        let mut c = seed;
        let mut d = seed.wrapping_sub(P1);
        while len - offset >= 16 {
            a = lane(a, unsafe { word(input, offset) });
            b = lane(b, unsafe { word(input, offset + 4) });
            c = lane(c, unsafe { word(input, offset + 8) });
            d = lane(d, unsafe { word(input, offset + 12) });
            offset += 16;
        }
        value = a.rotate_left(1).wrapping_add(b.rotate_left(7))
            .wrapping_add(c.rotate_left(12)).wrapping_add(d.rotate_left(18));
    } else {
        value = seed.wrapping_add(P5);
    }
    value = value.wrapping_add(len as u32);
    while len - offset >= 4 {
        value = value.wrapping_add(unsafe { word(input, offset) }.wrapping_mul(P3))
            .rotate_left(17).wrapping_mul(P4);
        offset += 4;
    }
    while offset < len {
        value = value.wrapping_add(u32::from(unsafe { *input.add(offset) }).wrapping_mul(P5))
            .rotate_left(11).wrapping_mul(P1);
        offset += 1;
    }
    finish(value)
}
