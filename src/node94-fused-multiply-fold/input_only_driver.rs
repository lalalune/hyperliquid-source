use node94_fused_multiply_fold::{apply_image, Prepared, Registers};
use std::{
    env, fs,
    io::{self, Write},
    process,
};

fn run() -> Result<(), String> {
    let path = env::args().nth(1).ok_or("expected input path")?;
    let input = fs::read(path).map_err(|e| e.to_string())?;
    if input.len() % 240 != 0 {
        return Err("expected complete 240-byte input records".into());
    }
    let mut output = Vec::with_capacity(input.len());
    for row in input.chunks_exact(240) {
        let mut fields = [0_u64; 14];
        for (field, bytes) in fields.iter_mut().zip(row[..112].chunks_exact(8)) {
            *field = u64::from_le_bytes(bytes.try_into().map_err(|_| "field width")?);
        }
        if fields[13] > 128 {
            return Err("image length exceeds 128".into());
        }
        let prepared = Prepared {
            rax: fields[0],
            r9: fields[1],
            r10: fields[2],
            r14: fields[3],
            r12: fields[4],
            rbp: fields[5],
            r15: fields[6],
            r8: fields[7],
        };
        let mut image = [0_u8; 128];
        image.copy_from_slice(&row[112..]);
        let result = apply_image(
            &mut image[..fields[13] as usize],
            fields[8],
            fields[9],
            fields[10],
            fields[11],
            fields[12],
            prepared,
        );
        let status = u64::from(result.is_some());
        let Registers {
            rax,
            rdx,
            rbx,
            rbp,
            rdi,
            rsi,
            r9,
            r10,
            r11,
            r12,
            r13,
            r14,
            r15,
        } = result.unwrap_or(Registers {
            rax: 0,
            rdx: 0,
            rbx: 0,
            rbp: 0,
            rdi: 0,
            rsi: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
        });
        for value in [
            status, rax, rdx, rbx, rbp, rdi, rsi, r9, r10, r11, r12, r13, r14, r15,
        ] {
            output.extend_from_slice(&value.to_le_bytes());
        }
        output.extend_from_slice(&image);
    }
    io::stdout().write_all(&output).map_err(|e| e.to_string())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(2);
    }
}
