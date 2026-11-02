# Original ELF VAs; strict Python decoder; Intel operand order.
0x1eb3c40: 48 8b 02                       mov rax, qword [rdx]
0x1eb3c43: 48 01 06                       add qword [rsi], rax
0x1eb3c46: 48 8b 42 08                    mov rax, qword [rdx+0x8]
0x1eb3c4a: 48 11 46 08                    adc qword [rsi+0x8], rax
0x1eb3c4e: 0f 92 c0                       setb al
0x1eb3c51: 48 8b 4a 10                    mov rcx, qword [rdx+0x10]
0x1eb3c55: 48 03 4e 10                    add rcx, qword [rsi+0x10]
0x1eb3c59: 41 0f 92 c0                    setb r8b
0x1eb3c5d: 04 ff                          add al, 0xff
0x1eb3c5f: 48 83 d1 00                    adc rcx, 0x0
0x1eb3c63: 0f 92 c0                       setb al
0x1eb3c66: 44 08 c0                       or al, r8b
0x1eb3c69: 48 89 4e 10                    mov qword [rsi+0x10], rcx
0x1eb3c6d: 48 8b 4a 18                    mov rcx, qword [rdx+0x18]
0x1eb3c71: 48 03 4e 18                    add rcx, qword [rsi+0x18]
0x1eb3c75: 0f 92 c2                       setb dl
0x1eb3c78: 0f b6 c0                       movzx eax, al
0x1eb3c7b: 83 e0 01                       and eax, 0x1
0x1eb3c7e: 48 01 c8                       add rax, rcx
0x1eb3c81: 0f 92 c1                       setb cl
0x1eb3c84: 08 d1                          or cl, dl
0x1eb3c86: 80 e1 01                       and cl, 0x1
0x1eb3c89: 48 89 46 18                    mov qword [rsi+0x18], rax
0x1eb3c8d: 0f 10 06                       movups xmm0, xmmword [rsi]
0x1eb3c90: 0f 11 07                       movups xmmword [rdi], xmm0
0x1eb3c93: 48 8b 46 10                    mov rax, qword [rsi+0x10]
0x1eb3c97: 48 89 47 10                    mov qword [rdi+0x10], rax
0x1eb3c9b: 48 8b 46 18                    mov rax, qword [rsi+0x18]
0x1eb3c9f: 48 89 47 18                    mov qword [rdi+0x18], rax
0x1eb3ca3: 88 4f 20                       mov byte [rdi+0x20], cl
0x1eb3ca6: c3                             ret
# Padding [0x1eb3ca7, 0x1eb3cb0): cccccccccccccccccc
