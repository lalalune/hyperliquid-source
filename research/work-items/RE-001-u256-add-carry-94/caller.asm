# Context only; caller body behavior is not bound.
0x1f67364: 48 8d 0d 1d 8f 72 03           lea rcx, qword [rip -> 0x5690288]
# Argument setup and overflow consumer:
0x1f67388: 48 8d 84 24 80 02 00 00        lea rax, qword [rsp+0x280]
0x1f67390: 48 8d 94 24 c0 02 00 00        lea rdx, qword [rsp+0x2c0]
0x1f67398: 48 8b 8c 24 70 02 00 00        mov rcx, qword [rsp+0x270]
0x1f673a0: 48 0b 8c 24 78 02 00 00        or rcx, qword [rsp+0x278]
0x1f673a8: 48 0f 45 d0                    cmovne rdx, rax
0x1f673ac: 48 8d bc 24 e0 03 00 00        lea rdi, qword [rsp+0x3e0]
0x1f673b4: 48 8d b4 24 e0 07 00 00        lea rsi, qword [rsp+0x7e0]
0x1f673bc: e8 7f c8 f4 ff                 call 0x1eb3c40
0x1f673c1: 80 bc 24 00 04 00 00 00        cmp byte [rsp+0x400], 0x0
0x1f673c9: 48 c7 c0 ff ff ff ff           mov rax, -0x1
0x1f673d0: 48 c7 c2 ff ff ff ff           mov rdx, -0x1
0x1f673d7: 48 c7 c1 ff ff ff ff           mov rcx, -0x1
0x1f673de: 48 c7 c6 ff ff ff ff           mov rsi, -0x1
0x1f673e5: 75 20                          jne 0x1f67407
0x1f673e7: 48 8b b4 24 e0 03 00 00        mov rsi, qword [rsp+0x3e0]
0x1f673ef: 48 8b 8c 24 e8 03 00 00        mov rcx, qword [rsp+0x3e8]
0x1f673f7: 48 8b 94 24 f0 03 00 00        mov rdx, qword [rsp+0x3f0]
0x1f673ff: 48 8b 84 24 f8 03 00 00        mov rax, qword [rsp+0x3f8]
