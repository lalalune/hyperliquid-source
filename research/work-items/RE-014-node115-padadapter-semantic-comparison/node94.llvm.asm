
artifacts/node/94/hl-node:	file format elf64-x86-64

Disassembly of section .text:

0000000001343c80 <.text>:
 157d000: 55                           	push	rbp
 157d001: 48 89 e5                     	mov	rbp, rsp
 157d004: 41 57                        	push	r15
 157d006: 41 56                        	push	r14
 157d008: 41 55                        	push	r13
 157d00a: 41 54                        	push	r12
 157d00c: 53                           	push	rbx
 157d00d: 48 83 ec 48                  	sub	rsp, 0x48
 157d011: 49 bd 80 80 80 80 80 80 80 80	movabs	r13, -0x7f7f7f7f7f7f7f80
 157d01b: 49 be 0a 0a 0a 0a 0a 0a 0a 0a	movabs	r14, 0xa0a0a0a0a0a0a0a
 157d025: 48 bb 00 01 01 01 01 01 01 01	movabs	rbx, 0x101010101010100
 157d02f: 48 8b 47 10                  	mov	rax, qword ptr [rdi + 0x10]
 157d033: 48 89 45 b0                  	mov	qword ptr [rbp - 0x50], rax
 157d037: 48 8b 07                     	mov	rax, qword ptr [rdi]
 157d03a: 48 89 45 b8                  	mov	qword ptr [rbp - 0x48], rax
 157d03e: 48 8b 47 08                  	mov	rax, qword ptr [rdi + 0x8]
 157d042: 48 89 45 c0                  	mov	qword ptr [rbp - 0x40], rax
 157d046: 48 89 75 d0                  	mov	qword ptr [rbp - 0x30], rsi
 157d04a: 48 8d 46 08                  	lea	rax, [rsi + 0x8]
 157d04e: 48 89 45 a8                  	mov	qword ptr [rbp - 0x58], rax
 157d052: 45 31 ff                     	xor	r15d, r15d
 157d055: 31 c0                        	xor	eax, eax
 157d057: 45 31 c0                     	xor	r8d, r8d
 157d05a: 48 89 55 98                  	mov	qword ptr [rbp - 0x68], rdx
 157d05e: eb 43                        	jmp	0x157d0a3 <.text+0x239423>
 157d060: 42 80 7c 2f ff 0a            	cmp	byte ptr [rdi + r13 - 0x1], 0xa
 157d066: 0f 94 c0                     	sete	al
 157d069: 4a 8d 34 07                  	lea	rsi, [rdi + r8]
 157d06d: 4d 29 c5                     	sub	r13, r8
 157d070: 48 8b 4d b0                  	mov	rcx, qword ptr [rbp - 0x50]
 157d074: 88 01                        	mov	byte ptr [rcx], al
 157d076: 48 8b 7d b8                  	mov	rdi, qword ptr [rbp - 0x48]
 157d07a: 4c 89 ea                     	mov	rdx, r13
 157d07d: 48 8b 45 c0                  	mov	rax, qword ptr [rbp - 0x40]
 157d081: ff 50 18                     	call	qword ptr [rax + 0x18]
 157d084: 4d 89 e0                     	mov	r8, r12
 157d087: 84 c0                        	test	al, al
 157d089: 48 8b 55 98                  	mov	rdx, qword ptr [rbp - 0x68]
 157d08d: 4d 89 f5                     	mov	r13, r14
 157d090: 49 be 0a 0a 0a 0a 0a 0a 0a 0a	movabs	r14, 0xa0a0a0a0a0a0a0a
 157d09a: 8b 45 cc                     	mov	eax, dword ptr [rbp - 0x34]
 157d09d: 0f 85 ba 01 00 00            	jne	0x157d25d <.text+0x2395dd>
 157d0a3: a8 01                        	test	al, 0x1
 157d0a5: 0f 85 ae 01 00 00            	jne	0x157d259 <.text+0x2395d9>
 157d0ab: 4c 39 fa                     	cmp	rdx, r15
 157d0ae: 73 10                        	jae	0x157d0c0 <.text+0x239440>
 157d0b0: 4d 89 fc                     	mov	r12, r15
 157d0b3: 48 8b 7d d0                  	mov	rdi, qword ptr [rbp - 0x30]
 157d0b7: e9 47 01 00 00               	jmp	0x157d203 <.text+0x239583>
 157d0bc: 0f 1f 40 00                  	nop	dword ptr [rax]
 157d0c0: 48 8b 7d d0                  	mov	rdi, qword ptr [rbp - 0x30]
 157d0c4: eb 16                        	jmp	0x157d0dc <.text+0x23945c>
 157d0c6: 66 2e 0f 1f 84 00 00 00 00 00	nop	word ptr cs:[rax + rax]
 157d0d0: 4d 89 e7                     	mov	r15, r12
 157d0d3: 4c 39 e2                     	cmp	rdx, r12
 157d0d6: 0f 82 27 01 00 00            	jb	0x157d203 <.text+0x239583>
 157d0dc: 48 89 d1                     	mov	rcx, rdx
 157d0df: 4c 29 f9                     	sub	rcx, r15
 157d0e2: 4a 8d 04 3f                  	lea	rax, [rdi + r15]
 157d0e6: 48 83 f9 0f                  	cmp	rcx, 0xf
 157d0ea: 77 34                        	ja	0x157d120 <.text+0x2394a0>
 157d0ec: 4c 39 fa                     	cmp	rdx, r15
 157d0ef: 0f 84 0b 01 00 00            	je	0x157d200 <.text+0x239580>
 157d0f5: 31 f6                        	xor	esi, esi
 157d0f7: 66 0f 1f 84 00 00 00 00 00   	nop	word ptr [rax + rax]
 157d100: 80 3c 30 0a                  	cmp	byte ptr [rax + rsi], 0xa
 157d104: 0f 84 c6 00 00 00            	je	0x157d1d0 <.text+0x239550>
 157d10a: 48 ff c6                     	inc	rsi
 157d10d: 48 39 f1                     	cmp	rcx, rsi
 157d110: 75 ee                        	jne	0x157d100 <.text+0x239480>
 157d112: e9 e9 00 00 00               	jmp	0x157d200 <.text+0x239580>
 157d117: 66 0f 1f 84 00 00 00 00 00   	nop	word ptr [rax + rax]
 157d120: 4c 8d 58 07                  	lea	r11, [rax + 0x7]
 157d124: 49 83 e3 f8                  	and	r11, -0x8
 157d128: 49 29 c3                     	sub	r11, rax
 157d12b: 75 53                        	jne	0x157d180 <.text+0x239500>
 157d12d: 4d 89 c4                     	mov	r12, r8
 157d130: 48 8d 71 f0                  	lea	rsi, [rcx - 0x10]
 157d134: 45 31 db                     	xor	r11d, r11d
 157d137: 48 8b 7d a8                  	mov	rdi, qword ptr [rbp - 0x58]
 157d13b: 4c 01 ff                     	add	rdi, r15
 157d13e: 66 90                        	nop
 157d140: 4e 8b 44 1f f8               	mov	r8, qword ptr [rdi + r11 - 0x8]
 157d145: 4d 89 c1                     	mov	r9, r8
 157d148: 4d 31 f1                     	xor	r9, r14
 157d14b: 49 89 da                     	mov	r10, rbx
 157d14e: 4d 29 ca                     	sub	r10, r9
 157d151: 4d 09 c2                     	or	r10, r8
 157d154: 4e 8b 04 1f                  	mov	r8, qword ptr [rdi + r11]
 157d158: 4d 31 f0                     	xor	r8, r14
 157d15b: 49 89 d9                     	mov	r9, rbx
 157d15e: 4d 29 c1                     	sub	r9, r8
 157d161: 4d 09 c1                     	or	r9, r8
 157d164: 4d 21 ea                     	and	r10, r13
 157d167: 4d 21 ca                     	and	r10, r9
 157d16a: 4d 39 ea                     	cmp	r10, r13
 157d16d: 75 41                        	jne	0x157d1b0 <.text+0x239530>
 157d16f: 49 83 c3 10                  	add	r11, 0x10
 157d173: 49 39 f3                     	cmp	r11, rsi
 157d176: 76 c8                        	jbe	0x157d140 <.text+0x2394c0>
 157d178: eb 36                        	jmp	0x157d1b0 <.text+0x239530>
 157d17a: 66 0f 1f 44 00 00            	nop	word ptr [rax + rax]
 157d180: 31 f6                        	xor	esi, esi
 157d182: 66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00    	nop	word ptr cs:[rax + rax]
 157d190: 80 3c 30 0a                  	cmp	byte ptr [rax + rsi], 0xa
 157d194: 74 3a                        	je	0x157d1d0 <.text+0x239550>
 157d196: 48 ff c6                     	inc	rsi
 157d199: 49 39 f3                     	cmp	r11, rsi
 157d19c: 75 f2                        	jne	0x157d190 <.text+0x239510>
 157d19e: 4d 89 c4                     	mov	r12, r8
 157d1a1: 48 8d 71 f0                  	lea	rsi, [rcx - 0x10]
 157d1a5: 49 39 f3                     	cmp	r11, rsi
 157d1a8: 76 8d                        	jbe	0x157d137 <.text+0x2394b7>
 157d1aa: 66 0f 1f 44 00 00            	nop	word ptr [rax + rax]
 157d1b0: 4c 89 de                     	mov	rsi, r11
 157d1b3: 4c 39 d9                     	cmp	rcx, r11
 157d1b6: 48 8b 7d d0                  	mov	rdi, qword ptr [rbp - 0x30]
 157d1ba: 4d 89 e0                     	mov	r8, r12
 157d1bd: 74 41                        	je	0x157d200 <.text+0x239580>
 157d1bf: 90                           	nop
 157d1c0: 80 3c 30 0a                  	cmp	byte ptr [rax + rsi], 0xa
 157d1c4: 74 0a                        	je	0x157d1d0 <.text+0x239550>
 157d1c6: 48 ff c6                     	inc	rsi
 157d1c9: 48 39 f1                     	cmp	rcx, rsi
 157d1cc: 75 f2                        	jne	0x157d1c0 <.text+0x239540>
 157d1ce: eb 30                        	jmp	0x157d200 <.text+0x239580>
 157d1d0: 4e 8d 24 3e                  	lea	r12, [rsi + r15]
 157d1d4: 49 ff c4                     	inc	r12
 157d1d7: 49 01 f7                     	add	r15, rsi
 157d1da: 49 39 d7                     	cmp	r15, rdx
 157d1dd: 0f 83 ed fe ff ff            	jae	0x157d0d0 <.text+0x239450>
 157d1e3: 80 3c 30 0a                  	cmp	byte ptr [rax + rsi], 0xa
 157d1e7: 0f 85 e3 fe ff ff            	jne	0x157d0d0 <.text+0x239450>
 157d1ed: 4d 89 ee                     	mov	r14, r13
 157d1f0: 31 c0                        	xor	eax, eax
 157d1f2: 4d 89 e7                     	mov	r15, r12
 157d1f5: 4d 89 e5                     	mov	r13, r12
 157d1f8: eb 1c                        	jmp	0x157d216 <.text+0x239596>
 157d1fa: 66 0f 1f 44 00 00            	nop	word ptr [rax + rax]
 157d200: 49 89 d4                     	mov	r12, rdx
 157d203: 4d 89 ee                     	mov	r14, r13
 157d206: b0 01                        	mov	al, 0x1
 157d208: 4d 89 e7                     	mov	r15, r12
 157d20b: 4d 89 c4                     	mov	r12, r8
 157d20e: 49 89 d5                     	mov	r13, rdx
 157d211: 4c 39 c2                     	cmp	rdx, r8
 157d214: 74 43                        	je	0x157d259 <.text+0x2395d9>
 157d216: 89 45 cc                     	mov	dword ptr [rbp - 0x34], eax
 157d219: 48 8b 45 b0                  	mov	rax, qword ptr [rbp - 0x50]
 157d21d: 80 38 00                     	cmp	byte ptr [rax], 0x0
 157d220: 74 27                        	je	0x157d249 <.text+0x2395c9>
 157d222: ba 04 00 00 00               	mov	edx, 0x4
 157d227: 48 8b 7d b8                  	mov	rdi, qword ptr [rbp - 0x48]
 157d22b: 48 8d 35 26 ce c8 fe         	lea	rsi, [rip - 0x13731da]  # 0x20a058
 157d232: 48 8b 45 c0                  	mov	rax, qword ptr [rbp - 0x40]
 157d236: 4c 89 45 a0                  	mov	qword ptr [rbp - 0x60], r8
 157d23a: ff 50 18                     	call	qword ptr [rax + 0x18]
 157d23d: 4c 8b 45 a0                  	mov	r8, qword ptr [rbp - 0x60]
 157d241: 48 8b 7d d0                  	mov	rdi, qword ptr [rbp - 0x30]
 157d245: 84 c0                        	test	al, al
 157d247: 75 14                        	jne	0x157d25d <.text+0x2395dd>
 157d249: 4d 39 c5                     	cmp	r13, r8
 157d24c: 0f 85 0e fe ff ff            	jne	0x157d060 <.text+0x2393e0>
 157d252: 31 c0                        	xor	eax, eax
 157d254: e9 10 fe ff ff               	jmp	0x157d069 <.text+0x2393e9>
 157d259: 31 c0                        	xor	eax, eax
 157d25b: eb 02                        	jmp	0x157d25f <.text+0x2395df>
 157d25d: b0 01                        	mov	al, 0x1
 157d25f: 48 83 c4 48                  	add	rsp, 0x48
 157d263: 5b                           	pop	rbx
 157d264: 41 5c                        	pop	r12
 157d266: 41 5d                        	pop	r13
 157d268: 41 5e                        	pop	r14
 157d26a: 41 5f                        	pop	r15
 157d26c: 5d                           	pop	rbp
 157d26d: c3                           	ret
