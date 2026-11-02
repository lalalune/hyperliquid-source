
artifacts/node/115/hl-node:     file format elf64-x86-64


Disassembly of section .text:

0000000002e1fe30 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2f28600>:
 2e1fe30:	41 57                	push   r15
 2e1fe32:	41 56                	push   r14
 2e1fe34:	53                   	push   rbx
 2e1fe35:	48 81 ec a0 00 00 00 	sub    rsp,0xa0
 2e1fe3c:	48 89 34 24          	mov    QWORD PTR [rsp],rsi
 2e1fe40:	4c 8b b7 c0 00 00 00 	mov    r14,QWORD PTR [rdi+0xc0]
 2e1fe47:	4c 89 f0             	mov    rax,r14
 2e1fe4a:	48 f7 d8             	neg    rax
 2e1fe4d:	71 78                	jno    2e1fec7 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2f28569>
 2e1fe4f:	48 8b 87 c8 00 00 00 	mov    rax,QWORD PTR [rdi+0xc8]
 2e1fe56:	48 85 c0             	test   rax,rax
 2e1fe59:	0f 84 c8 01 00 00    	je     2e20027 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2f28409>
 2e1fe5f:	48 8b 8f d0 00 00 00 	mov    rcx,QWORD PTR [rdi+0xd0]
 2e1fe66:	44 0f b7 88 c2 01 00 	movzx  r9d,WORD PTR [rax+0x1c2]
 2e1fe6d:	00 
 2e1fe6e:	45 89 cb             	mov    r11d,r9d
 2e1fe71:	41 c1 e3 05          	shl    r11d,0x5
 2e1fe75:	49 c7 c0 ff ff ff ff 	mov    r8,0xffffffffffffffff
 2e1fe7c:	45 31 d2             	xor    r10d,r10d
 2e1fe7f:	90                   	nop
 2e1fe80:	4c 89 db             	mov    rbx,r11
 2e1fe83:	4c 01 d3             	add    rbx,r10
 2e1fe86:	74 28                	je     2e1feb0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2f28580>
 2e1fe88:	4a 3b b4 c0 70 01 00 	cmp    rsi,QWORD PTR [rax+r8*8+0x170]
 2e1fe8f:	00 
 2e1fe90:	0f 97 c3             	seta   bl
 2e1fe93:	80 db 00             	sbb    bl,0x0
 2e1fe96:	49 83 c2 e0          	add    r10,0xffffffffffffffe0
 2e1fe9a:	49 ff c0             	inc    r8
 2e1fe9d:	80 fb 01             	cmp    bl,0x1
 2e1fea0:	74 de                	je     2e1fe80 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2f285b0>
 2e1fea2:	44 0f b6 cb          	movzx  r9d,bl
 2e1fea6:	45 85 c9             	test   r9d,r9d
 2e1fea9:	74 77                	je     2e1ff22 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2f2850e>
 2e1feab:	eb 06                	jmp    2e1feb3 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2f2857d>
 2e1fead:	0f 1f 00             	nop    DWORD PTR [rax]
 2e1feb0:	4d 89 c8             	mov    r8,r9
 2e1feb3:	48 83 e9 01          	sub    rcx,0x1
 2e1feb7:	0f 82 6a 01 00 00    	jb     2e20027 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2f28409>
 2e1febd:	4a 8b 84 c0 c8 01 00 	mov    rax,QWORD PTR [rax+r8*8+0x1c8]
 2e1fec4:	00 
 2e1fec5:	eb 9f                	jmp    2e1fe66 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2f285ca>
 2e1fec7:	48 89 d3             	mov    rbx,rdx
 2e1feca:	48 8d 87 c0 00 00 00 	lea    rax,[rdi+0xc0]
 2e1fed1:	48 89 e6             	mov    rsi,rsp
 2e1fed4:	49 89 ff             	mov    r15,rdi
 2e1fed7:	48 89 c7             	mov    rdi,rax
 2e1feda:	e8 71 60 6a ff       	call   24c5f50 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x38824e0>
 2e1fedf:	4c 89 ff             	mov    rdi,r15
 2e1fee2:	a8 01                	test   al,0x1
 2e1fee4:	0f 85 36 01 00 00    	jne    2e20020 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2f28410>
 2e1feea:	48 3b 97 d8 00 00 00 	cmp    rdx,QWORD PTR [rdi+0xd8]
 2e1fef1:	0f 83 29 01 00 00    	jae    2e20020 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2f28410>
 2e1fef7:	48 03 97 d0 00 00 00 	add    rdx,QWORD PTR [rdi+0xd0]
 2e1fefe:	31 c0                	xor    eax,eax
 2e1ff00:	4c 39 f2             	cmp    rdx,r14
 2e1ff03:	49 0f 43 c6          	cmovae rax,r14
 2e1ff07:	48 29 c2             	sub    rdx,rax
 2e1ff0a:	48 8b 87 c8 00 00 00 	mov    rax,QWORD PTR [rdi+0xc8]
 2e1ff11:	48 8d 0c 92          	lea    rcx,[rdx+rdx*4]
 2e1ff15:	48 8d 04 c8          	lea    rax,[rax+rcx*8]
 2e1ff19:	48 83 c0 08          	add    rax,0x8
 2e1ff1d:	48 89 da             	mov    rdx,rbx
 2e1ff20:	eb 07                	jmp    2e1ff29 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2f28507>
 2e1ff22:	4c 29 d0             	sub    rax,r10
 2e1ff25:	48 83 c0 e0          	add    rax,0xffffffffffffffe0
 2e1ff29:	f3 0f 6f 00          	movdqu xmm0,XMMWORD PTR [rax]
 2e1ff2d:	f3 0f 6f 48 10       	movdqu xmm1,XMMWORD PTR [rax+0x10]
 2e1ff32:	66 0f 7f 8c 24 90 00 	movdqa XMMWORD PTR [rsp+0x90],xmm1
 2e1ff39:	00 00 
 2e1ff3b:	66 0f 7f 84 24 80 00 	movdqa XMMWORD PTR [rsp+0x80],xmm0
 2e1ff42:	00 00 
 2e1ff44:	f3 0f 6f 12          	movdqu xmm2,XMMWORD PTR [rdx]
 2e1ff48:	f3 0f 6f 5a 10       	movdqu xmm3,XMMWORD PTR [rdx+0x10]
 2e1ff4d:	66 0f 74 d9          	pcmpeqb xmm3,xmm1
 2e1ff51:	66 0f 74 d0          	pcmpeqb xmm2,xmm0
 2e1ff55:	66 0f db d3          	pand   xmm2,xmm3
 2e1ff59:	66 0f d7 c2          	pmovmskb eax,xmm2
 2e1ff5d:	3d ff ff 00 00       	cmp    eax,0xffff
 2e1ff62:	0f 84 d2 00 00 00    	je     2e2003a <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2f283f6>
 2e1ff68:	48 c7 44 24 08 00 00 	mov    QWORD PTR [rsp+0x8],0x0
 2e1ff6f:	00 00 
 2e1ff71:	c7 44 24 18 00 00 00 	mov    DWORD PTR [rsp+0x18],0x0
 2e1ff78:	00 
 2e1ff79:	66 c7 44 24 1c 00 00 	mov    WORD PTR [rsp+0x1c],0x0
 2e1ff80:	c6 44 24 18 01       	mov    BYTE PTR [rsp+0x18],0x1
 2e1ff85:	48 8d 05 bc 1c 63 03 	lea    rax,[rip+0x3631cbc]        # 6451c48 <__register_atfork@plt+0x600b8>
 2e1ff8c:	48 89 44 24 40       	mov    QWORD PTR [rsp+0x40],rax
 2e1ff91:	48 8d 05 b8 7c 68 ff 	lea    rax,[rip+0xffffffffff687cb8]        # 24a7c50 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x38a07e0>
 2e1ff98:	48 89 44 24 48       	mov    QWORD PTR [rsp+0x48],rax
 2e1ff9d:	48 89 e0             	mov    rax,rsp
 2e1ffa0:	48 89 44 24 50       	mov    QWORD PTR [rsp+0x50],rax
 2e1ffa5:	48 8b 05 34 88 6c 03 	mov    rax,QWORD PTR [rip+0x36c8834]        # 64e87e0 <__register_atfork@plt+0xf6c50>
 2e1ffac:	48 89 44 24 58       	mov    QWORD PTR [rsp+0x58],rax
 2e1ffb1:	48 89 54 24 60       	mov    QWORD PTR [rsp+0x60],rdx
 2e1ffb6:	48 8b 05 2b 88 6c 03 	mov    rax,QWORD PTR [rip+0x36c882b]        # 64e87e8 <__register_atfork@plt+0xf6c58>
 2e1ffbd:	48 89 44 24 68       	mov    QWORD PTR [rsp+0x68],rax
 2e1ffc2:	48 8d 8c 24 80 00 00 	lea    rcx,[rsp+0x80]
 2e1ffc9:	00 
 2e1ffca:	48 89 4c 24 70       	mov    QWORD PTR [rsp+0x70],rcx
 2e1ffcf:	48 89 44 24 78       	mov    QWORD PTR [rsp+0x78],rax
 2e1ffd4:	48 8d 05 b1 9e 62 fd 	lea    rax,[rip+0xfffffffffd629eb1]        # 449e8c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x58fe5a4>
 2e1ffdb:	48 89 44 24 20       	mov    QWORD PTR [rsp+0x20],rax
 2e1ffe0:	48 8d 44 24 40       	lea    rax,[rsp+0x40]
 2e1ffe5:	48 89 44 24 28       	mov    QWORD PTR [rsp+0x28],rax
 2e1ffea:	48 8d 44 24 20       	lea    rax,[rsp+0x20]
 2e1ffef:	48 89 44 24 30       	mov    QWORD PTR [rsp+0x30],rax
 2e1fff4:	48 8d 05 15 06 7e ff 	lea    rax,[rip+0xffffffffff7e0615]        # 2600610 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3747e20>
 2e1fffb:	48 89 44 24 38       	mov    QWORD PTR [rsp+0x38],rax
 2e20000:	48 8d 35 50 b8 61 fd 	lea    rsi,[rip+0xfffffffffd61b850]        # 43b857 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x590cbd9>
 2e20007:	48 8d 0d 4a 1c 63 03 	lea    rcx,[rip+0x3631c4a]        # 6451c58 <__register_atfork@plt+0x600c8>
 2e2000e:	48 8d 7c 24 08       	lea    rdi,[rsp+0x8]
 2e20013:	48 8d 54 24 30       	lea    rdx,[rsp+0x30]
 2e20018:	ff 15 fa 0a 6c 03    	call   QWORD PTR [rip+0x36c0afa]        # 64e0b18 <__register_atfork@plt+0xeef88>
 2e2001e:	eb 1a                	jmp    2e2003a <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2f283f6>
 2e20020:	48 8b 34 24          	mov    rsi,QWORD PTR [rsp]
 2e20024:	48 89 da             	mov    rdx,rbx
 2e20027:	48 81 c7 a0 00 00 00 	add    rdi,0xa0
 2e2002e:	48 8d 0d 3b 1c 63 03 	lea    rcx,[rip+0x3631c3b]        # 6451c70 <__register_atfork@plt+0x600e0>
 2e20035:	e8 76 cd e8 ff       	call   2cacdb0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x309b680>
 2e2003a:	48 81 c4 a0 00 00 00 	add    rsp,0xa0
 2e20041:	5b                   	pop    rbx
 2e20042:	41 5e                	pop    r14
 2e20044:	41 5f                	pop    r15
 2e20046:	c3                   	ret
