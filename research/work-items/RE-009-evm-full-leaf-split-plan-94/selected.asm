
artifacts/node/94/hl-node:     file format elf64-x86-64


Disassembly of section .text:

0000000001ab3d31 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x34f40cf>:
 1ab3d31:	49 89 cd             	mov    r13,rcx
 1ab3d34:	4c 8b 3e             	mov    r15,QWORD PTR [rsi]
 1ab3d37:	41 0f b7 9f ca 02 00 	movzx  ebx,WORD PTR [r15+0x2ca]
 1ab3d3e:	00
 1ab3d3f:	48 83 fb 0b          	cmp    rbx,0xb
 1ab3d43:	73 2d                	jae    1ab3d72 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x34f408e>

artifacts/node/94/hl-node:     file format elf64-x86-64


Disassembly of section .text:

0000000001ab3d72 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x34f408e>:
 1ab3d72:	4c 89 7c 24 08       	mov    QWORD PTR [rsp+0x8],r15
 1ab3d77:	4c 8b 7e 10          	mov    r15,QWORD PTR [rsi+0x10]
 1ab3d7b:	49 83 ff 05          	cmp    r15,0x5
 1ab3d7f:	48 89 7c 24 28       	mov    QWORD PTR [rsp+0x28],rdi
 1ab3d84:	4c 89 84 24 c0 00 00 	mov    QWORD PTR [rsp+0xc0],r8
 1ab3d8b:	00
 1ab3d8c:	48 89 54 24 18       	mov    QWORD PTR [rsp+0x18],rdx
 1ab3d91:	0f 83 c8 00 00 00    	jae    1ab3e5f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x34f3fa1>
 1ab3d97:	4c 89 7c 24 10       	mov    QWORD PTR [rsp+0x10],r15
 1ab3d9c:	41 bc 04 00 00 00    	mov    r12d,0x4
 1ab3da2:	31 db                	xor    ebx,ebx
 1ab3da4:	e9 ee 00 00 00       	jmp    1ab3e97 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x34f3f69>

artifacts/node/94/hl-node:     file format elf64-x86-64


Disassembly of section .text:

0000000001ab3e5f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x34f3fa1>:
 1ab3e5f:	74 19                	je     1ab3e7a <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x34f3f86>
 1ab3e61:	49 83 ff 06          	cmp    r15,0x6
 1ab3e65:	75 1f                	jne    1ab3e86 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x34f3f7a>
 1ab3e67:	41 bc 05 00 00 00    	mov    r12d,0x5
 1ab3e6d:	b3 01                	mov    bl,0x1
 1ab3e6f:	48 c7 44 24 10 00 00 	mov    QWORD PTR [rsp+0x10],0x0
 1ab3e76:	00 00
 1ab3e78:	eb 1d                	jmp    1ab3e97 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x34f3f69>
 1ab3e7a:	31 db                	xor    ebx,ebx
 1ab3e7c:	4c 89 7c 24 10       	mov    QWORD PTR [rsp+0x10],r15
 1ab3e81:	4d 89 fc             	mov    r12,r15
 1ab3e84:	eb 11                	jmp    1ab3e97 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x34f3f69>
 1ab3e86:	49 83 c7 f9          	add    r15,0xfffffffffffffff9
 1ab3e8a:	4c 89 7c 24 10       	mov    QWORD PTR [rsp+0x10],r15
 1ab3e8f:	41 bc 06 00 00 00    	mov    r12d,0x6
 1ab3e95:	b3 01                	mov    bl,0x1
 1ab3e97:	48 8b 46 08          	mov    rax,QWORD PTR [rsi+0x8]
 1ab3e9b:	48 89 44 24 20       	mov    QWORD PTR [rsp+0x20],rax
 1ab3ea0:	bf d0 02 00 00       	mov    edi,0x2d0
 1ab3ea5:	ff 15 2d a1 cb 03    	call   QWORD PTR [rip+0x3cba12d]        # 576dfd8 <__register_atfork@plt+0x10cd98>
 1ab3eab:	48 85 c0             	test   rax,rax
 1ab3eae:	0f 84 e4 0a 00 00    	je     1ab4998 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x34f3468>
 1ab3eb4:	49 89 c6             	mov    r14,rax
 1ab3eb7:	48 c7 80 c0 02 00 00 	mov    QWORD PTR [rax+0x2c0],0x0
 1ab3ebe:	00 00 00 00
 1ab3ec2:	66 c7 80 ca 02 00 00 	mov    WORD PTR [rax+0x2ca],0x0
 1ab3ec9:	00 00
 1ab3ecb:	4c 8b 7c 24 08       	mov    r15,QWORD PTR [rsp+0x8]
 1ab3ed0:	41 0f b7 87 ca 02 00 	movzx  eax,WORD PTR [r15+0x2ca]
 1ab3ed7:	00
 1ab3ed8:	4c 89 e5             	mov    rbp,r12
 1ab3edb:	48 f7 d5             	not    rbp
 1ab3ede:	48 01 c5             	add    rbp,rax
 1ab3ee1:	66 41 89 ae ca 02 00 	mov    WORD PTR [r14+0x2ca],bp
 1ab3ee8:	00
 1ab3ee9:	4c 89 e0             	mov    rax,r12
 1ab3eec:	49 c1 e4 05          	shl    r12,0x5
 1ab3ef0:	43 0f 10 04 27       	movups xmm0,XMMWORD PTR [r15+r12*1]
 1ab3ef5:	43 0f 10 4c 27 10    	movups xmm1,XMMWORD PTR [r15+r12*1+0x10]
 1ab3efb:	0f 29 8c 24 b0 00 00 	movaps XMMWORD PTR [rsp+0xb0],xmm1
 1ab3f02:	00
 1ab3f03:	0f 29 84 24 a0 00 00 	movaps XMMWORD PTR [rsp+0xa0],xmm0
 1ab3f0a:	00
 1ab3f0b:	43 0f 10 84 27 60 01 	movups xmm0,XMMWORD PTR [r15+r12*1+0x160]
 1ab3f12:	00 00
 1ab3f14:	43 0f 10 8c 27 70 01 	movups xmm1,XMMWORD PTR [r15+r12*1+0x170]
 1ab3f1b:	00 00
 1ab3f1d:	0f 29 8c 24 20 01 00 	movaps XMMWORD PTR [rsp+0x120],xmm1
 1ab3f24:	00
 1ab3f25:	0f 29 84 24 10 01 00 	movaps XMMWORD PTR [rsp+0x110],xmm0
 1ab3f2c:	00
 1ab3f2d:	48 83 fd 0c          	cmp    rbp,0xc
 1ab3f31:	0f 83 48 0a 00 00    	jae    1ab497f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x34f3481>
 1ab3f37:	4c 89 2c 24          	mov    QWORD PTR [rsp],r13
 1ab3f3b:	89 5c 24 38          	mov    DWORD PTR [rsp+0x38],ebx
 1ab3f3f:	49 8d 9f 60 01 00 00 	lea    rbx,[r15+0x160]
 1ab3f46:	4b 8d 34 27          	lea    rsi,[r15+r12*1]
 1ab3f4a:	48 83 c6 20          	add    rsi,0x20
 1ab3f4e:	48 c1 e5 05          	shl    rbp,0x5
 1ab3f52:	4c 89 f7             	mov    rdi,r14
 1ab3f55:	48 89 ea             	mov    rdx,rbp
 1ab3f58:	49 89 c5             	mov    r13,rax
 1ab3f5b:	ff 15 7f a0 cb 03    	call   QWORD PTR [rip+0x3cba07f]        # 576dfe0 <__register_atfork@plt+0x10cda0>
 1ab3f61:	4a 8d 34 23          	lea    rsi,[rbx+r12*1]
 1ab3f65:	48 83 c6 20          	add    rsi,0x20
 1ab3f69:	49 8d be 60 01 00 00 	lea    rdi,[r14+0x160]
 1ab3f70:	48 89 ea             	mov    rdx,rbp
 1ab3f73:	ff 15 67 a0 cb 03    	call   QWORD PTR [rip+0x3cba067]        # 576dfe0 <__register_atfork@plt+0x10cda0>
 1ab3f79:	66 45 89 af ca 02 00 	mov    WORD PTR [r15+0x2ca],r13w
 1ab3f80:	00
 1ab3f81:	0f 28 84 24 a0 00 00 	movaps xmm0,XMMWORD PTR [rsp+0xa0]
 1ab3f88:	00
 1ab3f89:	0f 28 8c 24 b0 00 00 	movaps xmm1,XMMWORD PTR [rsp+0xb0]
 1ab3f90:	00
 1ab3f91:	0f 29 84 24 d0 00 00 	movaps XMMWORD PTR [rsp+0xd0],xmm0
 1ab3f98:	00
 1ab3f99:	0f 29 8c 24 e0 00 00 	movaps XMMWORD PTR [rsp+0xe0],xmm1
 1ab3fa0:	00
 1ab3fa1:	0f 28 84 24 10 01 00 	movaps xmm0,XMMWORD PTR [rsp+0x110]
 1ab3fa8:	00
 1ab3fa9:	0f 28 8c 24 20 01 00 	movaps xmm1,XMMWORD PTR [rsp+0x120]
 1ab3fb0:	00
 1ab3fb1:	0f 29 8c 24 00 01 00 	movaps XMMWORD PTR [rsp+0x100],xmm1
 1ab3fb8:	00
 1ab3fb9:	31 c9                	xor    ecx,ecx
 1ab3fbb:	80 7c 24 38 00       	cmp    BYTE PTR [rsp+0x38],0x0
 1ab3fc0:	4c 89 f2             	mov    rdx,r14
 1ab3fc3:	49 0f 44 d7          	cmove  rdx,r15
 1ab3fc7:	0f 29 84 24 f0 00 00 	movaps XMMWORD PTR [rsp+0xf0],xmm0
 1ab3fce:	00
 1ab3fcf:	4c 8b 6c 24 20       	mov    r13,QWORD PTR [rsp+0x20]
 1ab3fd4:	49 0f 44 cd          	cmove  rcx,r13

artifacts/node/94/hl-node:     file format elf64-x86-64


Disassembly of section .text:

00000000028547e1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x275361f>:
 28547e1:	48 89 34 24          	mov    QWORD PTR [rsp],rsi
 28547e5:	4c 8d 74 24 08       	lea    r14,[rsp+0x8]
 28547ea:	4c 89 4c 24 08       	mov    QWORD PTR [rsp+0x8],r9
 28547ef:	4c 89 54 24 10       	mov    QWORD PTR [rsp+0x10],r10
 28547f4:	4c 89 44 24 18       	mov    QWORD PTR [rsp+0x18],r8
 28547f9:	48 89 7c 24 20       	mov    QWORD PTR [rsp+0x20],rdi
 28547fe:	48 89 44 24 28       	mov    QWORD PTR [rsp+0x28],rax
 2854803:	48 c7 44 24 30 00 00 	mov    QWORD PTR [rsp+0x30],0x0
 285480a:	00 00
 285480c:	48 89 54 24 38       	mov    QWORD PTR [rsp+0x38],rdx
 2854811:	48 85 c0             	test   rax,rax
 2854814:	74 51                	je     2854867 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2753599>
 2854816:	48 8d 44 24 28       	lea    rax,[rsp+0x28]
 285481b:	48 8b 50 10          	mov    rdx,QWORD PTR [rax+0x10]
 285481f:	48 89 54 24 50       	mov    QWORD PTR [rsp+0x50],rdx
 2854824:	0f 10 00             	movups xmm0,XMMWORD PTR [rax]
 2854827:	0f 29 44 24 40       	movaps XMMWORD PTR [rsp+0x40],xmm0
 285482c:	41 0f 10 06          	movups xmm0,XMMWORD PTR [r14]
 2854830:	41 0f 10 4e 10       	movups xmm1,XMMWORD PTR [r14+0x10]
 2854835:	0f 29 4c 24 70       	movaps XMMWORD PTR [rsp+0x70],xmm1
 285483a:	0f 29 44 24 60       	movaps XMMWORD PTR [rsp+0x60],xmm0
 285483f:	4c 8d 4c 24 40       	lea    r9,[rsp+0x40]
 2854844:	48 8d bc 24 80 00 00 	lea    rdi,[rsp+0x80]
 285484b:	00
 285484c:	48 8d 74 24 40       	lea    rsi,[rsp+0x40]
 2854851:	48 8d 54 24 60       	lea    rdx,[rsp+0x60]
 2854856:	49 89 e0             	mov    r8,rsp
 2854859:	e8 c2 f4 25 ff       	call   1ab3d20 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x34f40e0>
 285485e:	48 8b 0c 24          	mov    rcx,QWORD PTR [rsp]
 2854862:	e9 83 00 00 00       	jmp    28548ea <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2753516>
