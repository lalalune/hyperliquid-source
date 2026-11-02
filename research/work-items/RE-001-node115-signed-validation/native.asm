
artifacts/node/115/hl-node:     file format elf64-x86-64


Disassembly of section .text:

00000000059d6b80 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3718b0>:
 59d6b80:	55                   	push   rbp
 59d6b81:	41 57                	push   r15
 59d6b83:	41 56                	push   r14
 59d6b85:	41 55                	push   r13
 59d6b87:	41 54                	push   r12
 59d6b89:	53                   	push   rbx
 59d6b8a:	48 81 ec 68 01 00 00 	sub    rsp,0x168
 59d6b91:	48 89 d5             	mov    rbp,rdx
 59d6b94:	49 89 f7             	mov    r15,rsi
 59d6b97:	48 89 fb             	mov    rbx,rdi
 59d6b9a:	48 8d 7e 18          	lea    rdi,[rsi+0x18]
 59d6b9e:	4c 8b 6e 18          	mov    r13,QWORD PTR [rsi+0x18]
 59d6ba2:	48 8d 86 a0 00 00 00 	lea    rax,[rsi+0xa0]
 59d6ba9:	48 8d 4e 50          	lea    rcx,[rsi+0x50]
 59d6bad:	48 be 01 00 00 00 00 	movabs rsi,0x8000000000000001
 59d6bb4:	00 00 80 
 59d6bb7:	49 39 f5             	cmp    r13,rsi
 59d6bba:	48 0f 45 c8          	cmovne rcx,rax
 59d6bbe:	48 8b 01             	mov    rax,QWORD PTR [rcx]
 59d6bc1:	48 ff c0             	inc    rax
 59d6bc4:	48 c7 c2 ff ff ff ff 	mov    rdx,0xffffffffffffffff
 59d6bcb:	48 0f 45 d0          	cmovne rdx,rax
 59d6bcf:	48 89 94 24 d8 00 00 	mov    QWORD PTR [rsp+0xd8],rdx
 59d6bd6:	00 
 59d6bd7:	4d 8d a7 a8 00 00 00 	lea    r12,[r15+0xa8]
 59d6bde:	49 8b 87 a8 00 00 00 	mov    rax,QWORD PTR [r15+0xa8]
 59d6be5:	48 89 84 24 d0 00 00 	mov    QWORD PTR [rsp+0xd0],rax
 59d6bec:	00 
 59d6bed:	48 39 f0             	cmp    rax,rsi
 59d6bf0:	4c 89 e0             	mov    rax,r12
 59d6bf3:	48 89 bc 24 c0 00 00 	mov    QWORD PTR [rsp+0xc0],rdi
 59d6bfa:	00 
 59d6bfb:	48 0f 44 c7          	cmove  rax,rdi
 59d6bff:	49 8d 4f 20          	lea    rcx,[r15+0x20]
 59d6c03:	49 39 f5             	cmp    r13,rsi
 59d6c06:	48 89 8c 24 c8 00 00 	mov    QWORD PTR [rsp+0xc8],rcx
 59d6c0d:	00 
 59d6c0e:	48 0f 44 c1          	cmove  rax,rcx
 59d6c12:	4c 8b 70 40          	mov    r14,QWORD PTR [rax+0x40]
 59d6c16:	48 8d 7c 24 10       	lea    rdi,[rsp+0x10]
 59d6c1b:	48 89 ee             	mov    rsi,rbp
 59d6c1e:	4c 89 f1             	mov    rcx,r14
 59d6c21:	ff 15 c9 1a b1 00    	call   QWORD PTR [rip+0xb11ac9]        # 64e86f0 <__register_atfork@plt+0xf6b60>
 59d6c27:	0f b6 44 24 10       	movzx  eax,BYTE PTR [rsp+0x10]
 59d6c2c:	0f 10 44 24 11       	movups xmm0,XMMWORD PTR [rsp+0x11]
 59d6c31:	0f 29 44 24 70       	movaps XMMWORD PTR [rsp+0x70],xmm0
 59d6c36:	8b 4c 24 21          	mov    ecx,DWORD PTR [rsp+0x21]
 59d6c3a:	89 8c 24 80 00 00 00 	mov    DWORD PTR [rsp+0x80],ecx
 59d6c41:	3c 2e                	cmp    al,0x2e
 59d6c43:	0f 85 69 02 00 00    	jne    59d6eb2 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x37157e>
 59d6c49:	66 0f 6f 44 24 70    	movdqa xmm0,XMMWORD PTR [rsp+0x70]
 59d6c4f:	66 0f 7f 84 24 20 01 	movdqa XMMWORD PTR [rsp+0x120],xmm0
 59d6c56:	00 00 
 59d6c58:	8b 84 24 80 00 00 00 	mov    eax,DWORD PTR [rsp+0x80]
 59d6c5f:	89 84 24 30 01 00 00 	mov    DWORD PTR [rsp+0x130],eax
 59d6c66:	66 0f 7f 84 24 50 01 	movdqa XMMWORD PTR [rsp+0x150],xmm0
 59d6c6d:	00 00 
 59d6c6f:	89 84 24 60 01 00 00 	mov    DWORD PTR [rsp+0x160],eax
 59d6c76:	f3 41 0f 6f 8f 1c 01 	movdqu xmm1,XMMWORD PTR [r15+0x11c]
 59d6c7d:	00 00 
 59d6c7f:	66 41 0f 6e 97 2c 01 	movd   xmm2,DWORD PTR [r15+0x12c]
 59d6c86:	00 00 
 59d6c88:	66 48 0f 6e d8       	movq   xmm3,rax
 59d6c8d:	66 0f 74 da          	pcmpeqb xmm3,xmm2
 59d6c91:	66 0f 74 c8          	pcmpeqb xmm1,xmm0
 59d6c95:	66 0f db cb          	pand   xmm1,xmm3
 59d6c99:	66 0f d7 c1          	pmovmskb eax,xmm1
 59d6c9d:	3d ff ff 00 00       	cmp    eax,0xffff
 59d6ca2:	0f 84 5c 02 00 00    	je     59d6f04 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x37152c>
 59d6ca8:	4c 89 7c 24 18       	mov    QWORD PTR [rsp+0x18],r15
 59d6cad:	49 81 c7 1c 01 00 00 	add    r15,0x11c
 59d6cb4:	48 c7 44 24 10 00 00 	mov    QWORD PTR [rsp+0x10],0x0
 59d6cbb:	00 00 
 59d6cbd:	4c 8d 64 24 70       	lea    r12,[rsp+0x70]
 59d6cc2:	48 8d 74 24 10       	lea    rsi,[rsp+0x10]
 59d6cc7:	4c 89 e7             	mov    rdi,r12
 59d6cca:	e8 71 20 e1 ff       	call   57e8d40 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x55f6f0>
 59d6ccf:	41 0f 10 07          	movups xmm0,XMMWORD PTR [r15]
 59d6cd3:	0f 29 84 24 a0 00 00 	movaps XMMWORD PTR [rsp+0xa0],xmm0
 59d6cda:	00 
 59d6cdb:	41 8b 47 10          	mov    eax,DWORD PTR [r15+0x10]
 59d6cdf:	89 84 24 b0 00 00 00 	mov    DWORD PTR [rsp+0xb0],eax
 59d6ce6:	48 8b 4d 20          	mov    rcx,QWORD PTR [rbp+0x20]
 59d6cea:	48 89 c8             	mov    rax,rcx
 59d6ced:	48 2d 30 f8 ff ff    	sub    rax,0xfffffffffffff830
 59d6cf3:	72 12                	jb     59d6d07 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x371729>
 59d6cf5:	48 81 c1 d0 07 00 00 	add    rcx,0x7d0
 59d6cfc:	48 c7 c0 ff ff ff ff 	mov    rax,0xffffffffffffffff
 59d6d03:	48 0f 43 c1          	cmovae rax,rcx
 59d6d07:	48 8b 55 60          	mov    rdx,QWORD PTR [rbp+0x60]
 59d6d0b:	48 89 d1             	mov    rcx,rdx
 59d6d0e:	48 81 e9 38 ff ff ff 	sub    rcx,0xffffffffffffff38
 59d6d15:	72 12                	jb     59d6d29 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x371707>
 59d6d17:	48 81 c2 c8 00 00 00 	add    rdx,0xc8
 59d6d1e:	48 c7 c1 ff ff ff ff 	mov    rcx,0xffffffffffffffff
 59d6d25:	48 0f 43 ca          	cmovae rcx,rdx
 59d6d29:	48 ff c1             	inc    rcx
 59d6d2c:	48 c7 c2 ff ff ff ff 	mov    rdx,0xffffffffffffffff
 59d6d33:	48 0f 45 d1          	cmovne rdx,rcx
 59d6d37:	48 39 c2             	cmp    rdx,rax
 59d6d3a:	48 0f 46 d0          	cmovbe rdx,rax
 59d6d3e:	49 39 d6             	cmp    r14,rdx
 59d6d41:	0f 92 44 24 0f       	setb   BYTE PTR [rsp+0xf]
 59d6d46:	48 c7 84 24 08 01 00 	mov    QWORD PTR [rsp+0x108],0x0
 59d6d4d:	00 00 00 00 00 
 59d6d52:	c7 84 24 18 01 00 00 	mov    DWORD PTR [rsp+0x118],0x0
 59d6d59:	00 00 00 00 
 59d6d5d:	66 c7 84 24 1c 01 00 	mov    WORD PTR [rsp+0x11c],0x0
 59d6d64:	00 00 00 
 59d6d67:	c6 84 24 18 01 00 00 	mov    BYTE PTR [rsp+0x118],0x1
 59d6d6e:	01 
 59d6d6f:	48 8d 05 89 18 f6 fa 	lea    rax,[rip+0xfffffffffaf61889]        # 9385ff <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x540fe31>
 59d6d76:	48 89 84 24 40 01 00 	mov    QWORD PTR [rsp+0x140],rax
 59d6d7d:	00 
 59d6d7e:	48 c7 84 24 48 01 00 	mov    QWORD PTR [rsp+0x148],0x3b
 59d6d85:	00 3b 00 00 00 
 59d6d8a:	4c 89 a4 24 e0 00 00 	mov    QWORD PTR [rsp+0xe0],r12
 59d6d91:	00 
 59d6d92:	48 8d 84 24 d8 00 00 	lea    rax,[rsp+0xd8]
 59d6d99:	00 
 59d6d9a:	48 89 84 24 e8 00 00 	mov    QWORD PTR [rsp+0xe8],rax
 59d6da1:	00 
 59d6da2:	48 8d 84 24 a0 00 00 	lea    rax,[rsp+0xa0]
 59d6da9:	00 
 59d6daa:	48 89 84 24 f0 00 00 	mov    QWORD PTR [rsp+0xf0],rax
 59d6db1:	00 
 59d6db2:	48 8d 84 24 50 01 00 	lea    rax,[rsp+0x150]
 59d6db9:	00 
 59d6dba:	48 89 84 24 f8 00 00 	mov    QWORD PTR [rsp+0xf8],rax
 59d6dc1:	00 
 59d6dc2:	48 8d 44 24 0f       	lea    rax,[rsp+0xf]
 59d6dc7:	48 89 84 24 00 01 00 	mov    QWORD PTR [rsp+0x100],rax
 59d6dce:	00 
 59d6dcf:	48 8d 84 24 40 01 00 	lea    rax,[rsp+0x140]
 59d6dd6:	00 
 59d6dd7:	48 89 44 24 10       	mov    QWORD PTR [rsp+0x10],rax
 59d6ddc:	48 8d 05 3d 34 e5 ff 	lea    rax,[rip+0xffffffffffe5343d]        # 582a220 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x51e210>
 59d6de3:	48 89 44 24 18       	mov    QWORD PTR [rsp+0x18],rax
 59d6de8:	48 8d 84 24 e0 00 00 	lea    rax,[rsp+0xe0]
 59d6def:	00 
 59d6df0:	48 89 44 24 20       	mov    QWORD PTR [rsp+0x20],rax
 59d6df5:	48 8d 05 a4 31 e5 ff 	lea    rax,[rip+0xffffffffffe531a4]        # 5829fa0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x51e490>
 59d6dfc:	48 89 44 24 28       	mov    QWORD PTR [rsp+0x28],rax
 59d6e01:	48 8d 84 24 e8 00 00 	lea    rax,[rsp+0xe8]
 59d6e08:	00 
 59d6e09:	48 89 44 24 30       	mov    QWORD PTR [rsp+0x30],rax
 59d6e0e:	48 8d 05 0b 33 e5 ff 	lea    rax,[rip+0xffffffffffe5330b]        # 582a120 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x51e310>
 59d6e15:	48 89 44 24 38       	mov    QWORD PTR [rsp+0x38],rax
 59d6e1a:	48 8d 84 24 f0 00 00 	lea    rax,[rsp+0xf0]
 59d6e21:	00 
 59d6e22:	48 89 44 24 40       	mov    QWORD PTR [rsp+0x40],rax
 59d6e27:	48 8d 05 f2 29 e5 ff 	lea    rax,[rip+0xffffffffffe529f2]        # 5829820 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x51ec10>
 59d6e2e:	48 89 44 24 48       	mov    QWORD PTR [rsp+0x48],rax
 59d6e33:	48 8d 8c 24 f8 00 00 	lea    rcx,[rsp+0xf8]
 59d6e3a:	00 
 59d6e3b:	48 89 4c 24 50       	mov    QWORD PTR [rsp+0x50],rcx
 59d6e40:	48 89 44 24 58       	mov    QWORD PTR [rsp+0x58],rax
 59d6e45:	48 8d 84 24 00 01 00 	lea    rax,[rsp+0x100]
 59d6e4c:	00 
 59d6e4d:	48 89 44 24 60       	mov    QWORD PTR [rsp+0x60],rax
 59d6e52:	48 8d 05 47 2c e5 ff 	lea    rax,[rip+0xffffffffffe52c47]        # 5829aa0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x51e990>
 59d6e59:	48 89 44 24 68       	mov    QWORD PTR [rsp+0x68],rax
 59d6e5e:	48 8d 35 bd 10 a6 fa 	lea    rsi,[rip+0xfffffffffaa610bd]        # 437f22 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x591050e>
 59d6e65:	48 8d 0d cc 00 ae 00 	lea    rcx,[rip+0xae00cc]        # 64b6f38 <__register_atfork@plt+0xc53a8>
 59d6e6c:	48 8d bc 24 08 01 00 	lea    rdi,[rsp+0x108]
 59d6e73:	00 
 59d6e74:	48 8d 54 24 10       	lea    rdx,[rsp+0x10]
 59d6e79:	ff 15 99 9c b0 00    	call   QWORD PTR [rip+0xb09c99]        # 64e0b18 <__register_atfork@plt+0xeef88>
 59d6e7f:	8b 84 24 b0 00 00 00 	mov    eax,DWORD PTR [rsp+0xb0]
 59d6e86:	89 43 11             	mov    DWORD PTR [rbx+0x11],eax
 59d6e89:	0f 28 84 24 a0 00 00 	movaps xmm0,XMMWORD PTR [rsp+0xa0]
 59d6e90:	00 
 59d6e91:	0f 11 43 01          	movups XMMWORD PTR [rbx+0x1],xmm0
 59d6e95:	8b 84 24 30 01 00 00 	mov    eax,DWORD PTR [rsp+0x130]
 59d6e9c:	89 43 25             	mov    DWORD PTR [rbx+0x25],eax
 59d6e9f:	66 0f 6f 84 24 20 01 	movdqa xmm0,XMMWORD PTR [rsp+0x120]
 59d6ea6:	00 00 
 59d6ea8:	f3 0f 7f 43 15       	movdqu XMMWORD PTR [rbx+0x15],xmm0
 59d6ead:	c6 03 0d             	mov    BYTE PTR [rbx],0xd
 59d6eb0:	eb 3d                	jmp    59d6eef <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x371541>
 59d6eb2:	8b 4c 24 54          	mov    ecx,DWORD PTR [rsp+0x54]
 59d6eb6:	89 4b 44             	mov    DWORD PTR [rbx+0x44],ecx
 59d6eb9:	0f 10 44 24 25       	movups xmm0,XMMWORD PTR [rsp+0x25]
 59d6ebe:	f3 0f 6f 4c 24 35    	movdqu xmm1,XMMWORD PTR [rsp+0x35]
 59d6ec4:	f3 0f 6f 54 24 45    	movdqu xmm2,XMMWORD PTR [rsp+0x45]
 59d6eca:	f3 0f 7f 53 35       	movdqu XMMWORD PTR [rbx+0x35],xmm2
 59d6ecf:	f3 0f 7f 4b 25       	movdqu XMMWORD PTR [rbx+0x25],xmm1
 59d6ed4:	0f 11 43 15          	movups XMMWORD PTR [rbx+0x15],xmm0
 59d6ed8:	8b 8c 24 80 00 00 00 	mov    ecx,DWORD PTR [rsp+0x80]
 59d6edf:	89 4b 11             	mov    DWORD PTR [rbx+0x11],ecx
 59d6ee2:	66 0f 6f 44 24 70    	movdqa xmm0,XMMWORD PTR [rsp+0x70]
 59d6ee8:	f3 0f 7f 43 01       	movdqu XMMWORD PTR [rbx+0x1],xmm0
 59d6eed:	88 03                	mov    BYTE PTR [rbx],al
 59d6eef:	48 89 d8             	mov    rax,rbx
 59d6ef2:	48 81 c4 68 01 00 00 	add    rsp,0x168
 59d6ef9:	5b                   	pop    rbx
 59d6efa:	41 5c                	pop    r12
 59d6efc:	41 5d                	pop    r13
 59d6efe:	41 5e                	pop    r14
 59d6f00:	41 5f                	pop    r15
 59d6f02:	5d                   	pop    rbp
 59d6f03:	c3                   	ret
 59d6f04:	4d 8b 77 10          	mov    r14,QWORD PTR [r15+0x10]
 59d6f08:	49 83 fe 64          	cmp    r14,0x64
 59d6f0c:	76 09                	jbe    59d6f17 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x371519>
 59d6f0e:	c6 03 29             	mov    BYTE PTR [rbx],0x29
 59d6f11:	4c 89 73 08          	mov    QWORD PTR [rbx+0x8],r14
 59d6f15:	eb d8                	jmp    59d6eef <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x371541>
 59d6f17:	4c 89 a4 24 b8 00 00 	mov    QWORD PTR [rsp+0xb8],r12
 59d6f1e:	00 
 59d6f1f:	48 89 ac 24 98 00 00 	mov    QWORD PTR [rsp+0x98],rbp
 59d6f26:	00 
 59d6f27:	48 c7 44 24 70 00 00 	mov    QWORD PTR [rsp+0x70],0x0
 59d6f2e:	00 00 
 59d6f30:	48 c7 84 24 80 00 00 	mov    QWORD PTR [rsp+0x80],0x0
 59d6f37:	00 00 00 00 00 
 59d6f3c:	4d 8b 67 08          	mov    r12,QWORD PTR [r15+0x8]
 59d6f40:	49 c1 e6 05          	shl    r14,0x5
 59d6f44:	31 ed                	xor    ebp,ebp
 59d6f46:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
 59d6f4d:	00 00 00 
 59d6f50:	49 39 ee             	cmp    r14,rbp
 59d6f53:	74 50                	je     59d6fa5 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x37148b>
 59d6f55:	49 8d 04 2c          	lea    rax,[r12+rbp*1]
 59d6f59:	f3 0f 6f 00          	movdqu xmm0,XMMWORD PTR [rax]
 59d6f5d:	f3 0f 6f 48 10       	movdqu xmm1,XMMWORD PTR [rax+0x10]
 59d6f62:	66 0f 7f 4c 24 20    	movdqa XMMWORD PTR [rsp+0x20],xmm1
 59d6f68:	66 0f 7f 44 24 10    	movdqa XMMWORD PTR [rsp+0x10],xmm0
 59d6f6e:	48 8d 7c 24 70       	lea    rdi,[rsp+0x70]
 59d6f73:	48 8d 74 24 10       	lea    rsi,[rsp+0x10]
 59d6f78:	e8 53 b9 7f ff       	call   51d28d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xb75b60>
 59d6f7d:	48 83 c5 20          	add    rbp,0x20
 59d6f81:	84 c0                	test   al,al
 59d6f83:	74 cb                	je     59d6f50 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3714e0>
 59d6f85:	f3 41 0f 6f 44 2c e0 	movdqu xmm0,XMMWORD PTR [r12+rbp*1-0x20]
 59d6f8c:	f3 41 0f 6f 4c 2c f0 	movdqu xmm1,XMMWORD PTR [r12+rbp*1-0x10]
 59d6f93:	f3 0f 7f 4b 11       	movdqu XMMWORD PTR [rbx+0x11],xmm1
 59d6f98:	f3 0f 7f 43 01       	movdqu XMMWORD PTR [rbx+0x1],xmm0
 59d6f9d:	c6 03 2a             	mov    BYTE PTR [rbx],0x2a
 59d6fa0:	e9 da 00 00 00       	jmp    59d707f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3713b1>
 59d6fa5:	49 bc 01 00 00 00 00 	movabs r12,0x8000000000000001
 59d6fac:	00 00 80 
 59d6faf:	4d 39 e5             	cmp    r13,r12
 59d6fb2:	75 1d                	jne    59d6fd1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x37145f>
 59d6fb4:	48 89 df             	mov    rdi,rbx
 59d6fb7:	48 8b b4 24 c8 00 00 	mov    rsi,QWORD PTR [rsp+0xc8]
 59d6fbe:	00 
 59d6fbf:	48 8b 94 24 98 00 00 	mov    rdx,QWORD PTR [rsp+0x98]
 59d6fc6:	00 
 59d6fc7:	e8 54 8d f8 ff       	call   595fd20 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e8710>
 59d6fcc:	e9 ae 00 00 00       	jmp    59d707f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3713b1>
 59d6fd1:	4c 8b ac 24 d0 00 00 	mov    r13,QWORD PTR [rsp+0xd0]
 59d6fd8:	00 
 59d6fd9:	4d 39 e5             	cmp    r13,r12
 59d6fdc:	4c 8b b4 24 98 00 00 	mov    r14,QWORD PTR [rsp+0x98]
 59d6fe3:	00 
 59d6fe4:	74 1a                	je     59d7000 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x371430>
 59d6fe6:	49 8b 87 d8 00 00 00 	mov    rax,QWORD PTR [r15+0xd8]
 59d6fed:	49 3b 47 48          	cmp    rax,QWORD PTR [r15+0x48]
 59d6ff1:	0f 86 81 00 00 00    	jbe    59d7078 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3713b8>
 59d6ff7:	49 3b 87 a0 00 00 00 	cmp    rax,QWORD PTR [r15+0xa0]
 59d6ffe:	73 78                	jae    59d7078 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3713b8>
 59d7000:	48 8d 7c 24 10       	lea    rdi,[rsp+0x10]
 59d7005:	48 8b b4 24 c0 00 00 	mov    rsi,QWORD PTR [rsp+0xc0]
 59d700c:	00 
 59d700d:	4c 89 f2             	mov    rdx,r14
 59d7010:	e8 7b 93 f8 ff       	call   5960390 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e80a0>
 59d7015:	80 7c 24 10 2e       	cmp    BYTE PTR [rsp+0x10],0x2e
 59d701a:	75 26                	jne    59d7042 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3713ee>
 59d701c:	4d 39 e5             	cmp    r13,r12
 59d701f:	74 1c                	je     59d703d <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3713f3>
 59d7021:	48 8d 7c 24 10       	lea    rdi,[rsp+0x10]
 59d7026:	48 8b b4 24 b8 00 00 	mov    rsi,QWORD PTR [rsp+0xb8]
 59d702d:	00 
 59d702e:	4c 89 f2             	mov    rdx,r14
 59d7031:	e8 ea 8c f8 ff       	call   595fd20 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e8710>
 59d7036:	80 7c 24 10 2e       	cmp    BYTE PTR [rsp+0x10],0x2e
 59d703b:	75 05                	jne    59d7042 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3713ee>
 59d703d:	c6 03 2e             	mov    BYTE PTR [rbx],0x2e
 59d7040:	eb 3d                	jmp    59d707f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3713b1>
 59d7042:	48 8b 44 24 50       	mov    rax,QWORD PTR [rsp+0x50]
 59d7047:	48 89 43 40          	mov    QWORD PTR [rbx+0x40],rax
 59d704b:	f3 0f 6f 44 24 10    	movdqu xmm0,XMMWORD PTR [rsp+0x10]
 59d7051:	f3 0f 6f 4c 24 20    	movdqu xmm1,XMMWORD PTR [rsp+0x20]
 59d7057:	f3 0f 6f 54 24 30    	movdqu xmm2,XMMWORD PTR [rsp+0x30]
 59d705d:	f3 0f 6f 5c 24 40    	movdqu xmm3,XMMWORD PTR [rsp+0x40]
 59d7063:	f3 0f 7f 5b 30       	movdqu XMMWORD PTR [rbx+0x30],xmm3
 59d7068:	f3 0f 7f 53 20       	movdqu XMMWORD PTR [rbx+0x20],xmm2
 59d706d:	f3 0f 7f 4b 10       	movdqu XMMWORD PTR [rbx+0x10],xmm1
 59d7072:	f3 0f 7f 03          	movdqu XMMWORD PTR [rbx],xmm0
 59d7076:	eb 07                	jmp    59d707f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3713b1>
 59d7078:	c6 03 0c             	mov    BYTE PTR [rbx],0xc
 59d707b:	48 89 43 08          	mov    QWORD PTR [rbx+0x8],rax
 59d707f:	48 8d 7c 24 70       	lea    rdi,[rsp+0x70]
 59d7084:	e8 d7 fa 86 ff       	call   5246b60 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xb018d0>
 59d7089:	e9 61 fe ff ff       	jmp    59d6eef <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x371541>
 59d708e:	eb 00                	jmp    59d7090 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3713a0>
 59d7090:	48 89 c3             	mov    rbx,rax
 59d7093:	48 8d 7c 24 70       	lea    rdi,[rsp+0x70]
 59d7098:	e8 c3 fa 86 ff       	call   5246b60 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xb018d0>
 59d709d:	48 89 df             	mov    rdi,rbx
 59d70a0:	e8 ab 99 a1 00       	call   63f0a50 <_Unwind_Resume@plt>
 59d70a5:	ff 15 15 84 b0 00    	call   QWORD PTR [rip+0xb08415]        # 64df4c0 <__register_atfork@plt+0xed930>
