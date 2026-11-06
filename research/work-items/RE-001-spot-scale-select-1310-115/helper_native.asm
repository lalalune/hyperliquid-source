
artifacts/node/115/hl-node:     file format elf64-x86-64


Disassembly of section .text:

0000000003d1a200 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x202e230>:
 3d1a200:	41 56                	push   r14
 3d1a202:	53                   	push   rbx
 3d1a203:	50                   	push   rax
 3d1a204:	48 8b 47 10          	mov    rax,QWORD PTR [rdi+0x10]
 3d1a208:	48 39 c6             	cmp    rsi,rax
 3d1a20b:	73 7e                	jae    3d1a28b <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x202e1a5>
 3d1a20d:	48 8b 47 08          	mov    rax,QWORD PTR [rdi+0x8]
 3d1a211:	48 c1 e6 05          	shl    rsi,0x5
 3d1a215:	48 8b 14 30          	mov    rdx,QWORD PTR [rax+rsi*1]
 3d1a219:	48 89 14 24          	mov    QWORD PTR [rsp],rdx
 3d1a21d:	48 8b 47 58          	mov    rax,QWORD PTR [rdi+0x58]
 3d1a221:	48 85 c0             	test   rax,rax
 3d1a224:	74 12                	je     3d1a238 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x202e1f8>
 3d1a226:	48 83 f8 01          	cmp    rax,0x1
 3d1a22a:	75 14                	jne    3d1a240 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x202e1f0>
 3d1a22c:	48 8b 47 50          	mov    rax,QWORD PTR [rdi+0x50]
 3d1a230:	48 3b 50 08          	cmp    rdx,QWORD PTR [rax+0x8]
 3d1a234:	74 3e                	je     3d1a274 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x202e1bc>
 3d1a236:	31 c0                	xor    eax,eax
 3d1a238:	48 83 c4 08          	add    rsp,0x8
 3d1a23c:	5b                   	pop    rbx
 3d1a23d:	41 5e                	pop    r14
 3d1a23f:	c3                   	ret
 3d1a240:	49 89 c6             	mov    r14,rax
 3d1a243:	48 8d 5f 48          	lea    rbx,[rdi+0x48]
 3d1a247:	48 8b 87 80 00 00 00 	mov    rax,QWORD PTR [rdi+0x80]
 3d1a24e:	48 8b b7 88 00 00 00 	mov    rsi,QWORD PTR [rdi+0x88]
 3d1a255:	48 89 c7             	mov    rdi,rax
 3d1a258:	e8 63 d0 9f 00       	call   47172c0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x1631170>
 3d1a25d:	48 89 e2             	mov    rdx,rsp
 3d1a260:	48 89 df             	mov    rdi,rbx
 3d1a263:	48 89 c6             	mov    rsi,rax
 3d1a266:	e8 15 7f 1b 00       	call   3ed2180 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x1e762b0>
 3d1a26b:	a8 01                	test   al,0x1
 3d1a26d:	74 12                	je     3d1a281 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x202e1af>
 3d1a26f:	4c 39 f2             	cmp    rdx,r14
 3d1a272:	73 2a                	jae    3d1a29e <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x202e192>
 3d1a274:	b8 e8 03 00 00       	mov    eax,0x3e8
 3d1a279:	48 83 c4 08          	add    rsp,0x8
 3d1a27d:	5b                   	pop    rbx
 3d1a27e:	41 5e                	pop    r14
 3d1a280:	c3                   	ret
 3d1a281:	31 c0                	xor    eax,eax
 3d1a283:	48 83 c4 08          	add    rsp,0x8
 3d1a287:	5b                   	pop    rbx
 3d1a288:	41 5e                	pop    r14
 3d1a28a:	c3                   	ret
 3d1a28b:	48 8d 15 e6 c3 75 02 	lea    rdx,[rip+0x275c3e6]        # 6476678 <__register_atfork@plt+0x84ae8>
 3d1a292:	48 89 f7             	mov    rdi,rsi
 3d1a295:	48 89 c6             	mov    rsi,rax
 3d1a298:	ff 15 82 53 7c 02    	call   QWORD PTR [rip+0x27c5382]        # 64df620 <__register_atfork@plt+0xeda90>
 3d1a29e:	4c 89 f6             	mov    rsi,r14
 3d1a2a1:	48 8d 05 88 98 77 02 	lea    rax,[rip+0x2779888]        # 6493b30 <__register_atfork@plt+0xa1fa0>
 3d1a2a8:	48 89 d7             	mov    rdi,rdx
 3d1a2ab:	48 89 c2             	mov    rdx,rax
 3d1a2ae:	ff 15 6c 53 7c 02    	call   QWORD PTR [rip+0x27c536c]        # 64df620 <__register_atfork@plt+0xeda90>
