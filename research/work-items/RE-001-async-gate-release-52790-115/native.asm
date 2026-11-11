
artifacts/node/115/hl-node:     file format elf64-x86-64


Disassembly of section .text:

0000000005a52790 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2f5ca0>:
 5a52790:	41 56                	push   r14
 5a52792:	53                   	push   rbx
 5a52793:	50                   	push   rax
 5a52794:	80 bf 90 00 00 00 03 	cmp    BYTE PTR [rdi+0x90],0x3
 5a5279b:	75 2a                	jne    5a527c7 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2f5c69>
 5a5279d:	80 bf 88 00 00 00 03 	cmp    BYTE PTR [rdi+0x88],0x3
 5a527a4:	75 21                	jne    5a527c7 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2f5c69>
 5a527a6:	48 89 f8             	mov    rax,rdi
 5a527a9:	48 83 c7 20          	add    rdi,0x20
 5a527ad:	49 89 c6             	mov    r14,rax
 5a527b0:	80 78 18 00          	cmp    BYTE PTR [rax+0x18],0x0
 5a527b4:	74 19                	je     5a527cf <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2f5c61>
 5a527b6:	48 8b 07             	mov    rax,QWORD PTR [rdi]
 5a527b9:	f0 48 ff 08          	lock dec QWORD PTR [rax]
 5a527bd:	75 1f                	jne    5a527de <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2f5c52>
 5a527bf:	ff 15 03 d6 a8 00    	call   QWORD PTR [rip+0xa8d603]        # 64dfdc8 <__register_atfork@plt+0xee238>
 5a527c5:	eb 17                	jmp    5a527de <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2f5c52>
 5a527c7:	48 83 c4 08          	add    rsp,0x8
 5a527cb:	5b                   	pop    rbx
 5a527cc:	41 5e                	pop    r14
 5a527ce:	c3                   	ret
 5a527cf:	48 8b 07             	mov    rax,QWORD PTR [rdi]
 5a527d2:	f0 48 ff 08          	lock dec QWORD PTR [rax]
 5a527d6:	75 06                	jne    5a527de <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2f5c52>
 5a527d8:	ff 15 da d5 a8 00    	call   QWORD PTR [rip+0xa8d5da]        # 64dfdb8 <__register_atfork@plt+0xee228>
 5a527de:	4c 89 f7             	mov    rdi,r14
 5a527e1:	48 83 c7 28          	add    rdi,0x28
 5a527e5:	48 83 c4 08          	add    rsp,0x8
 5a527e9:	5b                   	pop    rbx
 5a527ea:	41 5e                	pop    r14
 5a527ec:	e9 9f fc ff ff       	jmp    5a52490 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2f5fa0>
 5a527f1:	48 89 c3             	mov    rbx,rax
 5a527f4:	4c 89 f7             	mov    rdi,r14
 5a527f7:	48 83 c7 28          	add    rdi,0x28
 5a527fb:	e8 90 fc ff ff       	call   5a52490 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x2f5fa0>
 5a52800:	48 89 df             	mov    rdi,rbx
 5a52803:	e8 48 e2 99 00       	call   63f0a50 <_Unwind_Resume@plt>
 5a52808:	ff 15 b2 cc a8 00    	call   QWORD PTR [rip+0xa8ccb2]        # 64df4c0 <__register_atfork@plt+0xed930>
