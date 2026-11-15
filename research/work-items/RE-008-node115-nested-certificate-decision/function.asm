
hl-node:     file format elf64-x86-64


Disassembly of section .text:

000000000595fd20 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e8710>:
 595fd20:	push   %r15
 595fd22:	push   %r14
 595fd24:	push   %rbx
 595fd25:	sub    $0xd0,%rsp
 595fd2c:	mov    %rdi,%rbx
 595fd2f:	mov    %rsi,0x70(%rsp)
 595fd34:	mov    0x20(%rsi),%rcx
 595fd38:	mov    0x28(%rsi),%rax
 595fd3c:	mov    0x50(%rdx),%rdi
 595fd40:	mov    0x58(%rdx),%r8
 595fd44:	mov    %rcx,%r9
 595fd47:	xor    %rdi,%r9
 595fd4a:	mov    %rax,%r10
 595fd4d:	xor    %r8,%r10
 595fd50:	or     %r9,%r10
 595fd53:	jne    595fd6a <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e86c6>
 595fd55:	mov    0x30(%rsi),%rdi
 595fd59:	cmp    %rax,%rdi
 595fd5c:	jae    595fde5 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e864b>
 595fd62:	movb   $0x5,(%rbx)
 595fd65:	jmp    595ff68 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e84c8>
 595fd6a:	movb   $0x0,0x78(%rsp)
 595fd6f:	mov    %rcx,0x80(%rsp)
 595fd77:	mov    %rax,0x88(%rsp)
 595fd7f:	mov    %rdi,0x90(%rsp)
 595fd87:	mov    %r8,0x98(%rsp)
 595fd8f:	cmp    %rdi,%rcx
 595fd92:	jbe    595fef2 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e853e>
 595fd98:	lea    0x8(%rsp),%rdi
 595fd9d:	mov    %rsi,%r15
 595fda0:	mov    %rdx,%r14
 595fda3:	call   595f880 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e8bb0>
 595fda8:	movzbl 0x8(%rsp),%ecx
 595fdad:	cmp    $0x2e,%ecx
 595fdb0:	je     595ff78 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e84b8>
 595fdb6:	cmp    $0x10,%ecx
 595fdb9:	je     595fec1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e856f>
 595fdbf:	lea    0x18(%rsp),%rax
 595fdc4:	cmp    $0x13,%ecx
 595fdc7:	je     595fdd2 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e865e>
 595fdc9:	cmp    $0x20,%ecx
 595fdcc:	jne    595fef2 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e853e>
 595fdd2:	mov    0x10(%rsp),%rsi
 595fdd7:	test   %rsi,%rsi
 595fdda:	jne    595fee7 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e8549>
 595fde0:	jmp    595fef2 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e853e>
 595fde5:	jne    595fe81 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e85af>
 595fdeb:	mov    %rcx,0x28(%rsp)
 595fdf0:	mov    %rax,0x30(%rsp)
 595fdf5:	mov    %rax,0x38(%rsp)
 595fdfa:	mov    %rax,0x40(%rsp)
 595fdff:	mov    %rax,0x48(%rsp)
 595fe04:	pxor   %xmm0,%xmm0
 595fe08:	movdqu %xmm0,0x50(%rsp)
 595fe0e:	movdqu %xmm0,0x60(%rsp)
 595fe14:	movq   $0x0,0x8(%rsp)
 595fe1d:	movq   $0x8,0x10(%rsp)
 595fe26:	movdqu %xmm0,0x18(%rsp)
 595fe2c:	cmp    %rax,0x38(%rsi)
 595fe30:	jne    595fea5 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e858b>
 595fe32:	cmp    %rax,0x40(%rsi)
 595fe36:	jne    595fea5 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e858b>
 595fe38:	movdqu 0x48(%rsi),%xmm0
 595fe3d:	movdqu 0x58(%rsi),%xmm1
 595fe42:	movdqu 0x50(%rsp),%xmm2
 595fe48:	pcmpeqb %xmm0,%xmm2
 595fe4c:	movdqu 0x60(%rsp),%xmm0
 595fe52:	pcmpeqb %xmm1,%xmm0
 595fe56:	pand   %xmm2,%xmm0
 595fe5a:	pmovmskb %xmm0,%eax
 595fe5e:	cmp    $0xffff,%eax
 595fe63:	jne    595fea5 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e858b>
 595fe65:	lea    0x8(%rsp),%rax
 595fe6a:	mov    %rsi,%rdi
 595fe6d:	mov    %rax,%rsi
 595fe70:	call   4e08870 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf3fbc0>
 595fe75:	test   %al,%al
 595fe77:	je     595fea5 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e858b>
 595fe79:	movb   $0x2e,(%rbx)
 595fe7c:	jmp    595ff68 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e84c8>
 595fe81:	mov    0x38(%rsi),%rcx
 595fe85:	mov    0x40(%rsi),%r8
 595fe89:	cmp    %rdi,%rcx
 595fe8c:	jae    595fead <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e8583>
 595fe8e:	cmp    %r8,%rax
 595fe91:	ja     595fead <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e8583>
 595fe93:	cmp    %rcx,%r8
 595fe96:	ja     595fead <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e8583>
 595fe98:	mov    %rbx,%rdi
 595fe9b:	call   595f880 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e8bb0>
 595fea0:	jmp    595ff68 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e84c8>
 595fea5:	movb   $0x6,(%rbx)
 595fea8:	jmp    595ff68 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e84c8>
 595fead:	movb   $0x2d,(%rbx)
 595feb0:	mov    %rdi,0x8(%rbx)
 595feb4:	mov    %rcx,0x10(%rbx)
 595feb8:	mov    %r8,0x18(%rbx)
 595febc:	jmp    595ff68 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e84c8>
 595fec1:	mov    0x10(%rsp),%rsi
 595fec6:	test   %rsi,%rsi
 595fec9:	je     595fed8 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e8558>
 595fecb:	mov    0x18(%rsp),%rdi
 595fed0:	xor    %edx,%edx
 595fed2:	call   *0xb7f5c8(%rip)        # 64df4a0 <__register_atfork@plt+0xed910>
 595fed8:	mov    0x28(%rsp),%rsi
 595fedd:	test   %rsi,%rsi
 595fee0:	je     595fef2 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e853e>
 595fee2:	lea    0x30(%rsp),%rax
 595fee7:	mov    (%rax),%rdi
 595feea:	xor    %edx,%edx
 595feec:	call   *0xb7f5ae(%rip)        # 64df4a0 <__register_atfork@plt+0xed910>
 595fef2:	mov    0xb8(%rsp),%rax
 595fefa:	mov    %rax,0x40(%rbx)
 595fefe:	movzbl 0x78(%rsp),%eax
 595ff03:	mov    0x79(%rsp),%ecx
 595ff07:	movzwl 0x7d(%rsp),%edx
 595ff0c:	movzbl 0x7f(%rsp),%esi
 595ff11:	mov    0x80(%rsp),%rdi
 595ff19:	mov    0x88(%rsp),%r8
 595ff21:	mov    0x90(%rsp),%r9
 595ff29:	mov    0x98(%rsp),%r10
 595ff31:	mov    0xa0(%rsp),%r11
 595ff39:	movdqu 0xa8(%rsp),%xmm0
 595ff42:	movdqu %xmm0,0x30(%rbx)
 595ff47:	mov    %r10,0x20(%rbx)
 595ff4b:	mov    %r11,0x28(%rbx)
 595ff4f:	mov    %r8,0x10(%rbx)
 595ff53:	mov    %r9,0x18(%rbx)
 595ff57:	mov    %al,(%rbx)
 595ff59:	mov    %ecx,0x1(%rbx)
 595ff5c:	mov    %dx,0x5(%rbx)
 595ff60:	mov    %sil,0x7(%rbx)
 595ff64:	mov    %rdi,0x8(%rbx)
 595ff68:	mov    %rbx,%rax
 595ff6b:	add    $0xd0,%rsp
 595ff72:	pop    %rbx
 595ff73:	pop    %r14
 595ff75:	pop    %r15
 595ff77:	ret
 595ff78:	add    $0x20,%r15
 595ff7c:	movups 0x50(%r14),%xmm0
 595ff81:	movaps %xmm0,0xc0(%rsp)
 595ff89:	lea    0xc0(%rsp),%rax
 595ff91:	mov    %rax,0x8(%rsp)
 595ff96:	mov    0xb8a723(%rip),%rax        # 64ea6c0 <__register_atfork@plt+0xf8b30>
 595ff9d:	mov    %rax,0x10(%rsp)
 595ffa2:	mov    %r15,0x18(%rsp)
 595ffa7:	mov    %rax,0x20(%rsp)
 595ffac:	lea    0x70(%rsp),%rax
 595ffb1:	mov    %rax,0x28(%rsp)
 595ffb6:	lea    -0x1f8ed(%rip),%rax        # 59406d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x407d60>
 595ffbd:	mov    %rax,0x30(%rsp)
 595ffc2:	lea    -0x55280f0(%rip),%rdi        # 437ed9 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5910557>
 595ffc9:	lea    0xb568e0(%rip),%rdx        # 64b68b0 <__register_atfork@plt+0xc4d20>
 595ffd0:	lea    0x8(%rsp),%rsi
 595ffd5:	call   *0xb7f6dd(%rip)        # 64df6b8 <__register_atfork@plt+0xedb28>
 595ffdb:	ud2
 595ffdd:	mov    %rax,%rbx
 595ffe0:	lea    0x8(%rsp),%rdi
 595ffe5:	call   5953240 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3f51f0>
 595ffea:	mov    %rbx,%rdi
 595ffed:	call   63f0a50 <_Unwind_Resume@plt>
 595fff2:	call   *0xb7f4c8(%rip)        # 64df4c0 <__register_atfork@plt+0xed930>
 595fff8:	mov    %rax,%rbx
 595fffb:	lea    0x78(%rsp),%rdi
 5960000:	call   59539d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3f4a60>
 5960005:	mov    %rbx,%rdi
 5960008:	call   63f0a50 <_Unwind_Resume@plt>

hl-node:     file format elf64-x86-64


Disassembly of section .text:

000000000595f880 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e8bb0>:
 595f880:	push   %rbp
 595f881:	push   %r15
 595f883:	push   %r14
 595f885:	push   %r13
 595f887:	push   %r12
 595f889:	push   %rbx
 595f88a:	sub    $0x118,%rsp
 595f891:	mov    %rdx,%r13
 595f894:	mov    %rsi,%r14
 595f897:	mov    %rdi,%rbx
 595f89a:	mov    0x40(%rsi),%r15
 595f89e:	mov    %rsp,%rdi
 595f8a1:	mov    %rdx,%rsi
 595f8a4:	mov    %r15,%rdx
 595f8a7:	call   *0xb86c03(%rip)        # 64e64b0 <__register_atfork@plt+0xf4920>
 595f8ad:	movzbl (%rsp),%eax
 595f8b1:	cmp    $0x2e,%al
 595f8b3:	jne    595f947 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e8ae9>
 595f8b9:	mov    0x8(%rsp),%r12
 595f8be:	mov    %rsp,%rdi
 595f8c1:	mov    %r12,%rsi
 595f8c4:	mov    %r14,%rdx
 595f8c7:	call   4e00160 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf482d0>
 595f8cc:	movzbl (%rsp),%eax
 595f8d0:	cmp    $0x2e,%al
 595f8d2:	jne    595f989 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e8aa7>
 595f8d8:	mov    0x18(%rsp),%rax
 595f8dd:	movups 0x8(%rsp),%xmm0
 595f8e2:	movaps %xmm0,0x60(%rsp)
 595f8e7:	mov    %rax,0x70(%rsp)
 595f8ec:	mov    0x30(%r14),%rax
 595f8f0:	mov    %rax,0xc8(%rsp)
 595f8f8:	lea    0x60(%rsp),%rdx
 595f8fd:	mov    %r13,%rdi
 595f900:	mov    %r12,%rsi
 595f903:	call   *0xb88e77(%rip)        # 64e8780 <__register_atfork@plt+0xf6bf0>
 595f909:	test   %al,%al
 595f90b:	je     595f9dd <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e8a53>
 595f911:	mov    (%r14),%rax
 595f914:	mov    %rax,%rcx
 595f917:	neg    %rcx
 595f91a:	jno    595fa28 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e8a08>
 595f920:	mov    0x8(%r14),%rax
 595f924:	xor    %edx,%edx
 595f926:	mov    %rax,%rdi
 595f929:	test   %rax,%rax
 595f92c:	setne  %sil
 595f930:	je     595f936 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e8afa>
 595f932:	mov    0x18(%r14),%rdi
 595f936:	mov    0x10(%r14),%rcx
 595f93a:	mov    %sil,%dl
 595f93d:	xor    %esi,%esi
 595f93f:	mov    %rdx,%r8
 595f942:	jmp    595fa8a <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e89a6>
 595f947:	mov    0x1(%rsp),%ecx
 595f94b:	mov    0x4(%rsp),%edx
 595f94f:	mov    %edx,0x4(%rbx)
 595f952:	mov    %ecx,0x1(%rbx)
 595f955:	mov    0x8(%rsp),%rcx
 595f95a:	movups 0x20(%rsp),%xmm0
 595f95f:	movups %xmm0,0x20(%rbx)
 595f963:	movups 0x30(%rsp),%xmm0
 595f968:	movups %xmm0,0x30(%rbx)
 595f96c:	mov    0x40(%rsp),%rdx
 595f971:	mov    %rdx,0x40(%rbx)
 595f975:	movups 0x10(%rsp),%xmm0
 595f97a:	movups %xmm0,0x10(%rbx)
 595f97e:	mov    %al,(%rbx)
 595f980:	mov    %rcx,0x8(%rbx)
 595f984:	jmp    595fce6 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e874a>
 595f989:	movups 0x1(%rsp),%xmm0
 595f98e:	movups 0x10(%rsp),%xmm1
 595f993:	movups 0x20(%rsp),%xmm2
 595f998:	movups 0x30(%rsp),%xmm3
 595f99d:	movups %xmm1,0x8f(%rsp)
 595f9a5:	movaps %xmm0,0x80(%rsp)
 595f9ad:	mov    0x40(%rsp),%rcx
 595f9b2:	mov    %rcx,0x40(%rbx)
 595f9b6:	movups %xmm3,0x30(%rbx)
 595f9ba:	movups %xmm2,0x20(%rbx)
 595f9be:	movups 0x8f(%rsp),%xmm0
 595f9c6:	movups %xmm0,0x10(%rbx)
 595f9ca:	movaps 0x80(%rsp),%xmm0
 595f9d2:	movups %xmm0,0x1(%rbx)
 595f9d6:	mov    %al,(%rbx)
 595f9d8:	jmp    595fce6 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e874a>
 595f9dd:	movb   $0x7,(%rbx)
 595f9e0:	mov    0x60(%rsp),%rcx
 595f9e5:	test   %rcx,%rcx
 595f9e8:	je     595fc64 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e87cc>
 595f9ee:	mov    0x68(%rsp),%rdx
 595f9f3:	mov    0x70(%rsp),%rax
 595f9f8:	movq   $0x0,0x8(%rsp)
 595fa01:	mov    %rcx,0x10(%rsp)
 595fa06:	mov    %rdx,0x18(%rsp)
 595fa0b:	movq   $0x0,0x28(%rsp)
 595fa14:	mov    %rcx,0x30(%rsp)
 595fa19:	mov    %rdx,0x38(%rsp)
 595fa1e:	mov    $0x1,%ecx
 595fa23:	jmp    595fc68 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e87c8>
 595fa28:	mov    0x18(%r14),%rcx
 595fa2c:	test   %rcx,%rcx
 595fa2f:	je     595fa59 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e89d7>
 595fa31:	mov    0x10(%r14),%rdx
 595fa35:	xor    %esi,%esi
 595fa37:	cmp    %rax,%rdx
 595fa3a:	cmovae %rax,%rsi
 595fa3e:	sub    %rsi,%rdx
 595fa41:	mov    %rax,%rsi
 595fa44:	sub    %rdx,%rsi
 595fa47:	mov    %rcx,%rdi
 595fa4a:	sub    %rsi,%rdi
 595fa4d:	ja     595fa5f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e89d1>
 595fa4f:	add    %rdx,%rcx
 595fa52:	xor    %edi,%edi
 595fa54:	mov    %rcx,%rax
 595fa57:	jmp    595fa5f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e89d1>
 595fa59:	xor    %edx,%edx
 595fa5b:	xor    %eax,%eax
 595fa5d:	xor    %edi,%edi
 595fa5f:	mov    0x8(%r14),%rcx
 595fa63:	lea    (%rdx,%rdx,2),%rsi
 595fa67:	shl    $0x5,%rsi
 595fa6b:	add    %rcx,%rsi
 595fa6e:	lea    (%rax,%rax,2),%rax
 595fa72:	shl    $0x5,%rax
 595fa76:	add    %rcx,%rax
 595fa79:	lea    (%rdi,%rdi,2),%rdx
 595fa7d:	shl    $0x5,%rdx
 595fa81:	add    %rcx,%rdx
 595fa84:	mov    $0x2,%r8d
 595fa8a:	mov    %r8,0x80(%rsp)
 595fa92:	mov    %rsi,0x88(%rsp)
 595fa9a:	mov    %rax,0x90(%rsp)
 595faa2:	mov    %rcx,0x98(%rsp)
 595faaa:	mov    %rdx,0xa0(%rsp)
 595fab2:	movq   $0x0,0xa8(%rsp)
 595fabe:	mov    %rax,0xb0(%rsp)
 595fac6:	mov    %rcx,0xb8(%rsp)
 595face:	mov    %rdi,0xc0(%rsp)
 595fad6:	movups 0x20(%r14),%xmm0
 595fadb:	movaps %xmm0,0x100(%rsp)
 595fae3:	mov    0x38(%r14),%rbp
 595fae7:	add    $0x48,%r14
 595faeb:	lea    0x48(%rsp),%r13
 595faf0:	cmpl   $0x2,0x80(%rsp)
 595faf8:	jne    595fb60 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e88d0>
 595fafa:	mov    0x88(%rsp),%rax
 595fb02:	mov    0x90(%rsp),%rcx
 595fb0a:	cmp    %rcx,%rax
 595fb0d:	jne    595fb44 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e88ec>
 595fb0f:	lea    0x88(%rsp),%rdx
 595fb17:	movups 0x10(%rdx),%xmm0
 595fb1b:	movups %xmm0,(%rdx)
 595fb1e:	mov    %rax,0x98(%rsp)
 595fb26:	mov    %rcx,0xa0(%rsp)
 595fb2e:	mov    0x88(%rsp),%rax
 595fb36:	cmp    0x90(%rsp),%rax
 595fb3e:	je     595fc04 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e882c>
 595fb44:	lea    0x60(%rax),%rcx
 595fb48:	mov    %rcx,0x88(%rsp)
 595fb50:	lea    0x18(%rax),%rdx
 595fb54:	jmp    595fb6d <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e88c3>
 595fb56:	cs nopw 0x0(%rax,%rax,1)
 595fb60:	lea    0x80(%rsp),%rdi
 595fb68:	call   513b200 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc0d230>
 595fb6d:	test   %rax,%rax
 595fb70:	je     595fc0b <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e8825>
 595fb76:	mov    0x10(%rax),%ecx
 595fb79:	mov    %ecx,0xf0(%rsp)
 595fb80:	movups (%rax),%xmm0
 595fb83:	movaps %xmm0,0xe0(%rsp)
 595fb8b:	movups (%r14),%xmm1
 595fb8f:	movups 0x10(%r14),%xmm2
 595fb94:	movaps %xmm2,0x10(%rsp)
 595fb99:	movaps %xmm1,(%rsp)
 595fb9d:	mov    %ecx,0x10(%r13)
 595fba1:	movups %xmm0,0x0(%r13)
 595fba6:	movaps 0x100(%rsp),%xmm0
 595fbae:	movaps %xmm0,0x20(%rsp)
 595fbb3:	mov    0xc8(%rsp),%rax
 595fbbb:	mov    %rax,0x30(%rsp)
 595fbc0:	mov    %rbp,0x38(%rsp)
 595fbc5:	mov    %r15,0x40(%rsp)
 595fbca:	mov    %rsp,%rax
 595fbcd:	mov    %rax,0xd8(%rsp)
 595fbd5:	movq   $0x1,0xd0(%rsp)
 595fbe1:	lea    0xd0(%rsp),%rdi
 595fbe9:	lea    0xe0(%rsp),%rsi
 595fbf1:	mov    %r12,%rcx
 595fbf4:	call   *0xb868be(%rip)        # 64e64b8 <__register_atfork@plt+0xf4928>
 595fbfa:	test   %al,%al
 595fbfc:	jne    595faf0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e8940>
 595fc02:	jmp    595fc53 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e87dd>
 595fc04:	xor    %eax,%eax
 595fc06:	jmp    595fb50 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e88e0>
 595fc0b:	movb   $0x2e,(%rbx)
 595fc0e:	mov    0x60(%rsp),%rcx
 595fc13:	test   %rcx,%rcx
 595fc16:	je     595fca8 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e8788>
 595fc1c:	mov    0x68(%rsp),%rdx
 595fc21:	mov    0x70(%rsp),%rax
 595fc26:	movq   $0x0,0x8(%rsp)
 595fc2f:	mov    %rcx,0x10(%rsp)
 595fc34:	mov    %rdx,0x18(%rsp)
 595fc39:	movq   $0x0,0x28(%rsp)
 595fc42:	mov    %rcx,0x30(%rsp)
 595fc47:	mov    %rdx,0x38(%rsp)
 595fc4c:	mov    $0x1,%ecx
 595fc51:	jmp    595fcac <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e8784>
 595fc53:	movb   $0x2,(%rbx)
 595fc56:	mov    0x60(%rsp),%rcx
 595fc5b:	test   %rcx,%rcx
 595fc5e:	jne    595f9ee <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e8a42>
 595fc64:	xor    %ecx,%ecx
 595fc66:	xor    %eax,%eax
 595fc68:	mov    %rcx,(%rsp)
 595fc6c:	mov    %rcx,0x20(%rsp)
 595fc71:	mov    %rax,0x40(%rsp)
 595fc76:	lea    0x80(%rsp),%rbx
 595fc7e:	mov    %rsp,%r14
 595fc81:	data16 data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
 595fc90:	mov    %rbx,%rdi
 595fc93:	mov    %r14,%rsi
 595fc96:	call   51dc470 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xb6bfc0>
 595fc9b:	cmpq   $0x0,0x80(%rsp)
 595fca4:	jne    595fc90 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e87a0>
 595fca6:	jmp    595fce6 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e874a>
 595fca8:	xor    %ecx,%ecx
 595fcaa:	xor    %eax,%eax
 595fcac:	mov    %rcx,(%rsp)
 595fcb0:	mov    %rcx,0x20(%rsp)
 595fcb5:	mov    %rax,0x40(%rsp)
 595fcba:	lea    0x80(%rsp),%rbx
 595fcc2:	mov    %rsp,%r14
 595fcc5:	data16 cs nopw 0x0(%rax,%rax,1)
 595fcd0:	mov    %rbx,%rdi
 595fcd3:	mov    %r14,%rsi
 595fcd6:	call   51dc470 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xb6bfc0>
 595fcdb:	cmpq   $0x0,0x80(%rsp)
 595fce4:	jne    595fcd0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e8760>
 595fce6:	add    $0x118,%rsp
 595fced:	pop    %rbx
 595fcee:	pop    %r12
 595fcf0:	pop    %r13
 595fcf2:	pop    %r14
 595fcf4:	pop    %r15
 595fcf6:	pop    %rbp
 595fcf7:	ret
 595fcf8:	jmp    595fcfc <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e8734>
 595fcfa:	jmp    595fcfc <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e8734>
 595fcfc:	mov    %rax,%rbx
 595fcff:	lea    0x60(%rsp),%rdi
 595fd04:	call   5242510 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xb05f20>
 595fd09:	mov    %rbx,%rdi
 595fd0c:	call   63f0a50 <_Unwind_Resume@plt>
 595fd11:	call   *0xb7f7a9(%rip)        # 64df4c0 <__register_atfork@plt+0xed930>

hl-node:     file format elf64-x86-64


Disassembly of section .text:

0000000004e08870 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf3fbc0>:
 4e08870:	mov    0x18(%rdi),%rax
 4e08874:	cmp    0x18(%rsi),%rax
 4e08878:	jne    4e088bb <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf3fb75>
 4e0887a:	push   %rbx
 4e0887b:	sub    $0x90,%rsp
 4e08882:	mov    (%rsi),%rcx
 4e08885:	movabs $0x8000000000000000,%rdx
 4e0888f:	mov    (%rdi),%r8
 4e08892:	mov    %r8,%r9
 4e08895:	neg    %r9
 4e08898:	jno    4e088be <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf3fb72>
 4e0889a:	mov    0x8(%rdi),%r8
 4e0889e:	mov    0x10(%rdi),%rdi
 4e088a2:	xor    %r9d,%r9d
 4e088a5:	test   %r8,%r8
 4e088a8:	setne  %r9b
 4e088ac:	mov    %rax,%r11
 4e088af:	cmove  %r8,%r11
 4e088b3:	xor    %r10d,%r10d
 4e088b6:	mov    %r9,%rbx
 4e088b9:	jmp    4e0891b <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf3fb15>
 4e088bb:	xor    %eax,%eax
 4e088bd:	ret
 4e088be:	test   %rax,%rax
 4e088c1:	je     4e088e8 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf3fb48>
 4e088c3:	mov    0x10(%rdi),%r9
 4e088c7:	xor    %r10d,%r10d
 4e088ca:	cmp    %r8,%r9
 4e088cd:	cmovae %r8,%r10
 4e088d1:	sub    %r10,%r9
 4e088d4:	mov    %r8,%r10
 4e088d7:	sub    %r9,%r10
 4e088da:	mov    %rax,%r11
 4e088dd:	sub    %r10,%r11
 4e088e0:	ja     4e088f1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf3fb3f>
 4e088e2:	lea    (%r9,%rax,1),%r8
 4e088e6:	jmp    4e088ee <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf3fb42>
 4e088e8:	xor    %r9d,%r9d
 4e088eb:	xor    %r8d,%r8d
 4e088ee:	xor    %r11d,%r11d
 4e088f1:	mov    0x8(%rdi),%rdi
 4e088f5:	lea    (%r9,%r9,2),%r10
 4e088f9:	shl    $0x5,%r10
 4e088fd:	add    %rdi,%r10
 4e08900:	lea    (%r8,%r8,2),%r8
 4e08904:	shl    $0x5,%r8
 4e08908:	add    %rdi,%r8
 4e0890b:	lea    (%r11,%r11,2),%r9
 4e0890f:	shl    $0x5,%r9
 4e08913:	add    %rdi,%r9
 4e08916:	mov    $0x2,%ebx
 4e0891b:	mov    %rbx,(%rsp)
 4e0891f:	mov    %r10,0x8(%rsp)
 4e08924:	mov    %r8,0x10(%rsp)
 4e08929:	mov    %rdi,0x18(%rsp)
 4e0892e:	mov    %r9,0x20(%rsp)
 4e08933:	movq   $0x0,0x28(%rsp)
 4e0893c:	mov    %r8,0x30(%rsp)
 4e08941:	mov    %rdi,0x38(%rsp)
 4e08946:	mov    %r11,0x40(%rsp)
 4e0894b:	cmp    %rdx,%rcx
 4e0894e:	jne    4e0896c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf3fac4>
 4e08950:	mov    0x8(%rsi),%rcx
 4e08954:	mov    0x10(%rsi),%rdx
 4e08958:	xor    %esi,%esi
 4e0895a:	test   %rcx,%rcx
 4e0895d:	setne  %sil
 4e08961:	cmove  %rcx,%rax
 4e08965:	xor    %edi,%edi
 4e08967:	mov    %rsi,%r8
 4e0896a:	jmp    4e089cc <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf3fa64>
 4e0896c:	test   %rax,%rax
 4e0896f:	je     4e0899a <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf3fa96>
 4e08971:	mov    0x10(%rsi),%rdi
 4e08975:	xor    %edx,%edx
 4e08977:	cmp    %rcx,%rdi
 4e0897a:	cmovae %rcx,%rdx
 4e0897e:	sub    %rdx,%rdi
 4e08981:	mov    %rcx,%rdx
 4e08984:	sub    %rdi,%rdx
 4e08987:	mov    %rax,%r8
 4e0898a:	sub    %rdx,%r8
 4e0898d:	ja     4e089a1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf3fa8f>
 4e0898f:	add    %rdi,%rax
 4e08992:	xor    %r8d,%r8d
 4e08995:	mov    %rax,%rcx
 4e08998:	jmp    4e089a1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf3fa8f>
 4e0899a:	xor    %edi,%edi
 4e0899c:	xor    %ecx,%ecx
 4e0899e:	xor    %r8d,%r8d
 4e089a1:	mov    0x8(%rsi),%rdx
 4e089a5:	lea    (%rdi,%rdi,2),%rdi
 4e089a9:	shl    $0x5,%rdi
 4e089ad:	add    %rdx,%rdi
 4e089b0:	lea    (%rcx,%rcx,2),%rcx
 4e089b4:	shl    $0x5,%rcx
 4e089b8:	add    %rdx,%rcx
 4e089bb:	lea    (%r8,%r8,2),%rsi
 4e089bf:	shl    $0x5,%rsi
 4e089c3:	add    %rdx,%rsi
 4e089c6:	mov    $0x2,%r8d
 4e089cc:	mov    %r8,0x48(%rsp)
 4e089d1:	mov    %rdi,0x50(%rsp)
 4e089d6:	mov    %rcx,0x58(%rsp)
 4e089db:	mov    %rdx,0x60(%rsp)
 4e089e0:	mov    %rsi,0x68(%rsp)
 4e089e5:	movq   $0x0,0x70(%rsp)
 4e089ee:	mov    %rcx,0x78(%rsp)
 4e089f3:	mov    %rdx,0x80(%rsp)
 4e089fb:	mov    %rax,0x88(%rsp)
 4e08a03:	mov    %rsp,%rdi
 4e08a06:	lea    0x48(%rsp),%rsi
 4e08a0b:	call   4e550e0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef3350>
 4e08a10:	add    $0x90,%rsp
 4e08a17:	pop    %rbx
 4e08a18:	ret

hl-node:     file format elf64-x86-64


Disassembly of section .text:

0000000004e550e0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef3350>:
 4e550e0:	push   %rbp
 4e550e1:	push   %r15
 4e550e3:	push   %r14
 4e550e5:	push   %r13
 4e550e7:	push   %r12
 4e550e9:	push   %rbx
 4e550ea:	sub    $0x18,%rsp
 4e550ee:	mov    (%rdi),%r15
 4e550f1:	mov    0x8(%rdi),%r11
 4e550f5:	mov    0x10(%rdi),%rbx
 4e550f9:	mov    0x18(%rdi),%r9
 4e550fd:	mov    0x20(%rdi),%rax
 4e55101:	mov    %rax,0x8(%rsp)
 4e55106:	mov    0x40(%rdi),%rdi
 4e5510a:	mov    (%rsi),%r14
 4e5510d:	mov    0x8(%rsi),%rdx
 4e55111:	mov    0x10(%rsi),%r10
 4e55115:	mov    0x18(%rsi),%r8
 4e55119:	mov    0x20(%rsi),%rax
 4e5511d:	mov    %rax,(%rsp)
 4e55121:	mov    0x40(%rsi),%rax
 4e55125:	mov    %rax,0x10(%rsp)
 4e5512a:	nopw   0x0(%rax,%rax,1)
 4e55130:	cmp    $0x2,%r15
 4e55134:	jne    4e55160 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef32d0>
 4e55136:	cmp    %rbx,%r11
 4e55139:	jne    4e551a0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef3290>
 4e5513b:	cmp    %r9,0x8(%rsp)
 4e55140:	je     4e556b6 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2d7a>
 4e55146:	mov    0x8(%rsp),%rax
 4e5514b:	mov    %rbx,0x8(%rsp)
 4e55150:	mov    %r9,%r13
 4e55153:	test   %r13,%r13
 4e55156:	jne    4e551b2 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef327e>
 4e55158:	jmp    4e556b6 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2d7a>
 4e5515d:	nopl   (%rax)
 4e55160:	test   %rdi,%rdi
 4e55163:	je     4e556b6 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2d7a>
 4e55169:	cmp    $0x1,%r15
 4e5516d:	jne    4e557f1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2c3f>
 4e55173:	test   %r11,%r11
 4e55176:	je     4e55207 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef3229>
 4e5517c:	movzwl 0x3fe(%r11),%eax
 4e55184:	cmp    %rax,%r9
 4e55187:	jae    4e55370 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef30c0>
 4e5518d:	mov    %r11,%r15
 4e55190:	jmp    4e55394 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef309c>
 4e55195:	data16 cs nopw 0x0(%rax,%rax,1)
 4e551a0:	mov    %rbx,%rax
 4e551a3:	mov    %r9,%rbx
 4e551a6:	mov    %r11,%r13
 4e551a9:	test   %r13,%r13
 4e551ac:	je     4e556b6 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2d7a>
 4e551b2:	lea    0x60(%r13),%r11
 4e551b6:	lea    0x18(%r13),%r12
 4e551ba:	mov    $0x2,%r15d
 4e551c0:	mov    %rbx,%r9
 4e551c3:	mov    %rax,%rbx
 4e551c6:	cmp    $0x2,%r14
 4e551ca:	je     4e5545f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2fd1>
 4e551d0:	cmpq   $0x0,0x10(%rsp)
 4e551d6:	je     4e5571f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2d11>
 4e551dc:	cmp    $0x1,%r14
 4e551e0:	jne    4e557f1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2c3f>
 4e551e6:	test   %rdx,%rdx
 4e551e9:	je     4e552a9 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef3187>
 4e551ef:	movzwl 0x3fe(%rdx),%eax
 4e551f6:	cmp    %rax,%r8
 4e551f9:	jae    4e554f0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2f40>
 4e551ff:	mov    %rdx,%r14
 4e55202:	jmp    4e55514 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2f1c>
 4e55207:	test   %r9,%r9
 4e5520a:	je     4e55349 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef30e7>
 4e55210:	mov    %r9,%rax
 4e55213:	mov    %rbx,%r11
 4e55216:	and    $0x7,%rax
 4e5521a:	je     4e55692 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2d9e>
 4e55220:	xor    %ecx,%ecx
 4e55222:	data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
 4e55230:	mov    0x400(%r11),%r11
 4e55237:	inc    %rcx
 4e5523a:	cmp    %rcx,%rax
 4e5523d:	jne    4e55230 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef3200>
 4e5523f:	mov    %r9,%rax
 4e55242:	sub    %rcx,%rax
 4e55245:	cmp    $0x8,%r9
 4e55249:	jb     4e5528e <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef31a2>
 4e5524b:	nopl   0x0(%rax,%rax,1)
 4e55250:	mov    0x400(%r11),%rcx
 4e55257:	mov    0x400(%rcx),%rcx
 4e5525e:	mov    0x400(%rcx),%rcx
 4e55265:	mov    0x400(%rcx),%rcx
 4e5526c:	mov    0x400(%rcx),%rcx
 4e55273:	mov    0x400(%rcx),%rcx
 4e5527a:	mov    0x400(%rcx),%rcx
 4e55281:	mov    0x400(%rcx),%r11
 4e55288:	add    $0xfffffffffffffff8,%rax
 4e5528c:	jne    4e55250 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef31e0>
 4e5528e:	xor    %r9d,%r9d
 4e55291:	xor    %ebx,%ebx
 4e55293:	movzwl 0x3fe(%r11),%eax
 4e5529b:	cmp    %rax,%r9
 4e5529e:	jb     4e5518d <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef32a3>
 4e552a4:	jmp    4e55370 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef30c0>
 4e552a9:	test   %r8,%r8
 4e552ac:	je     4e554d5 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2f5b>
 4e552b2:	mov    %r8,%rax
 4e552b5:	mov    %r10,%rdx
 4e552b8:	and    $0x7,%rax
 4e552bc:	je     4e556a4 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2d8c>
 4e552c2:	xor    %ecx,%ecx
 4e552c4:	data16 data16 cs nopw 0x0(%rax,%rax,1)
 4e552d0:	mov    0x400(%rdx),%rdx
 4e552d7:	inc    %rcx
 4e552da:	cmp    %rcx,%rax
 4e552dd:	jne    4e552d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef3160>
 4e552df:	mov    %r8,%rax
 4e552e2:	sub    %rcx,%rax
 4e552e5:	cmp    $0x8,%r8
 4e552e9:	jb     4e5532e <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef3102>
 4e552eb:	nopl   0x0(%rax,%rax,1)
 4e552f0:	mov    0x400(%rdx),%rcx
 4e552f7:	mov    0x400(%rcx),%rcx
 4e552fe:	mov    0x400(%rcx),%rcx
 4e55305:	mov    0x400(%rcx),%rcx
 4e5530c:	mov    0x400(%rcx),%rcx
 4e55313:	mov    0x400(%rcx),%rcx
 4e5531a:	mov    0x400(%rcx),%rcx
 4e55321:	mov    0x400(%rcx),%rdx
 4e55328:	add    $0xfffffffffffffff8,%rax
 4e5532c:	jne    4e552f0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef3140>
 4e5532e:	xor    %r8d,%r8d
 4e55331:	xor    %r10d,%r10d
 4e55334:	movzwl 0x3fe(%rdx),%eax
 4e5533b:	cmp    %rax,%r8
 4e5533e:	jb     4e551ff <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef3231>
 4e55344:	jmp    4e554f0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2f40>
 4e55349:	xor    %r9d,%r9d
 4e5534c:	mov    %rbx,%r11
 4e5534f:	xor    %ebx,%ebx
 4e55351:	movzwl 0x3fe(%r11),%eax
 4e55359:	cmp    %rax,%r9
 4e5535c:	jb     4e5518d <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef32a3>
 4e55362:	data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
 4e55370:	mov    (%r11),%r15
 4e55373:	test   %r15,%r15
 4e55376:	je     4e557d3 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2c5d>
 4e5537c:	inc    %rbx
 4e5537f:	movzwl 0x3fc(%r11),%r9d
 4e55387:	mov    %r15,%r11
 4e5538a:	cmp    0x3fe(%r15),%r9w
 4e55392:	jae    4e55370 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef30c0>
 4e55394:	test   %rbx,%rbx
 4e55397:	je     4e55425 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef300b>
 4e5539d:	lea    (%r15,%r9,8),%rax
 4e553a1:	add    $0x408,%rax
 4e553a7:	mov    %rbx,%rcx
 4e553aa:	and    $0x7,%rcx
 4e553ae:	je     4e554c3 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2f6d>
 4e553b4:	xor    %r13d,%r13d
 4e553b7:	nopw   0x0(%rax,%rax,1)
 4e553c0:	mov    (%rax),%r11
 4e553c3:	lea    0x400(%r11),%rax
 4e553ca:	inc    %r13
 4e553cd:	cmp    %r13,%rcx
 4e553d0:	jne    4e553c0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef3070>
 4e553d2:	mov    %rbx,%r12
 4e553d5:	sub    %r13,%r12
 4e553d8:	cmp    $0x8,%rbx
 4e553dc:	jb     4e55421 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef300f>
 4e553de:	xchg   %ax,%ax
 4e553e0:	mov    (%rax),%rax
 4e553e3:	mov    0x400(%rax),%rax
 4e553ea:	mov    0x400(%rax),%rax
 4e553f1:	mov    0x400(%rax),%rax
 4e553f8:	mov    0x400(%rax),%rax
 4e553ff:	mov    0x400(%rax),%rax
 4e55406:	mov    0x400(%rax),%rax
 4e5540d:	mov    0x400(%rax),%r11
 4e55414:	lea    0x400(%r11),%rax
 4e5541b:	add    $0xfffffffffffffff8,%r12
 4e5541f:	jne    4e553e0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef3050>
 4e55421:	xor    %eax,%eax
 4e55423:	jmp    4e5542c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef3004>
 4e55425:	lea    0x1(%r9),%rax
 4e55429:	mov    %r15,%r11
 4e5542c:	dec    %rdi
 4e5542f:	lea    (%r9,%r9,4),%rcx
 4e55433:	lea    (%r15,%rcx,4),%r13
 4e55437:	add    $0x320,%r13
 4e5543e:	lea    (%r9,%r9,8),%rcx
 4e55442:	lea    (%r15,%rcx,8),%r12
 4e55446:	add    $0x8,%r12
 4e5544a:	mov    $0x1,%r15d
 4e55450:	mov    %rax,%r9
 4e55453:	xor    %ebx,%ebx
 4e55455:	cmp    $0x2,%r14
 4e55459:	jne    4e551d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef3260>
 4e5545f:	cmp    %r10,%rdx
 4e55462:	jne    4e55490 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2fa0>
 4e55464:	mov    (%rsp),%rcx
 4e55468:	cmp    %r8,%rcx
 4e5546b:	je     4e5571f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2d11>
 4e55471:	mov    %r10,%rdx
 4e55474:	mov    %r8,%rax
 4e55477:	test   %rax,%rax
 4e5547a:	jne    4e554a6 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2f8a>
 4e5547c:	jmp    4e5571f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2d11>
 4e55481:	data16 data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
 4e55490:	mov    %r10,%rcx
 4e55493:	mov    %r8,%r10
 4e55496:	mov    %rdx,%rax
 4e55499:	mov    (%rsp),%rdx
 4e5549d:	test   %rax,%rax
 4e554a0:	je     4e5571f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2d11>
 4e554a6:	mov    %rdx,(%rsp)
 4e554aa:	lea    0x60(%rax),%rdx
 4e554ae:	lea    0x18(%rax),%rbp
 4e554b2:	mov    $0x2,%r14d
 4e554b8:	mov    %r10,%r8
 4e554bb:	mov    %rcx,%r10
 4e554be:	jmp    4e555d7 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2e59>
 4e554c3:	mov    %rbx,%r12
 4e554c6:	cmp    $0x8,%rbx
 4e554ca:	jae    4e553e0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef3050>
 4e554d0:	jmp    4e55421 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef300f>
 4e554d5:	xor    %r8d,%r8d
 4e554d8:	mov    %r10,%rdx
 4e554db:	xor    %r10d,%r10d
 4e554de:	movzwl 0x3fe(%rdx),%eax
 4e554e5:	cmp    %rax,%r8
 4e554e8:	jb     4e551ff <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef3231>
 4e554ee:	xchg   %ax,%ax
 4e554f0:	mov    (%rdx),%r14
 4e554f3:	test   %r14,%r14
 4e554f6:	je     4e557e2 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2c4e>
 4e554fc:	inc    %r10
 4e554ff:	movzwl 0x3fc(%rdx),%r8d
 4e55507:	mov    %r14,%rdx
 4e5550a:	cmp    0x3fe(%r14),%r8w
 4e55512:	jae    4e554f0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2f40>
 4e55514:	test   %r10,%r10
 4e55517:	je     4e555a5 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2e8b>
 4e5551d:	lea    (%r14,%r8,8),%rax
 4e55521:	add    $0x408,%rax
 4e55527:	mov    %r10,%rcx
 4e5552a:	and    $0x7,%rcx
 4e5552e:	je     4e55680 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2db0>
 4e55534:	xor    %esi,%esi
 4e55536:	cs nopw 0x0(%rax,%rax,1)
 4e55540:	mov    (%rax),%rdx
 4e55543:	lea    0x400(%rdx),%rax
 4e5554a:	inc    %rsi
 4e5554d:	cmp    %rsi,%rcx
 4e55550:	jne    4e55540 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2ef0>
 4e55552:	mov    %r10,%rbp
 4e55555:	sub    %rsi,%rbp
 4e55558:	cmp    $0x8,%r10
 4e5555c:	jb     4e555a1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2e8f>
 4e5555e:	xchg   %ax,%ax
 4e55560:	mov    (%rax),%rax
 4e55563:	mov    0x400(%rax),%rax
 4e5556a:	mov    0x400(%rax),%rax
 4e55571:	mov    0x400(%rax),%rax
 4e55578:	mov    0x400(%rax),%rax
 4e5557f:	mov    0x400(%rax),%rax
 4e55586:	mov    0x400(%rax),%rax
 4e5558d:	mov    0x400(%rax),%rdx
 4e55594:	lea    0x400(%rdx),%rax
 4e5559b:	add    $0xfffffffffffffff8,%rbp
 4e5559f:	jne    4e55560 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2ed0>
 4e555a1:	xor    %ecx,%ecx
 4e555a3:	jmp    4e555ac <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2e84>
 4e555a5:	lea    0x1(%r8),%rcx
 4e555a9:	mov    %r14,%rdx
 4e555ac:	decq   0x10(%rsp)
 4e555b1:	lea    (%r8,%r8,4),%rax
 4e555b5:	lea    (%r14,%rax,4),%rax
 4e555b9:	add    $0x320,%rax
 4e555bf:	lea    (%r8,%r8,8),%rsi
 4e555c3:	lea    (%r14,%rsi,8),%rbp
 4e555c7:	add    $0x8,%rbp
 4e555cb:	mov    $0x1,%r14d
 4e555d1:	mov    %rcx,%r8
 4e555d4:	xor    %r10d,%r10d
 4e555d7:	movdqu 0x0(%r13),%xmm0
 4e555dd:	movdqu (%rax),%xmm1
 4e555e1:	pcmpeqb %xmm0,%xmm1
 4e555e5:	movd   0x10(%r13),%xmm0
 4e555eb:	movd   0x10(%rax),%xmm2
 4e555f0:	pcmpeqb %xmm0,%xmm2
 4e555f4:	pand   %xmm1,%xmm2
 4e555f8:	pmovmskb %xmm2,%eax
 4e555fc:	cmp    $0xffff,%eax
 4e55601:	jne    4e5571f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2d11>
 4e55607:	movzbl 0x40(%r12),%eax
 4e5560d:	cmp    0x40(%rbp),%al
 4e55610:	jne    4e5571f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2d11>
 4e55616:	movdqu (%r12),%xmm0
 4e5561c:	movdqu 0x10(%r12),%xmm1
 4e55623:	movdqu 0x0(%rbp),%xmm2
 4e55628:	pcmpeqb %xmm0,%xmm2
 4e5562c:	movdqu 0x10(%rbp),%xmm0
 4e55631:	pcmpeqb %xmm1,%xmm0
 4e55635:	pand   %xmm2,%xmm0
 4e55639:	pmovmskb %xmm0,%eax
 4e5563d:	cmp    $0xffff,%eax
 4e55642:	jne    4e5571f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2d11>
 4e55648:	movdqu 0x20(%r12),%xmm0
 4e5564f:	movdqu 0x30(%r12),%xmm1
 4e55656:	movdqu 0x20(%rbp),%xmm2
 4e5565b:	pcmpeqb %xmm0,%xmm2
 4e5565f:	movdqu 0x30(%rbp),%xmm0
 4e55664:	pcmpeqb %xmm1,%xmm0
 4e55668:	pand   %xmm2,%xmm0
 4e5566c:	pmovmskb %xmm0,%eax
 4e55670:	cmp    $0xffff,%eax
 4e55675:	je     4e55130 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef3300>
 4e5567b:	jmp    4e5571f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2d11>
 4e55680:	mov    %r10,%rbp
 4e55683:	cmp    $0x8,%r10
 4e55687:	jae    4e55560 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2ed0>
 4e5568d:	jmp    4e555a1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2e8f>
 4e55692:	mov    %r9,%rax
 4e55695:	cmp    $0x8,%r9
 4e55699:	jae    4e55250 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef31e0>
 4e5569f:	jmp    4e5528e <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef31a2>
 4e556a4:	mov    %r8,%rax
 4e556a7:	cmp    $0x8,%r8
 4e556ab:	jae    4e552f0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef3140>
 4e556b1:	jmp    4e5532e <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef3102>
 4e556b6:	cmp    $0x2,%r14
 4e556ba:	jne    4e556ce <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2d62>
 4e556bc:	xor    %r10,%rdx
 4e556bf:	mov    (%rsp),%rax
 4e556c3:	xor    %r8,%rax
 4e556c6:	or     %rdx,%rax
 4e556c9:	sete   %al
 4e556cc:	jmp    4e55721 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2d0f>
 4e556ce:	cmpq   $0x0,0x10(%rsp)
 4e556d4:	je     4e55730 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2d00>
 4e556d6:	cmp    $0x1,%r14
 4e556da:	jne    4e557f1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2c3f>
 4e556e0:	test   %rdx,%rdx
 4e556e3:	je     4e55734 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2cfc>
 4e556e5:	movzwl 0x3fe(%rdx),%eax
 4e556ec:	cmp    %rax,%r8
 4e556ef:	jb     4e5571f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2d11>
 4e556f1:	data16 data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
 4e55700:	mov    (%rdx),%rax
 4e55703:	test   %rax,%rax
 4e55706:	je     4e557fe <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2c32>
 4e5570c:	movzwl 0x3fc(%rdx),%ecx
 4e55713:	mov    %rax,%rdx
 4e55716:	cmp    0x3fe(%rax),%cx
 4e5571d:	jae    4e55700 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2d30>
 4e5571f:	xor    %eax,%eax
 4e55721:	add    $0x18,%rsp
 4e55725:	pop    %rbx
 4e55726:	pop    %r12
 4e55728:	pop    %r13
 4e5572a:	pop    %r14
 4e5572c:	pop    %r15
 4e5572e:	pop    %rbp
 4e5572f:	ret
 4e55730:	mov    $0x1,%al
 4e55732:	jmp    4e55721 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2d0f>
 4e55734:	test   %r8,%r8
 4e55737:	je     4e55767 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2cc9>
 4e55739:	mov    %r8,%rax
 4e5573c:	and    $0x7,%rax
 4e55740:	je     4e55772 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2cbe>
 4e55742:	xor    %ecx,%ecx
 4e55744:	mov    %r10,%rdx
 4e55747:	nopw   0x0(%rax,%rax,1)
 4e55750:	mov    0x400(%rdx),%rdx
 4e55757:	inc    %rcx
 4e5575a:	cmp    %rcx,%rax
 4e5575d:	jne    4e55750 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2ce0>
 4e5575f:	mov    %r8,%rax
 4e55762:	sub    %rcx,%rax
 4e55765:	jmp    4e55778 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2cb8>
 4e55767:	xor    %r8d,%r8d
 4e5576a:	mov    %r10,%rdx
 4e5576d:	jmp    4e556e5 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2d4b>
 4e55772:	mov    %r10,%rdx
 4e55775:	mov    %r8,%rax
 4e55778:	cmp    $0x8,%r8
 4e5577c:	jae    4e55786 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2caa>
 4e5577e:	xor    %r8d,%r8d
 4e55781:	jmp    4e556e5 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2d4b>
 4e55786:	xor    %r8d,%r8d
 4e55789:	nopl   0x0(%rax)
 4e55790:	mov    0x400(%rdx),%rcx
 4e55797:	mov    0x400(%rcx),%rcx
 4e5579e:	mov    0x400(%rcx),%rcx
 4e557a5:	mov    0x400(%rcx),%rcx
 4e557ac:	mov    0x400(%rcx),%rcx
 4e557b3:	mov    0x400(%rcx),%rcx
 4e557ba:	mov    0x400(%rcx),%rcx
 4e557c1:	mov    0x400(%rcx),%rdx
 4e557c8:	add    $0xfffffffffffffff8,%rax
 4e557cc:	jne    4e55790 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2ca0>
 4e557ce:	jmp    4e556e5 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2d4b>
 4e557d3:	lea    0x164df3e(%rip),%rdi        # 64a3718 <__register_atfork@plt+0xb1b88>
 4e557da:	call   *0x168a050(%rip)        # 64df830 <__register_atfork@plt+0xedca0>
 4e557e0:	jmp    4e5580b <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2c25>
 4e557e2:	lea    0x164df2f(%rip),%rdi        # 64a3718 <__register_atfork@plt+0xb1b88>
 4e557e9:	call   *0x168a041(%rip)        # 64df830 <__register_atfork@plt+0xedca0>
 4e557ef:	jmp    4e5580b <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xef2c25>
 4e557f1:	lea    0x164c870(%rip),%rdi        # 64a2068 <__register_atfork@plt+0xb04d8>
 4e557f8:	call   *0x168a032(%rip)        # 64df830 <__register_atfork@plt+0xedca0>
 4e557fe:	lea    0x164df13(%rip),%rdi        # 64a3718 <__register_atfork@plt+0xb1b88>
 4e55805:	call   *0x168a025(%rip)        # 64df830 <__register_atfork@plt+0xedca0>
 4e5580b:	ud2
 4e5580d:	ud2
 4e5580f:	ud2
 4e55811:	ud2

hl-node:     file format elf64-x86-64


Disassembly of section .text:

0000000004e00160 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf482d0>:
 4e00160:	push   %rbp
 4e00161:	push   %r15
 4e00163:	push   %r14
 4e00165:	push   %r13
 4e00167:	push   %r12
 4e00169:	push   %rbx
 4e0016a:	sub    $0xb8,%rsp
 4e00171:	mov    %rsi,%r15
 4e00174:	mov    (%rdx),%r8
 4e00177:	mov    %r8,%rax
 4e0017a:	neg    %rax
 4e0017d:	mov    %rdi,0x8(%rsp)
 4e00182:	mov    %r8,0x90(%rsp)
 4e0018a:	mov    %rdx,0x80(%rsp)
 4e00192:	jno    4e001bc <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf48274>
 4e00194:	mov    0x8(%rdx),%rdi
 4e00198:	mov    0x10(%rdx),%r8
 4e0019c:	xor    %ecx,%ecx
 4e0019e:	test   %rdi,%rdi
 4e001a1:	mov    0x18(%rdx),%rsi
 4e001a5:	mov    %rsi,0x58(%rsp)
 4e001aa:	cmove  %rdi,%rsi
 4e001ae:	setne  %cl
 4e001b1:	xor    %r13d,%r13d
 4e001b4:	mov    %rdi,%r14
 4e001b7:	mov    %rcx,%rax
 4e001ba:	jmp    4e00225 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf4820b>
 4e001bc:	mov    0x18(%rdx),%rsi
 4e001c0:	test   %rsi,%rsi
 4e001c3:	mov    %rsi,0x58(%rsp)
 4e001c8:	je     4e001ed <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf48243>
 4e001ca:	mov    0x10(%rdx),%rax
 4e001ce:	xor    %ecx,%ecx
 4e001d0:	cmp    %r8,%rax
 4e001d3:	cmovae %r8,%rcx
 4e001d7:	sub    %rcx,%rax
 4e001da:	mov    %r8,%r9
 4e001dd:	sub    %rax,%r9
 4e001e0:	mov    %rsi,%rcx
 4e001e3:	sub    %r9,%rcx
 4e001e6:	jbe    4e001f3 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf4823d>
 4e001e8:	mov    %r8,%rsi
 4e001eb:	jmp    4e001f8 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf48238>
 4e001ed:	xor    %eax,%eax
 4e001ef:	xor    %esi,%esi
 4e001f1:	jmp    4e001f6 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf4823a>
 4e001f3:	add    %rax,%rsi
 4e001f6:	xor    %ecx,%ecx
 4e001f8:	mov    0x8(%rdx),%rdi
 4e001fc:	lea    (%rax,%rax,2),%r13
 4e00200:	shl    $0x5,%r13
 4e00204:	add    %rdi,%r13
 4e00207:	lea    (%rsi,%rsi,2),%r14
 4e0020b:	shl    $0x5,%r14
 4e0020f:	add    %rdi,%r14
 4e00212:	lea    (%rcx,%rcx,2),%rcx
 4e00216:	shl    $0x5,%rcx
 4e0021a:	add    %rdi,%rcx
 4e0021d:	mov    $0x2,%eax
 4e00222:	mov    %rdi,%r8
 4e00225:	mov    %rax,0x10(%rsp)
 4e0022a:	mov    %r13,0x18(%rsp)
 4e0022f:	mov    %r14,0x20(%rsp)
 4e00234:	mov    %r8,0x28(%rsp)
 4e00239:	mov    %rcx,0x30(%rsp)
 4e0023e:	movq   $0x0,0x38(%rsp)
 4e00247:	mov    %rdi,0x88(%rsp)
 4e0024f:	mov    %rdi,0x40(%rsp)
 4e00254:	mov    %r8,0x48(%rsp)
 4e00259:	mov    %rsi,0x50(%rsp)
 4e0025e:	movabs $0x8000000000000000,%rcx
 4e00268:	cmp    %rcx,(%r15)
 4e0026b:	jne    4e003df <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf48051>
 4e00271:	mov    0x8(%r15),%rcx
 4e00275:	mov    %rcx,0xa8(%rsp)
 4e0027d:	test   %rcx,%rcx
 4e00280:	je     4e00520 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf47f10>
 4e00286:	mov    0x10(%r15),%rcx
 4e0028a:	mov    %rcx,0xa0(%rsp)
 4e00292:	mov    0x16df8b7(%rip),%r14        # 64dfb50 <__register_atfork@plt+0xedfc0>
 4e00299:	jmp    4e002a5 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf4818b>
 4e0029b:	nopl   0x0(%rax,%rax,1)
 4e002a0:	mov    0x10(%rsp),%rax
 4e002a5:	cmp    $0x2,%rax
 4e002a9:	jne    4e00300 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf48130>
 4e002ab:	mov    0x18(%rsp),%rax
 4e002b0:	mov    0x20(%rsp),%rdx
 4e002b5:	cmp    %rdx,%rax
 4e002b8:	jne    4e002e0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf48150>
 4e002ba:	lea    0x18(%rsp),%rcx
 4e002bf:	movups 0x10(%rcx),%xmm0
 4e002c3:	movups %xmm0,(%rcx)
 4e002c6:	mov    %rax,0x28(%rsp)
 4e002cb:	mov    %rdx,0x30(%rsp)
 4e002d0:	mov    0x18(%rsp),%rax
 4e002d5:	cmp    0x20(%rsp),%rax
 4e002da:	je     4e003cf <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf48061>
 4e002e0:	lea    0x60(%rax),%rcx
 4e002e4:	mov    %rcx,0x18(%rsp)
 4e002e9:	test   %rax,%rax
 4e002ec:	jne    4e00313 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf4811d>
 4e002ee:	jmp    4e00578 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf47eb8>
 4e002f3:	data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
 4e00300:	lea    0x10(%rsp),%rdi
 4e00305:	call   513b200 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc0d230>
 4e0030a:	test   %rax,%rax
 4e0030d:	je     4e00578 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf47eb8>
 4e00313:	mov    0x10(%rax),%ecx
 4e00316:	mov    %ecx,0x70(%rsp)
 4e0031a:	mov    %rax,0x98(%rsp)
 4e00322:	movups (%rax),%xmm0
 4e00325:	movaps %xmm0,0x60(%rsp)
 4e0032a:	mov    0xa0(%rsp),%r13
 4e00332:	mov    0xa8(%rsp),%rbp
 4e0033a:	lea    0x60(%rbp),%rsi
 4e0033e:	movzwl 0x13e(%rbp),%eax
 4e00345:	mov    %rax,0xb0(%rsp)
 4e0034d:	lea    0x0(,%rax,4),%eax
 4e00354:	lea    (%rax,%rax,4),%r12
 4e00358:	mov    $0xffffffffffffffff,%rbx
 4e0035f:	nop
 4e00360:	test   %r12,%r12
 4e00363:	je     4e003b0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf48080>
 4e00365:	lea    0x14(%rsi),%r15
 4e00369:	mov    $0x14,%edx
 4e0036e:	lea    0x60(%rsp),%rdi
 4e00373:	call   *%r14
 4e00376:	cltq
 4e00378:	test   %rax,%rax
 4e0037b:	sets   %cl
 4e0037e:	setg   %al
 4e00381:	sub    %cl,%al
 4e00383:	inc    %rbx
 4e00386:	add    $0xffffffffffffffec,%r12
 4e0038a:	mov    %r15,%rsi
 4e0038d:	cmp    $0x1,%al
 4e0038f:	je     4e00360 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf480d0>
 4e00391:	movzbl %al,%eax
 4e00394:	test   %eax,%eax
 4e00396:	je     4e002a0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf48190>
 4e0039c:	sub    $0x1,%r13
 4e003a0:	jae    4e003c2 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf4806e>
 4e003a2:	jmp    4e00516 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf47f1a>
 4e003a7:	nopw   0x0(%rax,%rax,1)
 4e003b0:	mov    0xb0(%rsp),%rbx
 4e003b8:	sub    $0x1,%r13
 4e003bc:	jb     4e00516 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf47f1a>
 4e003c2:	mov    0x140(%rbp,%rbx,8),%rbp
 4e003ca:	jmp    4e0033a <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf480f6>
 4e003cf:	xor    %eax,%eax
 4e003d1:	test   %rax,%rax
 4e003d4:	jne    4e00313 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf4811d>
 4e003da:	jmp    4e00578 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf47eb8>
 4e003df:	cmp    $0x2,%eax
 4e003e2:	jne    4e00474 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf47fbc>
 4e003e8:	lea    0x60(%rsp),%rbp
 4e003ed:	mov    %r13,%rbx
 4e003f0:	jmp    4e00438 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf47ff8>
 4e003f2:	data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
 4e00400:	lea    0x60(%r13),%rbx
 4e00404:	mov    %rbx,0x18(%rsp)
 4e00409:	test   %r13,%r13
 4e0040c:	je     4e00578 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf47eb8>
 4e00412:	mov    0x10(%r13),%eax
 4e00416:	mov    %eax,0x70(%rsp)
 4e0041a:	movups 0x0(%r13),%xmm0
 4e0041f:	movaps %xmm0,0x60(%rsp)
 4e00424:	mov    %r15,%rdi
 4e00427:	mov    %rbp,%rsi
 4e0042a:	call   57f54e0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x552f50>
 4e0042f:	test   %rax,%rax
 4e00432:	jne    4e0055b <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf47ed5>
 4e00438:	cmp    %r14,%rbx
 4e0043b:	mov    %rbx,%r13
 4e0043e:	jne    4e00400 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf48030>
 4e00440:	lea    0x18(%rsp),%rax
 4e00445:	movups 0x10(%rax),%xmm0
 4e00449:	movups %xmm0,(%rax)
 4e0044c:	mov    %r13,0x28(%rsp)
 4e00451:	mov    %r14,0x30(%rsp)
 4e00456:	mov    0x18(%rsp),%r13
 4e0045b:	mov    0x20(%rsp),%r14
 4e00460:	cmp    %r14,%r13
 4e00463:	je     4e00578 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf47eb8>
 4e00469:	lea    0x60(%r13),%rbx
 4e0046d:	mov    %rbx,0x18(%rsp)
 4e00472:	jmp    4e00412 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf4801e>
 4e00474:	lea    0x60(%rsp),%r12
 4e00479:	lea    0x10(%rsp),%rbp
 4e0047e:	xchg   %ax,%ax
 4e00480:	cmpl   $0x2,0x10(%rsp)
 4e00485:	jne    4e004d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf47f60>
 4e00487:	mov    0x18(%rsp),%r13
 4e0048c:	mov    0x20(%rsp),%rax
 4e00491:	cmp    %rax,%r13
 4e00494:	jne    4e004b8 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf47f78>
 4e00496:	lea    0x18(%rsp),%rcx
 4e0049b:	movups 0x10(%rcx),%xmm0
 4e0049f:	movups %xmm0,(%rcx)
 4e004a2:	mov    %r13,0x28(%rsp)
 4e004a7:	mov    %rax,0x30(%rsp)
 4e004ac:	mov    0x18(%rsp),%r13
 4e004b1:	cmp    0x20(%rsp),%r13
 4e004b6:	je     4e0050c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf47f24>
 4e004b8:	lea    0x60(%r13),%rax
 4e004bc:	mov    %rax,0x18(%rsp)
 4e004c1:	test   %r13,%r13
 4e004c4:	jne    4e004e4 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf47f4c>
 4e004c6:	jmp    4e00578 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf47eb8>
 4e004cb:	nopl   0x0(%rax,%rax,1)
 4e004d0:	mov    %rbp,%rdi
 4e004d3:	call   513b200 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc0d230>
 4e004d8:	mov    %rax,%r13
 4e004db:	test   %r13,%r13
 4e004de:	je     4e00578 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf47eb8>
 4e004e4:	mov    0x10(%r13),%eax
 4e004e8:	mov    %eax,0x70(%rsp)
 4e004ec:	movups 0x0(%r13),%xmm0
 4e004f1:	movaps %xmm0,0x60(%rsp)
 4e004f6:	mov    %r15,%rdi
 4e004f9:	mov    %r12,%rsi
 4e004fc:	call   57f54e0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x552f50>
 4e00501:	test   %rax,%rax
 4e00504:	je     4e00480 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf47fb0>
 4e0050a:	jmp    4e0055b <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf47ed5>
 4e0050c:	xor    %r13d,%r13d
 4e0050f:	test   %r13,%r13
 4e00512:	jne    4e004e4 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf47f4c>
 4e00514:	jmp    4e00578 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf47eb8>
 4e00516:	mov    0x98(%rsp),%r13
 4e0051e:	jmp    4e0055b <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf47ed5>
 4e00520:	cmp    $0x2,%eax
 4e00523:	jne    4e00549 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf47ee7>
 4e00525:	cmp    %r14,%r13
 4e00528:	jne    4e00556 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf47eda>
 4e0052a:	lea    0x18(%rsp),%rax
 4e0052f:	movups 0x10(%rax),%xmm0
 4e00533:	movups %xmm0,(%rax)
 4e00536:	mov    0x18(%rsp),%rax
 4e0053b:	xor    %r13d,%r13d
 4e0053e:	cmp    0x20(%rsp),%rax
 4e00543:	cmovne %rax,%r13
 4e00547:	jmp    4e00556 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf47eda>
 4e00549:	lea    0x10(%rsp),%rdi
 4e0054e:	call   513b200 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc0d230>
 4e00553:	mov    %rax,%r13
 4e00556:	test   %r13,%r13
 4e00559:	je     4e00578 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf47eb8>
 4e0055b:	mov    0x10(%r13),%eax
 4e0055f:	mov    0x8(%rsp),%rbx
 4e00564:	mov    %eax,0x11(%rbx)
 4e00567:	movups 0x0(%r13),%xmm0
 4e0056c:	movups %xmm0,0x1(%rbx)
 4e00570:	movb   $0x2c,(%rbx)
 4e00573:	jmp    4e0067b <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf47db5>
 4e00578:	mov    0x90(%rsp),%rdi
 4e00580:	movabs $0x8000000000000000,%rax
 4e0058a:	cmp    %rax,%rdi
 4e0058d:	jne    4e005c3 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf47e6d>
 4e0058f:	xor    %eax,%eax
 4e00591:	mov    0x88(%rsp),%r8
 4e00599:	test   %r8,%r8
 4e0059c:	setne  %al
 4e0059f:	mov    0x58(%rsp),%r9
 4e005a4:	cmove  %r8,%r9
 4e005a8:	mov    0x80(%rsp),%rcx
 4e005b0:	mov    0x10(%rcx),%rsi
 4e005b4:	xor    %ecx,%ecx
 4e005b6:	mov    %r8,%rdx
 4e005b9:	mov    %rax,%rdi
 4e005bc:	mov    0x8(%rsp),%rbx
 4e005c1:	jmp    4e00639 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf47df7>
 4e005c3:	mov    0x58(%rsp),%rdx
 4e005c8:	test   %rdx,%rdx
 4e005cb:	mov    0x88(%rsp),%r8
 4e005d3:	mov    0x80(%rsp),%rax
 4e005db:	je     4e00605 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf47e2b>
 4e005dd:	mov    0x10(%rax),%rax
 4e005e1:	xor    %ecx,%ecx
 4e005e3:	cmp    %rdi,%rax
 4e005e6:	cmovae %rdi,%rcx
 4e005ea:	sub    %rcx,%rax
 4e005ed:	mov    %rdi,%rcx
 4e005f0:	sub    %rax,%rcx
 4e005f3:	mov    %rdx,%rsi
 4e005f6:	sub    %rcx,%rsi
 4e005f9:	ja     4e0060b <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf47e25>
 4e005fb:	add    %rax,%rdx
 4e005fe:	xor    %esi,%esi
 4e00600:	mov    %rdx,%rdi
 4e00603:	jmp    4e0060b <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf47e25>
 4e00605:	xor    %eax,%eax
 4e00607:	xor    %edi,%edi
 4e00609:	xor    %esi,%esi
 4e0060b:	mov    0x8(%rsp),%rbx
 4e00610:	lea    (%rax,%rax,2),%rcx
 4e00614:	shl    $0x5,%rcx
 4e00618:	add    %r8,%rcx
 4e0061b:	lea    (%rdi,%rdi,2),%rdx
 4e0061f:	shl    $0x5,%rdx
 4e00623:	add    %r8,%rdx
 4e00626:	lea    (%rsi,%rsi,2),%rax
 4e0062a:	shl    $0x5,%rax
 4e0062e:	add    %r8,%rax
 4e00631:	mov    $0x2,%edi
 4e00636:	mov    %r8,%rsi
 4e00639:	mov    %rdi,0x10(%rsp)
 4e0063e:	mov    %rcx,0x18(%rsp)
 4e00643:	mov    %rdx,0x20(%rsp)
 4e00648:	mov    %rsi,0x28(%rsp)
 4e0064d:	mov    %rax,0x30(%rsp)
 4e00652:	movq   $0x0,0x38(%rsp)
 4e0065b:	mov    %r8,0x40(%rsp)
 4e00660:	mov    %rsi,0x48(%rsp)
 4e00665:	mov    %r9,0x50(%rsp)
 4e0066a:	lea    0x8(%rbx),%rdi
 4e0066e:	lea    0x10(%rsp),%rsi
 4e00673:	call   53492e0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x9ff150>
 4e00678:	movb   $0x2e,(%rbx)
 4e0067b:	mov    %rbx,%rax
 4e0067e:	add    $0xb8,%rsp
 4e00685:	pop    %rbx
 4e00686:	pop    %r12
 4e00688:	pop    %r13
 4e0068a:	pop    %r14
 4e0068c:	pop    %r15
 4e0068e:	pop    %rbp
 4e0068f:	ret

hl-node:     file format elf64-x86-64


Disassembly of section .text:

00000000057e8bd0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x55f860>:
 57e8bd0:	push   %rbp
 57e8bd1:	push   %r15
 57e8bd3:	push   %r14
 57e8bd5:	push   %r13
 57e8bd7:	push   %r12
 57e8bd9:	push   %rbx
 57e8bda:	sub    $0x78,%rsp
 57e8bde:	mov    %rsi,%rbx
 57e8be1:	xor    %eax,%eax
 57e8be3:	cmp    (%rcx),%rax
 57e8be6:	jno    57e8c9d <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x55f793>
 57e8bec:	mov    0x8(%rcx),%rax
 57e8bf0:	test   %rax,%rax
 57e8bf3:	je     57e8ced <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x55f743>
 57e8bf9:	mov    %rdi,0x8(%rsp)
 57e8bfe:	mov    %rdx,0x10(%rsp)
 57e8c03:	mov    0x10(%rcx),%r13
 57e8c07:	mov    0xcf6f42(%rip),%rbp        # 64dfb50 <__register_atfork@plt+0xedfc0>
 57e8c0e:	lea    0x60(%rax),%rsi
 57e8c12:	mov    %rax,0x20(%rsp)
 57e8c17:	movzwl 0x13e(%rax),%eax
 57e8c1e:	mov    %rax,0x18(%rsp)
 57e8c23:	lea    0x0(,%rax,4),%eax
 57e8c2a:	lea    (%rax,%rax,4),%r15
 57e8c2e:	mov    $0xffffffffffffffff,%r14
 57e8c35:	data16 cs nopw 0x0(%rax,%rax,1)
 57e8c40:	test   %r15,%r15
 57e8c43:	je     57e8c80 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x55f7b0>
 57e8c45:	lea    0x14(%rsi),%r12
 57e8c49:	mov    $0x14,%edx
 57e8c4e:	mov    %rbx,%rdi
 57e8c51:	call   *%rbp
 57e8c53:	cltq
 57e8c55:	test   %rax,%rax
 57e8c58:	sets   %cl
 57e8c5b:	setg   %al
 57e8c5e:	sub    %cl,%al
 57e8c60:	inc    %r14
 57e8c63:	add    $0xffffffffffffffec,%r15
 57e8c67:	mov    %r12,%rsi
 57e8c6a:	cmp    $0x1,%al
 57e8c6c:	je     57e8c40 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x55f7f0>
 57e8c6e:	movzbl %al,%eax
 57e8c71:	test   %eax,%eax
 57e8c73:	je     57e8cb7 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x55f779>
 57e8c75:	jmp    57e8c85 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x55f7ab>
 57e8c77:	nopw   0x0(%rax,%rax,1)
 57e8c80:	mov    0x18(%rsp),%r14
 57e8c85:	sub    $0x1,%r13
 57e8c89:	jb     57e8ced <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x55f743>
 57e8c8b:	mov    0x20(%rsp),%rax
 57e8c90:	mov    0x140(%rax,%r14,8),%rax
 57e8c98:	jmp    57e8c0e <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x55f822>
 57e8c9d:	mov    %rdi,0x8(%rsp)
 57e8ca2:	mov    %rdx,0x10(%rsp)
 57e8ca7:	mov    %rcx,%rdi
 57e8caa:	mov    %rbx,%rsi
 57e8cad:	call   57f54e0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x552f50>
 57e8cb2:	test   %rax,%rax
 57e8cb5:	jne    57e8ced <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x55f743>
 57e8cb7:	lea    0x58(%rsp),%r12
 57e8cbc:	mov    %r12,%rdi
 57e8cbf:	mov    0x8(%rsp),%rsi
 57e8cc4:	call   57e8d40 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x55f6f0>
 57e8cc9:	lea    0x28(%rsp),%rdi
 57e8cce:	mov    0x10(%rsp),%rsi
 57e8cd3:	mov    %r12,%rdx
 57e8cd6:	call   *0xcf7dfc(%rip)        # 64e0ad8 <__register_atfork@plt+0xeef48>
 57e8cdc:	cmpb   $0x0,0x28(%rsp)
 57e8ce1:	je     57e8cf1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x55f73f>
 57e8ce3:	mov    0x30(%rsp),%rdi
 57e8ce8:	mov    (%rdi),%rax
 57e8ceb:	call   *(%rax)
 57e8ced:	xor    %eax,%eax
 57e8cef:	jmp    57e8d2b <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x55f705>
 57e8cf1:	movdqu 0x29(%rsp),%xmm0
 57e8cf7:	movdqa %xmm0,0x40(%rsp)
 57e8cfd:	mov    0x39(%rsp),%eax
 57e8d01:	mov    %eax,0x50(%rsp)
 57e8d05:	movdqu (%rbx),%xmm1
 57e8d09:	movq   %rax,%xmm2
 57e8d0e:	movd   0x10(%rbx),%xmm3
 57e8d13:	pcmpeqb %xmm2,%xmm3
 57e8d17:	pcmpeqb %xmm0,%xmm1
 57e8d1b:	pand   %xmm3,%xmm1
 57e8d1f:	pmovmskb %xmm1,%eax
 57e8d23:	cmp    $0xffff,%eax
 57e8d28:	sete   %al
 57e8d2b:	add    $0x78,%rsp
 57e8d2f:	pop    %rbx
 57e8d30:	pop    %r12
 57e8d32:	pop    %r13
 57e8d34:	pop    %r14
 57e8d36:	pop    %r15
 57e8d38:	pop    %rbp
 57e8d39:	ret

hl-node:     file format elf64-x86-64


Disassembly of section .text:

000000000595bc40 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec7f0>:
 595bc40:	push   %rbp
 595bc41:	push   %r15
 595bc43:	push   %r14
 595bc45:	push   %r13
 595bc47:	push   %r12
 595bc49:	push   %rbx
 595bc4a:	sub    $0x58,%rsp
 595bc4e:	mov    %rdx,%r14
 595bc51:	mov    %rsi,%rbx
 595bc54:	mov    %rdi,%r15
 595bc57:	mov    %rsi,%rdi
 595bc5a:	mov    %rdx,%rsi
 595bc5d:	call   *0xb8ae35(%rip)        # 64e6a98 <__register_atfork@plt+0xf4f08>
 595bc63:	test   %al,%al
 595bc65:	je     595bca1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec78f>
 595bc67:	movq   0x88(%r15),%xmm0
 595bc70:	movq   %xmm0,%rax
 595bc75:	movabs $0x7fffffffffffffff,%rcx
 595bc7f:	and    %rax,%rcx
 595bc82:	movabs $0x7fefffffffffffff,%rax
 595bc8c:	cmp    %rax,%rcx
 595bc8f:	jle    595bca8 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec788>
 595bc91:	movsd  -0x55029e9(%rip),%xmm0        # 4592b0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x58ef180>
 595bc99:	movsd  %xmm0,0x8(%rsp)
 595bc9f:	jmp    595bcd4 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec75c>
 595bca1:	xor    %eax,%eax
 595bca3:	jmp    595c043 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec3ed>
 595bca8:	xorpd  %xmm1,%xmm1
 595bcac:	xorpd  %xmm2,%xmm2
 595bcb0:	maxsd  %xmm0,%xmm2
 595bcb4:	movsd  -0x55022ac(%rip),%xmm0        # 459a10 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x58eea20>
 595bcbc:	minsd  %xmm2,%xmm0
 595bcc0:	mov    $0x1,%al
 595bcc2:	movsd  %xmm0,0x8(%rsp)
 595bcc8:	ucomisd %xmm1,%xmm0
 595bccc:	jne    595bcd4 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec75c>
 595bcce:	jnp    595c043 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec3ed>
 595bcd4:	mov    (%r14),%rax
 595bcd7:	mov    0x8(%r14),%r8
 595bcdb:	test   %rax,%rax
 595bcde:	setne  %dil
 595bce2:	mov    0x10(%r14),%rcx
 595bce6:	mov    %rcx,%r10
 595bce9:	cmove  %rax,%r10
 595bced:	mov    0x20(%rbx),%rdx
 595bcf1:	mov    %rdx,0x20(%rsp)
 595bcf6:	test   %rdx,%rdx
 595bcf9:	mov    %rbx,0x10(%rsp)
 595bcfe:	je     595c052 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec3de>
 595bd04:	mov    0x28(%rbx),%rcx
 595bd08:	mov    %rcx,0x18(%rsp)
 595bd0d:	xor    %ebp,%ebp
 595bd0f:	xor    %r9d,%r9d
 595bd12:	jmp    595bd44 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec6ec>
 595bd14:	data16 data16 cs nopw 0x0(%rax,%rax,1)
 595bd20:	mov    $0x1,%ecx
 595bd25:	mov    $0x1,%dil
 595bd28:	mov    $0x0,%eax
 595bd2d:	mov    0x30(%rsp),%r9
 595bd32:	add    %rcx,%r9
 595bd35:	mov    (%rsp),%r8
 595bd39:	mov    0x28(%rsp),%r10
 595bd3e:	jb     595c259 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec1d7>
 595bd44:	sub    $0x1,%r10
 595bd48:	jb     595bfeb <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec445>
 595bd4e:	test   $0x1,%dil
 595bd52:	je     595c24c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec1e4>
 595bd58:	test   %rbp,%rbp
 595bd5b:	je     595bd80 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec6b0>
 595bd5d:	movzwl 0xe6(%rbp),%ecx
 595bd64:	cmp    %rcx,%r8
 595bd67:	jae    595be30 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec600>
 595bd6d:	mov    %rbp,%rcx
 595bd70:	mov    %r8,%rdx
 595bd73:	jmp    595be53 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec5dd>
 595bd78:	nopl   0x0(%rax,%rax,1)
 595bd80:	test   %r8,%r8
 595bd83:	je     595be15 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec61b>
 595bd89:	mov    %r8,%rcx
 595bd8c:	mov    %rax,%rbp
 595bd8f:	and    $0x7,%rcx
 595bd93:	je     595bfd2 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec45e>
 595bd99:	xor    %edx,%edx
 595bd9b:	nopl   0x0(%rax,%rax,1)
 595bda0:	mov    0xe8(%rbp),%rbp
 595bda7:	inc    %rdx
 595bdaa:	cmp    %rdx,%rcx
 595bdad:	jne    595bda0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec690>
 595bdaf:	mov    %r8,%rax
 595bdb2:	sub    %rdx,%rax
 595bdb5:	cmp    $0x8,%r8
 595bdb9:	jb     595bdfe <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec632>
 595bdbb:	nopl   0x0(%rax,%rax,1)
 595bdc0:	mov    0xe8(%rbp),%rcx
 595bdc7:	mov    0xe8(%rcx),%rcx
 595bdce:	mov    0xe8(%rcx),%rcx
 595bdd5:	mov    0xe8(%rcx),%rcx
 595bddc:	mov    0xe8(%rcx),%rcx
 595bde3:	mov    0xe8(%rcx),%rcx
 595bdea:	mov    0xe8(%rcx),%rcx
 595bdf1:	mov    0xe8(%rcx),%rbp
 595bdf8:	add    $0xfffffffffffffff8,%rax
 595bdfc:	jne    595bdc0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec670>
 595bdfe:	xor    %r8d,%r8d
 595be01:	xor    %eax,%eax
 595be03:	movzwl 0xe6(%rbp),%ecx
 595be0a:	cmp    %rcx,%r8
 595be0d:	jb     595bd6d <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec6c3>
 595be13:	jmp    595be30 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec600>
 595be15:	xor    %r8d,%r8d
 595be18:	mov    %rax,%rbp
 595be1b:	xor    %eax,%eax
 595be1d:	movzwl 0xe6(%rbp),%ecx
 595be24:	cmp    %rcx,%r8
 595be27:	jb     595bd6d <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec6c3>
 595be2d:	nopl   (%rax)
 595be30:	mov    0x0(%rbp),%rcx
 595be34:	test   %rcx,%rcx
 595be37:	je     595c23d <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec1f3>
 595be3d:	inc    %rax
 595be40:	movzwl 0xe4(%rbp),%edx
 595be47:	mov    %rcx,%rbp
 595be4a:	cmp    0xe6(%rcx),%dx
 595be51:	jae    595be30 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec600>
 595be53:	test   %rax,%rax
 595be56:	mov    %r9,0x30(%rsp)
 595be5b:	mov    %r10,0x28(%rsp)
 595be60:	je     595bf00 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec530>
 595be66:	lea    (%rcx,%rdx,8),%rsi
 595be6a:	add    $0xf0,%rsi
 595be71:	mov    %rax,%rdi
 595be74:	and    $0x7,%rdi
 595be78:	je     595bfc0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec470>
 595be7e:	xor    %r8d,%r8d
 595be81:	data16 data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
 595be90:	mov    (%rsi),%rbp
 595be93:	lea    0xe8(%rbp),%rsi
 595be9a:	inc    %r8
 595be9d:	cmp    %r8,%rdi
 595bea0:	jne    595be90 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec5a0>
 595bea2:	mov    %rax,%rdi
 595bea5:	sub    %r8,%rdi
 595bea8:	cmp    $0x8,%rax
 595beac:	jb     595bef1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec53f>
 595beae:	xchg   %ax,%ax
 595beb0:	mov    (%rsi),%rax
 595beb3:	mov    0xe8(%rax),%rax
 595beba:	mov    0xe8(%rax),%rax
 595bec1:	mov    0xe8(%rax),%rax
 595bec8:	mov    0xe8(%rax),%rax
 595becf:	mov    0xe8(%rax),%rax
 595bed6:	mov    0xe8(%rax),%rax
 595bedd:	mov    0xe8(%rax),%rbp
 595bee4:	lea    0xe8(%rbp),%rsi
 595beeb:	add    $0xfffffffffffffff8,%rdi
 595beef:	jne    595beb0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec580>
 595bef1:	movq   $0x0,(%rsp)
 595bef9:	jmp    595bf0b <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec525>
 595befb:	nopl   0x0(%rax,%rax,1)
 595bf00:	lea    0x1(%rdx),%rax
 595bf04:	mov    %rax,(%rsp)
 595bf08:	mov    %rcx,%rbp
 595bf0b:	lea    (%rdx,%rdx,4),%rax
 595bf0f:	mov    0x18(%rcx,%rax,4),%edx
 595bf13:	mov    %edx,0x50(%rsp)
 595bf17:	movupd 0x8(%rcx,%rax,4),%xmm0
 595bf1d:	movapd %xmm0,0x40(%rsp)
 595bf23:	mov    0x18(%rsp),%r15
 595bf28:	mov    0x20(%rsp),%r13
 595bf2d:	lea    0x8(%r13),%rsi
 595bf31:	movzwl 0xe6(%r13),%eax
 595bf39:	mov    %rax,0x38(%rsp)
 595bf3e:	lea    0x0(,%rax,4),%eax
 595bf45:	lea    (%rax,%rax,4),%r12
 595bf49:	mov    $0xffffffffffffffff,%rbx
 595bf50:	test   %r12,%r12
 595bf53:	je     595bfa0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec490>
 595bf55:	lea    0x14(%rsi),%r14
 595bf59:	mov    $0x14,%edx
 595bf5e:	lea    0x40(%rsp),%rdi
 595bf63:	call   *0xb83be7(%rip)        # 64dfb50 <__register_atfork@plt+0xedfc0>
 595bf69:	cltq
 595bf6b:	test   %rax,%rax
 595bf6e:	sets   %cl
 595bf71:	setg   %al
 595bf74:	sub    %cl,%al
 595bf76:	inc    %rbx
 595bf79:	add    $0xffffffffffffffec,%r12
 595bf7d:	mov    %r14,%rsi
 595bf80:	cmp    $0x1,%al
 595bf82:	je     595bf50 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec4e0>
 595bf84:	movzbl %al,%eax
 595bf87:	test   %eax,%eax
 595bf89:	je     595bd20 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec710>
 595bf8f:	sub    $0x1,%r15
 595bf93:	jae    595bfab <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec485>
 595bf95:	jmp    595bfe4 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec44c>
 595bf97:	nopw   0x0(%rax,%rax,1)
 595bfa0:	mov    0x38(%rsp),%rbx
 595bfa5:	sub    $0x1,%r15
 595bfa9:	jb     595bfe4 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec44c>
 595bfab:	mov    0xe8(%r13,%rbx,8),%r13
 595bfb3:	jmp    595bf2d <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec503>
 595bfb8:	nopl   0x0(%rax,%rax,1)
 595bfc0:	mov    %rax,%rdi
 595bfc3:	cmp    $0x8,%rax
 595bfc7:	jb     595bef1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec53f>
 595bfcd:	jmp    595beb0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec580>
 595bfd2:	mov    %r8,%rax
 595bfd5:	cmp    $0x8,%r8
 595bfd9:	jae    595bdc0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec670>
 595bfdf:	jmp    595bdfe <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec632>
 595bfe4:	xor    %ecx,%ecx
 595bfe6:	jmp    595bd25 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec70b>
 595bfeb:	mov    0x10(%rsp),%rbx
 595bff0:	movq   %r9,%xmm0
 595bff5:	movq   -0x550aded(%rip),%xmm1        # 451210 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x58f7220>
 595bffd:	punpckldq %xmm1,%xmm0
 595c001:	movapd -0x550be99(%rip),%xmm2        # 450170 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x58f82c0>
 595c009:	subpd  %xmm2,%xmm0
 595c00d:	movapd %xmm0,%xmm3
 595c011:	unpckhpd %xmm0,%xmm3
 595c015:	addsd  %xmm0,%xmm3
 595c019:	movq   0x30(%rbx),%xmm0
 595c01e:	punpckldq %xmm1,%xmm0
 595c022:	subpd  %xmm2,%xmm0
 595c026:	movapd %xmm0,%xmm1
 595c02a:	unpckhpd %xmm0,%xmm1
 595c02e:	addsd  %xmm0,%xmm1
 595c032:	movsd  0x8(%rsp),%xmm0
 595c038:	mulsd  %xmm1,%xmm0
 595c03c:	ucomisd %xmm0,%xmm3
 595c040:	seta   %al
 595c043:	add    $0x58,%rsp
 595c047:	pop    %rbx
 595c048:	pop    %r12
 595c04a:	pop    %r13
 595c04c:	pop    %r14
 595c04e:	pop    %r15
 595c050:	pop    %rbp
 595c051:	ret
 595c052:	xor    %r9d,%r9d
 595c055:	test   %r10,%r10
 595c058:	je     595bff0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec440>
 595c05a:	xor    %edx,%edx
 595c05c:	mov    0x10(%rsp),%rbx
 595c061:	jmp    595c087 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec3a9>
 595c063:	data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
 595c070:	inc    %r8
 595c073:	mov    $0x1,%dil
 595c076:	mov    %rsi,%rdx
 595c079:	mov    $0x0,%eax
 595c07e:	dec    %rcx
 595c081:	je     595bff0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec440>
 595c087:	test   $0x1,%dil
 595c08b:	je     595c24c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec1e4>
 595c091:	test   %rdx,%rdx
 595c094:	je     595c0b0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec380>
 595c096:	movzwl 0xe6(%rdx),%esi
 595c09d:	cmp    %rsi,%r8
 595c0a0:	jae    595c160 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec2d0>
 595c0a6:	mov    %rdx,%rsi
 595c0a9:	jmp    595c184 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec2ac>
 595c0ae:	xchg   %ax,%ax
 595c0b0:	test   %r8,%r8
 595c0b3:	je     595c145 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec2eb>
 595c0b9:	mov    %r8,%rsi
 595c0bc:	mov    %rax,%rdx
 595c0bf:	and    $0x7,%rsi
 595c0c3:	je     595c22b <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec205>
 595c0c9:	xor    %edi,%edi
 595c0cb:	nopl   0x0(%rax,%rax,1)
 595c0d0:	mov    0xe8(%rdx),%rdx
 595c0d7:	inc    %rdi
 595c0da:	cmp    %rdi,%rsi
 595c0dd:	jne    595c0d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec360>
 595c0df:	mov    %r8,%rax
 595c0e2:	sub    %rdi,%rax
 595c0e5:	cmp    $0x8,%r8
 595c0e9:	jb     595c12e <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec302>
 595c0eb:	nopl   0x0(%rax,%rax,1)
 595c0f0:	mov    0xe8(%rdx),%rdx
 595c0f7:	mov    0xe8(%rdx),%rdx
 595c0fe:	mov    0xe8(%rdx),%rdx
 595c105:	mov    0xe8(%rdx),%rdx
 595c10c:	mov    0xe8(%rdx),%rdx
 595c113:	mov    0xe8(%rdx),%rdx
 595c11a:	mov    0xe8(%rdx),%rdx
 595c121:	mov    0xe8(%rdx),%rdx
 595c128:	add    $0xfffffffffffffff8,%rax
 595c12c:	jne    595c0f0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec340>
 595c12e:	xor    %r8d,%r8d
 595c131:	xor    %eax,%eax
 595c133:	movzwl 0xe6(%rdx),%esi
 595c13a:	cmp    %rsi,%r8
 595c13d:	jb     595c0a6 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec38a>
 595c143:	jmp    595c160 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec2d0>
 595c145:	xor    %r8d,%r8d
 595c148:	mov    %rax,%rdx
 595c14b:	xor    %eax,%eax
 595c14d:	movzwl 0xe6(%rdx),%esi
 595c154:	cmp    %rsi,%r8
 595c157:	jb     595c0a6 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec38a>
 595c15d:	nopl   (%rax)
 595c160:	mov    (%rdx),%rsi
 595c163:	test   %rsi,%rsi
 595c166:	je     595c23d <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec1f3>
 595c16c:	inc    %rax
 595c16f:	movzwl 0xe4(%rdx),%r8d
 595c177:	mov    %rsi,%rdx
 595c17a:	cmp    0xe6(%rsi),%r8w
 595c182:	jae    595c160 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec2d0>
 595c184:	test   %rax,%rax
 595c187:	je     595c070 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec3c0>
 595c18d:	lea    (%rsi,%r8,8),%rdx
 595c191:	add    $0xf0,%rdx
 595c198:	mov    %rax,%rdi
 595c19b:	and    $0x7,%rdi
 595c19f:	je     595c220 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec210>
 595c1a1:	xor    %r8d,%r8d
 595c1a4:	data16 data16 cs nopw 0x0(%rax,%rax,1)
 595c1b0:	mov    (%rdx),%rsi
 595c1b3:	lea    0xe8(%rsi),%rdx
 595c1ba:	inc    %r8
 595c1bd:	cmp    %r8,%rdi
 595c1c0:	jne    595c1b0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec280>
 595c1c2:	mov    %rax,%rdi
 595c1c5:	sub    %r8,%rdi
 595c1c8:	cmp    $0x8,%rax
 595c1cc:	jb     595c211 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec21f>
 595c1ce:	xchg   %ax,%ax
 595c1d0:	mov    (%rdx),%rax
 595c1d3:	mov    0xe8(%rax),%rax
 595c1da:	mov    0xe8(%rax),%rax
 595c1e1:	mov    0xe8(%rax),%rax
 595c1e8:	mov    0xe8(%rax),%rax
 595c1ef:	mov    0xe8(%rax),%rax
 595c1f6:	mov    0xe8(%rax),%rax
 595c1fd:	mov    0xe8(%rax),%rsi
 595c204:	lea    0xe8(%rsi),%rdx
 595c20b:	add    $0xfffffffffffffff8,%rdi
 595c20f:	jne    595c1d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec260>
 595c211:	xor    %r8d,%r8d
 595c214:	jmp    595c073 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec3bd>
 595c219:	nopl   0x0(%rax)
 595c220:	mov    %rax,%rdi
 595c223:	cmp    $0x8,%rax
 595c227:	jae    595c1d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec260>
 595c229:	jmp    595c211 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec21f>
 595c22b:	mov    %r8,%rax
 595c22e:	cmp    $0x8,%r8
 595c232:	jae    595c0f0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec340>
 595c238:	jmp    595c12e <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3ec302>
 595c23d:	lea    0xb474d4(%rip),%rdi        # 64a3718 <__register_atfork@plt+0xb1b88>
 595c244:	call   *0xb835e6(%rip)        # 64df830 <__register_atfork@plt+0xedca0>
 595c24a:	ud2
 595c24c:	lea    0xb45e15(%rip),%rdi        # 64a2068 <__register_atfork@plt+0xb04d8>
 595c253:	call   *0xb835d7(%rip)        # 64df830 <__register_atfork@plt+0xedca0>
 595c259:	lea    0xb5a668(%rip),%rdi        # 64b68c8 <__register_atfork@plt+0xc4d38>
 595c260:	call   *0xb832ba(%rip)        # 64df520 <__register_atfork@plt+0xed990>
 595c266:	ud2

hl-node:     file format elf64-x86-64


Disassembly of section .text:

0000000004d3e1a0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x100a290>:
 4d3e1a0:	push   %r14
 4d3e1a2:	push   %rbx
 4d3e1a3:	sub    $0x68,%rsp
 4d3e1a7:	mov    %rdi,%r14
 4d3e1aa:	mov    %rsi,0x8(%rsp)
 4d3e1af:	mov    (%rsi),%rax
 4d3e1b2:	mov    0x8(%rsi),%rcx
 4d3e1b6:	xor    %edx,%edx
 4d3e1b8:	mov    %rax,%rdi
 4d3e1bb:	test   %rax,%rax
 4d3e1be:	setne  %dl
 4d3e1c1:	je     4d3e1c7 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x100a269>
 4d3e1c3:	mov    0x10(%rsi),%rdi
 4d3e1c7:	mov    %rdx,0x10(%rsp)
 4d3e1cc:	movq   $0x0,0x18(%rsp)
 4d3e1d5:	mov    %rax,0x20(%rsp)
 4d3e1da:	mov    %rcx,0x28(%rsp)
 4d3e1df:	mov    %rdx,0x30(%rsp)
 4d3e1e4:	movq   $0x0,0x38(%rsp)
 4d3e1ed:	mov    %rax,0x40(%rsp)
 4d3e1f2:	mov    %rcx,0x48(%rsp)
 4d3e1f7:	mov    %rdi,0x50(%rsp)
 4d3e1fc:	mov    %r14,0x58(%rsp)
 4d3e201:	lea    0x8(%rsp),%rax
 4d3e206:	mov    %rax,0x60(%rsp)
 4d3e20b:	lea    0x175eb5e(%rip),%rsi        # 649cd70 <__register_atfork@plt+0xab1e0>
 4d3e212:	lea    0x10(%rsp),%rdi
 4d3e217:	call   4e44c00 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf03830>
 4d3e21c:	mov    %rax,%rbx
 4d3e21f:	mov    (%r14),%rax
 4d3e222:	mov    %rax,%rcx
 4d3e225:	neg    %rcx
 4d3e228:	jno    4d3e24c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x100a1e4>
 4d3e22a:	mov    0x8(%r14),%rax
 4d3e22e:	xor    %ecx,%ecx
 4d3e230:	mov    %rax,%rdi
 4d3e233:	test   %rax,%rax
 4d3e236:	setne  %dl
 4d3e239:	je     4d3e23f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x100a1f1>
 4d3e23b:	mov    0x18(%r14),%rdi
 4d3e23f:	mov    0x10(%r14),%rsi
 4d3e243:	mov    %dl,%cl
 4d3e245:	xor    %edx,%edx
 4d3e247:	mov    %rcx,%r8
 4d3e24a:	jmp    4d3e2a2 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x100a18e>
 4d3e24c:	mov    0x18(%r14),%rsi
 4d3e250:	test   %rsi,%rsi
 4d3e253:	je     4d3e27d <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x100a1b3>
 4d3e255:	mov    0x10(%r14),%rdx
 4d3e259:	xor    %ecx,%ecx
 4d3e25b:	cmp    %rax,%rdx
 4d3e25e:	cmovae %rax,%rcx
 4d3e262:	sub    %rcx,%rdx
 4d3e265:	mov    %rax,%rdi
 4d3e268:	sub    %rdx,%rdi
 4d3e26b:	mov    %rsi,%rcx
 4d3e26e:	sub    %rdi,%rcx
 4d3e271:	ja     4d3e283 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x100a1ad>
 4d3e273:	add    %rdx,%rsi
 4d3e276:	xor    %ecx,%ecx
 4d3e278:	mov    %rsi,%rax
 4d3e27b:	jmp    4d3e283 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x100a1ad>
 4d3e27d:	xor    %edx,%edx
 4d3e27f:	xor    %eax,%eax
 4d3e281:	xor    %ecx,%ecx
 4d3e283:	mov    0x8(%r14),%rsi
 4d3e287:	shl    $0x5,%rdx
 4d3e28b:	add    %rsi,%rdx
 4d3e28e:	shl    $0x5,%rax
 4d3e292:	add    %rsi,%rax
 4d3e295:	shl    $0x5,%rcx
 4d3e299:	add    %rsi,%rcx
 4d3e29c:	mov    $0x2,%r8d
 4d3e2a2:	mov    %r8,0x10(%rsp)
 4d3e2a7:	mov    %rdx,0x18(%rsp)
 4d3e2ac:	mov    %rax,0x20(%rsp)
 4d3e2b1:	mov    %rsi,0x28(%rsp)
 4d3e2b6:	mov    %rcx,0x30(%rsp)
 4d3e2bb:	movq   $0x0,0x38(%rsp)
 4d3e2c4:	mov    %rax,0x40(%rsp)
 4d3e2c9:	mov    %rsi,0x48(%rsp)
 4d3e2ce:	mov    %rdi,0x50(%rsp)
 4d3e2d3:	lea    0x175ea7e(%rip),%rsi        # 649cd58 <__register_atfork@plt+0xab1c8>
 4d3e2da:	lea    0x10(%rsp),%rdi
 4d3e2df:	call   4e406f0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf07d40>
 4d3e2e4:	mov    %rax,%rcx
 4d3e2e7:	mov    %rax,%rsi
 4d3e2ea:	shr    $0x3f,%rsi
 4d3e2ee:	mov    $0x3,%edx
 4d3e2f3:	mov    %rbx,%rax
 4d3e2f6:	mul    %rdx
 4d3e2f9:	add    %rcx,%rcx
 4d3e2fc:	cmp    %rax,%rcx
 4d3e2ff:	sbb    %rdx,%rsi
 4d3e302:	setb   %al
 4d3e305:	add    $0x68,%rsp
 4d3e309:	pop    %rbx
 4d3e30a:	pop    %r14
 4d3e30c:	ret

hl-node:     file format elf64-x86-64


Disassembly of section .text:

000000000595e5c0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e9e70>:
 595e5c0:	push   %r14
 595e5c2:	push   %rbx
 595e5c3:	sub    $0xb8,%rsp
 595e5ca:	mov    %rdx,%r14
 595e5cd:	mov    %rdi,%rbx
 595e5d0:	mov    %rdx,0x8(%rsp)
 595e5d5:	lea    -0x50261ed(%rip),%rax        # 9383ef <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5410041>
 595e5dc:	mov    %rax,0x88(%rsp)
 595e5e4:	movq   $0x6,0x90(%rsp)
 595e5f0:	mov    0x20(%rsi),%rax
 595e5f4:	mov    0x60(%rsi),%r10
 595e5f8:	mov    %rax,%rdx
 595e5fb:	add    $0x7d0,%rdx
 595e602:	mov    $0xffffffffffffffff,%r8
 595e609:	mov    %rdx,%rcx
 595e60c:	cmovb  %r8,%rcx
 595e610:	cmp    $0xfffffffffffff830,%rax
 595e616:	mov    %rdx,%r9
 595e619:	cmovae %rcx,%r9
 595e61d:	mov    %r10,%rdi
 595e620:	sub    $0xffffffffffffff38,%rdi
 595e627:	jb     595e637 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e9df9>
 595e629:	add    $0xc8,%r10
 595e630:	cmovb  %r8,%r10
 595e634:	mov    %r10,%rdi
 595e637:	inc    %rdi
 595e63a:	cmove  %r8,%rdi
 595e63e:	cmp    %r9,%rdi
 595e641:	cmovbe %r9,%rdi
 595e645:	cmp    %rdi,%r14
 595e648:	jb     595e772 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e9cbe>
 595e64e:	lea    0x60(%rsi),%rax
 595e652:	lock incq 0x68(%rsi)
 595e657:	mov    %rdi,0x10(%rsp)
 595e65c:	movq   $0x0,0x70(%rsp)
 595e665:	movl   $0x0,0x80(%rsp)
 595e670:	movw   $0x0,0x84(%rsp)
 595e67a:	movb   $0x1,0x80(%rsp)
 595e682:	lea    0x88(%rsp),%rcx
 595e68a:	mov    %rcx,0xa8(%rsp)
 595e692:	lea    -0x348379(%rip),%rcx        # 5616320 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x732110>
 595e699:	mov    %rcx,0xb0(%rsp)
 595e6a1:	lea    -0x552146c(%rip),%rcx        # 43d23c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x590b1f4>
 595e6a8:	mov    %rcx,0x98(%rsp)
 595e6b0:	lea    0xa8(%rsp),%rcx
 595e6b8:	mov    %rcx,0xa0(%rsp)
 595e6c0:	lea    0x8(%rsp),%rcx
 595e6c5:	mov    %rcx,0x18(%rsp)
 595e6ca:	lea    0x10(%rsp),%rcx
 595e6cf:	mov    %rcx,0x20(%rsp)
 595e6d4:	mov    %rax,0x28(%rsp)
 595e6d9:	lea    0x98(%rsp),%rax
 595e6e1:	mov    %rax,0x30(%rsp)
 595e6e6:	lea    -0x1344cd(%rip),%rax        # 582a220 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x51e210>
 595e6ed:	mov    %rax,0x38(%rsp)
 595e6f2:	lea    0x18(%rsp),%rax
 595e6f7:	mov    %rax,0x40(%rsp)
 595e6fc:	lea    -0x1346e3(%rip),%rax        # 582a020 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x51e410>
 595e703:	mov    %rax,0x48(%rsp)
 595e708:	lea    0x20(%rsp),%rax
 595e70d:	mov    %rax,0x50(%rsp)
 595e712:	lea    -0x1345f9(%rip),%rax        # 582a120 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x51e310>
 595e719:	mov    %rax,0x58(%rsp)
 595e71e:	lea    0x28(%rsp),%rcx
 595e723:	mov    %rcx,0x60(%rsp)
 595e728:	mov    %rax,0x68(%rsp)
 595e72d:	lea    -0x552db0a(%rip),%rax        # 430c2a <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5917806>
 595e734:	lea    0xb5815d(%rip),%rcx        # 64b6898 <__register_atfork@plt+0xc4d08>
 595e73b:	lea    0x70(%rsp),%rdi
 595e740:	lea    0x30(%rsp),%rdx
 595e745:	mov    %rsi,%r14
 595e748:	mov    %rax,%rsi
 595e74b:	call   *0xb823c7(%rip)        # 64e0b18 <__register_atfork@plt+0xeef88>
 595e751:	mov    %r14,%rsi
 595e754:	mov    0x8(%rsp),%r14
 595e759:	mov    0x20(%rsi),%rax
 595e75d:	mov    %rax,%rdx
 595e760:	add    $0x7d0,%rdx
 595e767:	mov    $0xffffffffffffffff,%rcx
 595e76e:	cmovae %rdx,%rcx
 595e772:	cmp    $0xfffffffffffff830,%rax
 595e778:	cmovb  %rdx,%rcx
 595e77c:	lea    -0xc8(%r14),%rdx
 595e783:	cmp    %rdx,%rax
 595e786:	cmova  %rax,%rdx
 595e78a:	cmp    %rcx,%r14
 595e78d:	cmovb  %rax,%rdx
 595e791:	lea    0x30(%rsp),%rdi
 595e796:	call   4dce480 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf79fb0>
 595e79b:	mov    0x30(%rsp),%rax
 595e7a0:	cmp    $0x2,%rax
 595e7a4:	je     595e7d2 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e9c5e>
 595e7a6:	cmp    $0x1,%eax
 595e7a9:	jne    595e7f5 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e9c3b>
 595e7ab:	mov    0x50(%rsp),%rax
 595e7b0:	cmp    %rax,0x48(%rsp)
 595e7b5:	jne    595e7c3 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e9c6d>
 595e7b7:	mov    0x40(%rsp),%rax
 595e7bc:	cmp    %rax,0x38(%rsp)
 595e7c1:	je     595e7ea <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e9c46>
 595e7c3:	add    $0xffffffffffffffc0,%rax
 595e7c7:	lea    0x8(%rax),%rdx
 595e7cb:	test   %rax,%rax
 595e7ce:	jne    595e7e1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e9c4f>
 595e7d0:	jmp    595e7f5 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e9c3b>
 595e7d2:	lea    0x38(%rsp),%rdi
 595e7d7:	call   51f5620 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xb52e10>
 595e7dc:	test   %rax,%rax
 595e7df:	je     595e7f5 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e9c3b>
 595e7e1:	mov    %rdx,0x8(%rbx)
 595e7e5:	movb   $0x2e,(%rbx)
 595e7e8:	jmp    595e7fc <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e9c34>
 595e7ea:	xor    %eax,%eax
 595e7ec:	lea    0x8(%rax),%rdx
 595e7f0:	test   %rax,%rax
 595e7f3:	jne    595e7e1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e9c4f>
 595e7f5:	movb   $0x28,(%rbx)
 595e7f8:	mov    %r14,0x8(%rbx)
 595e7fc:	mov    %rbx,%rax
 595e7ff:	add    $0xb8,%rsp
 595e806:	pop    %rbx
 595e807:	pop    %r14
 595e809:	ret

hl-node:     file format elf64-x86-64


Disassembly of section .text:

000000000513b200 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc0d230>:
 513b200:	push   %rax
 513b201:	mov    0x40(%rdi),%rax
 513b205:	test   %rax,%rax
 513b208:	je     513b243 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc0d1ed>
 513b20a:	dec    %rax
 513b20d:	mov    %rax,0x40(%rdi)
 513b211:	cmpl   $0x1,(%rdi)
 513b214:	jne    513b40b <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc0d025>
 513b21a:	mov    0x8(%rdi),%rax
 513b21e:	test   %rax,%rax
 513b221:	je     513b247 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc0d1e9>
 513b223:	mov    0x10(%rdi),%rsi
 513b227:	mov    0x18(%rdi),%rcx
 513b22b:	movzwl 0x3fe(%rax),%edx
 513b232:	cmp    %rdx,%rcx
 513b235:	jae    513b300 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc0d130>
 513b23b:	mov    %rax,%rdx
 513b23e:	jmp    513b322 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc0d10e>
 513b243:	xor    %eax,%eax
 513b245:	pop    %rcx
 513b246:	ret
 513b247:	lea    0x10(%rdi),%rcx
 513b24b:	mov    0x10(%rdi),%rax
 513b24f:	mov    0x18(%rdi),%rdx
 513b253:	test   %rdx,%rdx
 513b256:	je     513b2ce <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc0d162>
 513b258:	mov    %rdx,%rsi
 513b25b:	and    $0x7,%rsi
 513b25f:	je     513b3ea <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc0d046>
 513b265:	xor    %r8d,%r8d
 513b268:	nopl   0x0(%rax,%rax,1)
 513b270:	mov    0x400(%rax),%rax
 513b277:	inc    %r8
 513b27a:	cmp    %r8,%rsi
 513b27d:	jne    513b270 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc0d1c0>
 513b27f:	mov    %rdx,%rsi
 513b282:	sub    %r8,%rsi
 513b285:	cmp    $0x8,%rdx
 513b289:	jb     513b2ce <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc0d162>
 513b28b:	nopl   0x0(%rax,%rax,1)
 513b290:	mov    0x400(%rax),%rax
 513b297:	mov    0x400(%rax),%rax
 513b29e:	mov    0x400(%rax),%rax
 513b2a5:	mov    0x400(%rax),%rax
 513b2ac:	mov    0x400(%rax),%rax
 513b2b3:	mov    0x400(%rax),%rax
 513b2ba:	mov    0x400(%rax),%rax
 513b2c1:	mov    0x400(%rax),%rax
 513b2c8:	add    $0xfffffffffffffff8,%rsi
 513b2cc:	jne    513b290 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc0d1a0>
 513b2ce:	movq   $0x1,(%rdi)
 513b2d5:	mov    %rax,0x8(%rdi)
 513b2d9:	xorps  %xmm0,%xmm0
 513b2dc:	movups %xmm0,(%rcx)
 513b2df:	xor    %ecx,%ecx
 513b2e1:	xor    %esi,%esi
 513b2e3:	movzwl 0x3fe(%rax),%edx
 513b2ea:	cmp    %rdx,%rcx
 513b2ed:	jb     513b23b <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc0d1f5>
 513b2f3:	data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
 513b300:	mov    (%rax),%rdx
 513b303:	test   %rdx,%rdx
 513b306:	je     513b3fc <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc0d034>
 513b30c:	inc    %rsi
 513b30f:	movzwl 0x3fc(%rax),%ecx
 513b316:	mov    %rdx,%rax
 513b319:	cmp    0x3fe(%rdx),%cx
 513b320:	jae    513b300 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc0d130>
 513b322:	test   %rsi,%rsi
 513b325:	je     513b362 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc0d0ce>
 513b327:	lea    (%rdx,%rcx,8),%rax
 513b32b:	add    $0x408,%rax
 513b331:	mov    %rsi,%r9
 513b334:	and    $0x7,%r9
 513b338:	je     513b36b <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc0d0c5>
 513b33a:	xor    %r10d,%r10d
 513b33d:	nopl   (%rax)
 513b340:	mov    (%rax),%r8
 513b343:	lea    0x400(%r8),%rax
 513b34a:	inc    %r10
 513b34d:	cmp    %r10,%r9
 513b350:	jne    513b340 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc0d0f0>
 513b352:	mov    %rsi,%r9
 513b355:	sub    %r10,%r9
 513b358:	cmp    $0x8,%rsi
 513b35c:	jae    513b374 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc0d0bc>
 513b35e:	xor    %esi,%esi
 513b360:	jmp    513b3c1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc0d06f>
 513b362:	lea    0x1(%rcx),%rsi
 513b366:	mov    %rdx,%r8
 513b369:	jmp    513b3c1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc0d06f>
 513b36b:	mov    %rsi,%r9
 513b36e:	cmp    $0x8,%rsi
 513b372:	jb     513b35e <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc0d0d2>
 513b374:	xor    %esi,%esi
 513b376:	cs nopw 0x0(%rax,%rax,1)
 513b380:	mov    (%rax),%rax
 513b383:	mov    0x400(%rax),%rax
 513b38a:	mov    0x400(%rax),%rax
 513b391:	mov    0x400(%rax),%rax
 513b398:	mov    0x400(%rax),%rax
 513b39f:	mov    0x400(%rax),%rax
 513b3a6:	mov    0x400(%rax),%rax
 513b3ad:	mov    0x400(%rax),%r8
 513b3b4:	lea    0x400(%r8),%rax
 513b3bb:	add    $0xfffffffffffffff8,%r9
 513b3bf:	jne    513b380 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc0d0b0>
 513b3c1:	lea    (%rcx,%rcx,4),%rax
 513b3c5:	lea    (%rdx,%rax,4),%rax
 513b3c9:	add    $0x320,%rax
 513b3cf:	lea    (%rcx,%rcx,8),%rcx
 513b3d3:	lea    0x8(%rdx,%rcx,8),%rdx
 513b3d8:	mov    %r8,0x8(%rdi)
 513b3dc:	movq   $0x0,0x10(%rdi)
 513b3e4:	mov    %rsi,0x18(%rdi)
 513b3e8:	pop    %rcx
 513b3e9:	ret
 513b3ea:	mov    %rdx,%rsi
 513b3ed:	cmp    $0x8,%rdx
 513b3f1:	jae    513b290 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc0d1a0>
 513b3f7:	jmp    513b2ce <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc0d162>
 513b3fc:	lea    0x1368315(%rip),%rdi        # 64a3718 <__register_atfork@plt+0xb1b88>
 513b403:	call   *0x13a4427(%rip)        # 64df830 <__register_atfork@plt+0xedca0>
 513b409:	ud2
 513b40b:	lea    0x1366c56(%rip),%rdi        # 64a2068 <__register_atfork@plt+0xb04d8>
 513b412:	call   *0x13a4418(%rip)        # 64df830 <__register_atfork@plt+0xedca0>
 513b418:	ud2

hl-node:     file format elf64-x86-64


Disassembly of section .text:

0000000004e44c00 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf03830>:
 4e44c00:	push   %rbp
 4e44c01:	push   %r15
 4e44c03:	push   %r14
 4e44c05:	push   %r13
 4e44c07:	push   %r12
 4e44c09:	push   %rbx
 4e44c0a:	sub    $0x78,%rsp
 4e44c0e:	mov    0x50(%rdi),%rax
 4e44c12:	mov    %rax,0x70(%rsp)
 4e44c17:	movups 0x40(%rdi),%xmm0
 4e44c1b:	movaps %xmm0,0x60(%rsp)
 4e44c20:	movups (%rdi),%xmm0
 4e44c23:	movups 0x10(%rdi),%xmm1
 4e44c27:	movups 0x20(%rdi),%xmm2
 4e44c2b:	movups 0x30(%rdi),%xmm3
 4e44c2f:	movaps %xmm3,0x50(%rsp)
 4e44c34:	movaps %xmm2,0x40(%rsp)
 4e44c39:	movaps %xmm1,0x30(%rsp)
 4e44c3e:	movaps %xmm0,0x20(%rsp)
 4e44c43:	lea    0x20(%rsp),%rdi
 4e44c48:	call   5138730 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc0fd00>
 4e44c4d:	test   %rax,%rax
 4e44c50:	je     4e44def <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf03641>
 4e44c56:	mov    %rax,%r15
 4e44c59:	xor    %ebx,%ebx
 4e44c5b:	jmp    4e44c91 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf0379f>
 4e44c5d:	nopl   (%rax)
 4e44c60:	mov    0x8(%rsp),%rbx
 4e44c65:	add    0x0(%rbp),%rbx
 4e44c69:	mov    %rbx,%rax
 4e44c6c:	mov    $0xffffffffffffffff,%rcx
 4e44c73:	cmovb  %rcx,%rax
 4e44c77:	cmovb  %rax,%rbx
 4e44c7b:	lea    0x20(%rsp),%rdi
 4e44c80:	call   5138730 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc0fd00>
 4e44c85:	mov    %rax,%r15
 4e44c88:	test   %rax,%rax
 4e44c8b:	je     4e44df1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf0363f>
 4e44c91:	mov    %rbx,0x8(%rsp)
 4e44c96:	jmp    4e44cb6 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf0377a>
 4e44c98:	nopl   0x0(%rax,%rax,1)
 4e44ca0:	lea    0x20(%rsp),%rdi
 4e44ca5:	call   5138730 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc0fd00>
 4e44caa:	mov    %rax,%r15
 4e44cad:	test   %rax,%rax
 4e44cb0:	je     4e44de8 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf03648>
 4e44cb6:	mov    0x68(%rsp),%r12
 4e44cbb:	mov    (%r12),%rbx
 4e44cbf:	mov    %rbx,%rax
 4e44cc2:	neg    %rax
 4e44cc5:	jno    4e44da0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf03690>
 4e44ccb:	mov    0x8(%r12),%rbx
 4e44cd0:	test   %rbx,%rbx
 4e44cd3:	je     4e44ca0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf03790>
 4e44cd5:	mov    0x10(%r12),%rax
 4e44cda:	mov    %rax,0x10(%rsp)
 4e44cdf:	lea    0x60(%rbx),%rsi
 4e44ce3:	movzwl 0x13e(%rbx),%eax
 4e44cea:	mov    %rax,0x18(%rsp)
 4e44cef:	lea    0x0(,%rax,4),%eax
 4e44cf6:	lea    (%rax,%rax,4),%r13
 4e44cfa:	mov    $0xffffffffffffffff,%r14
 4e44d01:	mov    %rbx,%rbp
 4e44d04:	data16 data16 cs nopw 0x0(%rax,%rax,1)
 4e44d10:	test   %r13,%r13
 4e44d13:	je     4e44d70 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf036c0>
 4e44d15:	lea    0x14(%rsi),%r12
 4e44d19:	mov    $0x14,%edx
 4e44d1e:	mov    %r15,%rdi
 4e44d21:	call   *0x169ae29(%rip)        # 64dfb50 <__register_atfork@plt+0xedfc0>
 4e44d27:	cltq
 4e44d29:	test   %rax,%rax
 4e44d2c:	sets   %cl
 4e44d2f:	setg   %al
 4e44d32:	sub    %cl,%al
 4e44d34:	add    $0x8,%rbp
 4e44d38:	inc    %r14
 4e44d3b:	add    $0xffffffffffffffec,%r13
 4e44d3f:	mov    %r12,%rsi
 4e44d42:	cmp    $0x1,%al
 4e44d44:	je     4e44d10 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf03720>
 4e44d46:	movzbl %al,%eax
 4e44d49:	test   %eax,%eax
 4e44d4b:	je     4e44c60 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf037d0>
 4e44d51:	mov    0x10(%rsp),%rax
 4e44d56:	sub    $0x1,%rax
 4e44d5a:	jae    4e44d84 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf036ac>
 4e44d5c:	jmp    4e44ca0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf03790>
 4e44d61:	data16 data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
 4e44d70:	mov    0x18(%rsp),%r14
 4e44d75:	mov    0x10(%rsp),%rax
 4e44d7a:	sub    $0x1,%rax
 4e44d7e:	jb     4e44ca0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf03790>
 4e44d84:	mov    %rax,0x10(%rsp)
 4e44d89:	mov    0x140(%rbx,%r14,8),%rbx
 4e44d91:	jmp    4e44cdf <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf03751>
 4e44d96:	cs nopw 0x0(%rax,%rax,1)
 4e44da0:	mov    %r12,%rdi
 4e44da3:	mov    %r15,%rsi
 4e44da6:	call   57f54e0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x552f50>
 4e44dab:	test   $0x1,%al
 4e44dad:	jne    4e44ca0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf03790>
 4e44db3:	cmp    0x18(%r12),%rdx
 4e44db8:	jae    4e44ca0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf03790>
 4e44dbe:	add    0x10(%r12),%rdx
 4e44dc3:	cmp    %rbx,%rdx
 4e44dc6:	mov    $0x0,%eax
 4e44dcb:	cmovae %rbx,%rax
 4e44dcf:	sub    %rax,%rdx
 4e44dd2:	mov    0x8(%r12),%rax
 4e44dd7:	shl    $0x5,%rdx
 4e44ddb:	lea    (%rax,%rdx,1),%rbp
 4e44ddf:	add    $0x18,%rbp
 4e44de3:	jmp    4e44c60 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf037d0>
 4e44de8:	mov    0x8(%rsp),%rbx
 4e44ded:	jmp    4e44df1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xf0363f>
 4e44def:	xor    %ebx,%ebx
 4e44df1:	mov    %rbx,%rax
 4e44df4:	add    $0x78,%rsp
 4e44df8:	pop    %rbx
 4e44df9:	pop    %r12
 4e44dfb:	pop    %r13
 4e44dfd:	pop    %r14
 4e44dff:	pop    %r15
 4e44e01:	pop    %rbp
 4e44e02:	ret

hl-node:     file format elf64-x86-64


Disassembly of section .text:

00000000057e8d40 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x55f6f0>:
 57e8d40:	push   %rbp
 57e8d41:	push   %r15
 57e8d43:	push   %r14
 57e8d45:	push   %r13
 57e8d47:	push   %r12
 57e8d49:	push   %rbx
 57e8d4a:	sub    $0x238,%rsp
 57e8d51:	mov    %rdi,%r14
 57e8d54:	mov    %rsi,0x20(%rsp)
 57e8d59:	mov    $0x1d,%edi
 57e8d5e:	call   *0xcf671c(%rip)        # 64df480 <__register_atfork@plt+0xed8f0>
 57e8d64:	test   %rax,%rax
 57e8d67:	je     57e8fcf <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x55f461>
 57e8d6d:	mov    %rax,%rbx
 57e8d70:	movups -0x4eb2a57(%rip),%xmm0        # 936320 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5412110>
 57e8d77:	movups %xmm0,0xd(%rax)
 57e8d7b:	movups -0x4eb2a6f(%rip),%xmm0        # 936313 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x541211d>
 57e8d82:	movups %xmm0,(%rax)
 57e8d85:	mov    $0x1,%edi
 57e8d8a:	call   5c842e0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc4150>
 57e8d8f:	mov    %rax,%r15
 57e8d92:	mov    %edx,%ebp
 57e8d94:	lea    0x150(%rsp),%rdi
 57e8d9c:	lea    0x20(%rsp),%rsi
 57e8da1:	xor    %edx,%edx
 57e8da3:	call   5823db0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x524680>
 57e8da8:	mov    $0x1,%r13b
 57e8dab:	mov    $0x1,%edi
 57e8db0:	call   5c842e0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc4150>
 57e8db5:	mov    %rax,(%rsp)
 57e8db9:	mov    %edx,0x8(%rsp)
 57e8dbd:	mov    %r15,0x28(%rsp)
 57e8dc2:	mov    %ebp,0x30(%rsp)
 57e8dc6:	lea    0x70(%rsp),%rdi
 57e8dcb:	mov    %rsp,%rsi
 57e8dce:	lea    0x28(%rsp),%rdx
 57e8dd3:	call   5c84210 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0xc4220>
 57e8dd8:	mov    0x150(%rsp),%rax
 57e8de0:	mov    0x158(%rsp),%r12
 57e8de8:	mov    $0x1,%r15d
 57e8dee:	mov    0x160(%rsp),%rdi
 57e8df6:	lea    -0x4eb338d(%rip),%rcx        # 935a70 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x54129c0>
 57e8dfd:	movslq (%rcx,%rax,4),%rax
 57e8e01:	add    %rcx,%rax
 57e8e04:	jmp    *%rax
 57e8e06:	xor    %r13d,%r13d
 57e8e09:	xor    %r12d,%r12d
 57e8e0c:	jmp    57e8e4b <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x55f5e5>
 57e8e0e:	xor    %r13d,%r13d
 57e8e11:	mov    $0x10,%esi
 57e8e16:	mov    %r12,%rdi
 57e8e19:	jmp    57e8e26 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x55f60a>
 57e8e1b:	test   %r12,%r12
 57e8e1e:	je     57e8e06 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x55f62a>
 57e8e20:	xor    %r13d,%r13d
 57e8e23:	mov    %r12,%rsi
 57e8e26:	xor    %edx,%edx
 57e8e28:	call   *0xcf6672(%rip)        # 64df4a0 <__register_atfork@plt+0xed910>
 57e8e2e:	xor    %r12d,%r12d
 57e8e31:	jmp    57e8e4b <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x55f5e5>
 57e8e33:	xor    %r13d,%r13d
 57e8e36:	call   57e1970 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x566ac0>
 57e8e3b:	xor    %r12d,%r12d
 57e8e3e:	jmp    57e8e4b <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x55f5e5>
 57e8e40:	mov    0x168(%rsp),%r13
 57e8e48:	mov    %rdi,%r15
 57e8e4b:	movq   $0x1d,0x28(%rsp)
 57e8e54:	mov    %rbx,0x30(%rsp)
 57e8e59:	movq   $0x1d,0x38(%rsp)
 57e8e62:	mov    %r12,0x40(%rsp)
 57e8e67:	mov    %r15,0x48(%rsp)
 57e8e6c:	mov    %r13,0x50(%rsp)
 57e8e71:	lea    0x58(%rsp),%rdi
 57e8e76:	lea    0x28(%rsp),%rsi
 57e8e7b:	mov    $0x2,%edx
 57e8e80:	call   5b3df10 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x20a520>
 57e8e85:	xorps  %xmm0,%xmm0
 57e8e88:	movaps %xmm0,0x10(%rsp)
 57e8e8d:	movaps %xmm0,(%rsp)
 57e8e91:	movaps %xmm0,0x130(%rsp)
 57e8e99:	movaps %xmm0,0x120(%rsp)
 57e8ea1:	movaps %xmm0,0x110(%rsp)
 57e8ea9:	movaps %xmm0,0x100(%rsp)
 57e8eb1:	movaps %xmm0,0xf0(%rsp)
 57e8eb9:	movaps %xmm0,0xe0(%rsp)
 57e8ec1:	movaps %xmm0,0xd0(%rsp)
 57e8ec9:	movaps %xmm0,0xc0(%rsp)
 57e8ed1:	movaps %xmm0,0xb0(%rsp)
 57e8ed9:	movaps %xmm0,0xa0(%rsp)
 57e8ee1:	movaps %xmm0,0x90(%rsp)
 57e8ee9:	movaps %xmm0,0x80(%rsp)
 57e8ef1:	movaps %xmm0,0x70(%rsp)
 57e8ef6:	movq   $0x88,0x140(%rsp)
 57e8f02:	movw   $0x1,0x148(%rsp)
 57e8f0c:	mov    0x60(%rsp),%r13
 57e8f11:	mov    0x68(%rsp),%rdx
 57e8f16:	lea    0x70(%rsp),%rdi
 57e8f1b:	mov    %r13,%rsi
 57e8f1e:	call   *0xcf7224(%rip)        # 64e0148 <__register_atfork@plt+0xee5b8>
 57e8f24:	lea    0x150(%rsp),%rbp
 57e8f2c:	lea    0x70(%rsp),%rsi
 57e8f31:	mov    $0xe0,%edx
 57e8f36:	mov    %rbp,%rdi
 57e8f39:	call   *0xcf65c9(%rip)        # 64df508 <__register_atfork@plt+0xed978>
 57e8f3f:	mov    %rsp,%rsi
 57e8f42:	mov    $0x20,%edx
 57e8f47:	mov    %rbp,%rdi
 57e8f4a:	call   *0xcf7200(%rip)        # 64e0150 <__register_atfork@plt+0xee5c0>
 57e8f50:	movaps (%rsp),%xmm0
 57e8f54:	movaps 0x10(%rsp),%xmm1
 57e8f59:	movaps %xmm0,0x150(%rsp)
 57e8f61:	movaps %xmm1,0x160(%rsp)
 57e8f69:	mov    0x58(%rsp),%rsi
 57e8f6e:	test   %rsi,%rsi
 57e8f71:	je     57e8f7e <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x55f4b2>
 57e8f73:	mov    %r13,%rdi
 57e8f76:	xor    %edx,%edx
 57e8f78:	call   *0xcf6522(%rip)        # 64df4a0 <__register_atfork@plt+0xed910>
 57e8f7e:	movaps 0x150(%rsp),%xmm0
 57e8f86:	movaps 0x160(%rsp),%xmm1
 57e8f8e:	movups %xmm1,0x10(%r14)
 57e8f93:	movups %xmm0,(%r14)
 57e8f97:	mov    $0x1d,%esi
 57e8f9c:	mov    %rbx,%rdi
 57e8f9f:	xor    %edx,%edx
 57e8fa1:	call   *0xcf64f9(%rip)        # 64df4a0 <__register_atfork@plt+0xed910>
 57e8fa7:	test   %r12,%r12
 57e8faa:	je     57e8fba <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x55f476>
 57e8fac:	mov    %r15,%rdi
 57e8faf:	mov    %r12,%rsi
 57e8fb2:	xor    %edx,%edx
 57e8fb4:	call   *0xcf64e6(%rip)        # 64df4a0 <__register_atfork@plt+0xed910>
 57e8fba:	mov    %r14,%rax
 57e8fbd:	add    $0x238,%rsp
 57e8fc4:	pop    %rbx
 57e8fc5:	pop    %r12
 57e8fc7:	pop    %r13
 57e8fc9:	pop    %r14
 57e8fcb:	pop    %r15
 57e8fcd:	pop    %rbp
 57e8fce:	ret
 57e8fcf:	mov    $0x1,%edi
 57e8fd4:	mov    $0x1d,%esi
 57e8fd9:	call   *0xcf64b9(%rip)        # 64df498 <__register_atfork@plt+0xed908>
 57e8fdf:	mov    %rax,%r14
 57e8fe2:	lea    0x28(%rsp),%rdi
 57e8fe7:	call   57d8780 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x56fcb0>
 57e8fec:	mov    %r14,%rdi
 57e8fef:	call   63f0a50 <_Unwind_Resume@plt>
 57e8ff4:	mov    %rax,%r14
 57e8ff7:	mov    0x58(%rsp),%rsi
 57e8ffc:	test   %rsi,%rsi
 57e8fff:	je     57e900c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x55f424>
 57e9001:	mov    %r13,%rdi
 57e9004:	xor    %edx,%edx
 57e9006:	call   *0xcf6494(%rip)        # 64df4a0 <__register_atfork@plt+0xed910>
 57e900c:	lea    0x28(%rsp),%rdi
 57e9011:	call   57d8780 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x56fcb0>
 57e9016:	mov    %r14,%rdi
 57e9019:	call   63f0a50 <_Unwind_Resume@plt>
 57e901e:	mov    %rax,%r14
 57e9021:	jmp    57e9061 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x55f3cf>
 57e9023:	mov    %rax,%r14
 57e9026:	cmpl   $0x8,0x150(%rsp)
 57e902e:	jne    57e904f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x55f3e1>
 57e9030:	mov    0x158(%rsp),%rsi
 57e9038:	test   %rsi,%rsi
 57e903b:	je     57e9061 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x55f3cf>
 57e903d:	mov    0x160(%rsp),%rdi
 57e9045:	xor    %edx,%edx
 57e9047:	call   *0xcf6453(%rip)        # 64df4a0 <__register_atfork@plt+0xed910>
 57e904d:	jmp    57e9061 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x55f3cf>
 57e904f:	test   %r13b,%r13b
 57e9052:	je     57e9061 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x55f3cf>
 57e9054:	lea    0x150(%rsp),%rdi
 57e905c:	call   57e1e70 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5665c0>
 57e9061:	mov    $0x1d,%esi
 57e9066:	mov    %rbx,%rdi
 57e9069:	xor    %edx,%edx
 57e906b:	call   *0xcf642f(%rip)        # 64df4a0 <__register_atfork@plt+0xed910>
 57e9071:	mov    %r14,%rdi
 57e9074:	call   63f0a50 <_Unwind_Resume@plt>
 57e9079:	call   *0xcf6441(%rip)        # 64df4c0 <__register_atfork@plt+0xed930>

hl-node:     file format elf64-x86-64


Disassembly of section .text:

0000000005823db0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x524680>:
 5823db0:	push   %rbp
 5823db1:	push   %r15
 5823db3:	push   %r14
 5823db5:	push   %r13
 5823db7:	push   %r12
 5823db9:	push   %rbx
 5823dba:	sub    $0x88,%rsp
 5823dc1:	mov    %rcx,%r15
 5823dc4:	mov    %rdx,%r12
 5823dc7:	mov    %rdi,%rbx
 5823dca:	mov    %rdx,0x30(%rsp)
 5823dcf:	mov    %rcx,0x38(%rsp)
 5823dd4:	mov    (%rsi),%rbp
 5823dd7:	mov    0x0(%rbp),%rax
 5823ddb:	mov    0x8(%rbp),%rsi
 5823ddf:	movq   $0x1,0x40(%rsp)
 5823de8:	lea    -0x4eee1ab(%rip),%rcx        # 935c44 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x54127ec>
 5823def:	movslq (%rcx,%rax,4),%rax
 5823df3:	add    %rcx,%rax
 5823df6:	jmp    *%rax
 5823df8:	lea    0x8(%rsp),%rdi
 5823dfd:	lea    0x30(%rsp),%rdx
 5823e02:	call   5967290 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e11a0>
 5823e07:	mov    0x8(%rsp),%rax
 5823e0c:	cmp    $0x8,%rax
 5823e10:	je     5823ea0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x524590>
 5823e16:	jmp    5823f1a <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x524516>
 5823e1b:	lea    0x40(%rsp),%rax
 5823e20:	mov    0x30(%rsi),%ecx
 5823e23:	xor    %edx,%edx
 5823e25:	cmp    $0x10000,%ecx
 5823e2b:	setae  %dl
 5823e2e:	cmp    $0xfb,%ecx
 5823e34:	lea    0x2c(%rdx,%rdx,1),%rcx
 5823e39:	mov    $0x2a,%edx
 5823e3e:	cmovae %rcx,%rdx
 5823e42:	mov    %rdx,0x40(%rsp)
 5823e47:	mov    (%rsi),%rdx
 5823e4a:	lea    0x8(%rsp),%rdi
 5823e4f:	mov    %rax,%rsi
 5823e52:	call   5822b90 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5258a0>
 5823e57:	mov    0x8(%rsp),%rax
 5823e5c:	cmp    $0x8,%rax
 5823e60:	je     5823ea0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x524590>
 5823e62:	jmp    5823f1a <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x524516>
 5823e67:	lea    0x8(%rsp),%rdi
 5823e6c:	lea    0x30(%rsp),%rdx
 5823e71:	call   5967e80 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e05b0>
 5823e76:	mov    0x8(%rsp),%rax
 5823e7b:	cmp    $0x8,%rax
 5823e7f:	je     5823ea0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x524590>
 5823e81:	jmp    5823f1a <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x524516>
 5823e86:	lea    0x8(%rsp),%rdi
 5823e8b:	lea    0x30(%rsp),%rdx
 5823e90:	call   5b56070 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x1f23c0>
 5823e95:	mov    0x8(%rsp),%rax
 5823e9a:	cmp    $0x8,%rax
 5823e9e:	jne    5823f1a <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x524516>
 5823ea0:	mov    0x40(%rsp),%r13
 5823ea5:	test   %r13,%r13
 5823ea8:	js     58241a6 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x52428a>
 5823eae:	lea    0x18(%rsp),%r14
 5823eb3:	je     5823f48 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5244e8>
 5823eb9:	mov    %r13,%rdi
 5823ebc:	call   *0xcbb5be(%rip)        # 64df480 <__register_atfork@plt+0xed8f0>
 5823ec2:	test   %rax,%rax
 5823ec5:	je     58241b1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x52427f>
 5823ecb:	mov    %r13,0x18(%rsp)
 5823ed0:	mov    %rax,0x20(%rsp)
 5823ed5:	movq   $0x0,0x28(%rsp)
 5823ede:	mov    %r12,0x8(%rsp)
 5823ee3:	mov    %r15,0x10(%rsp)
 5823ee8:	mov    0x0(%rbp),%rcx
 5823eec:	mov    0x8(%rbp),%r15
 5823ef0:	lea    -0x4eee29f(%rip),%rdx        # 935c58 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x54127d8>
 5823ef7:	movslq (%rdx,%rcx,4),%rcx
 5823efb:	add    %rdx,%rcx
 5823efe:	jmp    *%rcx
 5823f00:	lea    0x8(%rsp),%rdi
 5823f05:	lea    0x30(%rsp),%rdx
 5823f0a:	call   5966cd0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e1760>
 5823f0f:	mov    0x8(%rsp),%rax
 5823f14:	cmp    $0x8,%rax
 5823f18:	je     5823ea0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x524590>
 5823f1a:	mov    0x20(%rsp),%rcx
 5823f1f:	mov    %rcx,0x60(%rsp)
 5823f24:	movups 0x10(%rsp),%xmm0
 5823f29:	movaps %xmm0,0x50(%rsp)
 5823f2e:	mov    %rax,(%rbx)
 5823f31:	movaps 0x50(%rsp),%xmm0
 5823f36:	movups %xmm0,0x8(%rbx)
 5823f3a:	mov    0x60(%rsp),%rax
 5823f3f:	mov    %rax,0x18(%rbx)
 5823f43:	jmp    58240c4 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x52436c>
 5823f48:	mov    $0x1,%eax
 5823f4d:	mov    %r13,0x18(%rsp)
 5823f52:	mov    %rax,0x20(%rsp)
 5823f57:	movq   $0x0,0x28(%rsp)
 5823f60:	mov    %r12,0x8(%rsp)
 5823f65:	mov    %r15,0x10(%rsp)
 5823f6a:	mov    0x0(%rbp),%rcx
 5823f6e:	mov    0x8(%rbp),%r15
 5823f72:	lea    -0x4eee321(%rip),%rdx        # 935c58 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x54127d8>
 5823f79:	movslq (%rdx,%rcx,4),%rcx
 5823f7d:	add    %rdx,%rcx
 5823f80:	jmp    *%rcx
 5823f82:	test   %r13,%r13
 5823f85:	je     5824154 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5242dc>
 5823f8b:	xor    %ecx,%ecx
 5823f8d:	movb   $0x0,(%rax,%rcx,1)
 5823f91:	inc    %rcx
 5823f94:	mov    %rcx,0x28(%rsp)
 5823f99:	lea    0x30(%rsp),%rdi
 5823f9e:	lea    0x8(%rsp),%rdx
 5823fa3:	mov    %r15,%rsi
 5823fa6:	call   5967060 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e13d0>
 5823fab:	jmp    582405a <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5243d6>
 5823fb0:	test   %r13,%r13
 5823fb3:	je     58240d9 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x524357>
 5823fb9:	xor    %ecx,%ecx
 5823fbb:	movb   $0x4,(%rax,%rcx,1)
 5823fbf:	inc    %rcx
 5823fc2:	mov    %rcx,0x28(%rsp)
 5823fc7:	lea    0x30(%rsp),%rdi
 5823fcc:	lea    0x8(%rsp),%rdx
 5823fd1:	mov    %r15,%rsi
 5823fd4:	call   5b5b360 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x1ed0d0>
 5823fd9:	jmp    582405a <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5243d6>
 5823fdb:	test   %r13,%r13
 5823fde:	je     5824102 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x52432e>
 5823fe4:	xor    %ecx,%ecx
 5823fe6:	movb   $0x2,(%rax,%rcx,1)
 5823fea:	inc    %rcx
 5823fed:	mov    %rcx,0x28(%rsp)
 5823ff2:	lea    0x30(%rsp),%rdi
 5823ff7:	lea    0x8(%rsp),%rdx
 5823ffc:	mov    %r15,%rsi
 5823fff:	call   5967d90 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e06a0>
 5824004:	jmp    582405a <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5243d6>
 5824006:	test   %r13,%r13
 5824009:	je     582412b <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x524305>
 582400f:	xor    %ecx,%ecx
 5824011:	movb   $0x3,(%rax,%rcx,1)
 5824015:	inc    %rcx
 5824018:	mov    %rcx,0x28(%rsp)
 582401d:	lea    0x30(%rsp),%rdi
 5824022:	lea    0x8(%rsp),%rdx
 5824027:	mov    %r15,%rsi
 582402a:	call   5b561e0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x1f2250>
 582402f:	jmp    582405a <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5243d6>
 5824031:	test   %r13,%r13
 5824034:	je     582417d <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5242b3>
 582403a:	xor    %ecx,%ecx
 582403c:	movb   $0x1,(%rax,%rcx,1)
 5824040:	inc    %rcx
 5824043:	mov    %rcx,0x28(%rsp)
 5824048:	lea    0x30(%rsp),%rdi
 582404d:	lea    0x8(%rsp),%rdx
 5824052:	mov    %r15,%rsi
 5824055:	call   5966b90 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e18a0>
 582405a:	mov    0x30(%rsp),%rax
 582405f:	cmp    $0x8,%rax
 5824063:	jne    582407e <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5243b2>
 5824065:	mov    0x10(%r14),%rax
 5824069:	mov    %rax,0x18(%rbx)
 582406d:	movups (%r14),%xmm0
 5824071:	movups %xmm0,0x8(%rbx)
 5824075:	movq   $0x8,(%rbx)
 582407c:	jmp    58240c4 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x52436c>
 582407e:	mov    0x48(%rsp),%rcx
 5824083:	mov    %rcx,0x80(%rsp)
 582408b:	movups 0x38(%rsp),%xmm0
 5824090:	movaps %xmm0,0x70(%rsp)
 5824095:	mov    %rax,(%rbx)
 5824098:	mov    0x80(%rsp),%rax
 58240a0:	mov    %rax,0x18(%rbx)
 58240a4:	movaps 0x70(%rsp),%xmm0
 58240a9:	movups %xmm0,0x8(%rbx)
 58240ad:	mov    0x18(%rsp),%rsi
 58240b2:	test   %rsi,%rsi
 58240b5:	je     58240c4 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x52436c>
 58240b7:	mov    0x20(%rsp),%rdi
 58240bc:	xor    %edx,%edx
 58240be:	call   *0xcbb3dc(%rip)        # 64df4a0 <__register_atfork@plt+0xed910>
 58240c4:	mov    %rbx,%rax
 58240c7:	add    $0x88,%rsp
 58240ce:	pop    %rbx
 58240cf:	pop    %r12
 58240d1:	pop    %r13
 58240d3:	pop    %r14
 58240d5:	pop    %r15
 58240d7:	pop    %rbp
 58240d8:	ret
 58240d9:	mov    $0x1,%edx
 58240de:	mov    $0x1,%ecx
 58240e3:	mov    $0x1,%r8d
 58240e9:	mov    %r14,%rdi
 58240ec:	xor    %esi,%esi
 58240ee:	call   5963a10 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e4a20>
 58240f3:	mov    0x20(%rsp),%rax
 58240f8:	mov    0x28(%rsp),%rcx
 58240fd:	jmp    5823fbb <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x524475>
 5824102:	mov    $0x1,%edx
 5824107:	mov    $0x1,%ecx
 582410c:	mov    $0x1,%r8d
 5824112:	mov    %r14,%rdi
 5824115:	xor    %esi,%esi
 5824117:	call   5963a10 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e4a20>
 582411c:	mov    0x20(%rsp),%rax
 5824121:	mov    0x28(%rsp),%rcx
 5824126:	jmp    5823fe6 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x52444a>
 582412b:	mov    $0x1,%edx
 5824130:	mov    $0x1,%ecx
 5824135:	mov    $0x1,%r8d
 582413b:	mov    %r14,%rdi
 582413e:	xor    %esi,%esi
 5824140:	call   5963a10 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e4a20>
 5824145:	mov    0x20(%rsp),%rax
 582414a:	mov    0x28(%rsp),%rcx
 582414f:	jmp    5824011 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x52441f>
 5824154:	mov    $0x1,%edx
 5824159:	mov    $0x1,%ecx
 582415e:	mov    $0x1,%r8d
 5824164:	mov    %r14,%rdi
 5824167:	xor    %esi,%esi
 5824169:	call   5963a10 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e4a20>
 582416e:	mov    0x20(%rsp),%rax
 5824173:	mov    0x28(%rsp),%rcx
 5824178:	jmp    5823f8d <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5244a3>
 582417d:	mov    $0x1,%edx
 5824182:	mov    $0x1,%ecx
 5824187:	mov    $0x1,%r8d
 582418d:	mov    %r14,%rdi
 5824190:	xor    %esi,%esi
 5824192:	call   5963a10 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e4a20>
 5824197:	mov    0x20(%rsp),%rax
 582419c:	mov    0x28(%rsp),%rcx
 58241a1:	jmp    582403c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5243f4>
 58241a6:	xor    %edi,%edi
 58241a8:	mov    %r13,%rsi
 58241ab:	call   *0xcbb2e7(%rip)        # 64df498 <__register_atfork@plt+0xed908>
 58241b1:	mov    $0x1,%edi
 58241b6:	mov    %r13,%rsi
 58241b9:	call   *0xcbb2d9(%rip)        # 64df498 <__register_atfork@plt+0xed908>
 58241bf:	mov    %rax,%rbx
 58241c2:	mov    0x18(%rsp),%rsi
 58241c7:	test   %rsi,%rsi
 58241ca:	je     58241d9 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x524257>
 58241cc:	mov    0x20(%rsp),%rdi
 58241d1:	xor    %edx,%edx
 58241d3:	call   *0xcbb2c7(%rip)        # 64df4a0 <__register_atfork@plt+0xed910>
 58241d9:	mov    %rbx,%rdi
 58241dc:	call   63f0a50 <_Unwind_Resume@plt>

hl-node:     file format elf64-x86-64


Disassembly of section .text:

0000000005966b90 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e18a0>:
 5966b90:	push   %r15
 5966b92:	push   %r14
 5966b94:	push   %r12
 5966b96:	push   %rbx
 5966b97:	sub    $0x38,%rsp
 5966b9b:	mov    %rdx,%r14
 5966b9e:	mov    %rsi,%r15
 5966ba1:	mov    %rdi,%rbx
 5966ba4:	add    $0x48,%rsi
 5966ba8:	mov    %rsp,%rdi
 5966bab:	call   58221e0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x526250>
 5966bb0:	mov    (%rsp),%rax
 5966bb4:	cmp    $0x8,%rax
 5966bb8:	jne    5966c60 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e17d0>
 5966bbe:	lea    0x10(%r14),%r12
 5966bc2:	mov    0x20(%r15),%rdx
 5966bc6:	mov    %rsp,%rdi
 5966bc9:	mov    %r12,%rsi
 5966bcc:	call   5822910 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x525b20>
 5966bd1:	mov    (%rsp),%rax
 5966bd5:	cmp    $0x8,%rax
 5966bd9:	jne    5966c77 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e17b9>
 5966bdf:	mov    0x28(%r15),%rdx
 5966be3:	mov    %rsp,%rdi
 5966be6:	mov    %r12,%rsi
 5966be9:	call   5822910 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x525b20>
 5966bee:	mov    (%rsp),%rax
 5966bf2:	cmp    $0x8,%rax
 5966bf6:	jne    5966c77 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e17b9>
 5966bf8:	mov    0x30(%r15),%rdx
 5966bfc:	mov    %rsp,%rdi
 5966bff:	mov    %r12,%rsi
 5966c02:	call   5822910 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x525b20>
 5966c07:	mov    (%rsp),%rax
 5966c0b:	cmp    $0x8,%rax
 5966c0f:	jne    5966c60 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e17d0>
 5966c11:	mov    0x38(%r15),%rdx
 5966c15:	mov    %rsp,%rdi
 5966c18:	mov    %r12,%rsi
 5966c1b:	call   5822910 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x525b20>
 5966c20:	mov    (%rsp),%rax
 5966c24:	cmp    $0x8,%rax
 5966c28:	jne    5966c60 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e17d0>
 5966c2a:	mov    0x40(%r15),%rdx
 5966c2e:	mov    %rsp,%rdi
 5966c31:	mov    %r12,%rsi
 5966c34:	call   5822910 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x525b20>
 5966c39:	mov    (%rsp),%rax
 5966c3d:	cmp    $0x8,%rax
 5966c41:	jne    5966c60 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e17d0>
 5966c43:	mov    %rsp,%rdi
 5966c46:	mov    %r15,%rsi
 5966c49:	mov    %r14,%rdx
 5966c4c:	call   5822260 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5261d0>
 5966c51:	cmpl   $0x8,(%rsp)
 5966c55:	jne    5966caf <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e1781>
 5966c57:	movq   $0x8,(%rbx)
 5966c5e:	jmp    5966ca0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e1790>
 5966c60:	mov    0x18(%rsp),%rcx
 5966c65:	mov    %rcx,0x18(%rbx)
 5966c69:	movups 0x8(%rsp),%xmm0
 5966c6e:	movups %xmm0,0x8(%rbx)
 5966c72:	mov    %rax,(%rbx)
 5966c75:	jmp    5966ca0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e1790>
 5966c77:	mov    0x18(%rsp),%rcx
 5966c7c:	mov    %rcx,0x30(%rsp)
 5966c81:	movups 0x8(%rsp),%xmm0
 5966c86:	movaps %xmm0,0x20(%rsp)
 5966c8b:	mov    %rax,(%rbx)
 5966c8e:	movaps 0x20(%rsp),%xmm0
 5966c93:	movups %xmm0,0x8(%rbx)
 5966c97:	mov    0x30(%rsp),%rax
 5966c9c:	mov    %rax,0x18(%rbx)
 5966ca0:	mov    %rbx,%rax
 5966ca3:	add    $0x38,%rsp
 5966ca7:	pop    %rbx
 5966ca8:	pop    %r12
 5966caa:	pop    %r14
 5966cac:	pop    %r15
 5966cae:	ret
 5966caf:	movups (%rsp),%xmm0
 5966cb3:	movups 0x10(%rsp),%xmm1
 5966cb8:	movups %xmm1,0x10(%rbx)
 5966cbc:	movups %xmm0,(%rbx)
 5966cbf:	jmp    5966ca0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e1790>

hl-node:     file format elf64-x86-64


Disassembly of section .text:

0000000005822910 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x525b20>:
 5822910:	push   %r15
 5822912:	push   %r14
 5822914:	push   %rbx
 5822915:	cmp    $0xfb,%rdx
 582291c:	jae    582293a <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x525af6>
 582291e:	mov    0x10(%rsi),%rax
 5822922:	cmp    %rax,(%rsi)
 5822925:	je     5822a01 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x525a2f>
 582292b:	mov    0x8(%rsi),%rcx
 582292f:	mov    %dl,(%rcx,%rax,1)
 5822932:	inc    %rax
 5822935:	jmp    58229f0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x525a40>
 582293a:	cmp    $0x10000,%rdx
 5822941:	jae    582297b <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x525ab5>
 5822943:	mov    (%rsi),%rcx
 5822946:	mov    0x10(%rsi),%rax
 582294a:	cmp    %rax,%rcx
 582294d:	je     5822a37 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5259f9>
 5822953:	mov    0x8(%rsi),%r8
 5822957:	movb   $0xfb,(%r8,%rax,1)
 582295c:	inc    %rax
 582295f:	mov    %rax,0x10(%rsi)
 5822963:	sub    %rax,%rcx
 5822966:	cmp    $0x1,%rcx
 582296a:	jbe    5822a70 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5259c0>
 5822970:	mov    %dx,(%r8,%rax,1)
 5822975:	add    $0x2,%rax
 5822979:	jmp    58229f0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x525a40>
 582297b:	mov    %rdx,%rax
 582297e:	shr    $0x20,%rax
 5822982:	jne    58229bb <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x525a75>
 5822984:	mov    (%rsi),%rcx
 5822987:	mov    0x10(%rsi),%rax
 582298b:	cmp    %rax,%rcx
 582298e:	je     5822aaa <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x525986>
 5822994:	mov    0x8(%rsi),%r8
 5822998:	movb   $0xfc,(%r8,%rax,1)
 582299d:	inc    %rax
 58229a0:	mov    %rax,0x10(%rsi)
 58229a4:	sub    %rax,%rcx
 58229a7:	cmp    $0x3,%rcx
 58229ab:	jbe    5822ae3 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x52594d>
 58229b1:	mov    %edx,(%r8,%rax,1)
 58229b5:	add    $0x4,%rax
 58229b9:	jmp    58229f0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x525a40>
 58229bb:	mov    (%rsi),%rcx
 58229be:	mov    0x10(%rsi),%rax
 58229c2:	cmp    %rax,%rcx
 58229c5:	je     5822b1d <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x525913>
 58229cb:	mov    0x8(%rsi),%r8
 58229cf:	movb   $0xfd,(%r8,%rax,1)
 58229d4:	inc    %rax
 58229d7:	mov    %rax,0x10(%rsi)
 58229db:	sub    %rax,%rcx
 58229de:	cmp    $0x7,%rcx
 58229e2:	jbe    5822b56 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5258da>
 58229e8:	mov    %rdx,(%r8,%rax,1)
 58229ec:	add    $0x8,%rax
 58229f0:	mov    %rax,0x10(%rsi)
 58229f4:	movq   $0x8,(%rdi)
 58229fb:	pop    %rbx
 58229fc:	pop    %r14
 58229fe:	pop    %r15
 5822a00:	ret
 5822a01:	mov    %rdx,%rbx
 5822a04:	mov    $0x1,%edx
 5822a09:	mov    $0x1,%ecx
 5822a0e:	mov    $0x1,%r8d
 5822a14:	mov    %rdi,%r14
 5822a17:	mov    %rsi,%rdi
 5822a1a:	mov    %rsi,%r15
 5822a1d:	mov    %rax,%rsi
 5822a20:	call   5963a10 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e4a20>
 5822a25:	mov    %rbx,%rdx
 5822a28:	mov    %r15,%rsi
 5822a2b:	mov    %r14,%rdi
 5822a2e:	mov    0x10(%r15),%rax
 5822a32:	jmp    582292b <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x525b05>
 5822a37:	mov    %rdx,%rbx
 5822a3a:	mov    $0x1,%edx
 5822a3f:	mov    $0x1,%ecx
 5822a44:	mov    $0x1,%r8d
 5822a4a:	mov    %rdi,%r14
 5822a4d:	mov    %rsi,%rdi
 5822a50:	mov    %rsi,%r15
 5822a53:	mov    %rax,%rsi
 5822a56:	call   5963a10 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e4a20>
 5822a5b:	mov    %rbx,%rdx
 5822a5e:	mov    %r15,%rsi
 5822a61:	mov    %r14,%rdi
 5822a64:	mov    (%r15),%rcx
 5822a67:	mov    0x10(%r15),%rax
 5822a6b:	jmp    5822953 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x525add>
 5822a70:	mov    %rdx,%rbx
 5822a73:	mov    $0x2,%edx
 5822a78:	mov    $0x1,%ecx
 5822a7d:	mov    $0x1,%r8d
 5822a83:	mov    %rdi,%r14
 5822a86:	mov    %rsi,%rdi
 5822a89:	mov    %rsi,%r15
 5822a8c:	mov    %rax,%rsi
 5822a8f:	call   5963a10 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e4a20>
 5822a94:	mov    %rbx,%rdx
 5822a97:	mov    %r15,%rsi
 5822a9a:	mov    %r14,%rdi
 5822a9d:	mov    0x8(%r15),%r8
 5822aa1:	mov    0x10(%r15),%rax
 5822aa5:	jmp    5822970 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x525ac0>
 5822aaa:	mov    %rdx,%rbx
 5822aad:	mov    $0x1,%edx
 5822ab2:	mov    $0x1,%ecx
 5822ab7:	mov    $0x1,%r8d
 5822abd:	mov    %rdi,%r14
 5822ac0:	mov    %rsi,%rdi
 5822ac3:	mov    %rsi,%r15
 5822ac6:	mov    %rax,%rsi
 5822ac9:	call   5963a10 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e4a20>
 5822ace:	mov    %rbx,%rdx
 5822ad1:	mov    %r15,%rsi
 5822ad4:	mov    %r14,%rdi
 5822ad7:	mov    (%r15),%rcx
 5822ada:	mov    0x10(%r15),%rax
 5822ade:	jmp    5822994 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x525a9c>
 5822ae3:	mov    %rdx,%rbx
 5822ae6:	mov    $0x4,%edx
 5822aeb:	mov    $0x1,%ecx
 5822af0:	mov    $0x1,%r8d
 5822af6:	mov    %rdi,%r14
 5822af9:	mov    %rsi,%rdi
 5822afc:	mov    %rsi,%r15
 5822aff:	mov    %rax,%rsi
 5822b02:	call   5963a10 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e4a20>
 5822b07:	mov    %rbx,%rdx
 5822b0a:	mov    %r15,%rsi
 5822b0d:	mov    %r14,%rdi
 5822b10:	mov    0x8(%r15),%r8
 5822b14:	mov    0x10(%r15),%rax
 5822b18:	jmp    58229b1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x525a7f>
 5822b1d:	mov    %rdx,%rbx
 5822b20:	mov    $0x1,%edx
 5822b25:	mov    $0x1,%ecx
 5822b2a:	mov    $0x1,%r8d
 5822b30:	mov    %rdi,%r14
 5822b33:	mov    %rsi,%rdi
 5822b36:	mov    %rsi,%r15
 5822b39:	mov    %rax,%rsi
 5822b3c:	call   5963a10 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e4a20>
 5822b41:	mov    %rbx,%rdx
 5822b44:	mov    %r15,%rsi
 5822b47:	mov    %r14,%rdi
 5822b4a:	mov    (%r15),%rcx
 5822b4d:	mov    0x10(%r15),%rax
 5822b51:	jmp    58229cb <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x525a65>
 5822b56:	mov    %rdx,%rbx
 5822b59:	mov    $0x8,%edx
 5822b5e:	mov    $0x1,%ecx
 5822b63:	mov    $0x1,%r8d
 5822b69:	mov    %rdi,%r14
 5822b6c:	mov    %rsi,%rdi
 5822b6f:	mov    %rsi,%r15
 5822b72:	mov    %rax,%rsi
 5822b75:	call   5963a10 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e4a20>
 5822b7a:	mov    %rbx,%rdx
 5822b7d:	mov    %r15,%rsi
 5822b80:	mov    %r14,%rdi
 5822b83:	mov    0x8(%r15),%r8
 5822b87:	mov    0x10(%r15),%rax
 5822b8b:	jmp    58229e8 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x525a48>

hl-node:     file format elf64-x86-64


Disassembly of section .text:

00000000058221e0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x526250>:
 58221e0:	push   %r15
 58221e2:	push   %r14
 58221e4:	push   %rbx
 58221e5:	mov    %rdi,%rax
 58221e8:	mov    0x10(%rdx),%rcx
 58221ec:	mov    0x20(%rdx),%r9
 58221f0:	sub    %r9,%rcx
 58221f3:	cmp    $0x13,%rcx
 58221f7:	jbe    5822222 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x52620e>
 58221f9:	mov    0x18(%rdx),%rcx
 58221fd:	mov    0x10(%rsi),%edi
 5822200:	mov    %edi,0x10(%rcx,%r9,1)
 5822205:	movups (%rsi),%xmm0
 5822208:	movups %xmm0,(%rcx,%r9,1)
 582220d:	add    $0x14,%r9
 5822211:	mov    %r9,0x20(%rdx)
 5822215:	movq   $0x8,(%rax)
 582221c:	pop    %rbx
 582221d:	pop    %r14
 582221f:	pop    %r15
 5822221:	ret
 5822222:	lea    0x10(%rdx),%rdi
 5822226:	mov    %rdx,%rbx
 5822229:	mov    $0x14,%edx
 582222e:	mov    $0x1,%ecx
 5822233:	mov    $0x1,%r8d
 5822239:	mov    %rsi,%r14
 582223c:	mov    %r9,%rsi
 582223f:	mov    %rax,%r15
 5822242:	call   5963a10 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e4a20>
 5822247:	mov    %r14,%rsi
 582224a:	mov    %r15,%rax
 582224d:	mov    %rbx,%rdx
 5822250:	mov    0x20(%rbx),%r9
 5822254:	jmp    58221f9 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x526237>

hl-node:     file format elf64-x86-64


Disassembly of section .text:

0000000005822260 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5261d0>:
 5822260:	push   %r15
 5822262:	push   %r14
 5822264:	push   %rbx
 5822265:	mov    %rsi,%r9
 5822268:	mov    %rdi,%rax
 582226b:	mov    0x10(%rdx),%rcx
 582226f:	mov    0x20(%rdx),%rsi
 5822273:	sub    %rsi,%rcx
 5822276:	cmp    $0x1f,%rcx
 582227a:	jbe    58222a7 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x526189>
 582227c:	mov    0x18(%rdx),%rcx
 5822280:	movups (%r9),%xmm0
 5822284:	movups 0x10(%r9),%xmm1
 5822289:	movups %xmm1,0x10(%rcx,%rsi,1)
 582228e:	movups %xmm0,(%rcx,%rsi,1)
 5822292:	add    $0x20,%rsi
 5822296:	mov    %rsi,0x20(%rdx)
 582229a:	movq   $0x8,(%rax)
 58222a1:	pop    %rbx
 58222a2:	pop    %r14
 58222a4:	pop    %r15
 58222a6:	ret
 58222a7:	lea    0x10(%rdx),%rdi
 58222ab:	mov    %rdx,%rbx
 58222ae:	mov    $0x20,%edx
 58222b3:	mov    $0x1,%ecx
 58222b8:	mov    $0x1,%r8d
 58222be:	mov    %r9,%r14
 58222c1:	mov    %rax,%r15
 58222c4:	call   5963a10 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e4a20>
 58222c9:	mov    %r14,%r9
 58222cc:	mov    %r15,%rax
 58222cf:	mov    %rbx,%rdx
 58222d2:	mov    0x20(%rbx),%rsi
 58222d6:	jmp    582227c <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5261b4>

hl-node:     file format elf64-x86-64


Disassembly of section .text:

0000000005b3df10 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x20a520>:
 5b3df10:	push   %rbp
 5b3df11:	push   %r15
 5b3df13:	push   %r14
 5b3df15:	push   %r13
 5b3df17:	push   %r12
 5b3df19:	push   %rbx
 5b3df1a:	sub    $0x28,%rsp
 5b3df1e:	test   %rdx,%rdx
 5b3df21:	je     5b3df61 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x20a4cf>
 5b3df23:	mov    %rsi,%r14
 5b3df26:	shl    $0x3,%rdx
 5b3df2a:	lea    (%rdx,%rdx,2),%rbx
 5b3df2e:	xor    %esi,%esi
 5b3df30:	xor    %eax,%eax
 5b3df32:	data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
 5b3df40:	add    0x10(%r14,%rax,1),%rsi
 5b3df45:	jb     5b3e069 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x20a3c7>
 5b3df4b:	add    $0x18,%rax
 5b3df4f:	cmp    %rax,%rbx
 5b3df52:	jne    5b3df40 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x20a4f0>
 5b3df54:	test   %rsi,%rsi
 5b3df57:	jns    5b3dfaf <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x20a481>
 5b3df59:	xor    %edi,%edi
 5b3df5b:	call   *0x9a1537(%rip)        # 64df498 <__register_atfork@plt+0xed908>
 5b3df61:	mov    %rdi,0x20(%rsp)
 5b3df66:	movq   $0x0,0x8(%rsp)
 5b3df6f:	movq   $0x1,0x10(%rsp)
 5b3df78:	movq   $0x0,0x18(%rsp)
 5b3df81:	mov    0x18(%rsp),%rcx
 5b3df86:	mov    0x20(%rsp),%rax
 5b3df8b:	mov    %rcx,0x10(%rax)
 5b3df8f:	mov    0x8(%rsp),%rcx
 5b3df94:	mov    %rcx,(%rax)
 5b3df97:	mov    0x10(%rsp),%rcx
 5b3df9c:	mov    %rcx,0x8(%rax)
 5b3dfa0:	add    $0x28,%rsp
 5b3dfa4:	pop    %rbx
 5b3dfa5:	pop    %r12
 5b3dfa7:	pop    %r13
 5b3dfa9:	pop    %r14
 5b3dfab:	pop    %r15
 5b3dfad:	pop    %rbp
 5b3dfae:	ret
 5b3dfaf:	mov    %rdi,0x20(%rsp)
 5b3dfb4:	je     5b3dfd0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x20a460>
 5b3dfb6:	mov    %rsi,%r15
 5b3dfb9:	mov    %rsi,%rdi
 5b3dfbc:	call   *0x9a14be(%rip)        # 64df480 <__register_atfork@plt+0xed8f0>
 5b3dfc2:	test   %rax,%rax
 5b3dfc5:	je     5b3e076 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x20a3ba>
 5b3dfcb:	mov    %r15,%rsi
 5b3dfce:	jmp    5b3dfd5 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x20a45b>
 5b3dfd0:	mov    $0x1,%eax
 5b3dfd5:	mov    %rsi,0x8(%rsp)
 5b3dfda:	mov    %rax,0x10(%rsp)
 5b3dfdf:	movq   $0x0,0x18(%rsp)
 5b3dfe8:	xor    %r13d,%r13d
 5b3dfeb:	xor    %r15d,%r15d
 5b3dfee:	jmp    5b3e04b <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x20a3e5>
 5b3dff0:	mov    $0x1,%ecx
 5b3dff5:	mov    $0x1,%r8d
 5b3dffb:	lea    0x8(%rsp),%rdi
 5b3e000:	mov    %r13,%rsi
 5b3e003:	mov    %rbp,%rdx
 5b3e006:	call   5963a10 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x3e4a20>
 5b3e00b:	mov    0x10(%rsp),%rax
 5b3e010:	mov    0x18(%rsp),%r13
 5b3e015:	data16 cs nopw 0x0(%rax,%rax,1)
 5b3e020:	lea    (%rax,%r13,1),%rdi
 5b3e024:	mov    %r12,%rsi
 5b3e027:	mov    %rbp,%rdx
 5b3e02a:	mov    %rax,%r12
 5b3e02d:	call   *0x9a14d5(%rip)        # 64df508 <__register_atfork@plt+0xed978>
 5b3e033:	mov    %r12,%rax
 5b3e036:	add    %rbp,%r13
 5b3e039:	mov    %r13,0x18(%rsp)
 5b3e03e:	add    $0x18,%r15
 5b3e042:	cmp    %r15,%rbx
 5b3e045:	je     5b3df81 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x20a4af>
 5b3e04b:	mov    0x8(%r14,%r15,1),%r12
 5b3e050:	mov    0x10(%r14,%r15,1),%rbp
 5b3e055:	mov    0x8(%rsp),%rcx
 5b3e05a:	sub    %r13,%rcx
 5b3e05d:	cmp    %rcx,%rbp
 5b3e060:	ja     5b3dff0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x20a440>
 5b3e062:	test   %rbp,%rbp
 5b3e065:	jne    5b3e020 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x20a410>
 5b3e067:	jmp    5b3e036 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x20a3fa>
 5b3e069:	lea    0x97ea78(%rip),%rdi        # 64bcae8 <__register_atfork@plt+0xcaf58>
 5b3e070:	call   *0x9a14aa(%rip)        # 64df520 <__register_atfork@plt+0xed990>
 5b3e076:	mov    $0x1,%edi
 5b3e07b:	mov    %r15,%rsi
 5b3e07e:	call   *0x9a1414(%rip)        # 64df498 <__register_atfork@plt+0xed908>
 5b3e084:	mov    %rax,%rbx
 5b3e087:	mov    0x8(%rsp),%rsi
 5b3e08c:	test   %rsi,%rsi
 5b3e08f:	je     5b3e09e <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x20a392>
 5b3e091:	mov    0x10(%rsp),%rdi
 5b3e096:	xor    %edx,%edx
 5b3e098:	call   *0x9a1402(%rip)        # 64df4a0 <__register_atfork@plt+0xed910>
 5b3e09e:	mov    %rbx,%rdi
 5b3e0a1:	call   63f0a50 <_Unwind_Resume@plt>

hl-node:     file format elf64-x86-64


Disassembly of section .text:

0000000005cda910 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6db20>:
 5cda910:	push   %rbp
 5cda911:	push   %r15
 5cda913:	push   %r14
 5cda915:	push   %r13
 5cda917:	push   %r12
 5cda919:	push   %rbx
 5cda91a:	push   %rax
 5cda91b:	mov    %rdx,%r12
 5cda91e:	mov    %rsi,%r14
 5cda921:	mov    %rdi,%rbx
 5cda924:	cmpb   $0x0,0xd9(%rdi)
 5cda92b:	je     5cda95a <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6dad6>
 5cda92d:	movb   $0x0,0xd9(%rbx)
 5cda934:	mov    %rbx,%rdi
 5cda937:	call   *0x812233(%rip)        # 64ecb70 <__register_atfork@plt+0xfafe0>
 5cda93d:	movq   $0x0,0xc8(%rbx)
 5cda948:	mov    0xd0(%rbx),%r13
 5cda94f:	xor    %edi,%edi
 5cda951:	xor    %eax,%eax
 5cda953:	cmp    %r13,%r12
 5cda956:	jb     5cda985 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6daab>
 5cda958:	jmp    5cda9c5 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6da6b>
 5cda95a:	mov    0xc8(%rbx),%rdi
 5cda961:	mov    0xd0(%rbx),%r13
 5cda968:	sub    %rdi,%r13
 5cda96b:	jb     5cdad2d <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d703>
 5cda971:	cmp    %r13,%r12
 5cda974:	jae    5cda9c5 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6da6b>
 5cda976:	cmp    $0xc8,%rdi
 5cda97d:	ja     5cdace7 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d749>
 5cda983:	xor    %eax,%eax
 5cda985:	mov    %r12,%r15
 5cda988:	mov    $0xc8,%edx
 5cda98d:	sub    %rdi,%rdx
 5cda990:	cmp    %rdx,%r15
 5cda993:	ja     5cdac02 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d82e>
 5cda999:	test   %al,%al
 5cda99b:	jne    5cdacfe <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d732>
 5cda9a1:	test   %r15,%r15
 5cda9a4:	je     5cdacb1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d77f>
 5cda9aa:	lea    (%rbx,%rdi,1),%rcx
 5cda9ae:	cmp    $0x4,%r15
 5cda9b2:	jae    5cdac14 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d81c>
 5cda9b8:	xor    %eax,%eax
 5cda9ba:	mov    %rcx,%rdx
 5cda9bd:	mov    %r14,%rsi
 5cda9c0:	jmp    5cdac96 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d79a>
 5cda9c5:	xor    %ebp,%ebp
 5cda9c7:	mov    %r12,%r15
 5cda9ca:	jmp    5cda9f4 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6da3c>
 5cda9cc:	nopl   0x0(%rax)
 5cda9d0:	mov    %rbx,%rdi
 5cda9d3:	call   *0x812197(%rip)        # 64ecb70 <__register_atfork@plt+0xfafe0>
 5cda9d9:	add    %r13,%rbp
 5cda9dc:	sub    %r13,%r15
 5cda9df:	mov    0xd0(%rbx),%r13
 5cda9e6:	mov    $0x0,%edi
 5cda9eb:	cmp    %r13,%r15
 5cda9ee:	jb     5cdabe3 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d84d>
 5cda9f4:	mov    %r12,%rax
 5cda9f7:	sub    %rbp,%rax
 5cda9fa:	jb     5cdad17 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d719>
 5cdaa00:	cmp    $0xc8,%rdi
 5cdaa07:	ja     5cdace7 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d749>
 5cdaa0d:	mov    $0xc8,%edx
 5cdaa12:	sub    %rdi,%rdx
 5cdaa15:	cmp    %rdx,%r13
 5cdaa18:	ja     5cdacca <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d766>
 5cdaa1e:	cmp    %rax,%r13
 5cdaa21:	ja     5cdacfe <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d732>
 5cdaa27:	test   %r13,%r13
 5cdaa2a:	je     5cda9d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6da60>
 5cdaa2c:	lea    (%r14,%rbp,1),%rcx
 5cdaa30:	add    %rbx,%rdi
 5cdaa33:	cmp    $0x4,%r13
 5cdaa37:	jae    5cdaa50 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d9e0>
 5cdaa39:	mov    %rdi,%rdx
 5cdaa3c:	mov    %rcx,%rsi
 5cdaa3f:	xor    %eax,%eax
 5cdaa41:	jmp    5cdabaa <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d886>
 5cdaa46:	cs nopw 0x0(%rax,%rax,1)
 5cdaa50:	cmp    $0x20,%r13
 5cdaa54:	jae    5cdaa5d <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d9d3>
 5cdaa56:	xor    %eax,%eax
 5cdaa58:	jmp    5cdab76 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d8ba>
 5cdaa5d:	mov    %r13,%rax
 5cdaa60:	and    $0xffffffffffffffe0,%rax
 5cdaa64:	movups (%rcx),%xmm0
 5cdaa67:	movups 0x10(%rcx),%xmm1
 5cdaa6b:	movups (%rdi),%xmm2
 5cdaa6e:	xorps  %xmm0,%xmm2
 5cdaa71:	movups 0x10(%rdi),%xmm0
 5cdaa75:	xorps  %xmm1,%xmm0
 5cdaa78:	movups %xmm2,(%rdi)
 5cdaa7b:	movups %xmm0,0x10(%rdi)
 5cdaa7f:	cmp    $0x20,%rax
 5cdaa83:	je     5cdab67 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d8c9>
 5cdaa89:	movups 0x20(%rcx),%xmm0
 5cdaa8d:	movups 0x30(%rcx),%xmm1
 5cdaa91:	movups 0x20(%rdi),%xmm2
 5cdaa95:	xorps  %xmm0,%xmm2
 5cdaa98:	movups 0x30(%rdi),%xmm0
 5cdaa9c:	xorps  %xmm1,%xmm0
 5cdaa9f:	movups %xmm2,0x20(%rdi)
 5cdaaa3:	movups %xmm0,0x30(%rdi)
 5cdaaa7:	cmp    $0x40,%rax
 5cdaaab:	je     5cdab67 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d8c9>
 5cdaab1:	movups 0x40(%rcx),%xmm0
 5cdaab5:	movups 0x50(%rcx),%xmm1
 5cdaab9:	movups 0x40(%rdi),%xmm2
 5cdaabd:	xorps  %xmm0,%xmm2
 5cdaac0:	movups 0x50(%rdi),%xmm0
 5cdaac4:	xorps  %xmm1,%xmm0
 5cdaac7:	movups %xmm2,0x40(%rdi)
 5cdaacb:	movups %xmm0,0x50(%rdi)
 5cdaacf:	cmp    $0x60,%rax
 5cdaad3:	je     5cdab67 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d8c9>
 5cdaad9:	movups 0x60(%rcx),%xmm0
 5cdaadd:	movups 0x70(%rcx),%xmm1
 5cdaae1:	movups 0x60(%rdi),%xmm2
 5cdaae5:	xorps  %xmm0,%xmm2
 5cdaae8:	movups 0x70(%rdi),%xmm0
 5cdaaec:	xorps  %xmm1,%xmm0
 5cdaaef:	movups %xmm2,0x60(%rdi)
 5cdaaf3:	movups %xmm0,0x70(%rdi)
 5cdaaf7:	cmp    $0x80,%rax
 5cdaafd:	je     5cdab67 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d8c9>
 5cdaaff:	movups 0x80(%rcx),%xmm0
 5cdab06:	movups 0x90(%rcx),%xmm1
 5cdab0d:	movups 0x80(%rdi),%xmm2
 5cdab14:	xorps  %xmm0,%xmm2
 5cdab17:	movups 0x90(%rdi),%xmm0
 5cdab1e:	xorps  %xmm1,%xmm0
 5cdab21:	movups %xmm2,0x80(%rdi)
 5cdab28:	movups %xmm0,0x90(%rdi)
 5cdab2f:	cmp    $0xa0,%rax
 5cdab35:	je     5cdab67 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d8c9>
 5cdab37:	movups 0xa0(%rcx),%xmm0
 5cdab3e:	movups 0xb0(%rcx),%xmm1
 5cdab45:	movups 0xa0(%rdi),%xmm2
 5cdab4c:	xorps  %xmm0,%xmm2
 5cdab4f:	movups 0xb0(%rdi),%xmm0
 5cdab56:	xorps  %xmm1,%xmm0
 5cdab59:	movups %xmm2,0xa0(%rdi)
 5cdab60:	movups %xmm0,0xb0(%rdi)
 5cdab67:	cmp    %rax,%r13
 5cdab6a:	je     5cda9d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6da60>
 5cdab70:	test   $0x1c,%r13b
 5cdab74:	je     5cdabd5 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d85b>
 5cdab76:	mov    %rax,%r8
 5cdab79:	mov    %r13,%rax
 5cdab7c:	and    $0xfffffffffffffffc,%rax
 5cdab80:	lea    (%rdi,%rax,1),%rdx
 5cdab84:	lea    (%rcx,%rax,1),%rsi
 5cdab88:	nopl   0x0(%rax,%rax,1)
 5cdab90:	mov    (%rcx,%r8,1),%r9d
 5cdab94:	xor    %r9d,(%rdi,%r8,1)
 5cdab98:	add    $0x4,%r8
 5cdab9c:	cmp    %r8,%rax
 5cdab9f:	jne    5cdab90 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d8a0>
 5cdaba1:	cmp    %rax,%r13
 5cdaba4:	je     5cda9d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6da60>
 5cdabaa:	mov    %r13,%rcx
 5cdabad:	sub    %rax,%rcx
 5cdabb0:	xor    %eax,%eax
 5cdabb2:	data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
 5cdabc0:	movzbl (%rsi,%rax,1),%edi
 5cdabc4:	xor    %dil,(%rdx,%rax,1)
 5cdabc8:	inc    %rax
 5cdabcb:	cmp    %rax,%rcx
 5cdabce:	jne    5cdabc0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d870>
 5cdabd0:	jmp    5cda9d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6da60>
 5cdabd5:	add    %rax,%rdi
 5cdabd8:	add    %rax,%rcx
 5cdabdb:	mov    %rdi,%rdx
 5cdabde:	mov    %rcx,%rsi
 5cdabe1:	jmp    5cdabaa <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d886>
 5cdabe3:	sub    %rbp,%r12
 5cdabe6:	add    %rbp,%r14
 5cdabe9:	cmp    %r12,%r15
 5cdabec:	seta   %al
 5cdabef:	xor    %edi,%edi
 5cdabf1:	mov    $0xc8,%edx
 5cdabf6:	sub    %rdi,%rdx
 5cdabf9:	cmp    %rdx,%r15
 5cdabfc:	jbe    5cda999 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6da97>
 5cdac02:	lea    0x7ea807(%rip),%rcx        # 64c5410 <__register_atfork@plt+0xd3880>
 5cdac09:	xor    %edi,%edi
 5cdac0b:	mov    %r15,%rsi
 5cdac0e:	call   *0x80495c(%rip)        # 64df570 <__register_atfork@plt+0xed9e0>
 5cdac14:	cmp    $0x20,%r15
 5cdac18:	jae    5cdac1e <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d812>
 5cdac1a:	xor    %eax,%eax
 5cdac1c:	jmp    5cdac67 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d7c9>
 5cdac1e:	mov    %r15,%rax
 5cdac21:	and    $0xffffffffffffffe0,%rax
 5cdac25:	lea    (%rdi,%rbx,1),%rdx
 5cdac29:	add    $0x10,%rdx
 5cdac2d:	xor    %esi,%esi
 5cdac2f:	nop
 5cdac30:	movups (%r14,%rsi,1),%xmm0
 5cdac35:	movups 0x10(%r14,%rsi,1),%xmm1
 5cdac3b:	movups -0x10(%rdx,%rsi,1),%xmm2
 5cdac40:	xorps  %xmm0,%xmm2
 5cdac43:	movups (%rdx,%rsi,1),%xmm0
 5cdac47:	xorps  %xmm1,%xmm0
 5cdac4a:	movups %xmm2,-0x10(%rdx,%rsi,1)
 5cdac4f:	movups %xmm0,(%rdx,%rsi,1)
 5cdac53:	add    $0x20,%rsi
 5cdac57:	cmp    %rsi,%rax
 5cdac5a:	jne    5cdac30 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d800>
 5cdac5c:	cmp    %rax,%r15
 5cdac5f:	je     5cdacb1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d77f>
 5cdac61:	test   $0x1c,%r15b
 5cdac65:	je     5cdacdc <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d754>
 5cdac67:	mov    %rax,%r8
 5cdac6a:	mov    %r15,%rax
 5cdac6d:	and    $0xfffffffffffffffc,%rax
 5cdac71:	lea    (%rcx,%rax,1),%rdx
 5cdac75:	lea    (%r14,%rax,1),%rsi
 5cdac79:	nopl   0x0(%rax)
 5cdac80:	mov    (%r14,%r8,1),%r9d
 5cdac84:	xor    %r9d,(%rcx,%r8,1)
 5cdac88:	add    $0x4,%r8
 5cdac8c:	cmp    %r8,%rax
 5cdac8f:	jne    5cdac80 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d7b0>
 5cdac91:	cmp    %rax,%r15
 5cdac94:	je     5cdacb1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d77f>
 5cdac96:	mov    %r15,%rcx
 5cdac99:	sub    %rax,%rcx
 5cdac9c:	xor    %eax,%eax
 5cdac9e:	xchg   %ax,%ax
 5cdaca0:	movzbl (%rsi,%rax,1),%r8d
 5cdaca5:	xor    %r8b,(%rdx,%rax,1)
 5cdaca9:	inc    %rax
 5cdacac:	cmp    %rax,%rcx
 5cdacaf:	jne    5cdaca0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d790>
 5cdacb1:	add    %rdi,%r15
 5cdacb4:	mov    %r15,0xc8(%rbx)
 5cdacbb:	add    $0x8,%rsp
 5cdacbf:	pop    %rbx
 5cdacc0:	pop    %r12
 5cdacc2:	pop    %r13
 5cdacc4:	pop    %r14
 5cdacc6:	pop    %r15
 5cdacc8:	pop    %rbp
 5cdacc9:	ret
 5cdacca:	lea    0x7ea73f(%rip),%rcx        # 64c5410 <__register_atfork@plt+0xd3880>
 5cdacd1:	xor    %edi,%edi
 5cdacd3:	mov    %r13,%rsi
 5cdacd6:	call   *0x804894(%rip)        # 64df570 <__register_atfork@plt+0xed9e0>
 5cdacdc:	add    %rax,%rcx
 5cdacdf:	add    %rax,%r14
 5cdace2:	jmp    5cda9ba <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6da76>
 5cdace7:	lea    0x7ea73a(%rip),%rcx        # 64c5428 <__register_atfork@plt+0xd3898>
 5cdacee:	mov    $0xc8,%esi
 5cdacf3:	mov    $0xc8,%edx
 5cdacf8:	call   *0x804872(%rip)        # 64df570 <__register_atfork@plt+0xed9e0>
 5cdacfe:	lea    -0x538e818(%rip),%rdi        # 94c4ed <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x53fbf43>
 5cdad05:	lea    0x7ea6d4(%rip),%rdx        # 64c53e0 <__register_atfork@plt+0xd3850>
 5cdad0c:	mov    $0x28,%esi
 5cdad11:	call   *0x804a19(%rip)        # 64df730 <__register_atfork@plt+0xedba0>
 5cdad17:	lea    0x7ea64a(%rip),%rcx        # 64c5368 <__register_atfork@plt+0xd37d8>
 5cdad1e:	mov    %rbp,%rdi
 5cdad21:	mov    %r12,%rsi
 5cdad24:	mov    %r12,%rdx
 5cdad27:	call   *0x804843(%rip)        # 64df570 <__register_atfork@plt+0xed9e0>
 5cdad2d:	lea    0x7ea61c(%rip),%rdi        # 64c5350 <__register_atfork@plt+0xd37c0>
 5cdad34:	call   *0x804b0e(%rip)        # 64df848 <__register_atfork@plt+0xedcb8>

hl-node:     file format elf64-x86-64


Disassembly of section .text:

0000000005cdad40 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d6f0>:
 5cdad40:	push   %rbp
 5cdad41:	push   %r15
 5cdad43:	push   %r14
 5cdad45:	push   %r13
 5cdad47:	push   %r12
 5cdad49:	push   %rbx
 5cdad4a:	sub    $0xe8,%rsp
 5cdad51:	mov    %rdx,%r14
 5cdad54:	mov    %rsi,(%rsp)
 5cdad58:	mov    %rdi,%rsi
 5cdad5b:	lea    0x8(%rsp),%rdi
 5cdad60:	mov    $0xe0,%edx
 5cdad65:	call   *0x80479d(%rip)        # 64df508 <__register_atfork@plt+0xed978>
 5cdad6b:	cmpb   $0x1,0xe1(%rsp)
 5cdad73:	jne    5cdadb5 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d67b>
 5cdad75:	mov    0xd0(%rsp),%rdi
 5cdad7d:	mov    0xd8(%rsp),%rax
 5cdad85:	mov    %rax,%r15
 5cdad88:	sub    %rdi,%r15
 5cdad8b:	jb     5cdb023 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d40d>
 5cdad91:	cmp    %r15,%r14
 5cdad94:	jae    5cdae46 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d5ea>
 5cdad9a:	cmp    $0xc8,%rdi
 5cdada1:	ja     5cdafd8 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d458>
 5cdada7:	xor    %r15d,%r15d
 5cdadaa:	mov    %r14,%rdx
 5cdadad:	mov    %r14,%r12
 5cdadb0:	jmp    5cdaefc <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d534>
 5cdadb5:	movb   $0x1,0xe1(%rsp)
 5cdadbd:	mov    0xd0(%rsp),%rax
 5cdadc5:	cmp    $0xc8,%rax
 5cdadcb:	ja     5cdb009 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d427>
 5cdadd1:	je     5cdaf9b <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d495>
 5cdadd7:	mov    0xd8(%rsp),%rdi
 5cdaddf:	movzbl 0xe0(%rsp),%ecx
 5cdade7:	xor    %cl,0x8(%rsp,%rax,1)
 5cdadeb:	test   %rdi,%rdi
 5cdadee:	je     5cdb030 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d400>
 5cdadf4:	dec    %rdi
 5cdadf7:	cmp    $0xc8,%rdi
 5cdadfe:	ja     5cdafd8 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d458>
 5cdae04:	je     5cdaf9b <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d495>
 5cdae0a:	xorb   $0x80,0x8(%rsp,%rdi,1)
 5cdae0f:	lea    0x8(%rsp),%rdi
 5cdae14:	call   *0x811d56(%rip)        # 64ecb70 <__register_atfork@plt+0xfafe0>
 5cdae1a:	movq   $0x0,0xd0(%rsp)
 5cdae26:	mov    0xd8(%rsp),%rax
 5cdae2e:	xor    %edi,%edi
 5cdae30:	mov    %rax,%r15
 5cdae33:	cmp    %rax,%r14
 5cdae36:	jae    5cdae53 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d5dd>
 5cdae38:	mov    %r14,%rdx
 5cdae3b:	mov    %r14,%r12
 5cdae3e:	xor    %r15d,%r15d
 5cdae41:	jmp    5cdaefc <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d534>
 5cdae46:	cmp    $0xc8,%rdi
 5cdae4d:	ja     5cdafd8 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d458>
 5cdae53:	cmp    $0xc8,%rax
 5cdae59:	ja     5cdafef <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d441>
 5cdae5f:	lea    (%rsp,%rdi,1),%rsi
 5cdae63:	add    $0x8,%rsi
 5cdae67:	mov    (%rsp),%rdi
 5cdae6b:	mov    %r15,%rdx
 5cdae6e:	call   *0x804694(%rip)        # 64df508 <__register_atfork@plt+0xed978>
 5cdae74:	lea    0x8(%rsp),%rdi
 5cdae79:	call   *0x811cf1(%rip)        # 64ecb70 <__register_atfork@plt+0xfafe0>
 5cdae7f:	mov    %r14,%r12
 5cdae82:	sub    %r15,%r12
 5cdae85:	mov    0xd8(%rsp),%r13
 5cdae8d:	cmp    %r13,%r12
 5cdae90:	jb     5cdaeee <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d542>
 5cdae92:	lea    0x8(%rsp),%rbp
 5cdae97:	mov    0x811cd2(%rip),%rbx        # 64ecb70 <__register_atfork@plt+0xfafe0>
 5cdae9e:	xchg   %ax,%ax
 5cdaea0:	mov    %r14,%rdx
 5cdaea3:	sub    %r15,%rdx
 5cdaea6:	jb     5cdaf6f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d4c1>
 5cdaeac:	cmp    $0xc8,%r13
 5cdaeb3:	ja     5cdaf43 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d4ed>
 5cdaeb9:	cmp    %rdx,%r13
 5cdaebc:	ja     5cdaf5d <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d4d3>
 5cdaec2:	mov    (%rsp),%rax
 5cdaec6:	lea    (%rax,%r15,1),%rdi
 5cdaeca:	mov    %rbp,%rsi
 5cdaecd:	mov    %r13,%rdx
 5cdaed0:	call   *0x804632(%rip)        # 64df508 <__register_atfork@plt+0xed978>
 5cdaed6:	mov    %rbp,%rdi
 5cdaed9:	call   *%rbx
 5cdaedb:	add    %r13,%r15
 5cdaede:	sub    %r13,%r12
 5cdaee1:	mov    0xd8(%rsp),%r13
 5cdaee9:	cmp    %r13,%r12
 5cdaeec:	jae    5cdaea0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d590>
 5cdaeee:	mov    %r14,%rdx
 5cdaef1:	sub    %r15,%rdx
 5cdaef4:	jb     5cdaf85 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d4ab>
 5cdaefa:	xor    %edi,%edi
 5cdaefc:	mov    $0xc8,%eax
 5cdaf01:	sub    %rdi,%rax
 5cdaf04:	cmp    %rax,%r12
 5cdaf07:	ja     5cdafb1 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d47f>
 5cdaf0d:	cmp    %rdx,%r12
 5cdaf10:	ja     5cdafc6 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6d46a>
 5cdaf16:	mov    (%rsp),%rax
 5cdaf1a:	add    %r15,%rax
 5cdaf1d:	lea    (%rsp,%rdi,1),%rsi
 5cdaf21:	add    $0x8,%rsi
 5cdaf25:	mov    %rax,%rdi
 5cdaf28:	mov    %r12,%rdx
 5cdaf2b:	call   *0x8045d7(%rip)        # 64df508 <__register_atfork@plt+0xed978>
 5cdaf31:	add    $0xe8,%rsp
 5cdaf38:	pop    %rbx
 5cdaf39:	pop    %r12
 5cdaf3b:	pop    %r13
 5cdaf3d:	pop    %r14
 5cdaf3f:	pop    %r15
 5cdaf41:	pop    %rbp
 5cdaf42:	ret
 5cdaf43:	mov    $0xc8,%edx
 5cdaf48:	mov    %r13,%r15
 5cdaf4b:	lea    0x7ea4be(%rip),%rcx        # 64c5410 <__register_atfork@plt+0xd3880>
 5cdaf52:	xor    %edi,%edi
 5cdaf54:	mov    %r15,%rsi
 5cdaf57:	call   *0x804613(%rip)        # 64df570 <__register_atfork@plt+0xed9e0>
 5cdaf5d:	lea    0x7ea494(%rip),%rcx        # 64c53f8 <__register_atfork@plt+0xd3868>
 5cdaf64:	xor    %edi,%edi
 5cdaf66:	mov    %r13,%rsi
 5cdaf69:	call   *0x804601(%rip)        # 64df570 <__register_atfork@plt+0xed9e0>
 5cdaf6f:	lea    0x7ea43a(%rip),%rcx        # 64c53b0 <__register_atfork@plt+0xd3820>
 5cdaf76:	mov    %r15,%rdi
 5cdaf79:	mov    %r14,%rsi
 5cdaf7c:	mov    %r14,%rdx
 5cdaf7f:	call   *0x8045eb(%rip)        # 64df570 <__register_atfork@plt+0xed9e0>
 5cdaf85:	lea    0x7ea40c(%rip),%rcx        # 64c5398 <__register_atfork@plt+0xd3808>
 5cdaf8c:	mov    %r15,%rdi
 5cdaf8f:	mov    %r14,%rsi
 5cdaf92:	mov    %r14,%rdx
 5cdaf95:	call   *0x8045d5(%rip)        # 64df570 <__register_atfork@plt+0xed9e0>
 5cdaf9b:	lea    0x7ea46e(%rip),%rcx        # 64c5410 <__register_atfork@plt+0xd3880>
 5cdafa2:	mov    $0x1,%esi
 5cdafa7:	xor    %edi,%edi
 5cdafa9:	xor    %edx,%edx
 5cdafab:	call   *0x8045bf(%rip)        # 64df570 <__register_atfork@plt+0xed9e0>
 5cdafb1:	lea    0x7ea458(%rip),%rcx        # 64c5410 <__register_atfork@plt+0xd3880>
 5cdafb8:	xor    %edi,%edi
 5cdafba:	mov    %r12,%rsi
 5cdafbd:	mov    %rax,%rdx
 5cdafc0:	call   *0x8045aa(%rip)        # 64df570 <__register_atfork@plt+0xed9e0>
 5cdafc6:	lea    0x7ea42b(%rip),%rcx        # 64c53f8 <__register_atfork@plt+0xd3868>
 5cdafcd:	xor    %edi,%edi
 5cdafcf:	mov    %r12,%rsi
 5cdafd2:	call   *0x804598(%rip)        # 64df570 <__register_atfork@plt+0xed9e0>
 5cdafd8:	lea    0x7ea449(%rip),%rcx        # 64c5428 <__register_atfork@plt+0xd3898>
 5cdafdf:	mov    $0xc8,%esi
 5cdafe4:	mov    $0xc8,%edx
 5cdafe9:	call   *0x804581(%rip)        # 64df570 <__register_atfork@plt+0xed9e0>
 5cdafef:	mov    $0xc8,%edx
 5cdaff4:	sub    %rdi,%rdx
 5cdaff7:	lea    0x7ea412(%rip),%rcx        # 64c5410 <__register_atfork@plt+0xd3880>
 5cdaffe:	xor    %edi,%edi
 5cdb000:	mov    %r15,%rsi
 5cdb003:	call   *0x804567(%rip)        # 64df570 <__register_atfork@plt+0xed9e0>
 5cdb009:	lea    0x7ea418(%rip),%rcx        # 64c5428 <__register_atfork@plt+0xd3898>
 5cdb010:	mov    $0xc8,%esi
 5cdb015:	mov    $0xc8,%edx
 5cdb01a:	mov    %rax,%rdi
 5cdb01d:	call   *0x80454d(%rip)        # 64df570 <__register_atfork@plt+0xed9e0>
 5cdb023:	lea    0x7ea356(%rip),%rdi        # 64c5380 <__register_atfork@plt+0xd37f0>
 5cdb02a:	call   *0x804818(%rip)        # 64df848 <__register_atfork@plt+0xedcb8>
 5cdb030:	lea    0x7ea391(%rip),%rdi        # 64c53c8 <__register_atfork@plt+0xd3838>
 5cdb037:	call   *0x80480b(%rip)        # 64df848 <__register_atfork@plt+0xedcb8>

hl-node:     file format elf64-x86-64


Disassembly of section .text:

0000000005cda380 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6e0b0>:
 5cda380:	push   %rbp
 5cda381:	push   %r15
 5cda383:	push   %r14
 5cda385:	push   %r13
 5cda387:	push   %r12
 5cda389:	push   %rbx
 5cda38a:	sub    $0x60,%rsp
 5cda38e:	mov    %rdi,%rdx
 5cda391:	mov    (%rdi),%r8
 5cda394:	mov    0x8(%rdi),%rax
 5cda398:	mov    %rax,-0x30(%rsp)
 5cda39d:	mov    0x28(%rdi),%rax
 5cda3a1:	mov    %rax,-0x60(%rsp)
 5cda3a6:	mov    0x50(%rdi),%r12
 5cda3aa:	mov    0x78(%rdi),%r10
 5cda3ae:	mov    0xa0(%rdi),%rax
 5cda3b5:	mov    %rax,-0x18(%rsp)
 5cda3ba:	mov    0x30(%rdi),%rbp
 5cda3be:	mov    0x58(%rdi),%rsi
 5cda3c2:	mov    %rsi,-0x58(%rsp)
 5cda3c7:	mov    0x80(%rdi),%rcx
 5cda3ce:	mov    0xa8(%rdi),%rax
 5cda3d5:	mov    %rax,-0x48(%rsp)
 5cda3da:	mov    0x10(%rdi),%rsi
 5cda3de:	mov    %rsi,-0x28(%rsp)
 5cda3e3:	mov    0x38(%rdi),%r11
 5cda3e7:	mov    0x60(%rdi),%r15
 5cda3eb:	mov    0x88(%rdi),%rsi
 5cda3f2:	mov    0xb0(%rdi),%rax
 5cda3f9:	mov    %rax,-0x10(%rsp)
 5cda3fe:	mov    0x18(%rdi),%rdi
 5cda402:	mov    %rdi,-0x68(%rsp)
 5cda407:	mov    0x40(%rdx),%r13
 5cda40b:	mov    0x68(%rdx),%rax
 5cda40f:	mov    %rax,-0x70(%rsp)
 5cda414:	mov    0x90(%rdx),%rax
 5cda41b:	mov    %rax,-0x20(%rsp)
 5cda420:	mov    0xb8(%rdx),%rax
 5cda427:	mov    %rax,-0x40(%rsp)
 5cda42c:	mov    0x20(%rdx),%rdi
 5cda430:	mov    %rdi,-0x38(%rsp)
 5cda435:	mov    0x48(%rdx),%rdi
 5cda439:	mov    %rdi,-0x8(%rsp)
 5cda43e:	mov    0x70(%rdx),%rbx
 5cda442:	mov    0x98(%rdx),%r9
 5cda449:	mov    %rdx,0x30(%rsp)
 5cda44e:	mov    0xc0(%rdx),%rdx
 5cda455:	mov    %rdx,-0x80(%rsp)
 5cda45a:	xor    %edx,%edx
 5cda45c:	nopl   0x0(%rax)
 5cda460:	mov    %r8,(%rsp)
 5cda464:	mov    %rsi,-0x50(%rsp)
 5cda469:	mov    %rdx,0x58(%rsp)
 5cda46e:	mov    -0x60(%rsp),%rdx
 5cda473:	xor    %r8,%rdx
 5cda476:	mov    %r12,%rax
 5cda479:	xor    %r10,%rax
 5cda47c:	xor    %rdx,%rax
 5cda47f:	mov    %rbp,%rdx
 5cda482:	xor    -0x30(%rsp),%rdx
 5cda487:	mov    %r11,%rdi
 5cda48a:	mov    %r11,0x28(%rsp)
 5cda48f:	mov    -0x58(%rsp),%r11
 5cda494:	mov    %rcx,0x20(%rsp)
 5cda499:	xor    %rcx,%r11
 5cda49c:	xor    %rdx,%r11
 5cda49f:	xor    -0x28(%rsp),%rdi
 5cda4a4:	mov    %r9,%rcx
 5cda4a7:	mov    %r9,0x18(%rsp)
 5cda4ac:	mov    %r15,%r8
 5cda4af:	xor    %rsi,%r8
 5cda4b2:	xor    %rdi,%r8
 5cda4b5:	mov    %r13,%rsi
 5cda4b8:	xor    -0x68(%rsp),%rsi
 5cda4bd:	mov    -0x70(%rsp),%rdi
 5cda4c2:	mov    -0x20(%rsp),%r14
 5cda4c7:	xor    %r14,%rdi
 5cda4ca:	xor    %rsi,%rdi
 5cda4cd:	mov    -0x8(%rsp),%r9
 5cda4d2:	mov    %r9,%rsi
 5cda4d5:	xor    -0x38(%rsp),%rsi
 5cda4da:	mov    %rbx,-0x78(%rsp)
 5cda4df:	xor    %rcx,%rbx
 5cda4e2:	xor    %rsi,%rbx
 5cda4e5:	mov    -0x18(%rsp),%rsi
 5cda4ea:	xor    %rsi,%rax
 5cda4ed:	xor    -0x48(%rsp),%r11
 5cda4f2:	xor    -0x40(%rsp),%rdi
 5cda4f7:	mov    %rdi,%rdx
 5cda4fa:	rol    $1,%rdx
 5cda4fd:	xor    %r11,%rdx
 5cda500:	rol    $1,%r11
 5cda503:	xor    -0x80(%rsp),%rbx
 5cda508:	xor    %rbx,%r11
 5cda50b:	mov    (%rsp),%rcx
 5cda50f:	xor    %r11,%rcx
 5cda512:	mov    %rcx,0x10(%rsp)
 5cda517:	xor    %r11,-0x60(%rsp)
 5cda51c:	xor    %r11,%r12
 5cda51f:	xor    %r11,%r10
 5cda522:	xor    %rsi,%r11
 5cda525:	mov    %r11,0x50(%rsp)
 5cda52a:	mov    -0x10(%rsp),%rcx
 5cda52f:	xor    %rcx,%r8
 5cda532:	rol    $1,%rbx
 5cda535:	xor    %r8,%rbx
 5cda538:	rol    $1,%r8
 5cda53b:	xor    %rax,%r8
 5cda53e:	mov    -0x30(%rsp),%rsi
 5cda543:	xor    %r8,%rsi
 5cda546:	xor    %r8,%rbp
 5cda549:	xor    %r8,-0x58(%rsp)
 5cda54e:	xor    %r8,0x20(%rsp)
 5cda553:	xor    -0x48(%rsp),%r8
 5cda558:	mov    -0x28(%rsp),%r11
 5cda55d:	xor    %rdx,%r11
 5cda560:	xor    %rdx,0x28(%rsp)
 5cda565:	xor    %rdx,%r15
 5cda568:	xor    %rdx,-0x50(%rsp)
 5cda56d:	xor    %rcx,%rdx
 5cda570:	mov    %rdx,0x48(%rsp)
 5cda575:	xor    %rbx,-0x68(%rsp)
 5cda57a:	xor    %rbx,%r13
 5cda57d:	xor    %rbx,-0x70(%rsp)
 5cda582:	xor    %rbx,%r14
 5cda585:	rol    $1,%rax
 5cda588:	xor    -0x40(%rsp),%rbx
 5cda58d:	mov    %rbx,0x8(%rsp)
 5cda592:	xor    %rdi,%rax
 5cda595:	mov    -0x38(%rsp),%rcx
 5cda59a:	xor    %rax,%rcx
 5cda59d:	xor    %rax,%r9
 5cda5a0:	mov    -0x78(%rsp),%rdx
 5cda5a5:	xor    %rax,%rdx
 5cda5a8:	xor    %rax,0x18(%rsp)
 5cda5ad:	mov    %rax,%rdi
 5cda5b0:	rol    $0x15,%r14
 5cda5b4:	xor    -0x80(%rsp),%rdi
 5cda5b9:	rol    $0x37,%r13
 5cda5bd:	mov    %r13,%rbx
 5cda5c0:	rol    $0x2,%r8
 5cda5c4:	rol    $0xe,%rdi
 5cda5c8:	rol    $0x29,%r10
 5cda5cc:	mov    %rsi,0x40(%rsp)
 5cda5d1:	rol    $0x2b,%r15
 5cda5d5:	mov    %r11,%r13
 5cda5d8:	rol    $0x3e,%r13
 5cda5dc:	rol    $0x27,%rdx
 5cda5e0:	mov    %rcx,-0x78(%rsp)
 5cda5e5:	rol    $0x2c,%rbp
 5cda5e9:	mov    %rbp,%rax
 5cda5ec:	not    %rax
 5cda5ef:	and    %r15,%rax
 5cda5f2:	mov    %rax,(%rsp)
 5cda5f6:	mov    %r14,%rcx
 5cda5f9:	not    %rcx
 5cda5fc:	and    %rdi,%rcx
 5cda5ff:	xor    %r15,%rcx
 5cda602:	mov    %rcx,-0x28(%rsp)
 5cda607:	not    %r15
 5cda60a:	and    %r14,%r15
 5cda60d:	xor    %rbp,%r15
 5cda610:	mov    %r15,-0x30(%rsp)
 5cda615:	mov    0x10(%rsp),%rcx
 5cda61a:	mov    %rcx,%r11
 5cda61d:	not    %r11
 5cda620:	and    %rbp,%r11
 5cda623:	mov    %rbx,%rax
 5cda626:	not    %rax
 5cda629:	and    %rdx,%rax
 5cda62c:	xor    %r13,%rax
 5cda62f:	mov    %rax,-0x18(%rsp)
 5cda634:	mov    %r10,%rax
 5cda637:	not    %rax
 5cda63a:	mov    %r8,0x38(%rsp)
 5cda63f:	and    %r8,%rax
 5cda642:	xor    %rdx,%rax
 5cda645:	mov    %rax,-0x10(%rsp)
 5cda64a:	not    %rdx
 5cda64d:	and    %r10,%rdx
 5cda650:	xor    %rbx,%rdx
 5cda653:	mov    %rbx,%rax
 5cda656:	mov    %rdx,-0x48(%rsp)
 5cda65b:	mov    %r8,%rbx
 5cda65e:	not    %rbx
 5cda661:	and    %r13,%rbx
 5cda664:	not    %r13
 5cda667:	and    %rax,%r13
 5cda66a:	mov    %r13,-0x80(%rsp)
 5cda66f:	rol    $0x3,%r12
 5cda673:	mov    -0x68(%rsp),%rsi
 5cda678:	rol    $0x1c,%rsi
 5cda67c:	mov    -0x60(%rsp),%r15
 5cda681:	mov    0x20(%rsp),%rax
 5cda686:	rol    $0x2d,%rax
 5cda68a:	mov    0x48(%rsp),%rdx
 5cda68f:	rol    $0x3d,%rdx
 5cda693:	rol    $0x14,%r9
 5cda697:	mov    %r9,%r8
 5cda69a:	not    %r8
 5cda69d:	and    %r12,%r8
 5cda6a0:	xor    %rsi,%r8
 5cda6a3:	mov    %r8,-0x60(%rsp)
 5cda6a8:	mov    %r12,%rbp
 5cda6ab:	not    %rbp
 5cda6ae:	and    %rax,%rbp
 5cda6b1:	xor    %r9,%rbp
 5cda6b4:	mov    %rdx,%r13
 5cda6b7:	not    %r13
 5cda6ba:	and    %rsi,%r13
 5cda6bd:	not    %rsi
 5cda6c0:	and    %rsi,%r9
 5cda6c3:	mov    %rdi,%rsi
 5cda6c6:	not    %rsi
 5cda6c9:	and    %rcx,%rsi
 5cda6cc:	xor    %r14,%rsi
 5cda6cf:	mov    %rsi,-0x68(%rsp)
 5cda6d4:	xor    %rdi,%r11
 5cda6d7:	mov    %r11,-0x38(%rsp)
 5cda6dc:	mov    0x28(%rsp),%r8
 5cda6e1:	mov    %rax,%r11
 5cda6e4:	not    %r11
 5cda6e7:	and    %rdx,%r11
 5cda6ea:	xor    %r12,%r11
 5cda6ed:	xor    %rax,%r13
 5cda6f0:	xor    %rdx,%r9
 5cda6f3:	mov    %r9,-0x8(%rsp)
 5cda6f8:	xor    %r10,%rbx
 5cda6fb:	mov    %rbx,-0x40(%rsp)
 5cda700:	mov    -0x58(%rsp),%rax
 5cda705:	rol    $0xa,%rax
 5cda709:	mov    -0x50(%rsp),%rsi
 5cda70e:	rol    $0xf,%rsi
 5cda712:	mov    %r15,%r10
 5cda715:	rol    $0x24,%r10
 5cda719:	mov    %r10,-0x50(%rsp)
 5cda71e:	mov    -0x78(%rsp),%rdi
 5cda723:	rol    $0x1b,%rdi
 5cda727:	mov    %rdi,-0x78(%rsp)
 5cda72c:	mov    0x8(%rsp),%rdx
 5cda731:	rol    $0x38,%rdx
 5cda735:	mov    %rdx,0x8(%rsp)
 5cda73a:	not    %r10
 5cda73d:	and    %rax,%r10
 5cda740:	mov    %rax,%rcx
 5cda743:	not    %rcx
 5cda746:	and    %rsi,%rcx
 5cda749:	mov    %rdx,%r9
 5cda74c:	not    %r9
 5cda74f:	and    %rdi,%r9
 5cda752:	xor    %rsi,%r9
 5cda755:	mov    %r9,-0x20(%rsp)
 5cda75a:	not    %rsi
 5cda75d:	and    %rdx,%rsi
 5cda760:	xor    %rax,%rsi
 5cda763:	mov    0x40(%rsp),%r14
 5cda768:	rol    $1,%r14
 5cda76b:	rol    $0x6,%r8
 5cda76f:	mov    0x18(%rsp),%rbx
 5cda774:	rol    $0x8,%rbx
 5cda778:	mov    -0x70(%rsp),%r9
 5cda77d:	rol    $0x19,%r9
 5cda781:	mov    0x50(%rsp),%rdx
 5cda786:	rol    $0x12,%rdx
 5cda78a:	mov    %r8,%r12
 5cda78d:	not    %r12
 5cda790:	and    %r9,%r12
 5cda793:	mov    %rbx,%r15
 5cda796:	not    %r15
 5cda799:	and    %rdx,%r15
 5cda79c:	xor    %r9,%r15
 5cda79f:	mov    %r9,%rdi
 5cda7a2:	not    %rdi
 5cda7a5:	and    %rbx,%rdi
 5cda7a8:	mov    %rdx,%rax
 5cda7ab:	not    %rax
 5cda7ae:	and    %r14,%rax
 5cda7b1:	xor    %rbx,%rax
 5cda7b4:	mov    %rax,-0x70(%rsp)
 5cda7b9:	xor    %r14,%r12
 5cda7bc:	xor    %r8,%rdi
 5cda7bf:	mov    %rdi,-0x58(%rsp)
 5cda7c4:	not    %r14
 5cda7c7:	and    %r8,%r14
 5cda7ca:	mov    %r14,%rbx
 5cda7cd:	xor    %rdx,%rbx
 5cda7d0:	mov    -0x78(%rsp),%r9
 5cda7d5:	xor    %r9,%r10
 5cda7d8:	mov    -0x50(%rsp),%rax
 5cda7dd:	xor    %rax,%rcx
 5cda7e0:	not    %r9
 5cda7e3:	and    %rax,%r9
 5cda7e6:	mov    0x58(%rsp),%rdx
 5cda7eb:	xor    0x8(%rsp),%r9
 5cda7f0:	lea    -0x538e2df(%rip),%r8        # 94c518 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x53fbf18>
 5cda7f7:	mov    (%rsp),%rax
 5cda7fb:	xor    (%rdx,%r8,1),%rax
 5cda7ff:	mov    %rax,%r8
 5cda802:	mov    -0x80(%rsp),%rax
 5cda807:	xor    0x38(%rsp),%rax
 5cda80c:	mov    %rax,-0x80(%rsp)
 5cda811:	xor    0x10(%rsp),%r8
 5cda816:	add    $0x8,%rdx
 5cda81a:	cmp    $0xc0,%rdx
 5cda821:	jne    5cda460 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x6dfd0>
 5cda827:	mov    0x30(%rsp),%rdx
 5cda82c:	mov    %r8,(%rdx)
 5cda82f:	mov    %rsi,%rdi
 5cda832:	mov    -0x60(%rsp),%rsi
 5cda837:	mov    %rsi,0x28(%rdx)
 5cda83b:	mov    %r12,0x50(%rdx)
 5cda83f:	mov    %r10,0x78(%rdx)
 5cda843:	mov    -0x18(%rsp),%rax
 5cda848:	mov    %rax,0xa0(%rdx)
 5cda84f:	mov    -0x30(%rsp),%rax
 5cda854:	mov    %rax,0x8(%rdx)
 5cda858:	mov    %rbp,0x30(%rdx)
 5cda85c:	mov    -0x58(%rsp),%rax
 5cda861:	mov    %rax,0x58(%rdx)
 5cda865:	mov    %rcx,0x80(%rdx)
 5cda86c:	mov    -0x48(%rsp),%rax
 5cda871:	mov    %rax,0xa8(%rdx)
 5cda878:	mov    -0x28(%rsp),%rax
 5cda87d:	mov    %rax,0x10(%rdx)
 5cda881:	mov    %r11,0x38(%rdx)
 5cda885:	mov    %r15,0x60(%rdx)
 5cda889:	mov    %rdi,0x88(%rdx)
 5cda890:	mov    -0x10(%rsp),%rax
 5cda895:	mov    %rax,0xb0(%rdx)
 5cda89c:	mov    -0x68(%rsp),%rax
 5cda8a1:	mov    %rax,0x18(%rdx)
 5cda8a5:	mov    %r13,0x40(%rdx)
 5cda8a9:	mov    -0x70(%rsp),%rax
 5cda8ae:	mov    %rax,0x68(%rdx)
 5cda8b2:	mov    -0x20(%rsp),%rax
 5cda8b7:	mov    %rax,0x90(%rdx)
 5cda8be:	mov    -0x40(%rsp),%rax
 5cda8c3:	mov    %rax,0xb8(%rdx)
 5cda8ca:	mov    -0x38(%rsp),%rax
 5cda8cf:	mov    %rax,0x20(%rdx)
 5cda8d3:	mov    -0x8(%rsp),%rax
 5cda8d8:	mov    %rax,0x48(%rdx)
 5cda8dc:	mov    %rbx,0x70(%rdx)
 5cda8e0:	mov    %r9,0x98(%rdx)
 5cda8e7:	mov    -0x80(%rsp),%rax
 5cda8ec:	mov    %rax,0xc0(%rdx)
 5cda8f3:	add    $0x60,%rsp
 5cda8f7:	pop    %rbx
 5cda8f8:	pop    %r12
 5cda8fa:	pop    %r13
 5cda8fc:	pop    %r14
 5cda8fe:	pop    %r15
 5cda900:	pop    %rbp
 5cda901:	ret

hl-node:     file format elf64-x86-64


Disassembly of section .text:

0000000001536a90 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x48119a0>:
 1536a90:	push   %r15
 1536a92:	push   %r14
 1536a94:	push   %rbx
 1536a95:	sub    $0x310,%rsp
 1536a9c:	mov    %rdi,%rbx
 1536a9f:	mov    (%rsi),%r8
 1536aa2:	mov    0x8(%rsi),%r9
 1536aa6:	mov    0x10(%rsi),%r10
 1536aaa:	mov    0x18(%rsi),%r11
 1536aae:	mov    0x20(%rsi),%rcx
 1536ab2:	mov    0x28(%rsi),%rdi
 1536ab6:	mov    0x30(%rsi),%r14
 1536aba:	mov    0x38(%rsi),%r15
 1536abe:	movzbl 0x40(%rsi),%eax
 1536ac2:	movups (%rdx),%xmm0
 1536ac5:	movups 0x10(%rdx),%xmm1
 1536ac9:	movaps %xmm1,0x300(%rsp)
 1536ad1:	bswap  %r11
 1536ad4:	movaps %xmm0,0x2f0(%rsp)
 1536adc:	mov    %r11,0x180(%rsp)
 1536ae4:	bswap  %r10
 1536ae7:	mov    %r10,0x188(%rsp)
 1536aef:	bswap  %r9
 1536af2:	mov    %r9,0x190(%rsp)
 1536afa:	bswap  %r8
 1536afd:	bswap  %r15
 1536b00:	mov    %r8,0x198(%rsp)
 1536b08:	mov    %r15,0x1a0(%rsp)
 1536b10:	bswap  %r14
 1536b13:	mov    %r14,0x1a8(%rsp)
 1536b1b:	bswap  %rdi
 1536b1e:	mov    %rdi,0x1b0(%rsp)
 1536b26:	bswap  %rcx
 1536b29:	mov    %rcx,0x1b8(%rsp)
 1536b31:	cmp    $0x1c,%rax
 1536b35:	ja     1536b50 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x48118e0>
 1536b37:	xor    %ecx,%ecx
 1536b39:	lea    -0x10d0328(%rip),%rdx        # 466818 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x58e1c18>
 1536b40:	movslq (%rdx,%rax,4),%rsi
 1536b44:	add    %rdx,%rsi
 1536b47:	jmp    *%rsi
 1536b49:	mov    $0x1,%ecx
 1536b4e:	jmp    1536b5f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x48118d1>
 1536b50:	cmp    $0x22,%al
 1536b52:	jbe    1536f22 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x481150e>
 1536b58:	not    %eax
 1536b5a:	and    $0x1,%eax
 1536b5d:	mov    %eax,%ecx
 1536b5f:	xorps  %xmm0,%xmm0
 1536b62:	movaps %xmm0,0xd0(%rsp)
 1536b6a:	movaps %xmm0,0xc0(%rsp)
 1536b72:	movaps %xmm0,0xb0(%rsp)
 1536b7a:	movaps %xmm0,0xa0(%rsp)
 1536b82:	movb   $0x0,0xe0(%rsp)
 1536b8a:	mov    0x4fa8e3f(%rip),%r14        # 64df9d0 <__register_atfork@plt+0xede40>
 1536b91:	mov    (%r14),%rdi
 1536b94:	lea    0xa0(%rsp),%rsi
 1536b9c:	lea    0x180(%rsp),%rdx
 1536ba4:	call   *0x4fa8e2e(%rip)        # 64df9d8 <__register_atfork@plt+0xede48>
 1536baa:	cmp    $0x1,%eax
 1536bad:	jne    1536f0f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x4811521>
 1536bb3:	movzbl 0xa2(%rsp),%eax
 1536bbb:	mov    %al,0x2b0(%rsp)
 1536bc2:	movzwl 0xa0(%rsp),%eax
 1536bca:	mov    %ax,0x2ae(%rsp)
 1536bd2:	mov    0xd9(%rsp),%rax
 1536bda:	mov    %rax,0x1ee(%rsp)
 1536be2:	movups 0xcb(%rsp),%xmm0
 1536bea:	movaps %xmm0,0x1e0(%rsp)
 1536bf2:	movups 0xbb(%rsp),%xmm0
 1536bfa:	movups 0xab(%rsp),%xmm1
 1536c02:	mov    0xa3(%rsp),%rax
 1536c0a:	movaps %xmm1,0x10(%rsp)
 1536c0f:	movaps %xmm0,0x20(%rsp)
 1536c14:	movaps 0x1e0(%rsp),%xmm0
 1536c1c:	movaps %xmm0,0x30(%rsp)
 1536c21:	mov    0x1ee(%rsp),%rcx
 1536c29:	mov    %rcx,0x3e(%rsp)
 1536c2e:	mov    0x3e(%rsp),%rcx
 1536c33:	mov    %rcx,0x2e7(%rsp)
 1536c3b:	movaps 0x10(%rsp),%xmm0
 1536c40:	movaps 0x20(%rsp),%xmm1
 1536c45:	movaps 0x30(%rsp),%xmm2
 1536c4a:	movups %xmm2,0x2d9(%rsp)
 1536c52:	movups %xmm1,0x2c9(%rsp)
 1536c5a:	movups %xmm0,0x2b9(%rsp)
 1536c62:	mov    %rax,0x2b1(%rsp)
 1536c6a:	mov    0x4fb9438(%rip),%eax        # 64f00a8 <__register_atfork@plt+0xfe518>
 1536c70:	test   %eax,%eax
 1536c72:	jne    1536f29 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x4811507>
 1536c78:	xorps  %xmm0,%xmm0
 1536c7b:	movaps %xmm0,0xd0(%rsp)
 1536c83:	movaps %xmm0,0xc0(%rsp)
 1536c8b:	movaps %xmm0,0xb0(%rsp)
 1536c93:	movaps %xmm0,0xa0(%rsp)
 1536c9b:	mov    0x4fb93fe(%rip),%rdi        # 64f00a0 <__register_atfork@plt+0xfe510>
 1536ca2:	lea    0xa0(%rsp),%rsi
 1536caa:	lea    0x2ae(%rsp),%rdx
 1536cb2:	lea    0x2f0(%rsp),%rcx
 1536cba:	call   *0x4fa8d20(%rip)        # 64df9e0 <__register_atfork@plt+0xede50>
 1536cc0:	cmp    $0x1,%eax
 1536cc3:	jne    1536f0f <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x4811521>
 1536cc9:	movzbl 0xa2(%rsp),%eax
 1536cd1:	mov    %al,0x1c2(%rsp)
 1536cd8:	movzwl 0xa0(%rsp),%eax
 1536ce0:	mov    %ax,0x1c0(%rsp)
 1536ce8:	mov    0xd8(%rsp),%rax
 1536cf0:	mov    %rax,0x8d(%rsp)
 1536cf8:	movups 0xcb(%rsp),%xmm0
 1536d00:	movaps %xmm0,0x80(%rsp)
 1536d08:	movups 0xab(%rsp),%xmm0
 1536d10:	movaps %xmm0,0x60(%rsp)
 1536d15:	movups 0xbb(%rsp),%xmm1
 1536d1d:	movaps %xmm1,0x70(%rsp)
 1536d22:	mov    0xa3(%rsp),%rax
 1536d2a:	movups %xmm0,0x1cb(%rsp)
 1536d32:	movups %xmm1,0x1db(%rsp)
 1536d3a:	movaps 0x80(%rsp),%xmm0
 1536d42:	movups %xmm0,0x1eb(%rsp)
 1536d4a:	mov    0x8d(%rsp),%rcx
 1536d52:	mov    %rcx,0x1f8(%rsp)
 1536d5a:	mov    %rax,0x1c3(%rsp)
 1536d62:	xorps  %xmm0,%xmm0
 1536d65:	movaps %xmm0,0xd0(%rsp)
 1536d6d:	movaps %xmm0,0xc0(%rsp)
 1536d75:	movaps %xmm0,0xb0(%rsp)
 1536d7d:	movaps %xmm0,0xa0(%rsp)
 1536d85:	movb   $0x0,0xe0(%rsp)
 1536d8d:	movq   $0x41,0x8(%rsp)
 1536d96:	mov    (%r14),%rdi
 1536d99:	lea    0xa0(%rsp),%rsi
 1536da1:	lea    0x8(%rsp),%rdx
 1536da6:	lea    0x1c0(%rsp),%rcx
 1536dae:	mov    $0x2,%r8d
 1536db4:	call   *0x4fa8c2e(%rip)        # 64df9e8 <__register_atfork@plt+0xede58>
 1536dba:	movaps 0xa0(%rsp),%xmm0
 1536dc2:	movaps 0xb0(%rsp),%xmm1
 1536dca:	movaps 0xc0(%rsp),%xmm2
 1536dd2:	movaps 0xd0(%rsp),%xmm3
 1536dda:	movaps %xmm0,0x10(%rsp)
 1536ddf:	movaps %xmm1,0x20(%rsp)
 1536de4:	movaps %xmm2,0x30(%rsp)
 1536de9:	movaps %xmm3,0x40(%rsp)
 1536dee:	movzbl 0xe0(%rsp),%eax
 1536df6:	mov    %al,0x50(%rsp)
 1536dfa:	lea    0x11(%rsp),%rsi
 1536dff:	xorps  %xmm0,%xmm0
 1536e02:	movaps %xmm0,0x70(%rsp)
 1536e07:	movaps %xmm0,0x60(%rsp)
 1536e0c:	movaps %xmm0,0x280(%rsp)
 1536e14:	movaps %xmm0,0x270(%rsp)
 1536e1c:	movaps %xmm0,0x260(%rsp)
 1536e24:	movaps %xmm0,0x250(%rsp)
 1536e2c:	movaps %xmm0,0x240(%rsp)
 1536e34:	movaps %xmm0,0x230(%rsp)
 1536e3c:	movaps %xmm0,0x220(%rsp)
 1536e44:	movaps %xmm0,0x210(%rsp)
 1536e4c:	movaps %xmm0,0x200(%rsp)
 1536e54:	movaps %xmm0,0x1f0(%rsp)
 1536e5c:	movaps %xmm0,0x1e0(%rsp)
 1536e64:	movaps %xmm0,0x1d0(%rsp)
 1536e6c:	movaps %xmm0,0x1c0(%rsp)
 1536e74:	movq   $0x88,0x290(%rsp)
 1536e80:	movw   $0x1,0x298(%rsp)
 1536e8a:	lea    0x1c0(%rsp),%r14
 1536e92:	mov    $0x40,%edx
 1536e97:	mov    %r14,%rdi
 1536e9a:	call   *0x4fa92a8(%rip)        # 64e0148 <__register_atfork@plt+0xee5b8>
 1536ea0:	lea    0xa0(%rsp),%r15
 1536ea8:	mov    $0xe0,%edx
 1536ead:	mov    %r15,%rdi
 1536eb0:	mov    %r14,%rsi
 1536eb3:	call   *0x4fa864f(%rip)        # 64df508 <__register_atfork@plt+0xed978>
 1536eb9:	lea    0x60(%rsp),%rsi
 1536ebe:	mov    $0x20,%edx
 1536ec3:	mov    %r15,%rdi
 1536ec6:	call   *0x4fa9284(%rip)        # 64e0150 <__register_atfork@plt+0xee5c0>
 1536ecc:	movaps 0x60(%rsp),%xmm0
 1536ed1:	movaps 0x70(%rsp),%xmm1
 1536ed6:	movaps %xmm1,0xb0(%rsp)
 1536ede:	movaps %xmm0,0xa0(%rsp)
 1536ee6:	mov    0xbc(%rsp),%eax
 1536eed:	mov    %eax,0x11(%rbx)
 1536ef0:	movups 0xac(%rsp),%xmm0
 1536ef8:	movups %xmm0,0x1(%rbx)
 1536efc:	movb   $0x0,(%rbx)
 1536eff:	mov    %rbx,%rax
 1536f02:	add    $0x310,%rsp
 1536f09:	pop    %rbx
 1536f0a:	pop    %r14
 1536f0c:	pop    %r15
 1536f0e:	ret
 1536f0f:	mov    $0x3,%edi
 1536f14:	call   14cca30 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x487ba00>
 1536f19:	mov    %rax,0x8(%rbx)
 1536f1d:	movb   $0x1,(%rbx)
 1536f20:	jmp    1536eff <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x4811531>
 1536f22:	mov    $0x6,%edi
 1536f27:	jmp    1536f14 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x481151c>
 1536f29:	lea    0x4fb9170(%rip),%rax        # 64f00a0 <__register_atfork@plt+0xfe510>
 1536f30:	mov    %rax,0x8(%rsp)
 1536f35:	lea    0x8(%rsp),%rax
 1536f3a:	mov    %rax,0xa0(%rsp)
 1536f42:	lea    0x4fb915f(%rip),%rdi        # 64f00a8 <__register_atfork@plt+0xfe518>
 1536f49:	lea    0x4ec6748(%rip),%rcx        # 63fd698 <__register_atfork@plt+0xbb08>
 1536f50:	lea    0x4ec6769(%rip),%r8        # 63fd6c0 <__register_atfork@plt+0xbb30>
 1536f57:	lea    0xa0(%rsp),%rdx
 1536f5f:	mov    $0x1,%esi
 1536f64:	call   *0x4fa8a86(%rip)        # 64df9f0 <__register_atfork@plt+0xede60>
 1536f6a:	jmp    1536c78 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x48117b8>

hl-node:     file format elf64-x86-64


Disassembly of section .text:

000000000632b660 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e3230>:
 632b660:	endbr64
 632b664:	push   %r14
 632b666:	mov    %rdi,%rax
 632b669:	push   %r13
 632b66b:	push   %r12
 632b66d:	push   %rbp
 632b66e:	mov    %rdx,%rbp
 632b671:	push   %rbx
 632b672:	sub    $0x60,%rsp
 632b676:	mov    %fs:0x28,%rdx
 632b67f:	mov    %rdx,0x58(%rsp)
 632b684:	xor    %edx,%edx
 632b686:	movl   $0x0,0xc(%rsp)
 632b68e:	test   %rsi,%rsi
 632b691:	je     632b758 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e3328>
 632b697:	test   %rbp,%rbp
 632b69a:	je     632b770 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e3340>
 632b6a0:	mov    %ecx,%r12d
 632b6a3:	cmp    $0x3,%ecx
 632b6a6:	ja     632b790 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e3360>
 632b6ac:	lea    0xc(%rsp),%r14
 632b6b1:	lea    0x10(%rsp),%rdi
 632b6b6:	mov    %rsi,%rbx
 632b6b9:	mov    %rbp,%rsi
 632b6bc:	mov    %r14,%rdx
 632b6bf:	call   6321680 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5d9250>
 632b6c4:	lea    0x20(%rbp),%rsi
 632b6c8:	lea    0x30(%rsp),%rdi
 632b6cd:	mov    %r14,%rdx
 632b6d0:	mov    0xc(%rsp),%r13d
 632b6d5:	call   6321680 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5d9250>
 632b6da:	or     0xc(%rsp),%r13d
 632b6df:	jne    632b738 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e3308>
 632b6e1:	movdqa 0x10(%rsp),%xmm1
 632b6e7:	movdqa 0x20(%rsp),%xmm2
 632b6ed:	mov    %r12b,0x40(%rbx)
 632b6f1:	mov    $0x1,%eax
 632b6f6:	movdqa 0x30(%rsp),%xmm3
 632b6fc:	movdqa 0x40(%rsp),%xmm4
 632b702:	movups %xmm1,(%rbx)
 632b705:	movups %xmm2,0x10(%rbx)
 632b709:	movups %xmm3,0x20(%rbx)
 632b70d:	movups %xmm4,0x30(%rbx)
 632b711:	mov    0x58(%rsp),%rdx
 632b716:	sub    %fs:0x28,%rdx
 632b71f:	jne    632b7ab <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e337b>
 632b725:	add    $0x60,%rsp
 632b729:	pop    %rbx
 632b72a:	pop    %rbp
 632b72b:	pop    %r12
 632b72d:	pop    %r13
 632b72f:	pop    %r14
 632b731:	ret
 632b732:	nopw   0x0(%rax,%rax,1)
 632b738:	pxor   %xmm0,%xmm0
 632b73c:	movb   $0x0,0x40(%rbx)
 632b740:	xor    %eax,%eax
 632b742:	movups %xmm0,(%rbx)
 632b745:	movups %xmm0,0x10(%rbx)
 632b749:	movups %xmm0,0x20(%rbx)
 632b74d:	movups %xmm0,0x30(%rbx)
 632b751:	jmp    632b711 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e32e1>
 632b753:	nopl   0x0(%rax,%rax,1)
 632b758:	mov    0xb0(%rdi),%rsi
 632b75f:	lea    -0x5ef5391(%rip),%rdi        # 4363d5 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x591205b>
 632b766:	call   *0xa8(%rax)
 632b76c:	xor    %eax,%eax
 632b76e:	jmp    632b711 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e32e1>
 632b770:	mov    0xb0(%rdi),%rsi
 632b777:	lea    -0x5ef73e1(%rip),%rdi        # 43439d <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5914093>
 632b77e:	call   *0xa8(%rax)
 632b784:	xor    %eax,%eax
 632b786:	jmp    632b711 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e32e1>
 632b788:	nopl   0x0(%rax,%rax,1)
 632b790:	mov    0xb0(%rdi),%rsi
 632b797:	lea    -0x5ee8c57(%rip),%rdi        # 442b47 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x59058e9>
 632b79e:	call   *0xa8(%rax)
 632b7a4:	xor    %eax,%eax
 632b7a6:	jmp    632b711 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e32e1>
 632b7ab:	call   63f0d70 <__stack_chk_fail@plt>

hl-node:     file format elf64-x86-64


Disassembly of section .text:

000000000632b7b0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e3380>:
 632b7b0:	endbr64
 632b7b4:	push   %r15
 632b7b6:	mov    %rdi,%rax
 632b7b9:	push   %r14
 632b7bb:	push   %r13
 632b7bd:	push   %r12
 632b7bf:	push   %rbp
 632b7c0:	push   %rbx
 632b7c1:	mov    %rsi,%rbx
 632b7c4:	mov    %rcx,%rsi
 632b7c7:	sub    $0x108,%rsp
 632b7ce:	mov    %fs:0x28,%rcx
 632b7d7:	mov    %rcx,0xf8(%rsp)
 632b7df:	xor    %ecx,%ecx
 632b7e1:	test   %rsi,%rsi
 632b7e4:	je     632b8f0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e34c0>
 632b7ea:	test   %rdx,%rdx
 632b7ed:	je     632b910 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e34e0>
 632b7f3:	test   %rbx,%rbx
 632b7f6:	je     632b930 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e3500>
 632b7fc:	movdqu (%rdx),%xmm1
 632b800:	movdqu 0x10(%rdx),%xmm2
 632b805:	lea    0x40(%rsp),%rbp
 632b80a:	mov    %rsp,%r12
 632b80d:	movdqu 0x20(%rdx),%xmm3
 632b812:	movdqu 0x30(%rdx),%xmm4
 632b817:	mov    %rbp,%rdi
 632b81a:	lea    0x20(%rsp),%r13
 632b81f:	movzbl 0x40(%rdx),%r15d
 632b824:	lea    0xa0(%rsp),%r14
 632b82c:	xor    %edx,%edx
 632b82e:	movaps %xmm1,(%rsp)
 632b832:	movaps %xmm2,0x10(%rsp)
 632b837:	movaps %xmm3,0x20(%rsp)
 632b83c:	movaps %xmm4,0x30(%rsp)
 632b841:	call   6321680 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5d9250>
 632b846:	mov    %r15d,%r8d
 632b849:	mov    %rbp,%rcx
 632b84c:	mov    %r14,%rdx
 632b84f:	mov    %r13,%rsi
 632b852:	mov    %r12,%rdi
 632b855:	call   6329c10 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e17e0>
 632b85a:	test   %eax,%eax
 632b85c:	je     632b8d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e34a0>
 632b85e:	lea    0x60(%rsp),%rdi
 632b863:	mov    %r14,%rsi
 632b866:	call   6325530 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5dd100>
 632b86b:	movdqa 0x60(%rsp),%xmm5
 632b871:	movdqa 0x70(%rsp),%xmm6
 632b877:	mov    $0x1,%eax
 632b87c:	movdqa 0x80(%rsp),%xmm7
 632b885:	movups %xmm5,(%rbx)
 632b888:	movdqa 0x90(%rsp),%xmm5
 632b891:	movups %xmm6,0x10(%rbx)
 632b895:	movups %xmm7,0x20(%rbx)
 632b899:	movups %xmm5,0x30(%rbx)
 632b89d:	mov    0xf8(%rsp),%rdx
 632b8a5:	sub    %fs:0x28,%rdx
 632b8ae:	jne    632b94b <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e351b>
 632b8b4:	add    $0x108,%rsp
 632b8bb:	pop    %rbx
 632b8bc:	pop    %rbp
 632b8bd:	pop    %r12
 632b8bf:	pop    %r13
 632b8c1:	pop    %r14
 632b8c3:	pop    %r15
 632b8c5:	ret
 632b8c6:	cs nopw 0x0(%rax,%rax,1)
 632b8d0:	pxor   %xmm0,%xmm0
 632b8d4:	xor    %eax,%eax
 632b8d6:	movups %xmm0,(%rbx)
 632b8d9:	movups %xmm0,0x10(%rbx)
 632b8dd:	movups %xmm0,0x20(%rbx)
 632b8e1:	movups %xmm0,0x30(%rbx)
 632b8e5:	jmp    632b89d <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e346d>
 632b8e7:	nopw   0x0(%rax,%rax,1)
 632b8f0:	mov    0xb0(%rdi),%rsi
 632b8f7:	lea    -0x5edb8e4(%rip),%rdi        # 45001a <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x58f8416>
 632b8fe:	call   *0xa8(%rax)
 632b904:	xor    %eax,%eax
 632b906:	jmp    632b89d <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e346d>
 632b908:	nopl   0x0(%rax,%rax,1)
 632b910:	mov    0xb0(%rdi),%rsi
 632b917:	lea    -0x5ef3357(%rip),%rdi        # 4385c7 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x590fe69>
 632b91e:	call   *0xa8(%rax)
 632b924:	xor    %eax,%eax
 632b926:	jmp    632b89d <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e346d>
 632b92b:	nopl   0x0(%rax,%rax,1)
 632b930:	mov    0xb0(%rdi),%rsi
 632b937:	lea    -0x5ef9520(%rip),%rdi        # 43241e <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5916012>
 632b93e:	call   *0xa8(%rax)
 632b944:	xor    %eax,%eax
 632b946:	jmp    632b89d <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e346d>
 632b94b:	call   63f0d70 <__stack_chk_fail@plt>

hl-node:     file format elf64-x86-64


Disassembly of section .text:

000000000632b480 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e3050>:
 632b480:	endbr64
 632b484:	push   %r15
 632b486:	push   %r14
 632b488:	mov    %rdi,%r14
 632b48b:	push   %r13
 632b48d:	push   %r12
 632b48f:	push   %rbp
 632b490:	push   %rbx
 632b491:	sub    $0x78,%rsp
 632b495:	mov    %fs:0x28,%rax
 632b49e:	mov    %rax,0x68(%rsp)
 632b4a3:	xor    %eax,%eax
 632b4a5:	test   %rdx,%rdx
 632b4a8:	je     632b5a0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e3170>
 632b4ae:	mov    %r8d,%r15d
 632b4b1:	mov    %rdx,%rbx
 632b4b4:	mov    (%rdx),%rdx
 632b4b7:	mov    %r8d,%r13d
 632b4ba:	and    $0x100,%r15d
 632b4c1:	cmp    $0x1,%r15d
 632b4c5:	sbb    %rbp,%rbp
 632b4c8:	and    $0x20,%ebp
 632b4cb:	add    $0x21,%rbp
 632b4cf:	cmp    %rbp,%rdx
 632b4d2:	jb     632b5c0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e3190>
 632b4d8:	movq   $0x0,(%rbx)
 632b4df:	mov    %rsi,%r12
 632b4e2:	test   %rsi,%rsi
 632b4e5:	je     632b5e0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e31b0>
 632b4eb:	xor    %esi,%esi
 632b4ed:	mov    %r12,%rdi
 632b4f0:	mov    %rcx,0x8(%rsp)
 632b4f5:	call   63f0a90 <memset@plt>
 632b4fa:	mov    0x8(%rsp),%rcx
 632b4ff:	test   %rcx,%rcx
 632b502:	je     632b600 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e31d0>
 632b508:	cmp    $0x2,%r13b
 632b50c:	jne    632b620 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e31f0>
 632b512:	lea    0x10(%rsp),%r13
 632b517:	mov    %rcx,%rdx
 632b51a:	mov    %r14,%rdi
 632b51d:	mov    %r13,%rsi
 632b520:	call   6322270 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5d9e40>
 632b525:	test   %eax,%eax
 632b527:	jne    632b550 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e3120>
 632b529:	xor    %eax,%eax
 632b52b:	mov    0x68(%rsp),%rdx
 632b530:	sub    %fs:0x28,%rdx
 632b539:	jne    632b657 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e3227>
 632b53f:	add    $0x78,%rsp
 632b543:	pop    %rbx
 632b544:	pop    %rbp
 632b545:	pop    %r12
 632b547:	pop    %r13
 632b549:	pop    %r14
 632b54b:	pop    %r15
 632b54d:	ret
 632b54e:	xchg   %ax,%ax
 632b550:	mov    0x60(%rsp),%eax
 632b554:	test   %eax,%eax
 632b556:	jne    632b529 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e30f9>
 632b558:	mov    %r13,%rdi
 632b55b:	lea    0x38(%rsp),%r14
 632b560:	call   631d7c0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5d5390>
 632b565:	mov    %r14,%rdi
 632b568:	call   631d7c0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5d5390>
 632b56d:	lea    0x1(%r12),%rdi
 632b572:	mov    %r13,%rsi
 632b575:	call   631db90 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5d5760>
 632b57a:	test   %r15d,%r15d
 632b57d:	je     632b640 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e3210>
 632b583:	mov    0x38(%rsp),%eax
 632b587:	and    $0x1,%eax
 632b58a:	add    $0x2,%eax
 632b58d:	mov    %al,(%r12)
 632b591:	mov    %rbp,(%rbx)
 632b594:	mov    $0x1,%eax
 632b599:	jmp    632b52b <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e30fb>
 632b59b:	nopl   0x0(%rax,%rax,1)
 632b5a0:	mov    0xb0(%rdi),%rsi
 632b5a7:	lea    -0x5eea9d7(%rip),%rdi        # 440bd7 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5907859>
 632b5ae:	call   *0xa8(%r14)
 632b5b5:	jmp    632b529 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e30f9>
 632b5ba:	nopw   0x0(%rax,%rax,1)
 632b5c0:	mov    0xb0(%rdi),%rsi
 632b5c7:	lea    -0x59c9dc6(%rip),%rdi        # 961808 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x53e6c28>
 632b5ce:	call   *0xa8(%r14)
 632b5d5:	jmp    632b529 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e30f9>
 632b5da:	nopw   0x0(%rax,%rax,1)
 632b5e0:	mov    0xb0(%rdi),%rsi
 632b5e7:	lea    -0x5ee6d6d(%rip),%rdi        # 444881 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5903baf>
 632b5ee:	call   *0xa8(%r14)
 632b5f5:	jmp    632b529 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e30f9>
 632b5fa:	nopw   0x0(%rax,%rax,1)
 632b600:	mov    0xb0(%r14),%rsi
 632b607:	lea    -0x5ef91f0(%rip),%rdi        # 43241e <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5916012>
 632b60e:	call   *0xa8(%r14)
 632b615:	jmp    632b529 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e30f9>
 632b61a:	nopw   0x0(%rax,%rax,1)
 632b620:	mov    0xb0(%r14),%rsi
 632b627:	lea    -0x59c4496(%rip),%rdi        # 967198 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x53e1298>
 632b62e:	call   *0xa8(%r14)
 632b635:	jmp    632b529 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e30f9>
 632b63a:	nopw   0x0(%rax,%rax,1)
 632b640:	movb   $0x4,(%r12)
 632b645:	lea    0x21(%r12),%rdi
 632b64a:	mov    %r14,%rsi
 632b64d:	call   631db90 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5d5760>
 632b652:	jmp    632b591 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5e3161>
 632b657:	call   63f0d70 <__stack_chk_fail@plt>

hl-node:     file format elf64-x86-64


Disassembly of section .text:

0000000006321680 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5d9250>:
 6321680:	movabs $0xbaaedce6af48a03b,%r11
 632168a:	push   %rbp
 632168b:	mov    %rdi,%r9
 632168e:	mov    %rdx,%rdi
 6321691:	movabs $0xbfd25e8cd0364140,%rbp
 632169b:	push   %rbx
 632169c:	mov    0x18(%rsi),%rax
 63216a0:	bswap  %rax
 63216a3:	mov    %rax,(%r9)
 63216a6:	mov    0x10(%rsi),%r10
 63216aa:	bswap  %r10
 63216ad:	mov    %r10,0x8(%r9)
 63216b1:	mov    0x8(%rsi),%rbx
 63216b5:	mov    %rbx,%r8
 63216b8:	bswap  %r8
 63216bb:	mov    %r8,0x10(%r9)
 63216bf:	mov    (%rsi),%rdx
 63216c2:	cmp    $0xffffffffffffffff,%rdx
 63216c6:	mov    %rdx,%rsi
 63216c9:	setne  %dl
 63216cc:	cmp    $0xfffffffffffffffd,%r8
 63216d0:	bswap  %rsi
 63216d3:	setbe  %cl
 63216d6:	or     %ecx,%edx
 63216d8:	movabs $0xbaaedce6af48a03a,%rcx
 63216e2:	cmp    %r10,%rcx
 63216e5:	setae  %cl
 63216e8:	or     %edx,%ecx
 63216ea:	cmp    %r10,%r11
 63216ed:	movzbl %dl,%edx
 63216f0:	setb   %r11b
 63216f4:	cmp    %rax,%rbp
 63216f7:	movzbl %cl,%ecx
 63216fa:	not    %edx
 63216fc:	setb   %bpl
 6321700:	not    %ecx
 6321702:	or     %ebp,%r11d
 6321705:	movabs $0x402da1732fc9bebf,%rbp
 632170f:	movzbl %r11b,%r11d
 6321713:	and    %r11d,%ecx
 6321716:	xor    %r11d,%r11d
 6321719:	cmp    $0xffffffffffffffff,%rbx
 632171d:	sete   %r11b
 6321721:	and    %r11d,%edx
 6321724:	or     %edx,%ecx
 6321726:	movslq %ecx,%rbx
 6321729:	mov    %rbx,%r11
 632172c:	neg    %r11
 632172f:	and    %r11,%rbp
 6321732:	lea    0x0(%rbp,%rax,1),%rdx
 6321737:	mov    %rdx,(%r9)
 632173a:	xor    %edx,%edx
 632173c:	add    %rbp,%rax
 632173f:	movabs $0x4551231950b75fc4,%rbp
 6321749:	adc    $0x0,%rdx
 632174d:	and    %r11,%rbp
 6321750:	xor    %r11d,%r11d
 6321753:	mov    %rdx,%rax
 6321756:	xor    %edx,%edx
 6321758:	add    %rbp,%r10
 632175b:	adc    $0x0,%r11
 632175f:	add    %r10,%rax
 6321762:	mov    %rbx,%r10
 6321765:	adc    %r11,%rdx
 6321768:	mov    %rbx,%r11
 632176b:	mov    %rax,0x8(%r9)
 632176f:	sar    $0x3f,%r11
 6321773:	mov    %rdx,%rax
 6321776:	xor    %edx,%edx
 6321778:	add    %r8,%r10
 632177b:	adc    $0x0,%r11
 632177f:	add    %r10,%rax
 6321782:	adc    %r11,%rdx
 6321785:	mov    %rax,0x10(%r9)
 6321789:	mov    %rdx,%rax
 632178c:	add    %rsi,%rax
 632178f:	mov    %rax,0x18(%r9)
 6321793:	test   %rdi,%rdi
 6321796:	je     632179a <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x5d936a>
 6321798:	mov    %ecx,(%rdi)
 632179a:	pop    %rbx
 632179b:	pop    %rbp
 632179c:	ret
