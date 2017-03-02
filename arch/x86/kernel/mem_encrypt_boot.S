/*
 * AMD Memory Encryption Support
 *
 * Copyright (C) 2016 Advanced Micro Devices, Inc.
 *
 * Author: Tom Lendacky <thomas.lendacky@amd.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/linkage.h>
#include <asm/pgtable.h>
#include <asm/page.h>
#include <asm/processor-flags.h>
#include <asm/msr-index.h>

	.text
	.code64
ENTRY(sme_encrypt_execute)

#ifdef CONFIG_AMD_MEM_ENCRYPT
	/*
	 * Entry parameters:
	 *   RDI - virtual address for the encrypted kernel mapping
	 *   RSI - virtual address for the decrypted kernel mapping
	 *   RDX - length of kernel
	 *   RCX - address of the encryption workarea
	 *     - stack page (PAGE_SIZE)
	 *     - encryption routine page (PAGE_SIZE)
	 *     - intermediate copy buffer (PMD_PAGE_SIZE)
	 *    R8 - address of the pagetables to use for encryption
	 */

	/* Set up a one page stack in the non-encrypted memory area */
	movq	%rcx, %rax
	addq	$PAGE_SIZE, %rax
	movq	%rsp, %rbp
	movq	%rax, %rsp
	push	%rbp

	push	%r12
	push	%r13

	movq	%rdi, %r10
	movq	%rsi, %r11
	movq	%rdx, %r12
	movq	%rcx, %r13

	/* Copy encryption routine into the workarea */
	movq	%rax, %rdi
	leaq	.Lencrypt_start(%rip), %rsi
	movq	$(.Lencrypt_stop - .Lencrypt_start), %rcx
	rep	movsb

	/* Setup registers for call */
	movq	%r10, %rdi
	movq	%r11, %rsi
	movq	%r8, %rdx
	movq	%r12, %rcx
	movq	%rax, %r8
	addq	$PAGE_SIZE, %r8

	/* Call the encryption routine */
	call	*%rax

	pop	%r13
	pop	%r12

	pop	%rsp			/* Restore original stack pointer */
.Lencrypt_exit:
#endif	/* CONFIG_AMD_MEM_ENCRYPT */

	ret
ENDPROC(sme_encrypt_execute)

#ifdef CONFIG_AMD_MEM_ENCRYPT
/*
 * Routine used to encrypt kernel.
 *   This routine must be run outside of the kernel proper since
 *   the kernel will be encrypted during the process. So this
 *   routine is defined here and then copied to an area outside
 *   of the kernel where it will remain and run decrypted
 *   during execution.
 *
 *   On entry the registers must be:
 *     RDI - virtual address for the encrypted kernel mapping
 *     RSI - virtual address for the decrypted kernel mapping
 *     RDX - address of the pagetables to use for encryption
 *     RCX - length of kernel
 *      R8 - intermediate copy buffer
 *
 *     RAX - points to this routine
 *
 * The kernel will be encrypted by copying from the non-encrypted
 * kernel space to an intermediate buffer and then copying from the
 * intermediate buffer back to the encrypted kernel space. The physical
 * addresses of the two kernel space mappings are the same which
 * results in the kernel being encrypted "in place".
 */
.Lencrypt_start:
	/* Enable the new page tables */
	mov	%rdx, %cr3

	/* Flush any global TLBs */
	mov	%cr4, %rdx
	andq	$~X86_CR4_PGE, %rdx
	mov	%rdx, %cr4
	orq	$X86_CR4_PGE, %rdx
	mov	%rdx, %cr4

	/* Set the PAT register PA5 entry to write-protect */
	push	%rcx
	movl	$MSR_IA32_CR_PAT, %ecx
	rdmsr
	push	%rdx			/* Save original PAT value */
	andl	$0xffff00ff, %edx	/* Clear PA5 */
	orl	$0x00000500, %edx	/* Set PA5 to WP */
	wrmsr
	pop	%rdx			/* RDX contains original PAT value */
	pop	%rcx

	movq	%rcx, %r9		/* Save length */
	movq	%rdi, %r10		/* Save destination address */
	movq	%rsi, %r11		/* Save source address */

	wbinvd				/* Invalidate any cache entries */

	/* Copy/encrypt 2MB at a time */
1:
	movq	%r11, %rsi
	movq	%r8, %rdi
	movq	$PMD_PAGE_SIZE, %rcx
	rep	movsb

	movq	%r8, %rsi
	movq	%r10, %rdi
	movq	$PMD_PAGE_SIZE, %rcx
	rep	movsb

	addq	$PMD_PAGE_SIZE, %r11
	addq	$PMD_PAGE_SIZE, %r10
	subq	$PMD_PAGE_SIZE, %r9
	jnz	1b

	/* Restore PAT register */
	push	%rdx
	movl	$MSR_IA32_CR_PAT, %ecx
	rdmsr
	pop	%rdx
	wrmsr

	ret
.Lencrypt_stop:
#endif	/* CONFIG_AMD_MEM_ENCRYPT */
