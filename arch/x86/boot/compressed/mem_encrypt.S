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

#include <asm/processor-flags.h>
#include <asm/msr.h>
#include <asm/asm-offsets.h>
#include <uapi/asm/kvm_para.h>

	.text
	.code32
ENTRY(sev_enabled)
	xor	%eax, %eax

#ifdef CONFIG_AMD_MEM_ENCRYPT
	push	%ebx
	push	%ecx
	push	%edx

	/* Check if running under a hypervisor */
	movl	$0x40000000, %eax
	cpuid
	cmpl	$0x40000001, %eax
	jb	.Lno_sev

	movl	$0x40000001, %eax
	cpuid
	bt	$KVM_FEATURE_SEV, %eax
	jnc	.Lno_sev

	/*
	 * Check for memory encryption feature:
	 *   CPUID Fn8000_001F[EAX] - Bit 0
	 */
	movl	$0x8000001f, %eax
	cpuid
	bt	$0, %eax
	jnc	.Lno_sev

	/*
	 * Get memory encryption information:
	 *   CPUID Fn8000_001F[EBX] - Bits 5:0
	 *     Pagetable bit position used to indicate encryption
	 */
	movl	%ebx, %eax
	andl	$0x3f, %eax
	movl	%eax, sev_enc_bit(%ebp)
	jmp	.Lsev_exit

.Lno_sev:
	xor	%eax, %eax

.Lsev_exit:
	pop	%edx
	pop	%ecx
	pop	%ebx

#endif	/* CONFIG_AMD_MEM_ENCRYPT */

	ret
ENDPROC(sev_enabled)

	.bss
sev_enc_bit:
	.word	0
