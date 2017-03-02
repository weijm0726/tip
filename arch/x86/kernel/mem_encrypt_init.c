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
#include <linux/init.h>

#ifdef CONFIG_AMD_MEM_ENCRYPT

#include <linux/mem_encrypt.h>
#include <linux/mm.h>

#include <asm/sections.h>
#include <asm/processor-flags.h>
#include <asm/msr.h>
#include <asm/cmdline.h>

static char sme_cmdline_arg_on[] __initdata = "mem_encrypt=on";
static char sme_cmdline_arg_off[] __initdata = "mem_encrypt=off";

extern void sme_encrypt_execute(unsigned long, unsigned long, unsigned long,
				void *, pgd_t *);

#define PGD_FLAGS	_KERNPG_TABLE_NOENC
#define PUD_FLAGS	_KERNPG_TABLE_NOENC
#define PMD_FLAGS	__PAGE_KERNEL_LARGE_EXEC

static void __init *sme_pgtable_entry(pgd_t *pgd, void *next_page,
				      void *vaddr, pmdval_t pmd_val)
{
	pud_t *pud;
	pmd_t *pmd;

	pgd += pgd_index((unsigned long)vaddr);
	if (pgd_none(*pgd)) {
		pud = next_page;
		memset(pud, 0, sizeof(*pud) * PTRS_PER_PUD);
		native_set_pgd(pgd,
			       native_make_pgd((unsigned long)pud + PGD_FLAGS));
		next_page += sizeof(*pud) * PTRS_PER_PUD;
	} else {
		pud = (pud_t *)(native_pgd_val(*pgd) & ~PTE_FLAGS_MASK);
	}

	pud += pud_index((unsigned long)vaddr);
	if (pud_none(*pud)) {
		pmd = next_page;
		memset(pmd, 0, sizeof(*pmd) * PTRS_PER_PMD);
		native_set_pud(pud,
			       native_make_pud((unsigned long)pmd + PUD_FLAGS));
		next_page += sizeof(*pmd) * PTRS_PER_PMD;
	} else {
		pmd = (pmd_t *)(native_pud_val(*pud) & ~PTE_FLAGS_MASK);
	}

	pmd += pmd_index((unsigned long)vaddr);
	if (pmd_none(*pmd) || !pmd_large(*pmd))
		native_set_pmd(pmd, native_make_pmd(pmd_val));

	return next_page;
}

static unsigned long __init sme_pgtable_calc(unsigned long start,
					     unsigned long end)
{
	unsigned long addr, total;

	total = 0;
	addr = start;
	while (addr < end) {
		unsigned long pgd_end;

		pgd_end = (addr & PGDIR_MASK) + PGDIR_SIZE;
		if (pgd_end > end)
			pgd_end = end;

		total += sizeof(pud_t) * PTRS_PER_PUD * 2;

		while (addr < pgd_end) {
			unsigned long pud_end;

			pud_end = (addr & PUD_MASK) + PUD_SIZE;
			if (pud_end > end)
				pud_end = end;

			total += sizeof(pmd_t) * PTRS_PER_PMD * 2;

			addr = pud_end;
		}

		addr = pgd_end;
	}
	total += sizeof(pgd_t) * PTRS_PER_PGD;

	return total;
}

void __init sme_encrypt_kernel(void)
{
	pgd_t *pgd;
	void *workarea, *next_page, *vaddr;
	unsigned long kern_start, kern_end, kern_len;
	unsigned long index, paddr, pmd_flags;
	unsigned long exec_size, full_size;

	/* If SME is not active then no need to prepare */
	if (!sme_active())
		return;

	/* Set the workarea to be after the kernel */
	workarea = (void *)ALIGN(__pa_symbol(_end), PMD_PAGE_SIZE);

	/*
	 * Prepare for encrypting the kernel by building new pagetables with
	 * the necessary attributes needed to encrypt the kernel in place.
	 *
	 *   One range of virtual addresses will map the memory occupied
	 *   by the kernel as encrypted.
	 *
	 *   Another range of virtual addresses will map the memory occupied
	 *   by the kernel as decrypted and write-protected.
	 *
	 *     The use of write-protect attribute will prevent any of the
	 *     memory from being cached.
	 */

	/* Physical address gives us the identity mapped virtual address */
	kern_start = __pa_symbol(_text);
	kern_end = ALIGN(__pa_symbol(_end), PMD_PAGE_SIZE) - 1;
	kern_len = kern_end - kern_start + 1;

	/*
	 * Calculate required number of workarea bytes needed:
	 *   executable encryption area size:
	 *     stack page (PAGE_SIZE)
	 *     encryption routine page (PAGE_SIZE)
	 *     intermediate copy buffer (PMD_PAGE_SIZE)
	 *   pagetable structures for workarea (in case not currently mapped)
	 *   pagetable structures for the encryption of the kernel
	 */
	exec_size = (PAGE_SIZE * 2) + PMD_PAGE_SIZE;

	full_size = exec_size;
	full_size += ALIGN(exec_size, PMD_PAGE_SIZE) / PMD_PAGE_SIZE *
		     sizeof(pmd_t) * PTRS_PER_PMD;
	full_size += sme_pgtable_calc(kern_start, kern_end + exec_size);

	next_page = workarea + exec_size;

	/* Make sure the current pagetables have entries for the workarea */
	pgd = (pgd_t *)native_read_cr3();
	paddr = (unsigned long)workarea;
	while (paddr < (unsigned long)workarea + full_size) {
		vaddr = (void *)paddr;
		next_page = sme_pgtable_entry(pgd, next_page, vaddr,
					      paddr + PMD_FLAGS);

		paddr += PMD_PAGE_SIZE;
	}
	native_write_cr3(native_read_cr3());

	/* Calculate a PGD index to be used for the decrypted mapping */
	index = (pgd_index(kern_end + full_size) + 1) & (PTRS_PER_PGD - 1);
	index <<= PGDIR_SHIFT;

	/* Set and clear the PGD */
	pgd = next_page;
	memset(pgd, 0, sizeof(*pgd) * PTRS_PER_PGD);
	next_page += sizeof(*pgd) * PTRS_PER_PGD;

	/* Add encrypted (identity) mappings for the kernel */
	pmd_flags = PMD_FLAGS | _PAGE_ENC;
	paddr = kern_start;
	while (paddr < kern_end) {
		vaddr = (void *)paddr;
		next_page = sme_pgtable_entry(pgd, next_page, vaddr,
					      paddr + pmd_flags);

		paddr += PMD_PAGE_SIZE;
	}

	/* Add decrypted (non-identity) mappings for the kernel */
	pmd_flags = (PMD_FLAGS & ~_PAGE_CACHE_MASK) | (_PAGE_PAT | _PAGE_PWT);
	paddr = kern_start;
	while (paddr < kern_end) {
		vaddr = (void *)(paddr + index);
		next_page = sme_pgtable_entry(pgd, next_page, vaddr,
					      paddr + pmd_flags);

		paddr += PMD_PAGE_SIZE;
	}

	/* Add the workarea to both mappings */
	paddr = kern_end + 1;
	while (paddr < (kern_end + exec_size)) {
		vaddr = (void *)paddr;
		next_page = sme_pgtable_entry(pgd, next_page, vaddr,
					      paddr + PMD_FLAGS);

		vaddr = (void *)(paddr + index);
		next_page = sme_pgtable_entry(pgd, next_page, vaddr,
					      paddr + PMD_FLAGS);

		paddr += PMD_PAGE_SIZE;
	}

	/* Perform the encryption */
	sme_encrypt_execute(kern_start, kern_start + index, kern_len,
			    workarea, pgd);

}

unsigned long __init sme_get_me_mask(void)
{
	return sme_me_mask;
}

unsigned long __init sme_enable(void *boot_data)
{
	struct boot_params *bp = boot_data;
	unsigned int eax, ebx, ecx, edx;
	unsigned long cmdline_ptr;
	bool enable_if_found;
	void *cmdline_arg;
	u64 msr;

	/* Check for an AMD processor */
	eax = 0;
	ecx = 0;
	native_cpuid(&eax, &ebx, &ecx, &edx);
	if ((ebx != 0x68747541) || (edx != 0x69746e65) || (ecx != 0x444d4163))
		goto out;

	/* Check for the SME support leaf */
	eax = 0x80000000;
	ecx = 0;
	native_cpuid(&eax, &ebx, &ecx, &edx);
	if (eax < 0x8000001f)
		goto out;

	/*
	 * Check for the SME feature:
	 *   CPUID Fn8000_001F[EAX] - Bit 0
	 *     Secure Memory Encryption support
	 *   CPUID Fn8000_001F[EBX] - Bits 5:0
	 *     Pagetable bit position used to indicate encryption
	 */
	eax = 0x8000001f;
	ecx = 0;
	native_cpuid(&eax, &ebx, &ecx, &edx);
	if (!(eax & 1))
		goto out;

	/* Check if SME is enabled */
	msr = native_read_msr(MSR_K8_SYSCFG);
	if (!(msr & MSR_K8_SYSCFG_MEM_ENCRYPT))
		goto out;

	/*
	 * Fixups have not been to applied phys_base yet, so we must obtain
	 * the address to the SME command line option in the following way.
	 */
	if (IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT_ACTIVE_BY_DEFAULT)) {
		asm ("lea sme_cmdline_arg_off(%%rip), %0"
		     : "=r" (cmdline_arg)
		     : "p" (sme_cmdline_arg_off));
		enable_if_found = false;
	} else {
		asm ("lea sme_cmdline_arg_on(%%rip), %0"
		     : "=r" (cmdline_arg)
		     : "p" (sme_cmdline_arg_on));
		enable_if_found = true;
	}

	cmdline_ptr = bp->hdr.cmd_line_ptr | ((u64)bp->ext_cmd_line_ptr << 32);

	if (cmdline_find_option_bool((char *)cmdline_ptr, cmdline_arg))
		sme_me_mask = enable_if_found ? 1UL << (ebx & 0x3f) : 0;
	else
		sme_me_mask = enable_if_found ? 0 : 1UL << (ebx & 0x3f);

out:
	return sme_me_mask;
}

#else	/* !CONFIG_AMD_MEM_ENCRYPT */

void __init sme_encrypt_kernel(void)
{
}

unsigned long __init sme_get_me_mask(void)
{
	return 0;
}

unsigned long __init sme_enable(void)
{
	return 0;
}

#endif	/* CONFIG_AMD_MEM_ENCRYPT */
