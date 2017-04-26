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

#include <linux/mm.h>
#include <linux/dma-mapping.h>
#include <linux/swiotlb.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>

#include <asm/tlbflush.h>
#include <asm/fixmap.h>
#include <asm/setup.h>
#include <asm/bootparam.h>
#include <asm/cacheflush.h>
#include <asm/sections.h>
#include <asm/mem_encrypt.h>

/*
 * Since SME related variables are set early in the boot process they must
 * reside in the .data section so as not to be zeroed out when the .bss
 * section is later cleared.
 */
unsigned long sme_me_mask __section(.data) = 0;
EXPORT_SYMBOL_GPL(sme_me_mask);

/* Buffer used for early in-place encryption by BSP, no locking needed */
static char sme_early_buffer[PAGE_SIZE] __aligned(PAGE_SIZE);

/*
 * Sysfs support for SME.
 *   Create an sme directory under /sys/kernel/mm
 *   Create two sme entries under /sys/kernel/mm/sme:
 *     active - returns 0 if not active, 1 if active
 *     encryption_mask - returns the encryption mask in use
 */
static ssize_t active_show(struct kobject *kobj, struct kobj_attribute *attr,
			   char *buf)
{
	return sprintf(buf, "%u\n", sme_active());
}
static struct kobj_attribute active_attr = __ATTR_RO(active);

static ssize_t encryption_mask_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "0x%016lx\n", sme_me_mask);
}
static struct kobj_attribute encryption_mask_attr = __ATTR_RO(encryption_mask);

static struct attribute *sme_attrs[] = {
	&active_attr.attr,
	&encryption_mask_attr.attr,
	NULL
};

static struct attribute_group sme_attr_group = {
	.attrs = sme_attrs,
	.name = "sme",
};

static int __init sme_sysfs_init(void)
{
	int ret;

	ret = sysfs_create_group(mm_kobj, &sme_attr_group);
	if (ret) {
		pr_err("SME sysfs initialization failed\n");
		return ret;
	}

	return 0;
}
subsys_initcall(sme_sysfs_init);

/*
 * This routine does not change the underlying encryption setting of the
 * page(s) that map this memory. It assumes that eventually the memory is
 * meant to be accessed as either encrypted or decrypted but the contents
 * are currently not in the desired state.
 *
 * This routine follows the steps outlined in the AMD64 Architecture
 * Programmer's Manual Volume 2, Section 7.10.8 Encrypt-in-Place.
 */
static void __init __sme_early_enc_dec(resource_size_t paddr,
				       unsigned long size, bool enc)
{
	void *src, *dst;
	size_t len;

	if (!sme_me_mask)
		return;

	local_flush_tlb();
	wbinvd();

	/*
	 * There are limited number of early mapping slots, so map (at most)
	 * one page at time.
	 */
	while (size) {
		len = min_t(size_t, sizeof(sme_early_buffer), size);

		/*
		 * Create mappings for the current and desired format of
		 * the memory. Use a write-protected mapping for the source.
		 */
		src = enc ? early_memremap_decrypted_wp(paddr, len) :
			    early_memremap_encrypted_wp(paddr, len);

		dst = enc ? early_memremap_encrypted(paddr, len) :
			    early_memremap_decrypted(paddr, len);

		/*
		 * If a mapping can't be obtained to perform the operation,
		 * then eventual access of that area in the desired mode
		 * will cause a crash.
		 */
		BUG_ON(!src || !dst);

		/*
		 * Use a temporary buffer, of cache-line multiple size, to
		 * avoid data corruption as documented in the APM.
		 */
		memcpy(sme_early_buffer, src, len);
		memcpy(dst, sme_early_buffer, len);

		early_memunmap(dst, len);
		early_memunmap(src, len);

		paddr += len;
		size -= len;
	}
}

void __init sme_early_encrypt(resource_size_t paddr, unsigned long size)
{
	__sme_early_enc_dec(paddr, size, true);
}

void __init sme_early_decrypt(resource_size_t paddr, unsigned long size)
{
	__sme_early_enc_dec(paddr, size, false);
}

static void __init sme_early_pgtable_flush(void)
{
	write_cr3(__sme_pa_nodebug(early_level4_pgt));
}

static void __init __sme_early_map_unmap_mem(void *vaddr, unsigned long size,
					     bool map)
{
	unsigned long paddr = (unsigned long)vaddr - __PAGE_OFFSET;
	pmdval_t pmd_flags, pmd;

	/* Use early_pmd_flags but remove the encryption mask */
	pmd_flags = __sme_clr(early_pmd_flags);

	do {
		pmd = map ? (paddr & PMD_MASK) + pmd_flags : 0;
		__early_make_pgtable((unsigned long)vaddr, pmd);

		vaddr += PMD_SIZE;
		paddr += PMD_SIZE;
		size = (size <= PMD_SIZE) ? 0 : size - PMD_SIZE;
	} while (size);
}

static void __init __sme_map_unmap_bootdata(char *real_mode_data, bool map)
{
	struct boot_params *boot_data;
	unsigned long cmdline_paddr;

	__sme_early_map_unmap_mem(real_mode_data, sizeof(boot_params), map);
	boot_data = (struct boot_params *)real_mode_data;

	/*
	 * Determine the command line address only after having established
	 * the decrypted mapping.
	 */
	cmdline_paddr = boot_data->hdr.cmd_line_ptr |
			((u64)boot_data->ext_cmd_line_ptr << 32);

	if (cmdline_paddr)
		__sme_early_map_unmap_mem(__va(cmdline_paddr),
					  COMMAND_LINE_SIZE, map);
}

void __init sme_unmap_bootdata(char *real_mode_data)
{
	/* If SME is not active, the bootdata is in the correct state */
	if (!sme_active())
		return;

	/*
	 * The bootdata and command line aren't needed anymore so clear
	 * any mapping of them.
	 */
	__sme_map_unmap_bootdata(real_mode_data, false);

	sme_early_pgtable_flush();
}

void __init sme_map_bootdata(char *real_mode_data)
{
	/* If SME is not active, the bootdata is in the correct state */
	if (!sme_active())
		return;

	/*
	 * The bootdata and command line will not be encrypted, so they
	 * need to be mapped as decrypted memory so they can be copied
	 * properly.
	 */
	__sme_map_unmap_bootdata(real_mode_data, true);

	sme_early_pgtable_flush();
}

void __init sme_early_init(void)
{
	unsigned int i;

	if (!sme_me_mask)
		return;

	early_pmd_flags = __sme_set(early_pmd_flags);

	__supported_pte_mask = __sme_set(__supported_pte_mask);

	/* Update the protection map with memory encryption mask */
	for (i = 0; i < ARRAY_SIZE(protection_map); i++)
		protection_map[i] = pgprot_encrypted(protection_map[i]);
}

/* Architecture __weak replacement functions */
void __init mem_encrypt_init(void)
{
	if (!sme_me_mask)
		return;

	/* Call into SWIOTLB to update the SWIOTLB DMA buffers */
	swiotlb_update_mem_attributes();
}

void swiotlb_set_mem_attributes(void *vaddr, unsigned long size)
{
	WARN(PAGE_ALIGN(size) != size,
	     "size is not page-aligned (%#lx)\n", size);

	/* Make the SWIOTLB buffer area decrypted */
	set_memory_decrypted((unsigned long)vaddr, size >> PAGE_SHIFT);
}

void __init sme_clear_pgd(pgd_t *pgd_base, unsigned long start,
			  unsigned long end)
{
	unsigned long addr = start;
	pgdval_t *pgd_p;

	while (addr < end) {
		unsigned long pgd_end;

		pgd_end = (addr & PGDIR_MASK) + PGDIR_SIZE;
		if (pgd_end > end)
			pgd_end = end;

		pgd_p = (pgdval_t *)pgd_base + pgd_index(addr);
		*pgd_p = 0;

		addr = pgd_end;
	}
}

#define PGD_FLAGS	_KERNPG_TABLE_NOENC
#define PUD_FLAGS	_KERNPG_TABLE_NOENC
#define PMD_FLAGS	(__PAGE_KERNEL_LARGE_EXEC & ~_PAGE_GLOBAL)

static void __init *sme_populate_pgd(pgd_t *pgd_base, void *pgtable_area,
				     unsigned long vaddr, pmdval_t pmd_val)
{
	pgdval_t pgd, *pgd_p;
	pudval_t pud, *pud_p;
	pmdval_t pmd, *pmd_p;

	pgd_p = (pgdval_t *)pgd_base + pgd_index(vaddr);
	pgd = *pgd_p;
	if (pgd) {
		pud_p = (pudval_t *)(pgd & ~PTE_FLAGS_MASK);
	} else {
		pud_p = pgtable_area;
		memset(pud_p, 0, sizeof(*pud_p) * PTRS_PER_PUD);
		pgtable_area += sizeof(*pud_p) * PTRS_PER_PUD;

		*pgd_p = (pgdval_t)pud_p + PGD_FLAGS;
	}

	pud_p += pud_index(vaddr);
	pud = *pud_p;
	if (pud) {
		if (pud & _PAGE_PSE)
			goto out;

		pmd_p = (pmdval_t *)(pud & ~PTE_FLAGS_MASK);
	} else {
		pmd_p = pgtable_area;
		memset(pmd_p, 0, sizeof(*pmd_p) * PTRS_PER_PMD);
		pgtable_area += sizeof(*pmd_p) * PTRS_PER_PMD;

		*pud_p = (pudval_t)pmd_p + PUD_FLAGS;
	}

	pmd_p += pmd_index(vaddr);
	pmd = *pmd_p;
	if (!pmd || !(pmd & _PAGE_PSE))
		*pmd_p = pmd_val;

out:
	return pgtable_area;
}

static unsigned long __init sme_pgtable_calc(unsigned long len)
{
	unsigned long pud_tables, pmd_tables;
	unsigned long total = 0;

	/*
	 * Perform a relatively simplistic calculation of the pagetable
	 * entries that are needed. That mappings will be covered by 2MB
	 * PMD entries so we can conservatively calculate the required
	 * number of PUD and PMD structures needed to perform the mappings.
	 * Incrementing the count for each covers the case where the
	 * addresses cross entries.
	 */
	pud_tables = ALIGN(len, PGDIR_SIZE) / PGDIR_SIZE;
	pud_tables++;
	pmd_tables = ALIGN(len, PUD_SIZE) / PUD_SIZE;
	pmd_tables++;

	total += pud_tables * sizeof(pud_t) * PTRS_PER_PUD;
	total += pmd_tables * sizeof(pmd_t) * PTRS_PER_PMD;

	/*
	 * Now calculate the added pagetable structures needed to populate
	 * the new pagetables.
	 */
	pud_tables = ALIGN(total, PGDIR_SIZE) / PGDIR_SIZE;
	pmd_tables = ALIGN(total, PUD_SIZE) / PUD_SIZE;

	total += pud_tables * sizeof(pud_t) * PTRS_PER_PUD;
	total += pmd_tables * sizeof(pmd_t) * PTRS_PER_PMD;

	return total;
}

void __init sme_encrypt_kernel(void)
{
	pgd_t *pgd;
	void *pgtable_area;
	unsigned long kernel_start, kernel_end, kernel_len;
	unsigned long workarea_start, workarea_end, workarea_len;
	unsigned long execute_start, execute_end, execute_len;
	unsigned long pgtable_area_len;
	unsigned long decrypted_base;
	unsigned long paddr, pmd_flags;

	if (!sme_active())
		return;

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

	/* Physical addresses gives us the identity mapped virtual addresses */
	kernel_start = __pa_symbol(_text);
	kernel_end = ALIGN(__pa_symbol(_end), PMD_PAGE_SIZE);
	kernel_len = kernel_end - kernel_start;

	/* Set the encryption workarea to be immediately after the kernel */
	workarea_start = kernel_end;

	/*
	 * Calculate required number of workarea bytes needed:
	 *   executable encryption area size:
	 *     stack page (PAGE_SIZE)
	 *     encryption routine page (PAGE_SIZE)
	 *     intermediate copy buffer (PMD_PAGE_SIZE)
	 *   pagetable structures for the encryption of the kernel
	 *   pagetable structures for workarea (in case not currently mapped)
	 */
	execute_start = workarea_start;
	execute_end = execute_start + (PAGE_SIZE * 2) + PMD_PAGE_SIZE;
	execute_len = execute_end - execute_start;

	/*
	 * One PGD for both encrypted and decrypted mappings and a set of
	 * PUDs and PMDs for each of the encrypted and decrypted mappings.
	 */
	pgtable_area_len = sizeof(pgd_t) * PTRS_PER_PGD;
	pgtable_area_len += sme_pgtable_calc(execute_end - kernel_start) * 2;

	/* PUDs and PMDs needed in the current pagetables for the workarea */
	pgtable_area_len += sme_pgtable_calc(execute_len + pgtable_area_len);

	/*
	 * The total workarea includes the executable encryption area and
	 * the pagetable area.
	 */
	workarea_len = execute_len + pgtable_area_len;
	workarea_end = workarea_start + workarea_len;

	/*
	 * Set the address to the start of where newly created pagetable
	 * structures (PGDs, PUDs and PMDs) will be allocated. New pagetable
	 * structures are created when the workarea is added to the current
	 * pagetables and when the new encrypted and decrypted kernel
	 * mappings are populated.
	 */
	pgtable_area = (void *)execute_end;

	/*
	 * Make sure the current pagetable structure has entries for
	 * addressing the workarea.
	 */
	pgd = (pgd_t *)native_read_cr3();
	paddr = workarea_start;
	while (paddr < workarea_end) {
		pgtable_area = sme_populate_pgd(pgd, pgtable_area,
						paddr,
						paddr + PMD_FLAGS);

		paddr += PMD_PAGE_SIZE;
	}
	native_write_cr3((unsigned long)pgd);

	/*
	 * A new pagetable structure is being built to allow for the kernel
	 * to be encrypted. It starts with an empty PGD that will then be
	 * populated with new PUDs and PMDs as the encrypted and decrypted
	 * kernel mappings are created.
	 */
	pgd = pgtable_area;
	memset(pgd, 0, sizeof(*pgd) * PTRS_PER_PGD);
	pgtable_area += sizeof(*pgd) * PTRS_PER_PGD;

	/* Add encrypted kernel (identity) mappings */
	pmd_flags = PMD_FLAGS | _PAGE_ENC;
	paddr = kernel_start;
	while (paddr < kernel_end) {
		pgtable_area = sme_populate_pgd(pgd, pgtable_area,
						paddr,
						paddr + pmd_flags);

		paddr += PMD_PAGE_SIZE;
	}

	/*
	 * A different PGD index/entry must be used to get different
	 * pagetable entries for the decrypted mapping. Choose the next
	 * PGD index and convert it to a virtual address to be used as
	 * the base of the mapping.
	 */
	decrypted_base = (pgd_index(workarea_end) + 1) & (PTRS_PER_PGD - 1);
	decrypted_base <<= PGDIR_SHIFT;

	/* Add decrypted, write-protected kernel (non-identity) mappings */
	pmd_flags = (PMD_FLAGS & ~_PAGE_CACHE_MASK) | (_PAGE_PAT | _PAGE_PWT);
	paddr = kernel_start;
	while (paddr < kernel_end) {
		pgtable_area = sme_populate_pgd(pgd, pgtable_area,
						paddr + decrypted_base,
						paddr + pmd_flags);

		paddr += PMD_PAGE_SIZE;
	}

	/* Add decrypted workarea mappings to both kernel mappings */
	paddr = workarea_start;
	while (paddr < workarea_end) {
		pgtable_area = sme_populate_pgd(pgd, pgtable_area,
						paddr,
						paddr + PMD_FLAGS);

		pgtable_area = sme_populate_pgd(pgd, pgtable_area,
						paddr + decrypted_base,
						paddr + PMD_FLAGS);

		paddr += PMD_PAGE_SIZE;
	}

	/* Perform the encryption */
	sme_encrypt_execute(kernel_start, kernel_start + decrypted_base,
			    kernel_len, workarea_start, (unsigned long)pgd);

	/*
	 * At this point we are running encrypted.  Remove the mappings for
	 * the decrypted areas - all that is needed for this is to remove
	 * the PGD entry/entries.
	 */
	sme_clear_pgd(pgd, kernel_start + decrypted_base,
		      kernel_end + decrypted_base);

	sme_clear_pgd(pgd, workarea_start + decrypted_base,
		      workarea_end + decrypted_base);

	/* Flush the TLB - no globals so cr3 is enough */
	native_write_cr3(native_read_cr3());
}

unsigned long __init sme_enable(void)
{
	return sme_me_mask;
}

unsigned long sme_get_me_mask(void)
{
	return sme_me_mask;
}

#else	/* !CONFIG_AMD_MEM_ENCRYPT */

void __init sme_encrypt_kernel(void)	{ }
unsigned long __init sme_enable(void)	{ return 0; }

unsigned long sme_get_me_mask(void)	{ return 0; }

#endif	/* CONFIG_AMD_MEM_ENCRYPT */
