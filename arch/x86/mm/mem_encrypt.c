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
#include <linux/mm.h>
#include <linux/dma-mapping.h>
#include <linux/swiotlb.h>
#include <linux/mem_encrypt.h>

#include <asm/tlbflush.h>
#include <asm/fixmap.h>
#include <asm/setup.h>
#include <asm/bootparam.h>
#include <asm/cacheflush.h>

extern pmdval_t early_pmd_flags;
int __init __early_make_pgtable(unsigned long, pmdval_t);
void __init __early_pgtable_flush(void);

/*
 * Since SME related variables are set early in the boot process they must
 * reside in the .data section so as not to be zeroed out when the .bss
 * section is later cleared.
 */
unsigned long sme_me_mask __section(.data) = 0;
EXPORT_SYMBOL_GPL(sme_me_mask);

unsigned int sev_enabled __section(.data) = 0;
EXPORT_SYMBOL_GPL(sev_enabled);

/* Buffer used for early in-place encryption by BSP, no locking needed */
static char sme_early_buffer[PAGE_SIZE] __aligned(PAGE_SIZE);

/*
 * This routine does not change the underlying encryption setting of the
 * page(s) that map this memory. It assumes that eventually the memory is
 * meant to be accessed as either encrypted or decrypted but the contents
 * are currently not in the desired stated.
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
		 * Create write protected mappings for the current format
		 * of the memory.
		 */
		src = enc ? early_memremap_decrypted_wp(paddr, len) :
			    early_memremap_encrypted_wp(paddr, len);

		/*
		 * Create mappings for the desired format of the memory.
		 */
		dst = enc ? early_memremap_encrypted(paddr, len) :
			    early_memremap_decrypted(paddr, len);

		/*
		 * If a mapping can't be obtained to perform the operation,
		 * then eventual access of that area will in the desired
		 * mode will cause a crash.
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

static void __init __sme_early_map_unmap_mem(void *vaddr, unsigned long size,
					     bool map)
{
	unsigned long paddr = (unsigned long)vaddr - __PAGE_OFFSET;
	pmdval_t pmd_flags, pmd;

	/* Use early_pmd_flags but remove the encryption mask */
	pmd_flags = early_pmd_flags & ~sme_me_mask;

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

	__early_pgtable_flush();
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

	__early_pgtable_flush();
}

void __init sme_early_init(void)
{
	unsigned int i;

	if (!sme_me_mask)
		return;

	early_pmd_flags |= sme_me_mask;

	__supported_pte_mask |= sme_me_mask;

	/* Update the protection map with memory encryption mask */
	for (i = 0; i < ARRAY_SIZE(protection_map); i++)
		protection_map[i] = pgprot_encrypted(protection_map[i]);

	if (sev_active())
		swiotlb_force = SWIOTLB_FORCE;
}

static void *sme_alloc(struct device *dev, size_t size, dma_addr_t *dma_handle,
		       gfp_t gfp, unsigned long attrs)
{
	unsigned long dma_mask;
	unsigned int order;
	struct page *page;
	void *vaddr = NULL;

	dma_mask = dma_alloc_coherent_mask(dev, gfp);
	order = get_order(size);

	gfp &= ~__GFP_ZERO;

	page = alloc_pages_node(dev_to_node(dev), gfp, order);
	if (page) {
		dma_addr_t addr;

		/*
		 * Since we will be clearing the encryption bit, check the
		 * mask with it already cleared.
		 */
		addr = phys_to_dma(dev, page_to_phys(page)) & ~sme_me_mask;
		if ((addr + size) > dma_mask) {
			__free_pages(page, get_order(size));
		} else {
			vaddr = page_address(page);
			*dma_handle = addr;
		}
	}

	if (!vaddr)
		vaddr = swiotlb_alloc_coherent(dev, size, dma_handle, gfp);

	if (!vaddr)
		return NULL;

	/* Clear the SME encryption bit for DMA use if not swiotlb area */
	if (!is_swiotlb_buffer(dma_to_phys(dev, *dma_handle))) {
		set_memory_decrypted((unsigned long)vaddr, 1 << order);
		*dma_handle &= ~sme_me_mask;
	}

	return vaddr;
}

static void sme_free(struct device *dev, size_t size, void *vaddr,
		     dma_addr_t dma_handle, unsigned long attrs)
{
	/* Set the SME encryption bit for re-use if not swiotlb area */
	if (!is_swiotlb_buffer(dma_to_phys(dev, dma_handle)))
		set_memory_encrypted((unsigned long)vaddr,
				     1 << get_order(size));

	swiotlb_free_coherent(dev, size, vaddr, dma_handle);
}

static unsigned long __init get_pte_flags(unsigned long address)
{
	int level;
	pte_t *pte;
	unsigned long flags = _KERNPG_TABLE_NOENC | _PAGE_ENC;

	pte = lookup_address(address, &level);
	if (!pte)
		return flags;

	switch (level) {
	case PG_LEVEL_4K:
		flags = pte_flags(*pte);
		break;
	case PG_LEVEL_2M:
		flags = pmd_flags(*(pmd_t *)pte);
		break;
	case PG_LEVEL_1G:
		flags = pud_flags(*(pud_t *)pte);
		break;
	default:
		break;
	}

	return flags;
}

int __init early_set_memory_enc_dec(void *vaddr, unsigned long size,
				    unsigned long flags)
{
	unsigned long pfn, npages;
	unsigned long addr = (unsigned long)vaddr & PAGE_MASK;

	/* We are going to change the physical page attribute from C=1 to C=0.
	 * Flush the caches to ensure that all the data with C=1 is flushed to
	 * memory. Any caching of the vaddr after function returns will
	 * use C=0.
	 */
	clflush_cache_range(vaddr, size);

	npages = PAGE_ALIGN(size) >> PAGE_SHIFT;
	pfn = slow_virt_to_phys((void *)addr) >> PAGE_SHIFT;

	return kernel_map_pages_in_pgd(init_mm.pgd, pfn, addr, npages,
					flags & ~sme_me_mask);

}

int __init early_set_memory_decrypted(void *vaddr, unsigned long size)
{
	unsigned long flags = get_pte_flags((unsigned long)vaddr);

	return early_set_memory_enc_dec(vaddr, size, flags & ~sme_me_mask);
}

int __init early_set_memory_encrypted(void *vaddr, unsigned long size)
{
	unsigned long flags = get_pte_flags((unsigned long)vaddr);

	return early_set_memory_enc_dec(vaddr, size, flags | _PAGE_ENC);
}

static struct dma_map_ops sme_dma_ops = {
	.alloc                  = sme_alloc,
	.free                   = sme_free,
	.map_page               = swiotlb_map_page,
	.unmap_page             = swiotlb_unmap_page,
	.map_sg                 = swiotlb_map_sg_attrs,
	.unmap_sg               = swiotlb_unmap_sg_attrs,
	.sync_single_for_cpu    = swiotlb_sync_single_for_cpu,
	.sync_single_for_device = swiotlb_sync_single_for_device,
	.sync_sg_for_cpu        = swiotlb_sync_sg_for_cpu,
	.sync_sg_for_device     = swiotlb_sync_sg_for_device,
	.mapping_error          = swiotlb_dma_mapping_error,
};

/* Architecture __weak replacement functions */
void __init mem_encrypt_init(void)
{
	if (!sme_me_mask)
		return;

	/* Call into SWIOTLB to update the SWIOTLB DMA buffers */
	swiotlb_update_mem_attributes();

	/* Use SEV DMA operations if SEV is active */
	if (sev_active())
		dma_ops = &sme_dma_ops;

	pr_info("AMD Secure Memory Encryption (SME) active\n");
}

void swiotlb_set_mem_attributes(void *vaddr, unsigned long size)
{
	WARN(PAGE_ALIGN(size) != size,
	     "size is not page aligned (%#lx)\n", size);

	/* Make the SWIOTLB buffer area decrypted */
	set_memory_decrypted((unsigned long)vaddr, size >> PAGE_SHIFT);
}
