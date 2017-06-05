/*
 * AMD Memory Encryption Support
 *
 * Copyright (C) 2017 Advanced Micro Devices, Inc.
 *
 * Author: Tom Lendacky <thomas.lendacky@amd.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __ASM_GENERIC_MEM_ENCRYPT_H__
#define __ASM_GENERIC_MEM_ENCRYPT_H__

#ifndef __ASSEMBLY__

#define sme_me_mask	0UL

static inline bool sme_active(void)
{
	return false;
}

static inline u64 sme_dma_mask(void)
{
	return 0ULL;
}

static inline bool sme_iommu_supported(void)
{
	return true;
}

/*
 * The __sme_set() and __sme_clr() macros are useful for adding or removing
 * the encryption mask from a value (e.g. when dealing with pagetable
 * entries).
 */
#define __sme_set(x)		(x)
#define __sme_clr(x)		(x)

#endif	/* __ASSEMBLY__ */

#endif	/* __MEM_ENCRYPT_H__ */
