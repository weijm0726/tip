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

#ifndef __MEM_ENCRYPT_H__
#define __MEM_ENCRYPT_H__

#ifndef __ASSEMBLY__

#ifdef CONFIG_AMD_MEM_ENCRYPT

#include <asm/mem_encrypt.h>

#else	/* !CONFIG_AMD_MEM_ENCRYPT */

#ifndef sme_me_mask
#define sme_me_mask	0UL

static inline bool sme_active(void)
{
	return false;
}

static inline u64 sme_dma_mask(void)
{
	return 0ULL;
}

static inline int set_memory_encrypted(unsigned long vaddr, int numpages)
{
	return 0;
}

static inline int set_memory_decrypted(unsigned long vaddr, int numpages)
{
	return 0;
}

#endif

#endif	/* CONFIG_AMD_MEM_ENCRYPT */

#endif	/* __ASSEMBLY__ */

#endif	/* __MEM_ENCRYPT_H__ */
