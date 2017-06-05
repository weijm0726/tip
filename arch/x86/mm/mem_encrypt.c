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

/*
 * Since SME related variables are set early in the boot process they must
 * reside in the .data section so as not to be zeroed out when the .bss
 * section is later cleared.
 */
unsigned long sme_me_mask __section(.data) = 0;
EXPORT_SYMBOL_GPL(sme_me_mask);

void __init sme_encrypt_kernel(void)
{
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
