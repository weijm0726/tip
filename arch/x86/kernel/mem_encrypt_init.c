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

void __init sme_encrypt_kernel(void)
{
}

unsigned long __init sme_get_me_mask(void)
{
	return sme_me_mask;
}

unsigned long __init sme_enable(void)
{
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
