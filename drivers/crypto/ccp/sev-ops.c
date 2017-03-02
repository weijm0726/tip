/*
 * AMD Secure Encrypted Virtualization (SEV) command interface
 *
 * Copyright (C) 2016 Advanced Micro Devices, Inc.
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/spinlock_types.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>

#include <uapi/linux/psp-sev.h>

#include "psp-dev.h"
#include "sev-dev.h"

static int sev_ioctl_init(struct sev_issue_cmd *argp)
{
	int ret;
	struct sev_data_init *data;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	ret = sev_platform_init(data, &argp->error);

	kfree(data);
	return ret;
}

static int sev_ioctl_platform_status(struct sev_issue_cmd *argp)
{
	int ret;
	struct sev_data_status *data;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	ret = sev_platform_status(data, &argp->error);

	if (copy_to_user((void *)argp->data, data, sizeof(*data)))
		ret = -EFAULT;

	kfree(data);
	return ret;
}

static int sev_ioctl_pek_csr(struct sev_issue_cmd *argp)
{
	int ret;
	void *csr_addr = NULL;
	struct sev_data_pek_csr *data;
	struct sev_user_data_pek_csr input;

	if (copy_from_user(&input, (void *)argp->data,
			sizeof(struct sev_user_data_pek_csr)))
		return -EFAULT;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	/* copy PEK certificate from userspace */
	if (input.address && input.length) {
		csr_addr = kmalloc(input.length, GFP_KERNEL);
		if (!csr_addr) {
			ret = -ENOMEM;
			goto e_err;
		}
		if (copy_from_user(csr_addr, (void *)input.address,
				input.length)) {
			ret = -EFAULT;
			goto e_csr_free;
		}

		data->address = __psp_pa(csr_addr);
		data->length = input.length;
	}

	ret = sev_issue_cmd(SEV_CMD_PEK_CSR,
			data, SEV_DEFAULT_TIMEOUT, &argp->error);

	input.length = data->length;

	/* copy PEK certificate length to userspace */
	if (copy_to_user((void *)argp->data, &input,
			sizeof(struct sev_user_data_pek_csr)))
		ret = -EFAULT;
e_csr_free:
	kfree(csr_addr);
e_err:
	kfree(data);
	return ret;
}

static int sev_ioctl_pek_cert_import(struct sev_issue_cmd *argp)
{
	int ret;
	struct sev_data_pek_cert_import *data;
	struct sev_user_data_pek_cert_import input;
	void *pek_cert, *oca_cert;

	if (copy_from_user(&input, (void *)argp->data, sizeof(*data)))
		return -EFAULT;

	if (!input.pek_cert_address || !input.pek_cert_length ||
		!input.oca_cert_address || !input.oca_cert_length)
		return -EINVAL;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	/* copy PEK certificate from userspace */
	pek_cert = kmalloc(input.pek_cert_length, GFP_KERNEL);
	if (!pek_cert) {
		ret = -ENOMEM;
		goto e_free;
	}
	if (copy_from_user(pek_cert, (void *)input.pek_cert_address,
				input.pek_cert_length)) {
		ret = -EFAULT;
		goto e_free_pek_cert;
	}

	data->pek_cert_address = __psp_pa(pek_cert);
	data->pek_cert_length = input.pek_cert_length;

	/* copy OCA certificate from userspace */
	oca_cert = kmalloc(input.oca_cert_length, GFP_KERNEL);
	if (!oca_cert) {
		ret = -ENOMEM;
		goto e_free_pek_cert;
	}
	if (copy_from_user(oca_cert, (void *)input.oca_cert_address,
				input.oca_cert_length)) {
		ret = -EFAULT;
		goto e_free_oca_cert;
	}

	data->oca_cert_address = __psp_pa(oca_cert);
	data->oca_cert_length = input.oca_cert_length;

	ret = sev_issue_cmd(SEV_CMD_PEK_CERT_IMPORT,
			data, SEV_DEFAULT_TIMEOUT, &argp->error);
e_free_oca_cert:
	kfree(oca_cert);
e_free_pek_cert:
	kfree(pek_cert);
e_free:
	kfree(data);
	return ret;
}

static int sev_ioctl_pdh_cert_export(struct sev_issue_cmd *argp)
{
	int ret;
	struct sev_data_pdh_cert_export *data;
	struct sev_user_data_pdh_cert_export input;
	void *pdh_cert = NULL, *cert_chain = NULL;

	if (copy_from_user(&input, (void *)argp->data, sizeof(*data)))
		return -EFAULT;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	/* copy pdh certificate from userspace */
	if (input.pdh_cert_length && input.pdh_cert_address) {
		pdh_cert = kmalloc(input.pdh_cert_length, GFP_KERNEL);
		if (!pdh_cert) {
			ret = -ENOMEM;
			goto e_free;
		}
		if (copy_from_user(pdh_cert, (void *)input.pdh_cert_address,
					input.pdh_cert_length)) {
			ret = -EFAULT;
			goto e_free_pdh_cert;
		}

		data->pdh_cert_address = __psp_pa(pdh_cert);
		data->pdh_cert_length = input.pdh_cert_length;
	}

	/* copy cert_chain certificate from userspace */
	if (input.cert_chain_length && input.cert_chain_address) {
		cert_chain = kmalloc(input.cert_chain_length, GFP_KERNEL);
		if (!cert_chain) {
			ret = -ENOMEM;
			goto e_free_pdh_cert;
		}
		if (copy_from_user(cert_chain, (void *)input.cert_chain_address,
					input.cert_chain_length)) {
			ret = -EFAULT;
			goto e_free_cert_chain;
		}

		data->cert_chain_address = __psp_pa(cert_chain);
		data->cert_chain_length = input.cert_chain_length;
	}

	ret = sev_issue_cmd(SEV_CMD_PDH_CERT_EXPORT,
			data, SEV_DEFAULT_TIMEOUT, &argp->error);

	input.cert_chain_length = data->cert_chain_length;
	input.pdh_cert_length = data->pdh_cert_length;

	/* copy certificate length to userspace */
	if (copy_to_user((void *)argp->data, &input,
			sizeof(struct sev_user_data_pek_csr)))
		ret = -EFAULT;

e_free_cert_chain:
	kfree(cert_chain);
e_free_pdh_cert:
	kfree(pdh_cert);
e_free:
	kfree(data);
	return ret;
}

static long sev_ioctl(struct file *file, unsigned int ioctl, unsigned long arg)
{
	int ret = -EFAULT;
	void __user *argp = (void __user *)arg;
	struct sev_issue_cmd input;

	if (ioctl != SEV_ISSUE_CMD)
		return -EINVAL;

	if (copy_from_user(&input, argp, sizeof(struct sev_issue_cmd)))
		return -EFAULT;

	if (input.cmd > SEV_CMD_MAX)
		return -EINVAL;

	switch (input.cmd) {

	case SEV_USER_CMD_INIT: {
		ret = sev_ioctl_init(&input);
		break;
	}
	case SEV_USER_CMD_SHUTDOWN: {
		ret = sev_platform_shutdown(&input.error);
		break;
	}
	case SEV_USER_CMD_FACTORY_RESET: {
		ret = sev_issue_cmd(SEV_CMD_FACTORY_RESET, 0,
				SEV_DEFAULT_TIMEOUT, &input.error);
		break;
	}
	case SEV_USER_CMD_PLATFORM_STATUS: {
		ret = sev_ioctl_platform_status(&input);
		break;
	}
	case SEV_USER_CMD_PEK_GEN: {
		ret = sev_issue_cmd(SEV_CMD_PEK_GEN, 0,
				SEV_DEFAULT_TIMEOUT, &input.error);
		break;
	}
	case SEV_USER_CMD_PDH_GEN: {
		ret = sev_issue_cmd(SEV_CMD_PDH_GEN, 0,
				SEV_DEFAULT_TIMEOUT, &input.error);
		break;
	}
	case SEV_USER_CMD_PEK_CSR: {
		ret = sev_ioctl_pek_csr(&input);
		break;
	}
	case SEV_USER_CMD_PEK_CERT_IMPORT: {
		ret = sev_ioctl_pek_cert_import(&input);
		break;
	}
	case SEV_USER_CMD_PDH_CERT_EXPORT: {
		ret = sev_ioctl_pdh_cert_export(&input);
		break;
	}
	default:
		ret = -EINVAL;
		break;
	}

	if (copy_to_user(argp, &input, sizeof(struct sev_issue_cmd)))
		ret = -EFAULT;

	return ret;
}

const struct file_operations sev_fops = {
	.owner	= THIS_MODULE,
	.unlocked_ioctl = sev_ioctl,
};

int sev_ops_init(struct sev_device *sev)
{
	struct miscdevice *misc = &sev->misc;

	misc->minor = MISC_DYNAMIC_MINOR;
	misc->name = sev->name;
	misc->fops = &sev_fops;

	return misc_register(misc);
}

void sev_ops_destroy(struct sev_device *sev)
{
	misc_deregister(&sev->misc);
}

