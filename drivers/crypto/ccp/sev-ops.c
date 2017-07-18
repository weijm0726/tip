/*
 * AMD Secure Encrypted Virtualization (SEV) command interface
 *
 * Copyright (C) 2016-2017 Advanced Micro Devices, Inc.
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

static bool sev_initialized;
static int sev_platform_get_state(int *state, int *error)
{
	int ret;
	struct sev_data_status *data;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	ret = sev_platform_status(data, error);
	*state = data->state;

	kfree(data);
	return ret;
}

static int __sev_platform_init(int *error)
{
	int ret;
	struct sev_data_init *data;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	ret = sev_platform_init(data, error);

	kfree(data);
	return ret;
}

static int sev_ioctl_factory_reset(struct sev_issue_cmd *argp)
{
	return sev_issue_cmd(SEV_CMD_FACTORY_RESET, 0, &argp->error);
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
	int do_shutdown = 0;
	int ret, state, error;
	void *csr_addr = NULL;
	struct sev_data_pek_csr *data;
	struct sev_user_data_pek_csr input;

	if (copy_from_user(&input, (void *)argp->data,
			sizeof(struct sev_user_data_pek_csr)))
		return -EFAULT;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	/*
	 * PEK_CSR command can be issued when firmware is in INIT or WORKING
	 * state. If firmware is in UNINIT state then we transition into INIT
	 * state and issue the command.
	 */
	ret = sev_platform_get_state(&state, &argp->error);
	if (ret)
		return ret;

	if (state == SEV_STATE_UNINIT) {
		/* transition the plaform into INIT state */
		ret = __sev_platform_init(&argp->error);
		if (ret)
			return ret;
		do_shutdown = 1;
	}

	if (input.address) {
		csr_addr = kmalloc(input.length, GFP_KERNEL);
		if (!csr_addr) {
			ret = -ENOMEM;
			goto e_free;
		}
		data->address = __psp_pa(csr_addr);
		data->length = input.length;
	}

	ret = sev_issue_cmd(SEV_CMD_PEK_CSR, data, &argp->error);

	if (csr_addr) {
		if (copy_to_user((void *)input.address, csr_addr,
				input.length)) {
			ret = -EFAULT;
			goto e_free;
		}
	}

	input.length = data->length;
	if (copy_to_user((void *)argp->data, &input,
			sizeof(struct sev_user_data_pek_csr)))
		ret = -EFAULT;
e_free:
	if (do_shutdown)
		sev_platform_shutdown(&error);
	kfree(csr_addr);
	kfree(data);
	return ret;
}

static int sev_ioctl_pdh_gen(struct sev_issue_cmd *argp)
{
	int ret, state, error, do_shutdown = 0;

	/*
	 * PDH_GEN command can be issued when platform is in INIT or WORKING
	 * state. If we are in UNINIT state then transition into INIT.
	 */
	ret = sev_platform_get_state(&state, &argp->error);
	if (ret)
		return ret;

	if (state == SEV_STATE_UNINIT) {
		/* transition the plaform into INIT state */
		ret = __sev_platform_init(&argp->error);
		if (ret)
			return ret;
		do_shutdown = 1;
	}

	ret = sev_issue_cmd(SEV_CMD_PDH_GEN, 0,	&argp->error);
	if (do_shutdown)
		sev_platform_shutdown(&error);
	return ret;
}

static int sev_ioctl_pek_gen(struct sev_issue_cmd *argp)
{
	int do_shutdown = 0;
	int error, ret, state;

	/*
	 * PEK_GEN command can be issued only when firmware is in INIT state.
	 * If firmware is in UNINIT state then we transition into INIT state
	 * and issue the command and then shutdown.
	 */
	ret = sev_platform_get_state(&state, &argp->error);
	if (ret)
		return ret;

	if (state == SEV_STATE_UNINIT) {
		/* transition the plaform into INIT state */
		ret = __sev_platform_init(&argp->error);
		if (ret)
			return ret;

		do_shutdown = 1;
	}

	ret = sev_issue_cmd(SEV_CMD_PEK_GEN, 0,	&argp->error);

	if (do_shutdown)
		sev_platform_shutdown(&error);
	return ret;
}

static int sev_ioctl_pek_cert_import(struct sev_issue_cmd *argp)
{
	int ret, state, error, do_shutdown = 0;
	struct sev_data_pek_cert_import *data;
	struct sev_user_data_pek_cert_import input;
	void *pek_cert = NULL, *oca_cert = NULL;

	if (copy_from_user(&input, (void *)argp->data, sizeof(*data)))
		return -EFAULT;

	if (!input.pek_cert_address || !input.pek_cert_length ||
		!input.oca_cert_address || !input.oca_cert_length)
		return -EINVAL;

	ret = sev_platform_get_state(&state, &argp->error);
	if (ret)
		return ret;

	/*
	 * CERT_IMPORT command can be issued only when platform is in INIT
	 * state. If we are in UNINIT state then transition into INIT state
	 * and issue the command.
	 */
	if (state == SEV_STATE_UNINIT) {
		/* transition platform init INIT state */
		ret = __sev_platform_init(&argp->error);
		if (ret)
			return ret;
		do_shutdown = 1;
	}

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data) {
		ret = -ENOMEM;
		goto e_free;
	}

	pek_cert = kmalloc(input.pek_cert_length, GFP_KERNEL);
	if (!pek_cert) {
		ret = -ENOMEM;
		goto e_free;
	}

	/* copy PEK certificate from userspace */
	if (copy_from_user(pek_cert, (void *)input.pek_cert_address,
				input.pek_cert_length)) {
		ret = -EFAULT;
		goto e_free;
	}

	data->pek_cert_address = __psp_pa(pek_cert);
	data->pek_cert_length = input.pek_cert_length;

	oca_cert = kmalloc(input.oca_cert_length, GFP_KERNEL);
	if (!oca_cert) {
		ret = -ENOMEM;
		goto e_free;
	}

	/* copy OCA certificate from userspace */
	if (copy_from_user(oca_cert, (void *)input.oca_cert_address,
				input.oca_cert_length)) {
		ret = -EFAULT;
		goto e_free;
	}

	data->oca_cert_address = __psp_pa(oca_cert);
	data->oca_cert_length = input.oca_cert_length;

	ret = sev_issue_cmd(SEV_CMD_PEK_CERT_IMPORT, data, &argp->error);
e_free:
	if (do_shutdown)
		sev_platform_shutdown(&error);
	kfree(oca_cert);
	kfree(pek_cert);
	kfree(data);
	return ret;
}

static int sev_ioctl_pdh_cert_export(struct sev_issue_cmd *argp)
{
	int ret, state, error, need_shutdown = 0;
	struct sev_data_pdh_cert_export *data;
	struct sev_user_data_pdh_cert_export input;
	void *pdh_cert = NULL, *cert_chain = NULL;

	if (copy_from_user(&input, (void *)argp->data, sizeof(*data)))
		return -EFAULT;

	/*
	 * CERT_EXPORT command can be issued in INIT or WORKING state.
	 * If we are in UNINIT state then transition into INIT state and
	 * shutdown before exiting. But if platform is in WORKING state
	 * then EXPORT the certificate but do not shutdown the platform.
	 */
	ret = sev_platform_get_state(&state, &argp->error);
	if (ret)
		return ret;

	if (state == SEV_STATE_UNINIT) {
		ret = __sev_platform_init(&argp->error);
		if (ret)
			return ret;
		need_shutdown = 1;
	}

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data) {
		ret = -ENOMEM;
		goto e_free;
	}

	if (input.pdh_cert_address) {
		pdh_cert = kmalloc(input.pdh_cert_length, GFP_KERNEL);
		if (!pdh_cert) {
			ret = -ENOMEM;
			goto e_free;
		}

		data->pdh_cert_address = __psp_pa(pdh_cert);
		data->pdh_cert_length = input.pdh_cert_length;
	}

	if (input.cert_chain_address) {
		cert_chain = kmalloc(input.cert_chain_length, GFP_KERNEL);
		if (!cert_chain) {
			ret = -ENOMEM;
			goto e_free;
		}

		data->cert_chain_address = __psp_pa(cert_chain);
		data->cert_chain_length = input.cert_chain_length;
	}

	ret = sev_issue_cmd(SEV_CMD_PDH_CERT_EXPORT, data, &argp->error);

	input.cert_chain_length = data->cert_chain_length;
	input.pdh_cert_length = data->pdh_cert_length;

	/* copy PDH certificate to userspace */
	if (pdh_cert) {
		if (copy_to_user((void *)input.pdh_cert_address,
				pdh_cert, input.pdh_cert_length)) {
			ret = -EFAULT;
			goto e_free;
		}
	}

	/* copy certificate chain to userspace */
	if (cert_chain) {
		if (copy_to_user((void *)input.cert_chain_address,
				cert_chain, input.cert_chain_length)) {
			ret = -EFAULT;
			goto e_free;
		}
	}

	/* copy certificate length to userspace */
	if (copy_to_user((void *)argp->data, &input,
			sizeof(struct sev_user_data_pdh_cert_export)))
		ret = -EFAULT;

e_free:
	if (need_shutdown)
		sev_platform_shutdown(&error);

	kfree(cert_chain);
	kfree(pdh_cert);
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

	case SEV_USER_CMD_FACTORY_RESET: {
		ret = sev_ioctl_factory_reset(&input);
		break;
	}
	case SEV_USER_CMD_PLATFORM_STATUS: {
		ret = sev_ioctl_platform_status(&input);
		break;
	}
	case SEV_USER_CMD_PEK_GEN: {
		ret = sev_ioctl_pek_gen(&input);
		break;
	}
	case SEV_USER_CMD_PDH_GEN: {
		ret = sev_ioctl_pdh_gen(&input);
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

	/* if sev device is already registered then do nothing */
	if (sev_initialized)
		return 0;

	misc->minor = MISC_DYNAMIC_MINOR;
	misc->name = sev->name;
	misc->fops = &sev_fops;
	sev_initialized = true;

	return misc_register(misc);
}

void sev_ops_destroy(struct sev_device *sev)
{
	misc_deregister(&sev->misc);
}
