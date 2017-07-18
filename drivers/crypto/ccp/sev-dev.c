/*
 * AMD Secure Encrypted Virtualization (SEV) interface
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
#include <linux/delay.h>
#include <linux/wait.h>
#include <linux/jiffies.h>

#include "psp-dev.h"
#include "sev-dev.h"

extern const struct file_operations sev_fops;

static LIST_HEAD(sev_devs);
static DEFINE_SPINLOCK(sev_devs_lock);
static atomic_t sev_id;

static unsigned int sev_poll;
module_param(sev_poll, uint, 0444);
MODULE_PARM_DESC(sev_poll, "Poll for sev command completion - any non-zero value");

DEFINE_MUTEX(sev_cmd_mutex);

void sev_add_device(struct sev_device *sev)
{
	unsigned long flags;

	spin_lock_irqsave(&sev_devs_lock, flags);

	list_add_tail(&sev->entry, &sev_devs);

	spin_unlock_irqrestore(&sev_devs_lock, flags);
}

void sev_del_device(struct sev_device *sev)
{
	unsigned long flags;

	spin_lock_irqsave(&sev_devs_lock, flags);

	list_del(&sev->entry);
	spin_unlock_irqrestore(&sev_devs_lock, flags);
}

static struct sev_device *get_sev_master_device(void)
{
	struct psp_device *psp = psp_get_master_device();

	return psp ? psp->sev_data : NULL;
}

static int sev_wait_cmd_poll(struct sev_device *sev, unsigned int timeout,
			     unsigned int *reg)
{
	int wait = timeout * 10;	/* 100ms sleep => timeout * 10 */

	while (--wait) {
		msleep(100);

		*reg = ioread32(sev->io_regs + PSP_CMDRESP);
		if (*reg & PSP_CMDRESP_RESP)
			break;
	}

	if (!wait) {
		dev_err(sev->dev, "sev command timed out\n");
		return -ETIMEDOUT;
	}

	return 0;
}

static int sev_wait_cmd_ioc(struct sev_device *sev, unsigned int *reg)
{
	sev->int_rcvd = 0;

	wait_event(sev->int_queue, sev->int_rcvd);
	*reg = ioread32(sev->io_regs + PSP_CMDRESP);

	return 0;
}

static int sev_wait_cmd(struct sev_device *sev, unsigned int *reg)
{
	return (*reg & PSP_CMDRESP_IOC) ? sev_wait_cmd_ioc(sev, reg)
					: sev_wait_cmd_poll(sev, 10, reg);
}

static struct sev_device *sev_alloc_struct(struct psp_device *psp)
{
	struct device *dev = psp->dev;
	struct sev_device *sev;

	sev = devm_kzalloc(dev, sizeof(*sev), GFP_KERNEL);
	if (!sev)
		return NULL;

	sev->dev = dev;
	sev->psp = psp;
	sev->id = atomic_inc_return(&sev_id);

	snprintf(sev->name, sizeof(sev->name), "sev%u", sev->id);
	init_waitqueue_head(&sev->int_queue);

	return sev;
}

irqreturn_t sev_irq_handler(int irq, void *data)
{
	struct sev_device *sev = data;
	unsigned int status;

	status = ioread32(sev->io_regs + PSP_P2CMSG_INTSTS);
	if (status & (1 << PSP_CMD_COMPLETE_REG)) {
		int reg;

		reg = ioread32(sev->io_regs + PSP_CMDRESP);
		if (reg & PSP_CMDRESP_RESP) {
			sev->int_rcvd = 1;
			wake_up(&sev->int_queue);
		}
	}

	return IRQ_HANDLED;
}

static bool check_sev_support(struct sev_device *sev)
{
	/* Bit 0 in PSP_FEATURE_REG is set then SEV is support in PSP */
	if (ioread32(sev->io_regs + PSP_FEATURE_REG) & 1)
		return true;

	return false;
}

int sev_dev_init(struct psp_device *psp)
{
	struct device *dev = psp->dev;
	struct sev_device *sev;
	int ret;

	ret = -ENOMEM;
	sev = sev_alloc_struct(psp);
	if (!sev)
		goto e_err;
	psp->sev_data = sev;

	sev->io_regs = psp->io_regs;

	dev_dbg(dev, "checking SEV support ...\n");
	/* check SEV support */
	if (!check_sev_support(sev)) {
		dev_dbg(dev, "device does not support SEV\n");
		goto e_err;
	}

	dev_dbg(dev, "requesting an IRQ ...\n");
	/* Request an irq */
	ret = psp_request_sev_irq(sev->psp, sev_irq_handler, sev);
	if (ret) {
		dev_err(dev, "unable to allocate an IRQ\n");
		goto e_err;
	}

	/* initialize SEV ops */
	dev_dbg(dev, "init sev ops\n");
	ret = sev_ops_init(sev);
	if (ret) {
		dev_err(dev, "failed to init sev ops\n");
		goto e_irq;
	}

	sev_add_device(sev);

	dev_notice(dev, "sev enabled\n");

	return 0;

e_irq:
	psp_free_sev_irq(psp, sev);
e_err:
	psp->sev_data = NULL;

	dev_notice(dev, "sev initialization failed\n");

	return ret;
}

void sev_dev_destroy(struct psp_device *psp)
{
	struct sev_device *sev = psp->sev_data;

	psp_free_sev_irq(psp, sev);

	sev_ops_destroy(sev);

	sev_del_device(sev);
}

int sev_dev_resume(struct psp_device *psp)
{
	return 0;
}

int sev_dev_suspend(struct psp_device *psp, pm_message_t state)
{
	return 0;
}

static int sev_cmd_buffer_len(int cmd)
{
	int size;

	switch (cmd) {
	case SEV_CMD_INIT:
		size = sizeof(struct sev_data_init);
		break;
	case SEV_CMD_PLATFORM_STATUS:
		size = sizeof(struct sev_data_status);
		break;
	case SEV_CMD_PEK_CSR:
		size = sizeof(struct sev_data_pek_csr);
		break;
	case SEV_CMD_PEK_CERT_IMPORT:
		size = sizeof(struct sev_data_pek_cert_import);
		break;
	case SEV_CMD_PDH_CERT_EXPORT:
		size = sizeof(struct sev_data_pdh_cert_export);
		break;
	case SEV_CMD_LAUNCH_START:
		size = sizeof(struct sev_data_launch_start);
		break;
	case SEV_CMD_LAUNCH_UPDATE_DATA:
		size = sizeof(struct sev_data_launch_update_data);
		break;
	case SEV_CMD_LAUNCH_UPDATE_VMSA:
		size = sizeof(struct sev_data_launch_update_vmsa);
		break;
	case SEV_CMD_LAUNCH_FINISH:
		size = sizeof(struct sev_data_launch_finish);
		break;
	case SEV_CMD_LAUNCH_UPDATE_SECRET:
		size = sizeof(struct sev_data_launch_secret);
		break;
	case SEV_CMD_LAUNCH_MEASURE:
		size = sizeof(struct sev_data_launch_measure);
		break;
	case SEV_CMD_ACTIVATE:
		size = sizeof(struct sev_data_activate);
		break;
	case SEV_CMD_DEACTIVATE:
		size = sizeof(struct sev_data_deactivate);
		break;
	case SEV_CMD_DECOMMISSION:
		size = sizeof(struct sev_data_decommission);
		break;
	case SEV_CMD_GUEST_STATUS:
		size = sizeof(struct sev_data_guest_status);
		break;
	case SEV_CMD_DBG_DECRYPT:
	case SEV_CMD_DBG_ENCRYPT:
		size = sizeof(struct sev_data_dbg);
		break;
	case SEV_CMD_SEND_START:
		size = sizeof(struct sev_data_send_start);
		break;
	case SEV_CMD_SEND_UPDATE_DATA:
		size = sizeof(struct sev_data_send_update_data);
		break;
	case SEV_CMD_SEND_UPDATE_VMSA:
		size = sizeof(struct sev_data_send_update_vmsa);
		break;
	case SEV_CMD_SEND_FINISH:
		size = sizeof(struct sev_data_send_finish);
		break;
	case SEV_CMD_RECEIVE_START:
		size = sizeof(struct sev_data_receive_start);
		break;
	case SEV_CMD_RECEIVE_UPDATE_DATA:
		size = sizeof(struct sev_data_receive_update_data);
		break;
	case SEV_CMD_RECEIVE_UPDATE_VMSA:
		size = sizeof(struct sev_data_receive_update_vmsa);
		break;
	case SEV_CMD_RECEIVE_FINISH:
		size = sizeof(struct sev_data_receive_finish);
		break;
	default:
		size = 0;
		break;
	}

	return size;
}

int sev_issue_cmd(int cmd, void *data, int *psp_ret)
{
	struct sev_device *sev = get_sev_master_device();
	unsigned int phys_lsb, phys_msb;
	unsigned int reg, ret;

	if (!sev)
		return -ENODEV;

	if (psp_ret)
		*psp_ret = 0;

	/* Set the physical address for the PSP */
	phys_lsb = data ? lower_32_bits(__psp_pa(data)) : 0;
	phys_msb = data ? upper_32_bits(__psp_pa(data)) : 0;

	dev_dbg(sev->dev, "sev command id %#x buffer 0x%08x%08x\n",
			cmd, phys_msb, phys_lsb);
	print_hex_dump_debug("(in):  ", DUMP_PREFIX_OFFSET, 16, 2, data,
			sev_cmd_buffer_len(cmd), false);

	/* Only one command at a time... */
	mutex_lock(&sev_cmd_mutex);

	iowrite32(phys_lsb, sev->io_regs + PSP_CMDBUFF_ADDR_LO);
	iowrite32(phys_msb, sev->io_regs + PSP_CMDBUFF_ADDR_HI);
	wmb();

	reg = cmd;
	reg <<= PSP_CMDRESP_CMD_SHIFT;
	reg |= sev_poll ? 0 : PSP_CMDRESP_IOC;
	iowrite32(reg, sev->io_regs + PSP_CMDRESP);

	ret = sev_wait_cmd(sev, &reg);
	if (ret)
		goto unlock;

	if (psp_ret)
		*psp_ret = reg & PSP_CMDRESP_ERR_MASK;

	if (reg & PSP_CMDRESP_ERR_MASK) {
		dev_dbg(sev->dev, "sev command %u failed (%#010x)\n",
			cmd, reg & PSP_CMDRESP_ERR_MASK);
		ret = -EIO;
	}

unlock:
	mutex_unlock(&sev_cmd_mutex);
	print_hex_dump_debug("(out): ", DUMP_PREFIX_OFFSET, 16, 2, data,
			sev_cmd_buffer_len(cmd), false);
	return ret;
}

int sev_platform_init(struct sev_data_init *data, int *error)
{
	return sev_issue_cmd(SEV_CMD_INIT, data, error);
}
EXPORT_SYMBOL_GPL(sev_platform_init);

int sev_platform_shutdown(int *error)
{
	return sev_issue_cmd(SEV_CMD_SHUTDOWN, 0, error);
}
EXPORT_SYMBOL_GPL(sev_platform_shutdown);

int sev_platform_status(struct sev_data_status *data, int *error)
{
	return sev_issue_cmd(SEV_CMD_PLATFORM_STATUS, data, error);
}
EXPORT_SYMBOL_GPL(sev_platform_status);

int sev_issue_cmd_external_user(struct file *filep, unsigned int cmd,
				void *data, int *error)
{
	if (!filep || filep->f_op != &sev_fops)
		return -EBADF;

	return sev_issue_cmd(cmd, data, error);
}
EXPORT_SYMBOL_GPL(sev_issue_cmd_external_user);

int sev_guest_deactivate(struct sev_data_deactivate *data, int *error)
{
	return sev_issue_cmd(SEV_CMD_DEACTIVATE, data, error);
}
EXPORT_SYMBOL_GPL(sev_guest_deactivate);

int sev_guest_activate(struct sev_data_activate *data, int *error)
{
	return sev_issue_cmd(SEV_CMD_ACTIVATE, data, error);
}
EXPORT_SYMBOL_GPL(sev_guest_activate);

int sev_guest_decommission(struct sev_data_decommission *data, int *error)
{
	return sev_issue_cmd(SEV_CMD_DECOMMISSION, data, error);
}
EXPORT_SYMBOL_GPL(sev_guest_decommission);

int sev_guest_df_flush(int *error)
{
	return sev_issue_cmd(SEV_CMD_DF_FLUSH, 0, error);
}
EXPORT_SYMBOL_GPL(sev_guest_df_flush);
