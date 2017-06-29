/*
 * AMD Platform Security Processor (PSP) interface
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
#include <linux/delay.h>
#include <linux/hw_random.h>
#include <linux/ccp.h>

#include "sp-dev.h"
#include "psp-dev.h"

static LIST_HEAD(psp_devs);
static DEFINE_SPINLOCK(psp_devs_lock);

const struct psp_vdata psp_entry = {
	.offset = 0x10500,
};

void psp_add_device(struct psp_device *psp)
{
	unsigned long flags;

	spin_lock_irqsave(&psp_devs_lock, flags);

	list_add_tail(&psp->entry, &psp_devs);

	spin_unlock_irqrestore(&psp_devs_lock, flags);
}

void psp_del_device(struct psp_device *psp)
{
	unsigned long flags;

	spin_lock_irqsave(&psp_devs_lock, flags);

	list_del(&psp->entry);
	spin_unlock_irqrestore(&psp_devs_lock, flags);
}

static struct psp_device *psp_alloc_struct(struct sp_device *sp)
{
	struct device *dev = sp->dev;
	struct psp_device *psp;

	psp = devm_kzalloc(dev, sizeof(*psp), GFP_KERNEL);
	if (!psp)
		return NULL;

	psp->dev = dev;
	psp->sp = sp;

	snprintf(psp->name, sizeof(psp->name), "psp-%u", sp->ord);

	return psp;
}

irqreturn_t psp_irq_handler(int irq, void *data)
{
	unsigned int status;
	irqreturn_t ret = IRQ_HANDLED;
	struct psp_device *psp = data;

	/* read the interrupt status */
	status = ioread32(psp->io_regs + PSP_P2CMSG_INTSTS);

	/* invoke subdevice interrupt handlers */
	if (status) {
		if (psp->sev_irq_handler)
			ret = psp->sev_irq_handler(irq, psp->sev_irq_data);
		if (psp->tee_irq_handler)
			ret = psp->tee_irq_handler(irq, psp->tee_irq_data);
	}

	/* clear the interrupt status */
	iowrite32(status, psp->io_regs + PSP_P2CMSG_INTSTS);

	return ret;
}

static int psp_init(struct psp_device *psp)
{
	psp_add_device(psp);
	sev_dev_init(psp);

	return 0;
}

int psp_dev_init(struct sp_device *sp)
{
	struct device *dev = sp->dev;
	struct psp_device *psp;
	int ret;

	ret = -ENOMEM;
	psp = psp_alloc_struct(sp);
	if (!psp)
		goto e_err;
	sp->psp_data = psp;

	psp->vdata = (struct psp_vdata *)sp->dev_vdata->psp_vdata;
	if (!psp->vdata) {
		ret = -ENODEV;
		dev_err(dev, "missing driver data\n");
		goto e_err;
	}

	psp->io_regs = sp->io_map + psp->vdata->offset;

	/* Disable and clear interrupts until ready */
	iowrite32(0, psp->io_regs + PSP_P2CMSG_INTEN);
	iowrite32(0xffffffff, psp->io_regs + PSP_P2CMSG_INTSTS);

	dev_dbg(dev, "requesting an IRQ ...\n");
	/* Request an irq */
	ret = sp_request_psp_irq(psp->sp, psp_irq_handler, psp->name, psp);
	if (ret) {
		dev_err(dev, "psp: unable to allocate an IRQ\n");
		goto e_err;
	}

	sp_set_psp_master(sp);

	dev_dbg(dev, "initializing psp\n");
	ret = psp_init(psp);
	if (ret) {
		dev_err(dev, "failed to init psp\n");
		goto e_irq;
	}

	/* Enable interrupt */
	dev_dbg(dev, "Enabling interrupts ...\n");
	iowrite32(7, psp->io_regs + PSP_P2CMSG_INTEN);

	dev_notice(dev, "psp enabled\n");

	return 0;

e_irq:
	sp_free_psp_irq(psp->sp, psp);
e_err:
	sp->psp_data = NULL;

	dev_notice(dev, "psp initialization failed\n");

	return ret;
}

void psp_dev_destroy(struct sp_device *sp)
{
	struct psp_device *psp = sp->psp_data;

	sp_free_psp_irq(sp, psp);
	sev_dev_destroy(psp);

	psp_del_device(psp);
}

int psp_dev_resume(struct sp_device *sp)
{
	sev_dev_resume(sp->psp_data);
	return 0;
}

int psp_dev_suspend(struct sp_device *sp, pm_message_t state)
{
	sev_dev_suspend(sp->psp_data, state);
	return 0;
}

int psp_request_tee_irq(struct psp_device *psp, irq_handler_t handler,
			void *data)
{
	psp->tee_irq_data = data;
	psp->tee_irq_handler = handler;

	return 0;
}

int psp_free_tee_irq(struct psp_device *psp, void *data)
{
	if (psp->tee_irq_handler) {
		psp->tee_irq_data = NULL;
		psp->tee_irq_handler = NULL;
	}

	return 0;
}

int psp_request_sev_irq(struct psp_device *psp, irq_handler_t handler,
			void *data)
{
	psp->sev_irq_data = data;
	psp->sev_irq_handler = handler;

	return 0;
}

int psp_free_sev_irq(struct psp_device *psp, void *data)
{
	if (psp->sev_irq_handler) {
		psp->sev_irq_data = NULL;
		psp->sev_irq_handler = NULL;
	}

	return 0;
}

struct psp_device *psp_get_master_device(void)
{
	struct sp_device *sp = sp_get_psp_master_device();

	return sp ? sp->psp_data : NULL;
}
