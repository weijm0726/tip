/*
 * AMD Platform Security Processor (PSP) interface driver
 *
 * Copyright (C) 2017 Advanced Micro Devices, Inc.
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __PSP_DEV_H__
#define __PSP_DEV_H__

#include <linux/device.h>
#include <linux/pci.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/dmapool.h>
#include <linux/hw_random.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/irqreturn.h>
#include <linux/dmaengine.h>

#include "sp-dev.h"

#define PSP_P2CMSG_INTEN		0x0110
#define PSP_P2CMSG_INTSTS		0x0114

#define PSP_C2PMSG_ATTR_0		0x0118
#define PSP_C2PMSG_ATTR_1		0x011c
#define PSP_C2PMSG_ATTR_2		0x0120
#define PSP_C2PMSG_ATTR_3		0x0124
#define PSP_P2CMSG_ATTR_0		0x0128

#define PSP_CMDRESP_CMD_SHIFT		16
#define PSP_CMDRESP_IOC			BIT(0)
#define PSP_CMDRESP_RESP		BIT(31)
#define PSP_CMDRESP_ERR_MASK		0xffff

#define MAX_PSP_NAME_LEN		16

struct psp_device {
	struct list_head entry;

	struct psp_vdata *vdata;
	char name[MAX_PSP_NAME_LEN];

	struct device *dev;
	struct sp_device *sp;

	void __iomem *io_regs;

	irq_handler_t sev_irq_handler;
	void *sev_irq_data;
	irq_handler_t tee_irq_handler;
	void *tee_irq_data;

	void *sev_data;
	void *tee_data;
};

void psp_add_device(struct psp_device *psp);
void psp_del_device(struct psp_device *psp);

int psp_request_sev_irq(struct psp_device *psp, irq_handler_t handler,
			void *data);
int psp_free_sev_irq(struct psp_device *psp, void *data);

int psp_request_tee_irq(struct psp_device *psp, irq_handler_t handler,
			void *data);
int psp_free_tee_irq(struct psp_device *psp, void *data);

struct psp_device *psp_get_master_device(void);

extern const struct psp_vdata psp_entry;
#ifdef CONFIG_CRYPTO_DEV_PSP_SEV

int sev_dev_init(struct psp_device *psp);
void sev_dev_destroy(struct psp_device *psp);
int sev_dev_resume(struct psp_device *psp);
int sev_dev_suspend(struct psp_device *psp, pm_message_t state);

#else /* !CONFIG_CRYPTO_DEV_PSP_SEV */

static inline int sev_dev_init(struct psp_device *psp)
{
	return -ENODEV;
}

static inline void sev_dev_destroy(struct psp_device *psp) { }

static inline int sev_dev_resume(struct psp_device *psp)
{
	return -ENODEV;
}

static inline int sev_dev_suspend(struct psp_device *psp, pm_message_t state)
{
	return -ENODEV;
}

#endif /* CONFIG_CRYPTO_DEV_PSP_SEV */

#endif /* __PSP_DEV_H */
