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

#ifndef __SEV_DEV_H__
#define __SEV_DEV_H__

#include <linux/device.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/interrupt.h>
#include <linux/irqreturn.h>
#include <linux/miscdevice.h>

#include <linux/psp-sev.h>

#define PSP_C2PMSG(_num)		((_num) << 2)
#define PSP_CMDRESP			PSP_C2PMSG(32)
#define PSP_CMDBUFF_ADDR_LO		PSP_C2PMSG(56)
#define PSP_CMDBUFF_ADDR_HI             PSP_C2PMSG(57)
#define PSP_FEATURE_REG			PSP_C2PMSG(63)

#define PSP_P2CMSG(_num)		(_num << 2)
#define PSP_CMD_COMPLETE_REG		1
#define PSP_CMD_COMPLETE		PSP_P2CMSG(PSP_CMD_COMPLETE_REG)

#define MAX_PSP_NAME_LEN		16
#define SEV_DEFAULT_TIMEOUT		5

struct sev_device {
	struct list_head entry;

	struct dentry *debugfs;
	struct miscdevice misc;

	unsigned int id;
	char name[MAX_PSP_NAME_LEN];

	struct device *dev;
	struct sp_device *sp;
	struct psp_device *psp;

	void __iomem *io_regs;

	unsigned int int_rcvd;
	wait_queue_head_t int_queue;
};

void sev_add_device(struct sev_device *sev);
void sev_del_device(struct sev_device *sev);

int sev_ops_init(struct sev_device *sev);
void sev_ops_destroy(struct sev_device *sev);

int sev_issue_cmd(int cmd, void *data, int *error);

#endif /* __SEV_DEV_H */
