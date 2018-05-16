/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Microsoft Corp.
 * All rights reserved.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/uio.h>

#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_bus_vmbus.h>
#include <rte_pci.h>
#include <rte_bus_pci.h>
#include <rte_log.h>

#include "hn_logs.h"
#include "hn_var.h"
#include "hn_nvs.h"

#define SYSFS_PCI_SLOTS "/sys/bus/pci/slots"

static int hn_vf_pipe[2] = { -1, -1 };
static pthread_t hn_vf_thread;

/* Open /sys/bus/pci/slots/N/address and read PCI address */
static int hn_vf_read_slot(const char *path, struct rte_pci_addr *addr)
{
	unsigned int domain, bus, id;
	char line[PCI_PRI_STR_SIZE];
	FILE  *f;
	int ret = 0;

	f = fopen(path, "r");
	if (!f) {
		PMD_DRV_LOG(NOTICE, "can't open %s: %s",
			    path, strerror(errno));
		return -errno;
	}

	if (fgets(line, sizeof(line), f) == NULL) {
		ret = -errno;
		PMD_DRV_LOG(NOTICE, "can't read %s: %s",
			    path, strerror(errno));
	} else if (sscanf(line, "%x:%x:%x", &domain, &bus, &id) != 3) {
		PMD_DRV_LOG(NOTICE, "invalid address %s: %s",
			    path, line);
		ret = -EINVAL;
	} else {
		addr->domain = domain;
		addr->bus = bus;
		addr->devid = id;
		addr->function = 0;
	}

	fclose(f);
	return ret;
}

/*
 * Search for VF with matching serial #, return PCI address if found
 * This depends on the new /sys/bus/pci/slots/N directory which provides
 * a way to map serial number to PCI device.
 */
static int hn_vf_match(uint32_t serial, struct rte_pci_addr *addr)
{
	const char *sysfs_path = rte_pci_get_sysfs_path();
	struct dirent *ent;
	DIR *d;

	d = opendir(SYSFS_PCI_SLOTS);
	if (d == NULL) {
		PMD_DRV_LOG(ERR, "Can't open %s: %s",
			    sysfs_path, strerror(errno));
		return -1;
	}

	while ((ent = readdir(d))) {
		unsigned long slot_nr;
		char path[PATH_MAX];
		char *ep;

		if (ent->d_name[0] == '.')
			continue;

		slot_nr = strtoul(ent->d_name, &ep, 0);
		if (*ep) {
			PMD_DRV_LOG(INFO,
				    "skipping invalid PCI slot: %s",
				    ent->d_name);
			continue;
		}

		if (slot_nr != serial)
			continue;

		snprintf(path, sizeof(path), SYSFS_PCI_SLOTS "/%lu/address",
			 slot_nr);

		closedir(d);
		return hn_vf_read_slot(path, addr);
	}
	closedir(d);

	return 0;
}

/*
 * Map PCI address to EAL device name used for hotplug.
 * Only have to support PCI here.
 */
static void hn_pci_devname(char *devname, size_t len, const struct rte_pci_addr *addr)
{
	snprintf(devname, len, PCI_PRI_FMT,
		 addr->domain, addr->bus, addr->devid, addr->function);
}

/*
 * Find DPDK Ethernet device (port_id) which matches a device name
 */
static int hn_vf_eth_find(const char *devname, uint16_t *port_id)
{
	uint16_t pid;

	for (pid = 0; pid < RTE_MAX_ETHPORTS; pid++) {
		const struct rte_eth_dev *dev = &rte_eth_devices[pid];

		if (!rte_eth_dev_is_valid_port(pid))
			continue;

		PMD_DRV_LOG(DEBUG, "port %u name '%s'?", pid, dev->device->name);
		if (strcmp(devname, dev->device->name) == 0) {
			*port_id = pid;
			return 0;
		}
	}

	return -ENOENT;
}

/*
 * Attach new PCI VF device and return the port_id
 */
static int hn_vf_attach(struct hn_data *hv,
			const struct rte_pci_addr *addr,
			struct rte_eth_dev **vf_dev)
{
	char devname[RTE_DEV_NAME_MAX_LEN];
	struct rte_eth_dev_owner owner;
	uint16_t port_id;
	int ret;

	hn_pci_devname(devname, sizeof(devname), addr);
	if (hn_vf_eth_find(devname, &port_id) < 0) {
		ret = rte_eal_hotplug_add("pci", devname, "");
		if (ret != 0) {
			PMD_DRV_LOG(NOTICE, "hotplug failed for %s:%s",
				    devname, strerror(errno));
			return ret;
		}

		ret = hn_vf_eth_find(devname, &port_id);
		if (ret < 0) {
			PMD_DRV_LOG(NOTICE,
				    "No matching port found for %s", devname);
			return ret;
		}
	}

	ret = rte_eth_dev_owner_get(port_id, &owner);
	if (ret < 0) {
		PMD_DRV_LOG(ERR, "Can not find owner for port %d", port_id);
		return ret;
	}

	if (owner.id != hv->owner.id) {
		if (owner.id != RTE_ETH_DEV_NO_OWNER) {
			PMD_DRV_LOG(ERR, "Port %u already owned by other device %s",
				    port_id, owner.name);
			return -EBUSY;
		}

		ret = rte_eth_dev_owner_set(port_id, &hv->owner);
		if (ret < 0) {
			PMD_DRV_LOG(ERR, "Can set owner for port %d", port_id);
			return ret;
		}
	}

	PMD_DRV_LOG(INFO, "Attached VF device %s port %u", devname, port_id);
	*vf_dev = &rte_eth_devices[port_id];
	return 0;
}

/*
 * Add new VF device based on serial number to synthetic device
 */
static void hn_vf_add(struct rte_eth_dev *dev, uint32_t serial)
{
	struct hn_data *hv = dev->data->dev_private;
	struct rte_pci_addr addr;
	struct rte_eth_dev *vf_dev;

	if (hn_vf_match(serial, &addr)) {
		PMD_DRV_LOG(NOTICE, "No matching PCI found for %u", serial);
		return;
	}

	rte_spinlock_lock(&hv->vf_lock);
	if (hn_vf_attach(hv, &addr, &vf_dev) == 0) {

		/* XXX configure VF to have same RSS and queues as synthetic path */

		/* Start processing from VF */
		hv->vf_dev = vf_dev;
		dev->tx_pkt_burst = vf_dev->tx_pkt_burst;
	}
	rte_spinlock_unlock(&hv->vf_lock);

	hn_nvs_set_datapath(hv, NVS_DATAPATH_VF);
}

/*
 * Remove new VF device
 * Serial number is only used as a safety check.
 */
static void hn_vf_remove(struct rte_eth_dev *dev, uint32_t serial)
{
	struct hn_data *hv = dev->data->dev_private;
	struct rte_eth_dev *vf_dev = hv->vf_dev;
	char devname[RTE_DEV_NAME_MAX_LEN];
	struct rte_pci_addr addr;
	uint16_t port_id;

	if (vf_dev == NULL) {
		PMD_DRV_LOG(ERR, "VF path not active");
		return;
	}

	if (hn_vf_match(serial, &addr)) {
		PMD_DRV_LOG(ERR, "No matching PCI found for %u", serial);
		return;
	}

	hn_pci_devname(devname, sizeof(devname), &addr);
	if (hn_vf_eth_find(devname, &port_id) != 0) {
		PMD_DRV_LOG(ERR, "No ethdev found for %s", devname);
		return;
	}

	if (port_id != vf_dev->data->port_id) {
		PMD_DRV_LOG(ERR, "VF port_id does not match %u != %u",
			    port_id, hv->vf_dev->data->port_id);
		return;
	}

	hn_nvs_set_datapath(hv, NVS_DATAPATH_SYNTHETIC);

	/* Stop incoming packets from arriving on VF */
	rte_spinlock_lock(&hv->vf_lock);
	dev->tx_pkt_burst = &hn_xmit_pkts;
	hv->vf_dev = NULL;
	rte_spinlock_unlock(&hv->vf_lock);

	/* Give back ownership */
	rte_eth_dev_owner_unset(vf_dev->data->port_id, hv->owner.id);

	if (rte_eal_hotplug_remove("pci", devname) == 0)
		PMD_DRV_LOG(INFO, "Removed VF device %s", devname);
	else
		PMD_DRV_LOG(ERR, "Hotplug remove VF device %s failed", devname);
}

/* Handle VF association message from host */
static void
hn_nvs_handle_vfassoc(struct rte_eth_dev *dev,
		      const struct hn_nvs_vf_association *vf_assoc)
{
	PMD_DRV_LOG(DEBUG, "VF serial %u %s port %u",
		    vf_assoc->serial,
		    vf_assoc->allocated ? "add to" : "remove from",
		    dev->data->port_id);

	if (vf_assoc->allocated)
		hn_vf_add(dev, vf_assoc->serial);
	else
		hn_vf_remove(dev, vf_assoc->serial);
}

/* If VF is present, then cascade configuration down */
typedef void (*vf_ctrl_fn)(uint16_t port_id);

static void vf_call_func(struct rte_eth_dev *dev,
			 vf_ctrl_fn func)
{
	struct hn_data *hv = dev->data->dev_private;
	struct rte_eth_dev *vf_dev;

	rte_spinlock_lock(&hv->vf_lock);
	vf_dev = hv->vf_dev;
	if (vf_dev)
		func(vf_dev->data->port_id);
	rte_spinlock_unlock(&hv->vf_lock);
}

/* Configure VF if present.
 * Force VF to have same number of queues as synthetic device
 */
int hn_vf_dev_configure(struct rte_eth_dev *dev)
{
	const struct rte_eth_conf *dev_conf = &dev->data->dev_conf;
	struct hn_data *hv = dev->data->dev_private;
	struct rte_eth_dev *vf_dev;
	int ret = 0;

	rte_spinlock_lock(&hv->vf_lock);
	vf_dev = hv->vf_dev;
	if (vf_dev)
		ret = rte_eth_dev_configure(vf_dev->data->port_id,
					    dev->data->nb_rx_queues,
					    dev->data->nb_tx_queues,
					    dev_conf);
	rte_spinlock_unlock(&hv->vf_lock);
	return ret;
}

int hn_vf_dev_start(struct rte_eth_dev *dev)
{

	struct hn_data *hv = dev->data->dev_private;
	struct rte_eth_dev *vf_dev;
	int ret = 0;

	rte_spinlock_lock(&hv->vf_lock);
	vf_dev = hv->vf_dev;
	if (vf_dev)
		ret = rte_eth_dev_start(vf_dev->data->port_id);
	rte_spinlock_unlock(&hv->vf_lock);
	return ret;
}

void hn_vf_dev_reset(struct rte_eth_dev *dev)
{
	vf_call_func(dev, (vf_ctrl_fn)rte_eth_dev_reset);
}

void hn_vf_dev_stop(struct rte_eth_dev *dev)
{
	vf_call_func(dev, rte_eth_dev_stop);
}

void hn_vf_dev_close(struct rte_eth_dev *dev)
{
	vf_call_func(dev, rte_eth_dev_close);
}

void hn_vf_stats_reset(struct rte_eth_dev *dev)
{
	vf_call_func(dev, (vf_ctrl_fn)rte_eth_stats_reset);
}

int hn_vf_stats_get(struct rte_eth_dev *dev,
		    struct rte_eth_stats *stats)
{
	struct hn_data *hv = dev->data->dev_private;
	struct rte_eth_dev *vf_dev;
	int ret = 0;

	rte_spinlock_lock(&hv->vf_lock);
	vf_dev = hv->vf_dev;
	if (vf_dev)
		ret = rte_eth_stats_get(vf_dev->data->port_id, stats);
	rte_spinlock_unlock(&hv->vf_lock);
	return ret;
}

/* Handle inband notifications from host */
static void hn_vf_notify(struct rte_eth_dev *dev,
			 const void *buf, size_t len)
{
	const struct hn_nvs_hdr *hdr = buf;

	switch (hdr->type) {
	case NVS_TYPE_TXTBL_NOTE:
		/* Transmit indirection table has locking problems
		 * in DPDK and therefore not implemented
		 */
		PMD_DRV_LOG(DEBUG, "host notify of transmit indirection table");
		break;

	case NVS_TYPE_VFASSOC_NOTE:
		if (len < sizeof(struct hn_nvs_vf_association))
			PMD_DRV_LOG(ERR, "invalid vf association event");
		else
			hn_nvs_handle_vfassoc(dev, buf);
		break;

	default:
		PMD_DRV_LOG(INFO,
			    "got notify, nvs type %u", hdr->type);
	}
}

/*
 * Thread that reads pipe containing NVS events from host
 * Done in a seperate thread since doing VF registration is expensive.
 */
static void *
hn_vf_handler(void *arg __rte_unused)
{
	char event[BUFSIZ];
	uint16_t port_id;
	struct iovec iov[2];
	int cc;

	PMD_INIT_LOG(DEBUG, "VF event handler started");

	for (;;) {
		iov[0].iov_base = &port_id;
		iov[0].iov_len = sizeof(port_id);
		iov[1].iov_base = event;
		iov[1].iov_len = sizeof(event);

		cc = readv(hn_vf_pipe[0], iov, 2);
		if (cc < (int)sizeof(port_id) + (int)sizeof(struct hn_nvs_hdr))
			break;

		hn_vf_notify(&rte_eth_devices[port_id],
			     event, cc - sizeof(port_id));
	}

	if (cc < 0) {
		PMD_DRV_LOG(ERR, "VF event read failed: %s",
			    strerror(errno));
	}
	return NULL;
}

/*
 * Called when NVS inband events are received.
 * Send up a two part message with port_id and the NVS message
 * to the pipe to the netvsc-vf-event control thread.
 */
void hn_nvs_handle_notify(struct rte_eth_dev *dev,
			  const struct vmbus_chanpkt_hdr *pkt,
			  void *data)
{
	size_t len = vmbus_chanpkt_datalen(pkt);
	uint16_t port_id = dev->data->port_id;;
	struct iovec iov[2];

	if (unlikely(len < sizeof(struct hn_nvs_hdr))) {
		PMD_DRV_LOG(ERR, "invalid nvs notify");
		return;
	}

	iov[0].iov_base = &port_id;
	iov[0].iov_len = sizeof(port_id);
	iov[1].iov_base = data;
	iov[1].iov_len = len;

	if (writev(hn_vf_pipe[1], iov, 2) < 0)
		PMD_DRV_LOG(ERR, "write to nvs notify pipe failed");

}

/* Setup thread to handle VF discovery events */
void hn_vf_thread_setup(void)
{
	/* open pipe, use O_DIRECT so that messages are atomic */
	if (pipe2(hn_vf_pipe, O_CLOEXEC | O_DIRECT) < 0) {
		PMD_INIT_LOG(ERR, "VF create pipe failed: %s",
			     strerror(errno));
		return;
	}

	if (rte_ctrl_thread_create(&hn_vf_thread, "netvsc-vf-event", NULL,
				   hn_vf_handler, NULL) < 0) {
		PMD_INIT_LOG(ERR, "VF thread create failed: %s",
			     strerror(errno));
		return;
	}
}
