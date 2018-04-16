..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) Microsoft Corporation.

Netvsc (Hyper-V) poll mode driver.
================================================

Hyper-V is a hypervisor integrated into Window Server 2008, Windows 10
and later versions.  It supports a para-virtualized network interface
called netvsc that is visible on the virtual machine bus (VMBUS).  In
the Data Plane Development Kit (DPDK), we provide a Network Virtual
Service Client (NetVSC) Poll Mode Driver (PMD). The NetVSC PMD
supports Windows Server 2016 and Microsoft Azure cloud.

NetVSC Implementation in DPDK
-----------------------------

The Netvsc PMD is a standalone driver. VMBus network devices that are
being used by DPDK must be unbound from the Linux kernel driver
(hv_netvsc) and bound to the Userspace IO driver for Hyper-V
(uio_hv_generic).

This is most conveniently done with the
.. _`driverctl`: https://gitlab.com/driverctl/driverctl
script.

To list all VMBusus network devices:

    .. code-block:: console

	driverctl -b vmbus -v list-devices | grep netvsc


To override default kernel device with DPDK uio it is necessary to first determine the GUID associated with a particular existing Ethernet device then pass that to ``driverctl``.

    .. code-block:: console

	GUID=$(basename $(readlink /sys/class/net/eth1/device))
	driverctl -b vmbus set-override $GUID uio_hv_generic


The kernel must be version 5.0 or later to allow driver_override to work. With older kernels ethernet must be rebound manually using sysfs bind and unbind.

    .. code-block:: console

	NET_GUID="f8615163-df3e-46c5-913f-f2d2f965ed0e"
	DEV_GUID=$(basename $(readlink /sys/class/net/eth1/device))
	modprobe uio_hv_generic
	echo $NET_GUID > /sys/bus/vmbus/drivers/uio_hv_generic/new_id
	echo $DEV_GUID > /sys/bus/vmbus/drivers/hv_netvsc/unbind
	echo $DEV_GUID > /sys/bus/vmbus/drivers/uio_hv_generic/bind

.. Note::

   The dpkd-devbind.py script should not be used. It only handles PCI devices.



Features and Limitations of Hyper-V PMD
---------------------------------------

In this release, the hyper PMD driver provides the basic functionality of packet reception and transmission.

*   It supports merge-able buffers per packet when receiving packets and scattered buffer per packet
    when transmitting packets. The packet size supported is from 64 to 65536.

*   It supports multicast packets and promiscuous mode. In order to this to work, the guest network
    configuration on Hyper-V must be configured to allow this as well.

*   Hyper-V driver does not support MAC or VLAN filtering because the host does not support it.
    The device has only a single MAC address.

*   VLAN tags are always stripped and presented in mbuf tci field.

*   The Hyper-V driver does not use or support Link State or Rx interrupt.

*   The number of queues is limited by the host (currently 64).
    When used with 4.16 kernel only a single queue is available.

*   This driver is intended for use with synthetic path only.
    Accelerated Networking (SR-IOV) acceleration is not supported yet.
    Use the VDEV_NETVSC device for accelerated networking instead.


Prerequisites
-------------

The following prerequisites apply:

*   Linux kernel support for UIO on vmbus is done with the uio_hv_generic driver.
    This driver was originally added in 4.14 kernel, but that version lacks necessary
    features for networking. The 4.16 kernel will work but is limited to a single queue.
    Supporting multiple queues (subchannels) required additional changes
    which were added in 5.0.

*   VMBus uses Universal Unique Identifiers (UUID) to identify devices.
    Therefore the netvsc and vmbus drivers require the libuuid library
    to be installed.
