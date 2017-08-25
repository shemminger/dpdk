..  BSD LICENSE
    Copyright(c) Microsoft Corporation.  All rights reserved.
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions
    are met:

    * Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in
    the documentation and/or other materials provided with the
    distribution.
    * Neither the name of Microsoft Corporation nor the names of its
    contributors may be used to endorse or promote products derived
    from this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
    A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
    OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
    SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
    LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
    DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
    THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
    OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Poll Mode Driver for Hyper-V Network Virtual NIC
================================================

The Microsoft Hyper-V hypervisor supports a para-virtualized network interface that is
visible on the virtual machine bus (VMBUS).
In the Data Plane Development Kit (DPDK), we provide a Netwwork Virtual Service Client (NetVSC)
Poll Mode Driver (PMD). The NetVSC PMD supports Windows Server 2016 and Microsoft Azure cloud.

NetVSC Implementation in DPDK
-----------------------------

The Netvsc PMD is a standalone driver. VMBus network devices that are being used by DPDK must be
unbound from the Linux kernel driver (hv_netvsc) and bound to the Userspace IO driver
for Hyper-V (uio_hv_generic).

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

*   SR-IOV accleration is not supported yet.


Prerequisites
-------------

The following prerequisites apply:

*   Linux kernel  uio_hv_generic driver that supports subchannels. This should be present in 4.17 or later.

*   If using the Hyper-V PMD, the VDEV_NETVSC driver should *not* be used.
