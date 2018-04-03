/* SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2016-2018 Microsoft Corporation
 *   Copyright(c) 2013-2016 Brocade Communications Systems, Inc.
 *   All rights reserved.
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <strings.h>

#include <rte_ethdev.h>
#include <rte_memcpy.h>
#include <rte_string_fns.h>
#include <rte_memzone.h>
#include <rte_malloc.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <rte_common.h>
#include <rte_errno.h>
#include <rte_memory.h>
#include <rte_eal.h>
#include <rte_dev.h>
#include <rte_bus_vmbus.h>
#include <rte_spinlock.h>

#include "hn_logs.h"
#include "hn_var.h"
#include "hn_rndis.h"
#include "hn_nvs.h"
#include "ndis.h"

#define HN_NVS_SEND_MSG_SIZE \
	(sizeof(struct vmbus_chanpkt_hdr) + sizeof(struct hn_nvs_rndis))

#define HN_TXD_CACHE_SIZE	32 /* per cpu tx_descriptor pool cache */

struct hn_rxinfo {
	uint32_t	vlan_info;
	uint32_t	csum_info;
	uint32_t	hash_info;
	uint32_t	hash_value;
};
#define HN_RXINFO_VLAN			0x0001
#define HN_RXINFO_CSUM			0x0002
#define HN_RXINFO_HASHINF		0x0004
#define HN_RXINFO_HASHVAL		0x0008
#define HN_RXINFO_ALL			\
	(HN_RXINFO_VLAN |		\
	 HN_RXINFO_CSUM |		\
	 HN_RXINFO_HASHINF |		\
	 HN_RXINFO_HASHVAL)

#define HN_NDIS_VLAN_INFO_INVALID	0xffffffff
#define HN_NDIS_RXCSUM_INFO_INVALID	0
#define HN_NDIS_HASH_INFO_INVALID	0

/*
 * Per-transmit book keeping.
 * A slot in transmit ring (chim_index) is reserved for each transmit.
 *
 * There are two types of transmit:
 *   - buffered transmit where chimney buffer is used and RNDIS header
 *     is in the buffer. mbuf == NULL for this case.
 *
 *   - direct transmit where RNDIS header is in the in  rndis_pkt
 *     mbuf is freed after transmit.
 *
 * Descriptors come from per-port pool which is used
 * to limit number of outstanding requests per device.
 */
struct hn_txdesc {
	struct rte_mbuf *m;

	uint16_t	queue_id;
	uint16_t	chim_index;
	uint32_t	chim_size;
	uint32_t	data_size;
	uint32_t	packets;

	struct rndis_packet_msg *rndis_pkt;
};

#define HN_RNDIS_PKT_LEN				\
	(sizeof(struct rndis_packet_msg) +		\
	 RNDIS_PKTINFO_SIZE(NDIS_HASH_VALUE_SIZE) +	\
	 RNDIS_PKTINFO_SIZE(NDIS_VLAN_INFO_SIZE) +	\
	 RNDIS_PKTINFO_SIZE(NDIS_LSO2_INFO_SIZE) +	\
	 RNDIS_PKTINFO_SIZE(NDIS_TXCSUM_INFO_SIZE))

/* Threshold where chimney (copy) is used for small packets */
#define HN_CHIM_THRESHOLD	(HN_RNDIS_PKT_LEN + 256)

/* Minimum space required for a packet */
#define HN_PKTSIZE_MIN(align) \
	RTE_ALIGN(ETHER_MIN_LEN + HN_RNDIS_PKT_LEN, align)

#define DEFAULT_TX_FREE_THRESH 32U

static inline unsigned int hn_rndis_pktlen(const struct rndis_packet_msg *pkt)
{
	return pkt->pktinfooffset + pkt->pktinfolen;
}

static inline uint32_t
hn_rndis_pktmsg_offset(uint32_t ofs)
{
	return ofs - offsetof(struct rndis_packet_msg, dataoffset);
}

static void hn_txd_init(struct rte_mempool *mp __rte_unused,
			void *opaque, void *obj, unsigned int idx)
{
	struct hn_txdesc *txd = obj;
	struct rte_eth_dev *dev = opaque;
	struct rndis_packet_msg *pkt;

	memset(txd, 0, sizeof(*txd));
	txd->chim_index = idx;

	pkt = rte_malloc_socket("RNDIS_TX", HN_RNDIS_PKT_LEN,
				RTE_CACHE_LINE_SIZE, dev->device->numa_node);
	if (pkt == NULL)
		rte_exit(EXIT_FAILURE, "can not allocate RNDIS header");

	txd->rndis_pkt = pkt;
}

/*
 * Unlike Linux and FreeBSD, this driver uses a mempool
 * to limit outstanding transmits and reserve buffers
 */
int
hn_tx_pool_init(struct rte_eth_dev *dev)
{
	struct hn_data *hv = dev->data->dev_private;
	char name[RTE_MEMPOOL_NAMESIZE];
	struct rte_mempool *mp;

	snprintf(name, sizeof(name),
		 "hn_txd_%u", dev->data->port_id);

	PMD_INIT_LOG(DEBUG, "create a TX send pool %s n=%u size=%zu socket=%d",
		     name, hv->chim_cnt, sizeof(struct hn_txdesc),
		     dev->device->numa_node);

	mp = rte_mempool_create(name, hv->chim_cnt, sizeof(struct hn_txdesc),
				HN_TXD_CACHE_SIZE, 0,
				NULL, NULL,
				hn_txd_init, dev,
				dev->device->numa_node, 0);
	if (mp == NULL) {
		PMD_DRV_LOG(ERR,
			    "mempool %s create failed: %d", name, rte_errno);
		return -rte_errno;
	}

	hv->tx_pool = mp;
	return 0;
}

static void hn_reset_txagg(struct hn_tx_queue *txq)
{
	txq->agg_szleft = txq->agg_szmax;
	txq->agg_pktleft = txq->agg_pktmax;
	txq->agg_txd = NULL;
	txq->agg_prevpkt = NULL;
}

int
hn_dev_tx_queue_setup(struct rte_eth_dev *dev,
		      uint16_t queue_idx, uint16_t nb_desc __rte_unused,
		      unsigned int socket_id,
		      const struct rte_eth_txconf *tx_conf)

{
	struct hn_data *hv = dev->data->dev_private;
	struct hn_tx_queue *txq;
	uint32_t tx_free_thresh;

	PMD_INIT_FUNC_TRACE();

	txq = rte_zmalloc_socket("HN_TXQ", sizeof(*txq), RTE_CACHE_LINE_SIZE,
				 socket_id);
	if (!txq)
		return -ENOMEM;

	txq->hv = hv;
	txq->chan = hv->channels[queue_idx];
	txq->port_id = dev->data->port_id;
	txq->queue_id = queue_idx;

	tx_free_thresh = tx_conf->tx_free_thresh;
	if (tx_free_thresh == 0)
		tx_free_thresh = RTE_MIN(hv->chim_cnt / 4,
					 DEFAULT_TX_FREE_THRESH);

	if (tx_free_thresh >= hv->chim_cnt - 3) {
		RTE_LOG(ERR, PMD, "tx_free_thresh must be less than the "
			"number of TX entries minus 3 (%u)."
			" (tx_free_thresh=%u port=%u queue=%u)\n",
			hv->chim_cnt - 3,
			tx_free_thresh, dev->data->port_id, queue_idx);
		return -EINVAL;
	}

	txq->free_thresh = tx_free_thresh;

	txq->agg_szmax  = RTE_MIN(hv->chim_szmax, hv->rndis_agg_size);
	txq->agg_pktmax = hv->rndis_agg_pkts;
	txq->agg_align  = hv->rndis_agg_align;

	hn_reset_txagg(txq);

	PMD_DRV_LOG(INFO,
		    "tx queue aggregation packets=%u bytes=%u align=%u",
		    txq->agg_pktmax, txq->agg_szmax, txq->agg_align);

	dev->data->tx_queues[queue_idx] = txq;

	return 0;
}

void
hn_dev_tx_queue_release(void *arg)
{
	struct hn_tx_queue *txq = arg;
	struct hn_txdesc *txd;

	PMD_INIT_FUNC_TRACE();

	if (!txq)
		return;

	/* If any pending data is still present just drop it */
	txd = txq->agg_txd;
	if (txd)
		rte_mempool_put(txq->hv->tx_pool, txd);

	rte_free(txq);
}

static void
hn_nvs_send_completed(struct rte_eth_dev *dev,
		      uint16_t queue_id,
		      unsigned long xactid)
{
	struct hn_txdesc *txd = (struct hn_txdesc *)xactid;
	struct hn_tx_queue *txq;

	/* Control packets are sent with xacid == 0 */
	if (!txd)
		return;

	txq = dev->data->tx_queues[queue_id];

	PMD_TX_LOG(DEBUG, "port %u:%u complete tx %u mbuf %p size %u",
		   txq->port_id, txq->queue_id,
		   txd->chim_index, txd->m, txd->data_size);

	txq->stats.bytes += txd->data_size;
	txq->stats.packets += txd->packets;
	rte_pktmbuf_free(txd->m);

	rte_mempool_put(txq->hv->tx_pool, txd);
}

/* Handle transmit completion events */
static void
hn_nvs_handle_comp(struct rte_eth_dev *dev, uint16_t queue_id,
		   const struct vmbus_chanpkt_hdr *pkt,
		   const void *data)
{
	const struct hn_nvs_hdr *hdr = data;

	switch (hdr->type) {
	case NVS_TYPE_RNDIS_ACK:
		hn_nvs_send_completed(dev, queue_id, pkt->xactid);
		break;

	default:
		PMD_TX_LOG(NOTICE,
			   "unexpected send completion type %u",
			   hdr->type);
	}
}

/* Parse per-packet info (meta data) */
static int
hn_rndis_rxinfo(const void *info_data, unsigned int info_dlen,
		struct hn_rxinfo *info)
{
	const struct rndis_pktinfo *pi = info_data;
	uint32_t mask = 0;

	while (info_dlen != 0) {
		const void *data;
		uint32_t dlen;

		if (unlikely(info_dlen < sizeof(*pi)))
			return -EINVAL;

		if (unlikely(info_dlen < pi->size))
			return -EINVAL;
		info_dlen -= pi->size;

		if (unlikely(pi->size & RNDIS_PKTINFO_SIZE_ALIGNMASK))
			return -EINVAL;
		if (unlikely(pi->size < pi->offset))
			return -EINVAL;

		dlen = pi->size - pi->offset;
		data = pi->data;

		switch (pi->type) {
		case NDIS_PKTINFO_TYPE_VLAN:
			if (unlikely(dlen < NDIS_VLAN_INFO_SIZE))
				return -EINVAL;
			info->vlan_info = *((const uint32_t *)data);
			mask |= HN_RXINFO_VLAN;
			break;

		case NDIS_PKTINFO_TYPE_CSUM:
			if (unlikely(dlen < NDIS_RXCSUM_INFO_SIZE))
				return -EINVAL;
			info->csum_info = *((const uint32_t *)data);
			mask |= HN_RXINFO_CSUM;
			break;

		case NDIS_PKTINFO_TYPE_HASHVAL:
			if (unlikely(dlen < NDIS_HASH_VALUE_SIZE))
				return -EINVAL;
			info->hash_value = *((const uint32_t *)data);
			mask |= HN_RXINFO_HASHVAL;
			break;

		case NDIS_PKTINFO_TYPE_HASHINF:
			if (unlikely(dlen < NDIS_HASH_INFO_SIZE))
				return -EINVAL;
			info->hash_info = *((const uint32_t *)data);
			mask |= HN_RXINFO_HASHINF;
			break;

		default:
			goto next;
		}

		if (mask == HN_RXINFO_ALL)
			break; /* All found; done */
next:
		pi = (const struct rndis_pktinfo *)
		    ((const uint8_t *)pi + pi->size);
	}

	/*
	 * Final fixup.
	 * - If there is no hash value, invalidate the hash info.
	 */
	if (!(mask & HN_RXINFO_HASHVAL))
		info->hash_info = HN_NDIS_HASH_INFO_INVALID;
	return 0;
}

/* XXX this could be optimized */
static struct rte_mbuf *hn_build_mbuf(struct rte_mempool *mp,
				      const uint8_t *data, unsigned int dlen)
{
	struct rte_mbuf *m0 = NULL;
	struct rte_mbuf **top = &m0;
	uint32_t chunk;

	while (dlen > 0) {
		struct rte_mbuf *m;

		m = rte_pktmbuf_alloc(mp);
		if (unlikely(m == NULL)) {
			rte_pktmbuf_free(m0);
			return NULL;
		}

		*top = m;
		top = &m->next;

		chunk = RTE_MIN(dlen, rte_pktmbuf_tailroom(m));
		rte_memcpy(rte_pktmbuf_append(m, chunk),
			   data, chunk);

		data += chunk;
		dlen -= chunk;
	}

	return m0;
}

static void hn_rxpkt(struct hn_rx_queue *rxq, const void *data,
		     unsigned int dlen,
		     const struct hn_rxinfo *info)
{
	struct rte_mbuf *m;

	if (unlikely(dlen < ETHER_HDR_LEN)) {
		PMD_RX_LOG(NOTICE, "runt packet len %u", dlen);
		++rxq->stats.errors;
		return;
	}

	m = hn_build_mbuf(rxq->mb_pool, data, dlen);
	if (unlikely(m == NULL)) {
		struct rte_eth_dev *dev
			= &rte_eth_devices[rxq->port_id];
		dev->data->rx_mbuf_alloc_failed++;
		return;
	}

	m->port = rxq->port_id;
	m->ol_flags = 0;

	if (info->vlan_info != HN_NDIS_VLAN_INFO_INVALID) {
		m->vlan_tci = info->vlan_info;
		m->ol_flags |= PKT_RX_VLAN_STRIPPED | PKT_RX_VLAN;
	}

	if (info->csum_info != HN_NDIS_RXCSUM_INFO_INVALID) {
		if (info->csum_info & NDIS_RXCSUM_INFO_IPCS_OK)
			m->ol_flags |= PKT_RX_IP_CKSUM_GOOD;

		if (info->csum_info & (NDIS_RXCSUM_INFO_UDPCS_OK
				       | NDIS_RXCSUM_INFO_TCPCS_OK))
			m->ol_flags |= PKT_RX_L4_CKSUM_GOOD;
	}

	if (info->hash_info != HN_NDIS_HASH_INFO_INVALID) {
		m->ol_flags |= PKT_RX_RSS_HASH;
		m->hash.rss = info->hash_value;
	}

	PMD_RX_LOG(DEBUG, "port %u:%u RX size %u flags %#" PRIx64,
		   rxq->port_id, rxq->queue_id,
		   m->pkt_len, m->ol_flags);

	if (likely(rte_ring_sp_enqueue(rxq->rx_ring, m) == 0)) {
		++rxq->stats.packets;
		rxq->stats.bytes += m->pkt_len;
	} else {
		++rxq->ring_full;
		rte_pktmbuf_free(m);
	}
}

static void hn_rndis_rx_data(struct hn_rx_queue *rxq,
			     const void *data, uint32_t dlen)
{
	unsigned int data_off, data_len, pktinfo_off, pktinfo_len;
	const struct rndis_packet_msg *pkt;
	struct hn_rxinfo info = {
		.vlan_info = HN_NDIS_VLAN_INFO_INVALID,
		.csum_info = HN_NDIS_RXCSUM_INFO_INVALID,
		.hash_info = HN_NDIS_HASH_INFO_INVALID,
	};
	int err;

	if (unlikely(dlen < sizeof(*pkt))) {
		PMD_RX_LOG(ERR, "invalid RNDIS packet message");
		return;
	}


	pkt = data;

	if (unlikely(dlen < pkt->len)) {
		PMD_RX_LOG(ERR, "truncated RNDIS packet message, (%u < %u)",
			    dlen, pkt->len);
		return;
	}

	if (unlikely(pkt->len < pkt->datalen
		     + pkt->oobdatalen + pkt->pktinfolen)) {
		PMD_RX_LOG(ERR,
			   "invalid RNDIS packet len %u, data %u, oob %u, pktinfo %u",
			   pkt->len, pkt->datalen, pkt->oobdatalen,
			   pkt->pktinfolen);
		return;
	}

	if (unlikely(pkt->datalen == 0)) {
		PMD_RX_LOG(ERR, "invalid RNDIS packet message, no data");
		return;
	}

	/*
	 * Check offsets.
	 */
#define IS_OFFSET_INVALID(ofs)			\
	((ofs) < RNDIS_PACKET_MSG_OFFSET_MIN ||	\
	 ((ofs) & RNDIS_PACKET_MSG_OFFSET_ALIGNMASK))

	/* XXX Hyper-V does not meet data offset alignment requirement */
	if (unlikely(pkt->dataoffset < RNDIS_PACKET_MSG_OFFSET_MIN)) {
		PMD_DRV_LOG(ERR, "invalid RNDIS packet data offset %u",
			    pkt->dataoffset);
		return;
	}

	if (likely(pkt->pktinfooffset > 0) &&
	    unlikely(IS_OFFSET_INVALID(pkt->pktinfooffset))) {
		PMD_DRV_LOG(ERR, "invalid RNDIS packet pktinfo offset %u",
			    pkt->pktinfooffset);
		return;
	}
#undef IS_OFFSET_INVALID

	data_off = RNDIS_PACKET_MSG_OFFSET_ABS(pkt->dataoffset);
	data_len = pkt->datalen;
	pktinfo_off = RNDIS_PACKET_MSG_OFFSET_ABS(pkt->pktinfooffset);
	pktinfo_len = pkt->pktinfolen;

	if (likely(pktinfo_len > 0)) {
		err = hn_rndis_rxinfo((const uint8_t *)pkt + pktinfo_off,
				      pktinfo_len, &info);
		if (err) {
			PMD_DRV_LOG(ERR, "invalid RNDIS packet info");
			return;
		}
	}

	if (unlikely(data_off + data_len > pkt->len)) {
		PMD_DRV_LOG(ERR,
			    "invalid RNDIS data len %u, data abs %d len %d",
			    pkt->len, data_off, data_len);
		return;
	}

	hn_rxpkt(rxq, (const uint8_t *)pkt + data_off, data_len, &info);
}

static void
hn_rndis_receive(const struct rte_eth_dev *dev,
		 struct hn_rx_queue *rxq, const void *buf, uint32_t len)
{
	const struct rndis_msghdr *hdr = buf;

	switch (hdr->type) {
	case RNDIS_PACKET_MSG:
		if (dev->data->dev_started)
			hn_rndis_rx_data(rxq, buf, len);
		break;

	case RNDIS_INDICATE_STATUS_MSG:
		hn_rndis_link_status(rxq->hv, buf);
		break;

	case RNDIS_INITIALIZE_CMPLT:
	case RNDIS_QUERY_CMPLT:
	case RNDIS_SET_CMPLT:
		hn_rndis_receive_response(rxq->hv, buf, len);
		break;

	default:
		PMD_DRV_LOG(NOTICE,
			    "unexpected RNDIS message (type %#x len %u)",
			    hdr->type, len);
		break;
	}
}

static void
hn_nvs_handle_rxbuf(struct rte_eth_dev *dev,
		    struct hn_data *hv,
		    struct hn_rx_queue *rxq,
		    const struct vmbus_chanpkt_hdr *hdr,
		    const void *buf)
{
	const struct vmbus_chanpkt_rxbuf *pkt;
	const struct hn_nvs_hdr *nvs_hdr = buf;
	uint32_t rxbuf_sz = hv->rxbuf_res->len;
	char *rxbuf = hv->rxbuf_res->addr;
	unsigned int i, hlen, count;

	/* At minimum we need type header */
	if (unlikely(vmbus_chanpkt_datalen(hdr) < sizeof(*nvs_hdr))) {
		PMD_RX_LOG(ERR, "invalid receive nvs RNDIS");
		return;
	}

	/* Make sure that this is a RNDIS message. */
	if (unlikely(nvs_hdr->type != NVS_TYPE_RNDIS)) {
		PMD_RX_LOG(ERR, "nvs type %u, not RNDIS",
			    nvs_hdr->type);
		return;
	}

	hlen = vmbus_chanpkt_getlen(hdr->hlen);
	if (unlikely(hlen < sizeof(*pkt))) {
		PMD_RX_LOG(ERR, "invalid rxbuf chanpkt");
		return;
	}

	pkt = container_of(hdr, const struct vmbus_chanpkt_rxbuf, hdr);
	if (unlikely(pkt->rxbuf_id != NVS_RXBUF_SIG)) {
		PMD_RX_LOG(ERR, "invalid rxbuf_id 0x%08x",
			    pkt->rxbuf_id);
		return;
	}

	count = pkt->rxbuf_cnt;
	if (unlikely(hlen < offsetof(struct vmbus_chanpkt_rxbuf,
				     rxbuf[count]))) {
		PMD_RX_LOG(ERR, "invalid rxbuf_cnt %u", count);
		return;
	}

	/* Each range represents 1 RNDIS pkt that contains 1 Ethernet frame */
	for (i = 0; i < count; ++i) {
		unsigned int ofs, len;

		ofs = pkt->rxbuf[i].ofs;
		len = pkt->rxbuf[i].len;

		if (unlikely(ofs + len > rxbuf_sz)) {
			PMD_RX_LOG(ERR,
				    "%uth RNDIS msg overflow ofs %u, len %u",
				    i, ofs, len);
			continue;
		}

		if (unlikely(len == 0)) {
			PMD_RX_LOG(ERR, "%uth RNDIS msg len %u", i, len);
			continue;
		}

		hn_rndis_receive(dev, rxq, rxbuf + ofs, len);
	}

	/*
	 * Ack the consumed RXBUF associated w/ this channel packet,
	 * so that this RXBUF can be recycled by the hypervisor.
	 */
	hn_nvs_ack_rxbuf(rxq, pkt->hdr.xactid);
}

struct hn_rx_queue *hn_rx_queue_alloc(struct hn_data *hv,
				      uint16_t queue_id,
				      unsigned int socket_id)
{
	struct hn_rx_queue *rxq;

	rxq = rte_zmalloc_socket("HN_RXQ", sizeof(*rxq),
				 RTE_CACHE_LINE_SIZE, socket_id);
	if (rxq) {
		rxq->hv = hv;
		rxq->chan = hv->channels[queue_id];
		rte_spinlock_init(&rxq->ring_lock);
		rxq->port_id = hv->port_id;
		rxq->queue_id = queue_id;
	}
	return rxq;
}

int
hn_dev_rx_queue_setup(struct rte_eth_dev *dev,
		      uint16_t queue_idx, uint16_t nb_desc,
		      unsigned int socket_id,
		      const struct rte_eth_rxconf *rx_conf __rte_unused,
		      struct rte_mempool *mp)
{
	struct hn_data *hv = dev->data->dev_private;
	uint32_t qmax = hv->rxbuf_section_cnt;
	char ring_name[RTE_RING_NAMESIZE];
	struct hn_rx_queue *rxq;
	unsigned int count;
	size_t size;
	int err;

	PMD_INIT_FUNC_TRACE();

	if (nb_desc == 0 || nb_desc > qmax)
		nb_desc = qmax;

	if (queue_idx == 0) {
		rxq = hv->primary;
	} else {
		rxq = hn_rx_queue_alloc(hv, queue_idx, socket_id);
		if (!rxq)
			return -ENOMEM;
	}

	count = rte_align32pow2(nb_desc);
	size = sizeof(struct rte_ring) + count * sizeof(void *);
	rxq->rx_ring = rte_malloc_socket("RX_RING", size,
					 RTE_CACHE_LINE_SIZE,
					 socket_id);
	if (!rxq->rx_ring) {
		rte_free(rxq);
		return -ENOMEM;
	}
	rxq->mb_pool = mp;

	/*
	 * Staging ring from receive event logic to rx_pkts.
	 * rx_pkts assumes caller is handling multi-thread issue.
	 * event logic has locking.
	 */
	snprintf(ring_name, sizeof(ring_name),
		 "hn_rx_%u_%u", dev->data->port_id, queue_idx);
	err = rte_ring_init(rxq->rx_ring, ring_name,
			    count, 0);
	if (err) {
		rte_free(rxq->rx_ring);
		rte_free(rxq);
		return err;
	}

	dev->data->rx_queues[queue_idx] = rxq;
	return 0;
}

void
hn_dev_rx_queue_release(void *arg)
{
	struct hn_rx_queue *rxq = arg;

	PMD_INIT_FUNC_TRACE();

	if (!rxq)
		return;

	rte_free(rxq->rx_ring);
	rxq->rx_ring = NULL;
	rxq->mb_pool = NULL;

	if (rxq != rxq->hv->primary)
		rte_free(rxq);
}

static void
hn_nvs_handle_notify(const struct vmbus_chanpkt_hdr *pkthdr,
		     const void *data)
{
	const struct hn_nvs_hdr *hdr = data;

	if (unlikely(vmbus_chanpkt_datalen(pkthdr) < sizeof(*hdr))) {
		PMD_DRV_LOG(ERR, "invalid nvs notify");
		return;
	}

	PMD_DRV_LOG(INFO,
		    "got notify, nvs type %u", hdr->type);
}

/*
 * Process pending events on the channel.
 * Called from both Rx queue poll and Tx cleanup
 */
void hn_process_events(struct hn_data *hv, uint16_t queue_id)
{
	struct rte_eth_dev *dev = &rte_eth_devices[hv->port_id];
	struct hn_rx_queue *rxq;
	int ret = 0;

	rxq = queue_id == 0 ? hv->primary : dev->data->rx_queues[queue_id];

	/* If no pending data then nothing to do */
	if (rte_vmbus_chan_rx_empty(rxq->chan))
		return;

	/*
	 * Since channel is shared between Rx and TX queue need to have a lock
	 * since DPDK does not force same CPU to be used for Rx/Tx.
	 */
	if (unlikely(!rte_spinlock_trylock(&rxq->ring_lock)))
		return;

	for (;;) {
		char event_buf[NVS_RESPSIZE_MAX];
		uint32_t len = sizeof(event_buf);
		const struct vmbus_chanpkt_hdr *pkt;
		const void *data;

		ret = rte_vmbus_chan_recv_raw(rxq->chan, event_buf, &len);
		if (ret == -ENOBUFS) {
			rte_exit(EXIT_FAILURE,
				 "event buffer size %u not large enough for %u",
				 NVS_RESPSIZE_MAX, len);
		}
		if (ret != 0)
			break;

		pkt = (const struct vmbus_chanpkt_hdr *)event_buf;
		data = event_buf + vmbus_chanpkt_getlen(pkt->hlen);

		switch (pkt->type) {
		case VMBUS_CHANPKT_TYPE_COMP:
			hn_nvs_handle_comp(dev, queue_id, pkt, data);
			break;

		case VMBUS_CHANPKT_TYPE_RXBUF:
			hn_nvs_handle_rxbuf(dev, hv, rxq, pkt, data);
			break;

		case VMBUS_CHANPKT_TYPE_INBAND:
			hn_nvs_handle_notify(pkt, data);
			break;

		default:
			PMD_DRV_LOG(ERR,
				    "unknown chan pkt %u", pkt->type);
			break;
		}
	}
	rte_spinlock_unlock(&rxq->ring_lock);

	if (unlikely(ret != -EAGAIN)) {
		PMD_DRV_LOG(ERR,
			    "channel receive failed: %d",
			    ret);
	}
}


/* Return start of section of send buffer */
static inline void *hn_chim_addr(const struct hn_data *hv,
				 const struct hn_txdesc *txd,
				 uint32_t offset)
{
	return (uint8_t *)hv->chim_res->addr
		+ txd->chim_index * hv->chim_szmax + offset;
}

static void hn_append_to_chim(struct hn_tx_queue *txq,
			      struct rndis_packet_msg *pkt,
			      const struct rte_mbuf *m)
{
	struct hn_txdesc *txd = txq->agg_txd;
	uint8_t *buf = (uint8_t *)pkt;
	unsigned int data_offs;

	data_offs = RNDIS_PACKET_MSG_OFFSET_ABS(pkt->dataoffset);
	txd->chim_size += pkt->len;
	txd->data_size += m->pkt_len;
	++txd->packets;

	for (; m; m = m->next) {
		uint16_t len = rte_pktmbuf_data_len(m);

		rte_memcpy(buf + data_offs,
			   rte_pktmbuf_mtod(m, const char *), len);
		data_offs += len;
	}
}

/*
 * Send pending aggregated data in chimney buffer (if any).
 * Returns error if send was unsuccessful because channel ring buffer
 * was full.
 */
static int hn_flush_txagg(struct hn_tx_queue *txq, bool *need_sig)

{
	struct hn_txdesc *txd = txq->agg_txd;
	struct hn_nvs_rndis rndis;
	int ret;

	if (!txd)
		return 0;

	PMD_TX_LOG(DEBUG,
		   "port %u:%u send chim index %u size %u packets %u size %u",
		   txq->port_id, txq->queue_id,
		   txd->chim_index, txd->chim_size,
		   txd->packets, txd->data_size);

	rndis = (struct hn_nvs_rndis) {
		.type = NVS_TYPE_RNDIS,
		.rndis_mtype = NVS_RNDIS_MTYPE_DATA,
		.chim_idx = txd->chim_index,
		.chim_sz = txd->chim_size,
	};

	ret = hn_nvs_send(txq->chan, VMBUS_CHANPKT_FLAG_RC,
			  &rndis, sizeof(rndis), (uintptr_t)txd, need_sig);

	if (likely(ret == 0))
		hn_reset_txagg(txq);

	return ret;
}

static struct hn_txdesc *hn_new_txd(struct hn_data *hv,
				    const struct hn_tx_queue *txq)
{
	struct hn_txdesc *txd;

	if (unlikely(rte_mempool_get(hv->tx_pool, (void **)&txd)))
		return NULL;

	txd->m = NULL;
	txd->queue_id = txq->queue_id;
	txd->packets = 0;
	txd->data_size = 0;
	txd->chim_size = 0;

	return txd;
}

static void *
hn_try_txagg(struct hn_data *hv, struct hn_tx_queue *txq, uint32_t pktsize)
{
	struct hn_txdesc *agg_txd = txq->agg_txd;
	struct rndis_packet_msg *pkt;
	void *chim;

	if (agg_txd) {
		unsigned int padding, olen;

		/*
		 * Update the previous RNDIS packet's total length,
		 * it can be increased due to the mandatory alignment
		 * padding for this RNDIS packet.  And update the
		 * aggregating txdesc's chimney sending buffer size
		 * accordingly.
		 *
		 * Zero-out the padding, as required by the RNDIS spec.
		 */
		pkt = txq->agg_prevpkt;
		olen = pkt->len;
		padding = RTE_ALIGN(olen, txq->agg_align) - olen;
		if (padding > 0) {
			agg_txd->chim_size += padding;
			pkt->len += padding;
			memset((uint8_t *)pkt + olen, 0, padding);
		}

		chim = (uint8_t *) pkt + pkt->len;

		txq->agg_pktleft--;
		txq->agg_szleft -= pktsize;
		if (txq->agg_szleft < HN_PKTSIZE_MIN(txq->agg_align)) {
			/*
			 * Probably can't aggregate more packets,
			 * flush this aggregating txdesc proactively.
			 */
			txq->agg_pktleft = 0;
		}
	} else {
		agg_txd = hn_new_txd(hv, txq);
		if (!agg_txd)
			return NULL;

		chim = (uint8_t *)hv->chim_res->addr
			+ agg_txd->chim_index * hv->chim_szmax;

		txq->agg_txd = agg_txd;
		txq->agg_pktleft = txq->agg_pktmax - 1;
		txq->agg_szleft = txq->agg_szmax - pktsize;
	}
	txq->agg_prevpkt = chim;

	return chim;
}

static inline void *
hn_rndis_pktinfo_append(struct rndis_packet_msg *pkt,
			uint32_t pi_dlen, uint32_t pi_type)
{
	const uint32_t pi_size = RNDIS_PKTINFO_SIZE(pi_dlen);
	struct rndis_pktinfo *pi;

	/*
	 * Per-packet-info does not move; it only grows.
	 *
	 * NOTE:
	 * pktinfooffset in this phase counts from the beginning
	 * of rndis_packet_msg.
	 */
	pi = (struct rndis_pktinfo *)((uint8_t *)pkt + hn_rndis_pktlen(pkt));

	pkt->pktinfolen += pi_size;

	pi->size = pi_size;
	pi->type = pi_type;
	pi->offset = RNDIS_PKTINFO_OFFSET;

	return pi->data;
}

/* Put RNDIS header and packet info on packet */
static void hn_encap(struct rndis_packet_msg *pkt,
		     uint16_t queue_id,
		     const struct rte_mbuf *m)
{
	unsigned int hlen = m->l2_len + m->l3_len;
	uint32_t *pi_data;
	uint32_t pkt_hlen;

	pkt->type = RNDIS_PACKET_MSG;
	pkt->len = m->pkt_len;
	pkt->dataoffset = 0;
	pkt->datalen = m->pkt_len;
	pkt->oobdataoffset = 0;
	pkt->oobdatalen = 0;
	pkt->oobdataelements = 0;
	pkt->pktinfooffset = sizeof(*pkt);
	pkt->pktinfolen = 0;
	pkt->vchandle = 0;
	pkt->reserved = 0;

	/*
	 * Set the hash value for this packet, to the queue_id to cause
	 * TX done event for this packet on the right channel.
	 */
	pi_data = hn_rndis_pktinfo_append(pkt, NDIS_HASH_VALUE_SIZE,
					  NDIS_PKTINFO_TYPE_HASHVAL);
	*pi_data = queue_id;

	if (m->ol_flags & PKT_TX_VLAN_PKT) {
		pi_data = hn_rndis_pktinfo_append(pkt,
				NDIS_VLAN_INFO_SIZE, NDIS_PKTINFO_TYPE_VLAN);
		*pi_data = m->vlan_tci;
	}

	if (m->ol_flags & PKT_TX_TCP_SEG) {
		pi_data = hn_rndis_pktinfo_append(pkt,
				NDIS_LSO2_INFO_SIZE, NDIS_PKTINFO_TYPE_LSO);

		if (m->ol_flags & PKT_TX_IPV6) {
			*pi_data = NDIS_LSO2_INFO_MAKEIPV6(hlen,
							   m->tso_segsz);
		} else {
			*pi_data = NDIS_LSO2_INFO_MAKEIPV4(hlen,
							   m->tso_segsz);
		}
	} else if (m->ol_flags &
		   (PKT_TX_TCP_CKSUM | PKT_TX_UDP_CKSUM | PKT_TX_IP_CKSUM)) {
		pi_data = hn_rndis_pktinfo_append(pkt,
				NDIS_TXCSUM_INFO_SIZE, NDIS_PKTINFO_TYPE_CSUM);
		*pi_data = 0;

		if (m->ol_flags & PKT_TX_IPV6)
			*pi_data |= NDIS_TXCSUM_INFO_IPV6;
		if (m->ol_flags & PKT_TX_IPV4) {
			*pi_data |= NDIS_TXCSUM_INFO_IPV4;

			if (m->ol_flags & PKT_TX_IP_CKSUM)
				*pi_data |= NDIS_TXCSUM_INFO_IPCS;
		}

		if (m->ol_flags & PKT_TX_TCP_CKSUM)
			*pi_data |= NDIS_TXCSUM_INFO_MKTCPCS(hlen);
		else if (m->ol_flags & PKT_TX_UDP_CKSUM)
			*pi_data |= NDIS_TXCSUM_INFO_MKUDPCS(hlen);
	}

	pkt_hlen = pkt->pktinfooffset + pkt->pktinfolen;
	/* Fixup RNDIS packet message total length */
	pkt->len += pkt_hlen;

	/* Convert RNDIS packet message offsets */
	pkt->dataoffset = hn_rndis_pktmsg_offset(pkt_hlen);
	pkt->pktinfooffset = hn_rndis_pktmsg_offset(pkt->pktinfooffset);
}

/* Build scatter gather list from chained mbuf */
static inline int hn_xmit_sg(struct hn_tx_queue *txq,
			     struct hn_txdesc *txd,
			     struct rte_mbuf *m,
			     bool *need_sig)
{
	unsigned int segs = m->nb_segs + 1;
	struct vmbus_gpa sg[segs];
	rte_iova_t addr;
	unsigned int i;

	PMD_TX_LOG(DEBUG, "port %u:%u sg mbuf %p segs %u size %u",
		   txq->port_id, txq->queue_id, m, segs,
		   txd->data_size);

	/* pass IOVA of rndis header in first segment */
	addr = rte_malloc_virt2iova(txd->rndis_pkt);
	sg[0].page = addr / PAGE_SIZE;
	sg[0].ofs = addr & PAGE_MASK;
	sg[0].len = hn_rndis_pktlen(txd->rndis_pkt);

	for (i = 1; i < segs; i++, m = m->next) {
		addr = rte_mbuf_data_iova(m);
		sg[i].page = addr / PAGE_SIZE;
		sg[i].ofs = addr & PAGE_MASK;
		sg[i].len = rte_pktmbuf_data_len(m);
	}

	return hn_nvs_send_rndis_sglist(txq->chan, NVS_RNDIS_MTYPE_DATA,
					(uintptr_t)txd, sg, segs, need_sig);
}

uint16_t
hn_xmit_pkts(void *ptxq, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	struct hn_tx_queue *txq = ptxq;
	struct hn_data *hv = txq->hv;
	bool need_sig = false;
	uint16_t nb_tx;
	int ret;

	if (unlikely(hv->closed))
		return 0;

	if (rte_mempool_avail_count(hv->tx_pool) <= txq->free_thresh)
		hn_process_events(hv, txq->queue_id);

	for (nb_tx = 0; nb_tx < nb_pkts; nb_tx++) {
		struct rte_mbuf *m = tx_pkts[nb_tx];
		uint32_t pkt_size = m->pkt_len + HN_RNDIS_PKT_LEN;
		struct rndis_packet_msg *pkt;

		/* For small packets aggregate them in chimney buffer */
		if (m->pkt_len + HN_RNDIS_PKT_LEN < HN_CHIM_THRESHOLD) {
			/* If this packet will not fit, then flush  */
			if (RTE_ALIGN(pkt_size, txq->agg_align) < txq->agg_szleft)
				if (hn_flush_txagg(txq, &need_sig))
					goto fail;

			pkt = hn_try_txagg(hv, txq, pkt_size);
			if (unlikely(pkt == NULL))
				goto fail;

			hn_encap(pkt, txq->queue_id, m);
			hn_append_to_chim(txq, pkt, m);

			rte_pktmbuf_free(m);

			/* if buffer is full, flush */
			if (txq->agg_pktleft == 0 &&
			    hn_flush_txagg(txq, &need_sig))
				goto fail;
		} else {
			struct hn_txdesc *txd;

			/* flush pending buffer first */
			if (hn_flush_txagg(txq, &need_sig))
				goto fail;

			/* Send larger packets directly */
			txd = hn_new_txd(hv, txq);
			if (unlikely(txd == NULL))
				goto fail;

			pkt = txd->rndis_pkt;
			txd->m = m;
			txd->data_size = m->pkt_len;
			txd->packets = 1;

			hn_encap(pkt, txq->queue_id, m);

			ret = hn_xmit_sg(txq, txd, m, &need_sig);
			if (unlikely(ret != 0)) {
				PMD_TX_LOG(ERR, "sg send failed: %d", ret);
				rte_mempool_put(hv->tx_pool, txd);
				goto fail;
			}
		}
	}

	/* If partial buffer left, then try and send it.
	 * if that fails, then reuse it on next send.
	 */
	hn_flush_txagg(txq, &need_sig);

fail:
	if (need_sig)
		rte_vmbus_chan_signal_tx(txq->chan);

	return nb_tx;
}

uint16_t
hn_recv_pkts(void *prxq, struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	struct hn_rx_queue *rxq = prxq;
	struct hn_data *hv = rxq->hv;

	if (unlikely(hv->closed))
		return 0;

	/* Get all outstanding receive completions */
	hn_process_events(hv, rxq->queue_id);

	/* Get mbufs off staging ring */
	return rte_ring_sc_dequeue_burst(rxq->rx_ring, (void **)rx_pkts,
					 nb_pkts, NULL);
}
