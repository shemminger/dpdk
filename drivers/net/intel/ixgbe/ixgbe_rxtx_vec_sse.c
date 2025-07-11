/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <stdint.h>
#include <ethdev_driver.h>
#include <rte_malloc.h>

#include "ixgbe_ethdev.h"
#include "ixgbe_rxtx.h"
#include "ixgbe_rxtx_vec_common.h"

#include "../common/rx_vec_x86.h"

#include <rte_vect.h>

static inline void
ixgbe_rxq_rearm(struct ci_rx_queue *rxq)
{
	RTE_BUILD_BUG_ON(sizeof(union ci_rx_desc) != sizeof(union ixgbe_adv_rx_desc));
	ci_rxq_rearm(rxq, CI_RX_VEC_LEVEL_SSE);
}

#ifdef RTE_LIB_SECURITY
static inline void
desc_to_olflags_v_ipsec(__m128i descs[4], struct rte_mbuf **rx_pkts)
{
	__m128i sterr, rearm, tmp_e, tmp_p;
	uint32_t *rearm0 = (uint32_t *)rx_pkts[0]->rearm_data + 2;
	uint32_t *rearm1 = (uint32_t *)rx_pkts[1]->rearm_data + 2;
	uint32_t *rearm2 = (uint32_t *)rx_pkts[2]->rearm_data + 2;
	uint32_t *rearm3 = (uint32_t *)rx_pkts[3]->rearm_data + 2;
	const __m128i ipsec_sterr_msk =
			_mm_set1_epi32(IXGBE_RXDADV_IPSEC_STATUS_SECP |
				       IXGBE_RXDADV_IPSEC_ERROR_AUTH_FAILED);
	const __m128i ipsec_proc_msk  =
			_mm_set1_epi32(IXGBE_RXDADV_IPSEC_STATUS_SECP);
	const __m128i ipsec_err_flag  =
			_mm_set1_epi32(RTE_MBUF_F_RX_SEC_OFFLOAD_FAILED |
				       RTE_MBUF_F_RX_SEC_OFFLOAD);
	const __m128i ipsec_proc_flag = _mm_set1_epi32(RTE_MBUF_F_RX_SEC_OFFLOAD);

	rearm = _mm_set_epi32(*rearm3, *rearm2, *rearm1, *rearm0);
	sterr = _mm_set_epi32(_mm_extract_epi32(descs[3], 2),
			      _mm_extract_epi32(descs[2], 2),
			      _mm_extract_epi32(descs[1], 2),
			      _mm_extract_epi32(descs[0], 2));
	sterr = _mm_and_si128(sterr, ipsec_sterr_msk);
	tmp_e = _mm_cmpeq_epi32(sterr, ipsec_sterr_msk);
	tmp_p = _mm_cmpeq_epi32(sterr, ipsec_proc_msk);
	sterr = _mm_or_si128(_mm_and_si128(tmp_e, ipsec_err_flag),
				_mm_and_si128(tmp_p, ipsec_proc_flag));
	rearm = _mm_or_si128(rearm, sterr);
	*rearm0 = _mm_extract_epi32(rearm, 0);
	*rearm1 = _mm_extract_epi32(rearm, 1);
	*rearm2 = _mm_extract_epi32(rearm, 2);
	*rearm3 = _mm_extract_epi32(rearm, 3);
}
#endif

static inline void
desc_to_olflags_v(__m128i descs[4], __m128i mbuf_init, uint8_t vlan_flags,
		  uint16_t udp_p_flag, struct rte_mbuf **rx_pkts)
{
	__m128i ptype0, ptype1, vtag0, vtag1, csum, udp_csum_skip;
	__m128i rearm0, rearm1, rearm2, rearm3;

	/* mask everything except rss type */
	const __m128i rsstype_msk = _mm_set_epi16(
			0x0000, 0x0000, 0x0000, 0x0000,
			0x000F, 0x000F, 0x000F, 0x000F);

	/* mask the lower byte of ol_flags */
	const __m128i ol_flags_msk = _mm_set_epi16(
			0x0000, 0x0000, 0x0000, 0x0000,
			0x00FF, 0x00FF, 0x00FF, 0x00FF);

	/* map rss type to rss hash flag */
	const __m128i rss_flags = _mm_set_epi8(RTE_MBUF_F_RX_FDIR, 0, 0, 0,
			0, 0, 0, RTE_MBUF_F_RX_RSS_HASH,
			RTE_MBUF_F_RX_RSS_HASH, 0, RTE_MBUF_F_RX_RSS_HASH, 0,
			RTE_MBUF_F_RX_RSS_HASH, RTE_MBUF_F_RX_RSS_HASH, RTE_MBUF_F_RX_RSS_HASH, 0);

	/* mask everything except vlan present and l4/ip csum error */
	const __m128i vlan_csum_msk = _mm_set_epi16(
		(IXGBE_RXDADV_ERR_TCPE | IXGBE_RXDADV_ERR_IPE) >> 16,
		(IXGBE_RXDADV_ERR_TCPE | IXGBE_RXDADV_ERR_IPE) >> 16,
		(IXGBE_RXDADV_ERR_TCPE | IXGBE_RXDADV_ERR_IPE) >> 16,
		(IXGBE_RXDADV_ERR_TCPE | IXGBE_RXDADV_ERR_IPE) >> 16,
		IXGBE_RXD_STAT_VP, IXGBE_RXD_STAT_VP,
		IXGBE_RXD_STAT_VP, IXGBE_RXD_STAT_VP);

	/* map vlan present (0x8), IPE (0x2), L4E (0x1) to ol_flags */
	const __m128i vlan_csum_map_lo = _mm_set_epi8(
		0, 0, 0, 0,
		vlan_flags | RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_BAD,
		vlan_flags | RTE_MBUF_F_RX_IP_CKSUM_BAD,
		vlan_flags | RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_BAD,
		vlan_flags | RTE_MBUF_F_RX_IP_CKSUM_GOOD,
		0, 0, 0, 0,
		RTE_MBUF_F_RX_IP_CKSUM_BAD | RTE_MBUF_F_RX_L4_CKSUM_BAD,
		RTE_MBUF_F_RX_IP_CKSUM_BAD,
		RTE_MBUF_F_RX_IP_CKSUM_GOOD | RTE_MBUF_F_RX_L4_CKSUM_BAD,
		RTE_MBUF_F_RX_IP_CKSUM_GOOD);

	const __m128i vlan_csum_map_hi = _mm_set_epi8(
		0, 0, 0, 0,
		0, RTE_MBUF_F_RX_L4_CKSUM_GOOD >> sizeof(uint8_t), 0,
		RTE_MBUF_F_RX_L4_CKSUM_GOOD >> sizeof(uint8_t),
		0, 0, 0, 0,
		0, RTE_MBUF_F_RX_L4_CKSUM_GOOD >> sizeof(uint8_t), 0,
		RTE_MBUF_F_RX_L4_CKSUM_GOOD >> sizeof(uint8_t));

	/* mask everything except UDP header present if specified */
	const __m128i udp_hdr_p_msk = _mm_set_epi16
		(0, 0, 0, 0,
		 udp_p_flag, udp_p_flag, udp_p_flag, udp_p_flag);

	const __m128i udp_csum_bad_shuf = _mm_set_epi8
		(0, 0, 0, 0, 0, 0, 0, 0,
		 0, 0, 0, 0, 0, 0, ~(uint8_t)RTE_MBUF_F_RX_L4_CKSUM_BAD, 0xFF);

	ptype0 = _mm_unpacklo_epi16(descs[0], descs[1]);
	ptype1 = _mm_unpacklo_epi16(descs[2], descs[3]);
	vtag0 = _mm_unpackhi_epi16(descs[0], descs[1]);
	vtag1 = _mm_unpackhi_epi16(descs[2], descs[3]);

	ptype0 = _mm_unpacklo_epi32(ptype0, ptype1);
	/* save the UDP header present information */
	udp_csum_skip = _mm_and_si128(ptype0, udp_hdr_p_msk);
	ptype0 = _mm_and_si128(ptype0, rsstype_msk);
	ptype0 = _mm_shuffle_epi8(rss_flags, ptype0);

	vtag1 = _mm_unpacklo_epi32(vtag0, vtag1);
	vtag1 = _mm_and_si128(vtag1, vlan_csum_msk);

	/* csum bits are in the most significant, to use shuffle we need to
	 * shift them. Change mask to 0xc000 to 0x0003.
	 */
	csum = _mm_srli_epi16(vtag1, 14);

	/* now or the most significant 64 bits containing the checksum
	 * flags with the vlan present flags.
	 */
	csum = _mm_srli_si128(csum, 8);
	vtag1 = _mm_or_si128(csum, vtag1);

	/* convert VP, IPE, L4E to ol_flags */
	vtag0 = _mm_shuffle_epi8(vlan_csum_map_hi, vtag1);
	vtag0 = _mm_slli_epi16(vtag0, sizeof(uint8_t));

	vtag1 = _mm_shuffle_epi8(vlan_csum_map_lo, vtag1);
	vtag1 = _mm_and_si128(vtag1, ol_flags_msk);
	vtag1 = _mm_or_si128(vtag0, vtag1);

	vtag1 = _mm_or_si128(ptype0, vtag1);

	/* convert the UDP header present 0x200 to 0x1 for aligning with each
	 * RTE_MBUF_F_RX_L4_CKSUM_BAD value in low byte of 16 bits word ol_flag in
	 * vtag1 (4x16). Then mask out the bad checksum value by shuffle and
	 * bit-mask.
	 */
	udp_csum_skip = _mm_srli_epi16(udp_csum_skip, 9);
	udp_csum_skip = _mm_shuffle_epi8(udp_csum_bad_shuf, udp_csum_skip);
	vtag1 = _mm_and_si128(vtag1, udp_csum_skip);

	/*
	 * At this point, we have the 4 sets of flags in the low 64-bits
	 * of vtag1 (4x16).
	 * We want to extract these, and merge them with the mbuf init data
	 * so we can do a single 16-byte write to the mbuf to set the flags
	 * and all the other initialization fields. Extracting the
	 * appropriate flags means that we have to do a shift and blend for
	 * each mbuf before we do the write.
	 */
	rearm0 = _mm_blend_epi16(mbuf_init, _mm_slli_si128(vtag1, 8), 0x10);
	rearm1 = _mm_blend_epi16(mbuf_init, _mm_slli_si128(vtag1, 6), 0x10);
	rearm2 = _mm_blend_epi16(mbuf_init, _mm_slli_si128(vtag1, 4), 0x10);
	rearm3 = _mm_blend_epi16(mbuf_init, _mm_slli_si128(vtag1, 2), 0x10);

	/* write the rearm data and the olflags in one write */
	RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, ol_flags) !=
			offsetof(struct rte_mbuf, rearm_data) + 8);
	RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, rearm_data) !=
			RTE_ALIGN(offsetof(struct rte_mbuf, rearm_data), 16));
	_mm_store_si128((__m128i *)&rx_pkts[0]->rearm_data, rearm0);
	_mm_store_si128((__m128i *)&rx_pkts[1]->rearm_data, rearm1);
	_mm_store_si128((__m128i *)&rx_pkts[2]->rearm_data, rearm2);
	_mm_store_si128((__m128i *)&rx_pkts[3]->rearm_data, rearm3);
}

static inline uint32_t get_packet_type(int index,
				       uint32_t pkt_info,
				       uint32_t etqf_check,
				       uint32_t tunnel_check)
{
	if (etqf_check & (0x02 << (index * IXGBE_VPMD_DESCS_PER_LOOP)))
		return RTE_PTYPE_UNKNOWN;

	if (tunnel_check & (0x02 << (index * IXGBE_VPMD_DESCS_PER_LOOP))) {
		pkt_info &= IXGBE_PACKET_TYPE_MASK_TUNNEL;
		return ptype_table_tn[pkt_info];
	}

	pkt_info &= IXGBE_PACKET_TYPE_MASK_82599;
	return ptype_table[pkt_info];
}

static inline void
desc_to_ptype_v(__m128i descs[4], uint16_t pkt_type_mask,
		struct rte_mbuf **rx_pkts)
{
	__m128i etqf_mask = _mm_set_epi64x(0x800000008000LL, 0x800000008000LL);
	__m128i ptype_mask = _mm_set_epi32(
		pkt_type_mask, pkt_type_mask, pkt_type_mask, pkt_type_mask);
	__m128i tunnel_mask =
		_mm_set_epi64x(0x100000001000LL, 0x100000001000LL);

	uint32_t etqf_check, tunnel_check, pkt_info;

	__m128i ptype0 = _mm_unpacklo_epi32(descs[0], descs[2]);
	__m128i ptype1 = _mm_unpacklo_epi32(descs[1], descs[3]);

	/* interleave low 32 bits,
	 * now we have 4 ptypes in a XMM register
	 */
	ptype0 = _mm_unpacklo_epi32(ptype0, ptype1);

	/* create a etqf bitmask based on the etqf bit. */
	etqf_check = _mm_movemask_epi8(_mm_and_si128(ptype0, etqf_mask));

	/* shift left by IXGBE_PACKET_TYPE_SHIFT, and apply ptype mask */
	ptype0 = _mm_and_si128(_mm_srli_epi32(ptype0, IXGBE_PACKET_TYPE_SHIFT),
			       ptype_mask);

	/* create a tunnel bitmask based on the tunnel bit */
	tunnel_check = _mm_movemask_epi8(
		_mm_slli_epi32(_mm_and_si128(ptype0, tunnel_mask), 0x3));

	pkt_info = _mm_extract_epi32(ptype0, 0);
	rx_pkts[0]->packet_type =
		get_packet_type(0, pkt_info, etqf_check, tunnel_check);
	pkt_info = _mm_extract_epi32(ptype0, 1);
	rx_pkts[1]->packet_type =
		get_packet_type(1, pkt_info, etqf_check, tunnel_check);
	pkt_info = _mm_extract_epi32(ptype0, 2);
	rx_pkts[2]->packet_type =
		get_packet_type(2, pkt_info, etqf_check, tunnel_check);
	pkt_info = _mm_extract_epi32(ptype0, 3);
	rx_pkts[3]->packet_type =
		get_packet_type(3, pkt_info, etqf_check, tunnel_check);
}

/**
 * vPMD raw receive routine, only accept(nb_pkts >= IXGBE_VPMD_DESCS_PER_LOOP)
 *
 * Notice:
 * - nb_pkts < IXGBE_VPMD_DESCS_PER_LOOP, just return no packet
 * - floor align nb_pkts to a IXGBE_VPMD_DESCS_PER_LOOP power-of-two
 */
static inline uint16_t
_recv_raw_pkts_vec(struct ci_rx_queue *rxq, struct rte_mbuf **rx_pkts,
		uint16_t nb_pkts, uint8_t *split_packet)
{
	volatile union ixgbe_adv_rx_desc *rxdp;
	struct ci_rx_entry *sw_ring;
	uint16_t nb_pkts_recd;
#ifdef RTE_LIB_SECURITY
	uint8_t use_ipsec = rxq->using_ipsec;
#endif
	int pos;
	uint64_t var;
	__m128i shuf_msk;
	__m128i crc_adjust = _mm_set_epi16(
				0, 0, 0,    /* ignore non-length fields */
				-rxq->crc_len, /* sub crc on data_len */
				0,          /* ignore high-16bits of pkt_len */
				-rxq->crc_len, /* sub crc on pkt_len */
				0, 0            /* ignore pkt_type field */
			);
	/*
	 * compile-time check the above crc_adjust layout is correct.
	 * NOTE: the first field (lowest address) is given last in set_epi16
	 * call above.
	 */
	RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, pkt_len) !=
			offsetof(struct rte_mbuf, rx_descriptor_fields1) + 4);
	RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, data_len) !=
			offsetof(struct rte_mbuf, rx_descriptor_fields1) + 8);
	__m128i dd_check, eop_check;
	__m128i mbuf_init;
	uint8_t vlan_flags;
	uint16_t udp_p_flag = 0; /* Rx Descriptor UDP header present */

	/*
	 * Under the circumstance that `rx_tail` wrap back to zero
	 * and the advance speed of `rx_tail` is greater than `rxrearm_start`,
	 * `rx_tail` will catch up with `rxrearm_start` and surpass it.
	 * This may cause some mbufs be reused by application.
	 *
	 * So we need to make some restrictions to ensure that
	 * `rx_tail` will not exceed `rxrearm_start`.
	 */
	nb_pkts = RTE_MIN(nb_pkts, IXGBE_VPMD_RXQ_REARM_THRESH);

	/* nb_pkts has to be floor-aligned to IXGBE_VPMD_DESCS_PER_LOOP */
	nb_pkts = RTE_ALIGN_FLOOR(nb_pkts, IXGBE_VPMD_DESCS_PER_LOOP);

	/* Just the act of getting into the function from the application is
	 * going to cost about 7 cycles
	 */
	rxdp = rxq->ixgbe_rx_ring + rxq->rx_tail;

	rte_prefetch0(rxdp);

	/* See if we need to rearm the RX queue - gives the prefetch a bit
	 * of time to act
	 */
	if (rxq->rxrearm_nb > IXGBE_VPMD_RXQ_REARM_THRESH)
		ixgbe_rxq_rearm(rxq);

	/* Before we start moving massive data around, check to see if
	 * there is actually a packet available
	 */
	if (!(rxdp->wb.upper.status_error &
				rte_cpu_to_le_32(IXGBE_RXDADV_STAT_DD)))
		return 0;

	if (rxq->rx_udp_csum_zero_err)
		udp_p_flag = IXGBE_RXDADV_PKTTYPE_UDP;

	/* 4 packets DD mask */
	dd_check = _mm_set_epi64x(0x0000000100000001LL, 0x0000000100000001LL);

	/* 4 packets EOP mask */
	eop_check = _mm_set_epi64x(0x0000000200000002LL, 0x0000000200000002LL);

	/* mask to shuffle from desc. to mbuf */
	shuf_msk = _mm_set_epi8(
		7, 6, 5, 4,  /* octet 4~7, 32bits rss */
		15, 14,      /* octet 14~15, low 16 bits vlan_macip */
		13, 12,      /* octet 12~13, 16 bits data_len */
		0xFF, 0xFF,  /* skip high 16 bits pkt_len, zero out */
		13, 12,      /* octet 12~13, low 16 bits pkt_len */
		0xFF, 0xFF,  /* skip 32 bit pkt_type */
		0xFF, 0xFF
		);
	/*
	 * Compile-time verify the shuffle mask
	 * NOTE: some field positions already verified above, but duplicated
	 * here for completeness in case of future modifications.
	 */
	RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, pkt_len) !=
			offsetof(struct rte_mbuf, rx_descriptor_fields1) + 4);
	RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, data_len) !=
			offsetof(struct rte_mbuf, rx_descriptor_fields1) + 8);
	RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, vlan_tci) !=
			offsetof(struct rte_mbuf, rx_descriptor_fields1) + 10);
	RTE_BUILD_BUG_ON(offsetof(struct rte_mbuf, hash) !=
			offsetof(struct rte_mbuf, rx_descriptor_fields1) + 12);

	mbuf_init = _mm_set_epi64x(0, rxq->mbuf_initializer);

	/* Cache is empty -> need to scan the buffer rings, but first move
	 * the next 'n' mbufs into the cache
	 */
	sw_ring = &rxq->sw_ring[rxq->rx_tail];

	/* ensure these 2 flags are in the lower 8 bits */
	RTE_BUILD_BUG_ON((RTE_MBUF_F_RX_VLAN | RTE_MBUF_F_RX_VLAN_STRIPPED) > UINT8_MAX);
	vlan_flags = rxq->vlan_flags & UINT8_MAX;

	/* A. load 4 packet in one loop
	 * [A*. mask out 4 unused dirty field in desc]
	 * B. copy 4 mbuf point from swring to rx_pkts
	 * C. calc the number of DD bits among the 4 packets
	 * [C*. extract the end-of-packet bit, if requested]
	 * D. fill info. from desc to mbuf
	 */
	for (pos = 0, nb_pkts_recd = 0; pos < nb_pkts;
			pos += IXGBE_VPMD_DESCS_PER_LOOP,
			rxdp += IXGBE_VPMD_DESCS_PER_LOOP) {
		__m128i descs[IXGBE_VPMD_DESCS_PER_LOOP];
		__m128i pkt_mb1, pkt_mb2, pkt_mb3, pkt_mb4;
		__m128i zero, staterr, sterr_tmp1, sterr_tmp2;
		/* 2 64 bit or 4 32 bit mbuf pointers in one XMM reg. */
		__m128i mbp1;
#if defined(RTE_ARCH_X86_64)
		__m128i mbp2;
#endif

		/* B.1 load 2 (64 bit) or 4 (32 bit) mbuf points */
		mbp1 = _mm_loadu_si128((__m128i *)&sw_ring[pos]);

		/* Read desc statuses backwards to avoid race condition */
		/* A.1 load desc[3] */
		descs[3] = _mm_loadu_si128(RTE_CAST_PTR(const __m128i *, rxdp + 3));
		rte_compiler_barrier();

		/* B.2 copy 2 64 bit or 4 32 bit mbuf point into rx_pkts */
		_mm_storeu_si128((__m128i *)&rx_pkts[pos], mbp1);

#if defined(RTE_ARCH_X86_64)
		/* B.1 load 2 64 bit mbuf points */
		mbp2 = _mm_loadu_si128((__m128i *)&sw_ring[pos+2]);
#endif

		/* A.1 load desc[2-0] */
		descs[2] = _mm_loadu_si128(RTE_CAST_PTR(const __m128i *, rxdp + 2));
		rte_compiler_barrier();
		descs[1] = _mm_loadu_si128(RTE_CAST_PTR(const __m128i *, rxdp + 1));
		rte_compiler_barrier();
		descs[0] = _mm_loadu_si128(RTE_CAST_PTR(const __m128i *, rxdp));

#if defined(RTE_ARCH_X86_64)
		/* B.2 copy 2 mbuf point into rx_pkts  */
		_mm_storeu_si128((__m128i *)&rx_pkts[pos+2], mbp2);
#endif

		if (split_packet) {
			rte_mbuf_prefetch_part2(rx_pkts[pos]);
			rte_mbuf_prefetch_part2(rx_pkts[pos + 1]);
			rte_mbuf_prefetch_part2(rx_pkts[pos + 2]);
			rte_mbuf_prefetch_part2(rx_pkts[pos + 3]);
		}

		/* avoid compiler reorder optimization */
		rte_compiler_barrier();

		/* D.1 pkt 3,4 convert format from desc to pktmbuf */
		pkt_mb4 = _mm_shuffle_epi8(descs[3], shuf_msk);
		pkt_mb3 = _mm_shuffle_epi8(descs[2], shuf_msk);

		/* D.1 pkt 1,2 convert format from desc to pktmbuf */
		pkt_mb2 = _mm_shuffle_epi8(descs[1], shuf_msk);
		pkt_mb1 = _mm_shuffle_epi8(descs[0], shuf_msk);

		/* C.1 4=>2 filter staterr info only */
		sterr_tmp2 = _mm_unpackhi_epi32(descs[3], descs[2]);
		/* C.1 4=>2 filter staterr info only */
		sterr_tmp1 = _mm_unpackhi_epi32(descs[1], descs[0]);

		/* set ol_flags with vlan packet type */
		desc_to_olflags_v(descs, mbuf_init, vlan_flags, udp_p_flag,
				  &rx_pkts[pos]);

#ifdef RTE_LIB_SECURITY
		if (unlikely(use_ipsec))
			desc_to_olflags_v_ipsec(descs, &rx_pkts[pos]);
#endif

		/* D.2 pkt 3,4 set in_port/nb_seg and remove crc */
		pkt_mb4 = _mm_add_epi16(pkt_mb4, crc_adjust);
		pkt_mb3 = _mm_add_epi16(pkt_mb3, crc_adjust);

		/* C.2 get 4 pkts staterr value  */
		zero = _mm_xor_si128(dd_check, dd_check);
		staterr = _mm_unpacklo_epi32(sterr_tmp1, sterr_tmp2);

		/* D.3 copy final 3,4 data to rx_pkts */
		_mm_storeu_si128((void *)&rx_pkts[pos+3]->rx_descriptor_fields1,
				pkt_mb4);
		_mm_storeu_si128((void *)&rx_pkts[pos+2]->rx_descriptor_fields1,
				pkt_mb3);

		/* D.2 pkt 1,2 set in_port/nb_seg and remove crc */
		pkt_mb2 = _mm_add_epi16(pkt_mb2, crc_adjust);
		pkt_mb1 = _mm_add_epi16(pkt_mb1, crc_adjust);

		/* C* extract and record EOP bit */
		if (split_packet) {
			__m128i eop_shuf_mask = _mm_set_epi8(
					0xFF, 0xFF, 0xFF, 0xFF,
					0xFF, 0xFF, 0xFF, 0xFF,
					0xFF, 0xFF, 0xFF, 0xFF,
					0x04, 0x0C, 0x00, 0x08
					);

			/* and with mask to extract bits, flipping 1-0 */
			__m128i eop_bits = _mm_andnot_si128(staterr, eop_check);
			/* the staterr values are not in order, as the count
			 * of dd bits doesn't care. However, for end of
			 * packet tracking, we do care, so shuffle. This also
			 * compresses the 32-bit values to 8-bit
			 */
			eop_bits = _mm_shuffle_epi8(eop_bits, eop_shuf_mask);
			/* store the resulting 32-bit value */
			*(int *)split_packet = _mm_cvtsi128_si32(eop_bits);
			split_packet += IXGBE_VPMD_DESCS_PER_LOOP;
		}

		/* C.3 calc available number of desc */
		staterr = _mm_and_si128(staterr, dd_check);
		staterr = _mm_packs_epi32(staterr, zero);

		/* D.3 copy final 1,2 data to rx_pkts */
		_mm_storeu_si128((void *)&rx_pkts[pos+1]->rx_descriptor_fields1,
				pkt_mb2);
		_mm_storeu_si128((void *)&rx_pkts[pos]->rx_descriptor_fields1,
				pkt_mb1);

		desc_to_ptype_v(descs, rxq->pkt_type_mask, &rx_pkts[pos]);

		/* C.4 calc available number of desc */
		var = rte_popcount64(_mm_cvtsi128_si64(staterr));
		nb_pkts_recd += var;
		if (likely(var != IXGBE_VPMD_DESCS_PER_LOOP))
			break;
	}

	/* Update our internal tail pointer */
	rxq->rx_tail = (uint16_t)(rxq->rx_tail + nb_pkts_recd);
	rxq->rx_tail = (uint16_t)(rxq->rx_tail & (rxq->nb_rx_desc - 1));
	rxq->rxrearm_nb = (uint16_t)(rxq->rxrearm_nb + nb_pkts_recd);

	return nb_pkts_recd;
}

/**
 * vPMD receiIXGBE_VPMD_RX_BURSTt(nb_pkts >= IXGBE_VPMD_DESCS_PER_LOOP)
 *
 * Notice:
 * - nb_pkts <IXGBE_VPMD_RX_BURSTOOP, just return no packet
 * - floor align nb_pkts to a IXGBE_VPMD_DESCS_PER_LOOP power-of-two
 */
uint16_t
ixgbe_recv_pkts_vec(void *rx_queue, struct rte_mbuf **rx_pkts,
		uint16_t nb_pkts)
{
	return _recv_raw_pkts_vec(rx_queue, rx_pkts, nb_pkts, NULL);
}

/**
 * vPMD receive routine that reassembles scattered packets
 *
 * Notice:
 * - nb_pkts < IXGBE_VPMD_DESCS_PER_LOOP, just return no packet
 * - floor align nb_pkts to a IXGBE_VPMD_DESCS_PER_LOOP power-of-two
 */
static uint16_t
ixgbe_recv_scattered_burst_vec(void *rx_queue, struct rte_mbuf **rx_pkts,
			       uint16_t nb_pkts)
{
	struct ci_rx_queue *rxq = rx_queue;
	uint8_t split_flags[IXGBE_VPMD_RX_BURST] = {0};

	/* get some new buffers */
	uint16_t nb_bufs = _recv_raw_pkts_vec(rxq, rx_pkts, nb_pkts,
			split_flags);
	if (nb_bufs == 0)
		return 0;

	/* happy day case, full burst + no packets to be joined */
	const uint64_t *split_fl64 = (uint64_t *)split_flags;
	if (rxq->pkt_first_seg == NULL &&
			split_fl64[0] == 0 && split_fl64[1] == 0 &&
			split_fl64[2] == 0 && split_fl64[3] == 0)
		return nb_bufs;

	/* reassemble any packets that need reassembly*/
	unsigned i = 0;
	if (rxq->pkt_first_seg == NULL) {
		/* find the first split flag, and only reassemble then*/
		while (i < nb_bufs && !split_flags[i])
			i++;
		if (i == nb_bufs)
			return nb_bufs;
		rxq->pkt_first_seg = rx_pkts[i];
	}
	return i + ci_rx_reassemble_packets(&rx_pkts[i], nb_bufs - i, &split_flags[i],
		&rxq->pkt_first_seg, &rxq->pkt_last_seg, rxq->crc_len);
}

/**
 * vPMD receive routine that reassembles scattered packets.
 */
uint16_t
ixgbe_recv_scattered_pkts_vec(void *rx_queue, struct rte_mbuf **rx_pkts,
			      uint16_t nb_pkts)
{
	uint16_t retval = 0;

	while (nb_pkts > IXGBE_VPMD_RX_BURST) {
		uint16_t burst;

		burst = ixgbe_recv_scattered_burst_vec(rx_queue,
						       rx_pkts + retval,
						       IXGBE_VPMD_RX_BURST);
		retval += burst;
		nb_pkts -= burst;
		if (burst < IXGBE_VPMD_RX_BURST)
			return retval;
	}

	return retval + ixgbe_recv_scattered_burst_vec(rx_queue,
						       rx_pkts + retval,
						       nb_pkts);
}

static inline void
vtx1(volatile union ixgbe_adv_tx_desc *txdp,
		struct rte_mbuf *pkt, uint64_t flags)
{
	__m128i descriptor = _mm_set_epi64x((uint64_t)pkt->pkt_len << 46 |
			flags | pkt->data_len,
			pkt->buf_iova + pkt->data_off);
	_mm_store_si128(RTE_CAST_PTR(__m128i *, &txdp->read), descriptor);
}

static inline void
vtx(volatile union ixgbe_adv_tx_desc *txdp,
		struct rte_mbuf **pkt, uint16_t nb_pkts,  uint64_t flags)
{
	int i;

	for (i = 0; i < nb_pkts; ++i, ++txdp, ++pkt)
		vtx1(txdp, *pkt, flags);
}

uint16_t
ixgbe_xmit_fixed_burst_vec(void *tx_queue, struct rte_mbuf **tx_pkts,
			   uint16_t nb_pkts)
{
	struct ci_tx_queue *txq = (struct ci_tx_queue *)tx_queue;
	volatile union ixgbe_adv_tx_desc *txdp;
	struct ci_tx_entry_vec *txep;
	uint16_t n, nb_commit, tx_id;
	/* for VF, we need to set CC bit */
	const uint64_t cc = txq->is_vf ? (uint64_t)IXGBE_ADVTXD_CC << 32ULL : 0;
	uint64_t flags = DCMD_DTYP_FLAGS | cc;
	uint64_t rs = IXGBE_ADVTXD_DCMD_RS | DCMD_DTYP_FLAGS | cc;
	int i;

	/* cross rx_thresh boundary is not allowed */
	nb_pkts = RTE_MIN(nb_pkts, txq->tx_rs_thresh);

	if (txq->nb_tx_free < txq->tx_free_thresh)
		ixgbe_tx_free_bufs_vec(txq);

	nb_commit = nb_pkts = (uint16_t)RTE_MIN(txq->nb_tx_free, nb_pkts);
	if (unlikely(nb_pkts == 0))
		return 0;

	tx_id = txq->tx_tail;
	txdp = &txq->ixgbe_tx_ring[tx_id];
	txep = &txq->sw_ring_vec[tx_id];

	txq->nb_tx_free = (uint16_t)(txq->nb_tx_free - nb_pkts);

	n = (uint16_t)(txq->nb_tx_desc - tx_id);
	if (nb_commit >= n) {

		ci_tx_backlog_entry_vec(txep, tx_pkts, n);

		for (i = 0; i < n - 1; ++i, ++tx_pkts, ++txdp)
			vtx1(txdp, *tx_pkts, flags);

		vtx1(txdp, *tx_pkts++, rs);

		nb_commit = (uint16_t)(nb_commit - n);

		tx_id = 0;
		txq->tx_next_rs = (uint16_t)(txq->tx_rs_thresh - 1);

		/* avoid reach the end of ring */
		txdp = &txq->ixgbe_tx_ring[tx_id];
		txep = &txq->sw_ring_vec[tx_id];
	}

	ci_tx_backlog_entry_vec(txep, tx_pkts, nb_commit);

	vtx(txdp, tx_pkts, nb_commit, flags);

	tx_id = (uint16_t)(tx_id + nb_commit);
	if (tx_id > txq->tx_next_rs) {
		txq->ixgbe_tx_ring[txq->tx_next_rs].read.cmd_type_len |=
			rte_cpu_to_le_32(IXGBE_ADVTXD_DCMD_RS);
		txq->tx_next_rs = (uint16_t)(txq->tx_next_rs +
			txq->tx_rs_thresh);
	}

	txq->tx_tail = tx_id;

	IXGBE_PCI_REG_WC_WRITE(txq->qtx_tail, txq->tx_tail);

	return nb_pkts;
}
