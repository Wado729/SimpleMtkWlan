//
//  MtkMwx.cpp
//  SimpleMtkWlan
//
//  Created by laobamac (王孝慈) on 2026/5/5.
//  Copyright © 2026 laobamac (王孝慈). All rights reserved.
//

/*	$OpenBSD: if_mwx.c,v 1.9 2026/05/09 12:13:15 claudio Exp $ */
/*
 * Copyright (c) 2022 Claudio Jeker <claudio@openbsd.org>
 * Copyright (c) 2021 MediaTek Inc.
 * Copyright (c) 2021 Lorenzo Bianconi <lorenzo.bianconi83@gmail.com>
 * Copyright (c) 2017 Stefan Sperling <stsp@openbsd.org>
 * Copyright (c) 2016 Felix Fietkau <nbd@nbd.name>
 * Copyright (c) 2007-2010 Damien Bergamini <damien.bergamini@free.fr>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "MtkMwx.hpp"
#ifdef AIRPORT_WCL
#include "WCL/WCL.hpp"
#endif

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/bitfield.h>
#include <sys/kpi_mbuf.h>
#include <sys/_if_ether.h>
#include <sys/_if_media.h>
#include <sys/_malloc.h>
#include <sys/_mbuf.h>
#include <sys/_task.h>
#include <net/ethernet.h>
#include <net80211/ieee80211_proto.h>
#include <net80211/ieee80211_radiotap.h>
#include <FwData.h>

#include "if_mwxreg.h"

OSDefineMetaClassAndStructors(MtkMwx, MtkHalService)

#ifndef NBPFILTER
#define NBPFILTER 0
#endif

#define PCI_VENDOR_MEDIATEK            0x14c3
#define PCI_PRODUCT_MEDIATEK_MT7921    0x7961
#define PCI_PRODUCT_MEDIATEK_MT7921K   0x0608
#define PCI_PRODUCT_MEDIATEK_MT7922    0x7922

/*
 * RX rate histogram from the P-RXV (RXD group 3) of unicast frames, to see
 * which rates the AP actually uses. Field layout from Linux mt76_connac2_mac.h.
 */
#define MWX_PRXV_TX_RATE(v)	((v) & 0x7f)
#define MWX_PRXV_NSTS(v)	(((v) >> 7) & 0x7)
#define MWX_PRXV_LDPC(v)	(((v) >> 11) & 0x1)
#define MWX_PRXV_FRAME_MODE(v)	(((v) >> 12) & 0x7)
#define MWX_PRXV_SGI(v)		(((v) >> 15) & 0x3)
#define MWX_PRXV_STBC(v)	(((v) >> 22) & 0x3)
#define MWX_PRXV_TX_MODE(v)	(((v) >> 24) & 0xf)
static uint32_t mwx_rxr_mode[16], mwx_rxr_bw[4], mwx_rxr_nss[4], mwx_rxr_mcs[16];
static uint32_t mwx_rxr_sgi, mwx_rxr_stbc, mwx_rxr_ldpc, mwx_rxr_total;
/* Last unicast RX rate: the firmware does TX rate control and reports none. */
static int mwx_rxr_last_mcs = -1;
static uint32_t mwx_rxr_last_kbps;

/* HT/VHT 1SS long GI data rates in 100 kbit/s, by bandwidth and MCS. */
static const uint16_t mwx_vht_rate[3][10] = {
	{ 65, 130, 195, 260, 390, 520, 585, 650, 780, 867 },
	{ 135, 270, 405, 540, 810, 1080, 1215, 1350, 1620, 1800 },
	{ 293, 585, 878, 1170, 1755, 2340, 2633, 2925, 3510, 3900 },
};

static void
mwx_rx_rate_account(uint32_t v0)
{
	uint32_t mode = MWX_PRXV_TX_MODE(v0), idx = MWX_PRXV_TX_RATE(v0);
	uint32_t nss = MWX_PRXV_NSTS(v0) + 1;

	mwx_rxr_total++;
	mwx_rxr_mode[mode]++;
	mwx_rxr_bw[MWX_PRXV_FRAME_MODE(v0) & 3]++;
	if (mode == 2 || mode == 3) {		/* HT: idx = MCS 0-15 */
		nss = (idx >> 3) + 1;
		idx &= 7;
	}
	mwx_rxr_nss[(nss - 1) & 3]++;
	mwx_rxr_mcs[idx & 0xf]++;
	if (MWX_PRXV_SGI(v0))
		mwx_rxr_sgi++;
	if (MWX_PRXV_STBC(v0))
		mwx_rxr_stbc++;
	if (MWX_PRXV_LDPC(v0))
		mwx_rxr_ldpc++;

	if (mode >= 2 && mode <= 4 && idx <= 9 && (MWX_PRXV_FRAME_MODE(v0) & 3) < 3) {
		uint32_t kbps = mwx_vht_rate[MWX_PRXV_FRAME_MODE(v0) & 3][idx] *
		    100 * nss;
		if (MWX_PRXV_SGI(v0))
			kbps = kbps * 10 / 9;
		mwx_rxr_last_kbps = kbps;
		mwx_rxr_last_mcs = mode == 4 ? (int)idx : (int)(idx + 8 * (nss - 1));
	}
}

extern uint32_t ieee80211_bar_rx_count;

/* RX decrypt path counters, reported by MtkMwx::debugPoll(). */
static uint32_t mwx_rx_hwdec_cnt, mwx_rx_swdec_cnt;
static uint32_t mwx_rx_ctl_cnt, mwx_rx_bar_cnt;	/* control frames reaching the driver */

/* RX drop reason counters, reported by MtkMwx::debugPoll(). */
#define MWX_RX_DROP_REASONS	12
static const char *mwx_rx_drop_name[MWX_RX_DROP_REASONS];
static uint32_t mwx_rx_drop_cnt[MWX_RX_DROP_REASONS];

static void
mwx_rx_drop_count(const char *reason)
{
	int i;

	for (i = 0; i < MWX_RX_DROP_REASONS; i++) {
		if (mwx_rx_drop_name[i] == NULL)
			mwx_rx_drop_name[i] = reason;
		if (mwx_rx_drop_name[i] == reason) {
			mwx_rx_drop_cnt[i]++;
			return;
		}
	}
}

/* Route every HAL printf through the persistent debug log. */
#undef printf
#define printf(x...) mtk_dbg_log(x)

/*
 * mwx_mcu_alloc_msg() reserves room for the MCU TXD in front of the payload.
 * Keep payload + TXD within one 4K cluster: a 4096-byte chunk needs a 16K
 * jumbo cluster, which is often unavailable during early boot (ENOMEM).
 */
#define MWX_FW_CHUNK_SIZE	(4096 - sizeof(struct mwx_mcu_txd))

#define MWX_LOG(x...) printf("SimpleMtkWlan-mwx: " x)
#define MWX_DEV_LOG(sc, fmt, args...) \
	printf("SimpleMtkWlan-mwx: %s: " fmt, DEVNAME(sc), ##args)

#define ifnet _ifnet
#define mbuf __mbuf

#undef KASSERT
#define KASSERT(exp, ...) do { if (!(exp)) panic("mwx assertion failed: %s", #exp); } while (0)
#ifndef __unused
#define __unused __attribute__((unused))
#endif
#ifndef ISSET
#define ISSET(t, f) (((t) & (f)) != 0)
#endif
#ifndef IEEE80211_CHAN_40MHZ
#define IEEE80211_CHAN_40MHZ IEEE80211_CHAN_HT40
#endif
#ifndef IEEE80211_CHAN_6GHZ
#define IEEE80211_CHAN_6GHZ 0
#endif
#ifndef IEEE80211_IS_CHAN_6GHZ
#define IEEE80211_IS_CHAN_6GHZ(_c) false
#endif

#ifndef M_DEVBUF
#define M_DEVBUF 0
#endif
#ifndef M_NOWAIT
#define M_NOWAIT 0
#endif
#ifndef M_WAITOK
#define M_WAITOK 0
#endif
#ifndef M_ZERO
#define M_ZERO 0
#endif

static MtkMwx *gMwxHal;

static inline void *
mallocarray(size_t n, size_t size, int type, int flags)
{
	if (size != 0 && n > SIZE_MAX / size)
		return NULL;
	return malloc(n * size, type, flags);
}

static inline void
mwx_free_mem(void *addr)
{
	free(addr);
}

#define free(addr, type, size) mwx_free_mem(addr)

static inline int
loadfirmware(const char *name, u_char **buf, size_t *len)
{
	MWX_LOG("firmware lookup start name=%s\n", name);
	OSData *data = getFWDescByName(name);
	if (data == NULL) {
		MWX_LOG("firmware lookup failed name=%s error=%d\n", name, ENOENT);
		return ENOENT;
	}
	*len = data->getLength();
	*buf = (u_char *)malloc(*len, M_DEVBUF, M_WAITOK);
	if (*buf == NULL) {
		data->release();
		MWX_LOG("firmware copy allocation failed name=%s size=%zu error=%d\n",
		    name, *len, ENOMEM);
		return ENOMEM;
	}
	memcpy(*buf, data->getBytesNoCopy(), *len);
	data->release();
	MWX_LOG("firmware lookup ok name=%s size=%zu\n", name, *len);
	return 0;
}

static inline int
tsleep_nsec(void *ident, int priority, const char *wmesg, uint64_t timo)
{
	if (gMwxHal == NULL)
		return EWOULDBLOCK;
	return gMwxHal->mwxSleepNsec(ident, priority, wmesg, timo);
}

static inline void
config_mountroot(struct device *self, void (*fn)(struct device *))
{
	fn(self);
}

static inline void delay(int usec) {
    if (usec <= 0) return;
    if (usec < 1000) IODelay(usec);
    else IOSleep((usec + 999) / 1000);
}

static inline struct mbuf *
m_pullup(struct mbuf *m, size_t len)
{
	struct mbuf *n = NULL;
	size_t pktlen;
	u_int32_t chunks = 1;
	static uint32_t pullup_rebuild_log_count;

	if (m == NULL)
		return NULL;
	if (mbuf_len(m) >= len)
		return m;

	pktlen = mbuf_pkthdr_len(m);
	if (len > pktlen) {
		m_freem(m);
		return NULL;
	}

	if (pullup_rebuild_log_count < 32) {
		MWX_LOG("m_pullup rebuild len=%zu first_len=%zu pktlen=%zu\n",
		    len, mbuf_len(m), pktlen);
		pullup_rebuild_log_count++;
	}
	if (mbuf_allocpacket(M_DONTWAIT, pktlen, &chunks, &n) != 0) {
		m_freem(m);
		return NULL;
	}
	mbuf_setlen(n, pktlen);
	mbuf_pkthdr_setlen(n, pktlen);
	if (mbuf_copydata(m, 0, pktlen, mtod(n, void *)) != 0) {
		m_freem(n);
		m_freem(m);
		return NULL;
	}
	m_freem(m);
	return n;
}

static inline void
m_adj(struct mbuf *m, int len)
{
	mbuf_adj(m, len);
}

static inline struct mbuf *
m_prepend(struct mbuf *m, size_t len, int how)
{
	return mbuf_prepend(&m, len, how) == 0 ? m : NULL;
}

static inline size_t
m_leadingspace(struct mbuf *m)
{
	return mbuf_leadingspace(m);
}

static inline size_t
m_trailingspace(struct mbuf *m)
{
	return mbuf_trailingspace(m);
}

static inline struct mbuf *
m_gethdr(int how, int type)
{
	struct mbuf *m = NULL;
	mbuf_gethdr(how, type, &m);
	return m;
}

static inline struct mbuf *
MCLGETL(struct mbuf *m, int how, size_t len)
{
	u_int32_t chunks = 1;
	if (m == NULL) {
		if (mbuf_allocpacket(how, len, &chunks, &m) != 0)
			return NULL;
	} else if (mbuf_getcluster(how, mbuf_type(m), len, &m) != 0) {
		return NULL;
	}
	return m;
}

static const struct pci_matchid mwx_devices[] = {
	{ PCI_VENDOR_MEDIATEK, PCI_PRODUCT_MEDIATEK_MT7921 },
	{ PCI_VENDOR_MEDIATEK, PCI_PRODUCT_MEDIATEK_MT7921K },
	{ PCI_VENDOR_MEDIATEK, PCI_PRODUCT_MEDIATEK_MT7922 },
};

/* Keep the OpenBSD DPRINTF path available, but do not enable it by default.
 * The PCIe interrupt and MCU paths can otherwise flood the kernel log. */
/* #define MWX_DEBUG	1 */

#define	MT7921_ROM_PATCH	"mwx-mt7961_patch_mcu_1_2_hdr"
#define	MT7921_FIRMWARE_WM	"mwx-mt7961_ram_code_1"
#define	MT7922_ROM_PATCH	"mwx-mt7922_patch_mcu_1_1_hdr"
#define	MT7922_FIRMWARE_WM	"mwx-mt7922_ram_code_1"

#if NBPFILTER > 0
struct mwx_rx_radiotap_header {
	struct ieee80211_radiotap_header	wr_ihdr;
	uint64_t				wr_tsft;
	uint8_t					wr_flags;
	uint8_t					wr_rate;
	uint16_t				wr_chan_freq;
	uint16_t				wr_chan_flags;
	int8_t					wr_dbm_antsignal;
	int8_t					wr_dbm_antnoise;
} __packed;

#define	MWX_RX_RADIOTAP_PRESENT				\
	((1 << IEEE80211_RADIOTAP_TSFT) |		\
	(1 << IEEE80211_RADIOTAP_FLAGS) |		\
	(1 << IEEE80211_RADIOTAP_RATE) |		\
	(1 << IEEE80211_RADIOTAP_CHANNEL) |		\
	(1 << IEEE80211_RADIOTAP_DBM_ANTSIGNAL) |	\
	(1 << IEEE80211_RADIOTAP_DBM_ANTNOISE))

struct mwx_tx_radiotap_header {
	struct ieee80211_radiotap_header	wt_ihdr;
	uint8_t					wt_flags;
	uint8_t					wt_rate;
	uint16_t				wt_chan_freq;
	uint16_t				wt_chan_flags;
} __packed;

#define	MWX_TX_RADIOTAP_PRESENT			\
	((1 << IEEE80211_RADIOTAP_FLAGS) |	\
	(1 << IEEE80211_RADIOTAP_RATE) |	\
	(1 << IEEE80211_RADIOTAP_CHANNEL))

#endif

struct mwx_txwi {
	struct mt76_txwi		*mt_desc;
	struct mbuf			*mt_mbuf;
	bus_dmamap_t			mt_map;
	LIST_ENTRY(mwx_txwi)		mt_entry;
	u_int32_t			mt_addr;
	u_int				mt_idx;
	int				mt_busy;
};

struct mwx_txwi_desc {
	struct mt76_txwi		*mt_desc;
	struct mwx_txwi			*mt_data;

	u_int				mt_count;
	u_int				mt_nfree;	/* entries on mt_freelist */
	bus_dmamap_t			mt_map;
	bus_dma_segment_t		mt_seg;
	LIST_HEAD(, mwx_txwi)		mt_freelist;
};

struct mwx_queue_data {
	struct mbuf			*md_mbuf;
	struct mwx_txwi			*md_txwi;
	bus_dmamap_t			md_map;
};

struct mwx_queue {
	uint32_t			mq_regbase;
	u_int				mq_count;
	u_int				mq_prod;
	u_int				mq_cons;

	struct mwx_desc		*mq_desc;
	struct mwx_queue_data		*mq_data;

	bus_dmamap_t			mq_map;
	bus_dma_segment_t		mq_seg;
	int				mq_wakeme;
};

struct mwx_hw_capa {
	int8_t		has_2ghz;
	int8_t		has_5ghz;
	int8_t		has_6ghz;
	uint8_t		antenna_mask;
	uint8_t		num_streams;
};

struct mwx_node {
	struct ieee80211_node	ni;
	uint16_t		wcid;
	uint16_t		flags;
};
#define	MWX_NODE_FLAG_HAVE_PAIRWISE_KEY		0x1
#define	MWX_NODE_FLAG_HAVE_GROUP_KEY		0x2

struct mwx_vif {
	struct mwx_node		vif_mn;
	uint8_t			idx;
	uint8_t			omac_idx;
	uint8_t			band_idx;
	uint8_t			wmm_idx;
	uint8_t			scan_seq_num;
};

enum mwx_hw_type {
	MWX_HW_MT7921,
	MWX_HW_MT7922,
};

struct mwx_setkey_task_arg {
	struct ieee80211_node	*ni;
	struct ieee80211_key	*k;
};

struct mwx_softc {
	struct device		sc_dev;
	struct ieee80211com	sc_ic;

	enum mwx_hw_type	sc_hwtype;

	struct mwx_queue	sc_txq;
	struct mwx_queue	sc_txmcuq;
	struct mwx_queue	sc_txfwdlq;

	struct mwx_queue	sc_rxq;
	struct mwx_queue	sc_rxmcuq;
	struct mwx_queue	sc_rxfwdlq;

	struct mwx_txwi_desc	sc_txwi;

	bus_space_tag_t		sc_st;
	bus_space_handle_t	sc_memh;
	bus_size_t		sc_mems;
	bus_dma_tag_t		sc_dmat;
	pcitag_t		sc_tag;
	pci_chipset_tag_t	sc_pc;
	void			*sc_ih;

	int			(*sc_newstate)(struct ieee80211com *,
				    enum ieee80211_state, int);

	struct taskq		*sc_nswq;
	struct task		sc_newstate_task;
	struct task		sc_bgscan_done_task;
	struct task		sc_setkey_task;
	struct task		sc_scan_task;
	struct task		sc_reset_task;
	CTimeout		*sc_reset_to;
	u_int			sc_flags;
#define MWX_FLAG_SCANNING		0x01
#define MWX_FLAG_BGSCAN			0x02
	int			sc_coredump_cnt;
	int8_t			sc_resetting;
	int8_t			sc_hard_reset;	/* reload firmware on reset */
	int8_t			sc_tx_amsdu;	/* hardware TX A-MSDU (-mtknoamsdu: off) */
	volatile int8_t		sc_suspended;	/* system sleep: leave the hardware alone */
	uint32_t		sc_tx_full_cnt;	/* output paused: no TXWI / ring slot */
	int8_t			sc_sta_added;	/* peer STA record exists in fw */
	bool sc_detaching, sc_net_attached;
	int8_t			sc_fw_loaded;

	enum ieee80211_state	sc_ns_state;
	int			sc_ns_arg;

	struct ieee80211_node_switch_bss_arg	*sc_bgscan_arg;
	size_t			sc_bgscan_arg_size;

	struct mwx_setkey_task_arg	sc_setkey_arg[8];
	int			sc_setkey_cur;
	int			sc_setkey_tail;

#if NBPFILTER > 0
	caddr_t			sc_drvbpf;
	union {
		struct mwx_rx_radiotap_header th;
		uint8_t pad[IEEE80211_RADIOTAP_HDRLEN];
	}			sc_rxtapu;
	int			sc_rxtap_len;
	union {
		struct mwx_tx_radiotap_header th;
		uint8_t pad[IEEE80211_RADIOTAP_HDRLEN];
	}			sc_txtapu;
	int			sc_txtap_len;
#define	sc_rxtap	sc_rxtapu.th
#define	sc_txtap	sc_txtapu.th
#endif

	struct mwx_vif		sc_vif;
	uint32_t		sc_wcid_mask;
	uint32_t		sc_intr_mask;

	/* mcu */
	uint32_t		sc_mcu_seq;
	struct {
		struct mbuf	*mcu_m;
		uint32_t	 mcu_cmd;
		uint32_t	 mcu_int;
	}			sc_mcu_wait[16];
	uint8_t			sc_scan_seq_num;

	/* phy / hw */
	struct mwx_hw_capa	sc_capa;
	uint8_t			sc_lladdr[ETHER_ADDR_LEN];
	char			sc_alpha2[4]; /* regulatory-domain */

	int16_t			sc_coverage_class;
	uint8_t			sc_slottime;

	/* mac specific */
	uint32_t		sc_rxfilter;

	/* diagnostic counters, all rate-limited at print sites */
	uint32_t		sc_rx_process_events;
	uint32_t		sc_rx_pkt_event;
	uint32_t		sc_rx_pkt_txrx_notify;
	uint32_t		sc_rx_pkt_normal_mcu;
	uint32_t		sc_rx_pkt_normal;
	uint32_t		sc_rx_pkt_unknown;
	uint32_t		sc_rx_fill_fail;
	uint32_t		sc_rx_delivered;
	uint32_t		sc_scan_done_count;
	uint32_t		sc_scan_last_ieee80211_nodes;

};

const uint8_t mwx_channels_2ghz[] = {
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14
};

#define MWX_NUM_2GHZ_CHANNELS   nitems(mwx_channels_2ghz)

const uint8_t mwx_channels_5ghz[] = {
	36, 40, 44, 48, 52, 56, 60, 64,
	100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
	149, 153, 157, 161, 165, 169, 173
};

#define MWX_NUM_5GHZ_CHANNELS   nitems(mwx_channels_5ghz)

const uint8_t mwx_channels_6ghz[] = {
	/* UNII-5 */
	1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57,
	61, 65, 69, 73, 77, 81, 85, 89, 93,
	/* UNII-6 */
	97, 101, 105, 109, 113, 117,
	/* UNII-7 */
	121, 125, 129, 133, 137, 141, 145, 149, 153, 157, 161, 165, 169,
	173, 177, 181, 185,
	/* UNII-8 */
	189, 193, 197, 201, 205, 209, 213, 217, 221, 225, 229, 233
};

const struct mwx_rate {
	uint16_t	rate;
	uint16_t	hw_value;
} mt76_rates[] = {
	{	2,	(MT_PHY_TYPE_CCK << 8) | 0 },
	{	4,	(MT_PHY_TYPE_CCK << 8) | 1 },
	{	11,	(MT_PHY_TYPE_CCK << 8) | 2 },
	{	22,	(MT_PHY_TYPE_CCK << 8) | 3 },
	{	12,	(MT_PHY_TYPE_OFDM << 8) | 11 },
	{	18,	(MT_PHY_TYPE_OFDM << 8) | 15 },
	{	24,	(MT_PHY_TYPE_OFDM << 8) | 10 },
	{	36,	(MT_PHY_TYPE_OFDM << 8) | 14 },
	{	48,	(MT_PHY_TYPE_OFDM << 8) | 9 },
	{	72,	(MT_PHY_TYPE_OFDM << 8) | 13 },
	{	96,	(MT_PHY_TYPE_OFDM << 8) | 8 },
	{	108,	(MT_PHY_TYPE_OFDM << 8) | 12 },
};


#define MWX_NUM_6GHZ_CHANNELS   nitems(mwx_channels_6ghz)

#define MWX_RATE_HT_SISO_MCS_INV_PLCP 0x20

#define	DEVNAME(s)	((s)->sc_dev.dv_xname)
#define	DEVDEBUG(x)	((x)->sc_ic.ic_if.if_flags & IFF_DEBUG)

#define MWX_RX_DROP_LOG(sc, reason, rv, rxd0, rxd1, rxd2, rxd3, rxd4) do { \
	mwx_rx_drop_count(reason); \
	if ((sc)->sc_rx_fill_fail < 64) { \
		MWX_DEV_LOG((sc), \
		    "rx drop reason=%s rv=%d rxd=%08x/%08x/%08x/%08x/%08x len=%zu\n", \
		    (reason), (rv), (rxd0), (rxd1), (rxd2), (rxd3), \
		    (rxd4), mbuf_len(m)); \
	} \
} while (0)

#ifdef MWX_DEBUG
#define	DPRINTF(x...)		MWX_LOG(x)
#else
#define	DPRINTF(x...)
#endif

#ifdef MWX_PACKET_HEXDUMP
static void
pkt_hex_dump(struct mbuf *m)
{
	int len, rowsize = 16;
	int i, l, linelen;
	uint8_t *data;

	printf("Packet hex dump:\n");
	data = mtod(m, uint8_t *);
	len = mbuf_len(m);

	for (i = 0; i < len; i += linelen) {
		printf("%04x\t", i);
		linelen = len - i;
		if (len - i > rowsize)
			linelen = rowsize;
		for (l = 0; l < linelen; l++)
			printf("%02X ", (uint32_t)data[l]);
		data += linelen;
		printf("\n");
	}
}
#endif

int	mwx_init(struct ifnet *);
int	mwx_init_hw(struct ifnet *);
void	mwx_stop(struct ifnet *);
void	mwx_watchdog(struct ifnet *);
void	mwx_start(struct ifnet *);
int	mwx_ioctl(struct ifnet *, u_long, caddr_t);

struct ieee80211_node *mwx_node_alloc(struct ieee80211com *);
int	mwx_media_change(struct ifnet *);
#if NBPFILTER > 0
void	mwx_radiotap_attach(struct mwx_softc *);
#endif

int	mwx_newstate(struct ieee80211com *, enum ieee80211_state, int);
void	mwx_newstate_task(void *);
int	mwx_scan(struct mwx_softc *);
int	mwx_bgscan(struct ieee80211com *);
void	mwx_bgscan_done(struct ieee80211com *,
	    struct ieee80211_node_switch_bss_arg *, size_t);
void	mwx_bgscan_done_task(void *);
int	mwx_set_key(struct ieee80211com *, struct ieee80211_node *,
	    struct ieee80211_key *);
void	mwx_delete_key(struct ieee80211com *, struct ieee80211_node *,
	    struct ieee80211_key *);
void	mwx_setkey_task(void *);

int	mwx_tx(struct mwx_softc *, struct mbuf *, struct ieee80211_node *);
void	mwx_rx(struct mwx_softc *, struct mbuf *, struct mbuf_list *);
int	mwx_count_nodes(struct ieee80211com *);
int	mwx_intr(void *);
int	mwx_preinit(struct mwx_softc *);
void	mwx_attach_hook(struct device *);
bool	mwx_attach(struct device *, struct device *, void *);
int	mwx_activate(struct device *, int);

void	mwx_reset(struct mwx_softc *);
void	mwx_reset_timeo(void *);
void	mwx_reset_task(void *);
int	mwx_txwi_alloc(struct mwx_softc *, int);
void	mwx_txwi_free(struct mwx_softc *);
struct mwx_txwi	*mwx_txwi_get(struct mwx_softc *);
void	mwx_txwi_put(struct mwx_softc *, struct mwx_txwi *);
int	mwx_txwi_enqueue(struct mwx_softc *, struct mwx_txwi *, struct mbuf *);
int	mwx_queue_alloc(struct mwx_softc *, struct mwx_queue *, int, uint32_t);
void	mwx_queue_free(struct mwx_softc *, struct mwx_queue *);
void	mwx_queue_reset(struct mwx_softc *, struct mwx_queue *);
int	mwx_buf_fill(struct mwx_softc *, struct mwx_queue_data *,
	    struct mwx_desc *);
int	mwx_queue_fill(struct mwx_softc *, struct mwx_queue *);
int	mwx_dma_alloc(struct mwx_softc *);
int	mwx_dma_reset(struct mwx_softc *, int);
void	mwx_dma_free(struct mwx_softc *);
int	mwx_dma_tx_enqueue(struct mwx_softc *, struct mwx_queue *,
	    struct mbuf *);
int	mwx_dma_txwi_enqueue(struct mwx_softc *, struct mwx_queue *,
	    struct mwx_txwi *);
void	mwx_dma_tx_cleanup(struct mwx_softc *, struct mwx_queue *);
void	mwx_dma_tx_done(struct mwx_softc *);
void	mwx_dma_rx_process(struct mwx_softc *, struct mbuf_list *);
void	mwx_dma_rx_dequeue(struct mwx_softc *, struct mwx_queue *,
	    struct mbuf_list *);
void	mwx_dma_rx_done(struct mwx_softc *, struct mwx_queue *);

struct mbuf	*mwx_mcu_alloc_msg(size_t);
void	mwx_mcu_set_len(struct mbuf *, void *);
int	mwx_mcu_send_mbuf(struct mwx_softc *, uint32_t, struct mbuf *, int *);
int	mwx_mcu_send_msg(struct mwx_softc *, uint32_t, void *, size_t, int *);
int	mwx_mcu_send_wait(struct mwx_softc *, uint32_t, void *, size_t);
int	mwx_mcu_send_mbuf_wait(struct mwx_softc *, uint32_t, struct mbuf *);
void	mwx_mcu_rx_event(struct mwx_softc *, struct mbuf *);
int	mwx_mcu_wait_resp_int(struct mwx_softc *, uint32_t, int, uint32_t *);
int	mwx_mcu_wait_resp_msg(struct mwx_softc *, uint32_t, int,
	    struct mbuf **);

int		mwx_dma_disable(struct mwx_softc *sc, int force);
void		mwx_dma_enable(struct mwx_softc *sc);
int		mwx_pci_flr(struct mwx_softc *, IOPCIDevice *);
static void	mwx_node_chan_width(struct ieee80211_node *, uint8_t *, uint8_t *);
int		mwx_ampdu_rx_start(struct ieee80211com *, struct ieee80211_node *,
		    uint8_t);
void		mwx_ampdu_rx_stop(struct ieee80211com *, struct ieee80211_node *,
		    uint8_t);
int		mwx_ampdu_tx_start(struct ieee80211com *, struct ieee80211_node *,
		    uint8_t);
void		mwx_ampdu_tx_stop(struct ieee80211com *, struct ieee80211_node *,
		    uint8_t);
int		mwx_mcu_fw_pmctrl(struct mwx_softc *);
int		mwx_mcu_drv_pmctrl(struct mwx_softc *);
int		mwx_wfsys_reset(struct mwx_softc *sc);
uint32_t	mwx_reg_addr(struct mwx_softc *, uint32_t);
int		mwx_init_hardware(struct mwx_softc *);
int		mt7921_mcu_init(struct mwx_softc *);
int		mwx_load_firmware(struct mwx_softc *);
int		mwx_mac_wtbl_update(struct mwx_softc *, int);
void		mwx_mac_init_band(struct mwx_softc *sc, uint32_t);
void		mwx_mac_init(struct mwx_softc *);
int		mwx_mcu_patch_sem_ctrl(struct mwx_softc *, int);
int		mwx_mcu_init_download(struct mwx_softc *, uint32_t,
		    uint32_t, uint32_t);
int		mwx_mcu_send_firmware(struct mwx_softc *, int,
		    u_char *, size_t, size_t);
int		mwx_mcu_start_patch(struct mwx_softc *);
int		mwx_mcu_start_firmware(struct mwx_softc *, uint32_t,
		    uint32_t);
int		mt7921_mcu_get_nic_capability(struct mwx_softc *);
int		mt7921_mcu_fw_log_2_host(struct mwx_softc *, uint8_t);
int		mt7921_mcu_set_eeprom(struct mwx_softc *);
int		mt7921_mcu_set_rts_thresh(struct mwx_softc *, uint32_t,
		    uint8_t);
int		mwx_mcu_set_deep_sleep(struct mwx_softc *, int);
void		mt7921_mcu_low_power_event(struct mwx_softc *, struct mbuf *);
void		mt7921_mcu_tx_done_event(struct mwx_softc *, struct mbuf *);
void		mwx_end_scan_task(void *);
void		mt7921_mcu_scan_event(struct mwx_softc *, struct mbuf *);
int		mt7921_mcu_hw_scan(struct mwx_softc *, int);
int		mt7921_mcu_hw_scan_cancel(struct mwx_softc *);
int		mt7921_mcu_set_mac_enable(struct mwx_softc *, int, int);
int		mt7921_mcu_set_channel_domain(struct mwx_softc *);
uint8_t		mt7921_mcu_chan_bw(struct ieee80211_channel *channel);
int		mt7921_mcu_set_chan_info(struct mwx_softc *, int);
void		mt7921_mcu_build_sku(struct mwx_softc *, int, int8_t *);
int		mt7921_mcu_rate_txpower_band(struct mwx_softc *, int,
		    const uint8_t *, int, int);
int		mt7921_mcu_set_rate_txpower(struct mwx_softc *);
void		mt7921_mac_reset_counters(struct mwx_softc *);
void		mt7921_mac_set_timing(struct mwx_softc *);
int		mt7921_mcu_uni_add_dev(struct mwx_softc *, struct mwx_vif *,
		    struct mwx_node *, int);
int		mt7921_mcu_set_sniffer(struct mwx_softc *, int);
int		mt7921_mcu_set_beacon_filter(struct mwx_softc *, int);
int		mt7921_mcu_set_bss_pm(struct mwx_softc *, int);
int		mt7921_mcu_set_tx(struct mwx_softc *, struct mwx_vif *);
int		mt7921_mac_fill_rx(struct mwx_softc *, struct mbuf *,
		    struct ieee80211_rxinfo *);
uint32_t	mt7921_mac_tx_rate_val(struct mwx_softc *);
void		mt7921_mac_write_txwi_80211(struct mwx_softc *, struct mbuf *,
		    struct ieee80211_node *, struct mt76_txwi *);
void		mt7921_mac_write_txwi(struct mwx_softc *, struct mbuf *,
		    struct ieee80211_node *, struct mt76_txwi *);
void		mwx_mac_tx_free(struct mwx_softc *, struct mbuf *);
int		mt7921_set_channel(struct mwx_softc *);
int mt7921_mcu_set_associated_bss(struct mwx_softc *, int);
int mt7921_mcu_set_associated_peer(struct mwx_softc *);

uint8_t		 mt7921_get_phy_mode_v2(struct mwx_softc *,
		    struct ieee80211_node *);
struct mbuf	*mwx_alloc_sta_req_tlv(int);
void		*mwx_append_len(struct mbuf *, int);
void		*mwx_append_tlv(struct mbuf *, uint16_t *, int, int);
struct mbuf	*mwx_fill_sta_req_hdr(struct mbuf *, struct mwx_vif *,
		    uint8_t, uint16_t, uint16_t);
void		 mt7921_mcu_add_basic_tlv(struct mbuf *, uint16_t *,
		    struct mwx_softc *, struct ieee80211_node *, int, int);
void		 mt7921_mcu_add_sta_tlv(struct mbuf *, uint16_t *,
		    struct mwx_softc *, struct ieee80211_node *, int, int);
int		 mt7921_mcu_wtbl_generic_tlv(struct mbuf *, uint16_t *,
		    struct mwx_softc *, struct ieee80211_node *);
int		 mt7921_mcu_wtbl_hdr_trans_tlv(struct mbuf *, uint16_t *,
		    struct mwx_softc *, struct ieee80211_node *);
int		 mt7921_mcu_wtbl_ht_tlv(struct mbuf *, uint16_t *,
		    struct mwx_softc *, struct ieee80211_node *);
int		 mt7921_mac_sta_update(struct mwx_softc *,
		    struct ieee80211_node *, int, int);
void		 mt7921_mcu_add_key_tlv(struct mbuf *, uint16_t *,
		    struct ieee80211_key *, int);
int		 mt7921_mcu_sta_key_update(struct mwx_softc *,
		    struct ieee80211_node *, struct ieee80211_key *);
void		 mt7921_mcu_sta_key_delete(struct mwx_softc *,
			    struct ieee80211_node *, struct ieee80211_key *);

static inline int
mwx_dbm_to_rssi(int dbm)
{
	if (dbm <= -100)
		return 0;
	if (dbm >= 0)
		return 100;
	return dbm + 100;
}

static inline uint32_t
mwx_read(struct mwx_softc *sc, uint32_t reg)
{
	reg = mwx_reg_addr(sc, reg);
	return bus_space_read_4(sc->sc_st, sc->sc_memh, reg);
}

static inline void
mwx_write(struct mwx_softc *sc, uint32_t reg, uint32_t val)
{
	reg = mwx_reg_addr(sc, reg);
	bus_space_write_4(sc->sc_st, sc->sc_memh, reg, val);
}

static inline void
mwx_barrier(struct mwx_softc *sc)
{
	bus_space_barrier(sc->sc_st, sc->sc_memh, 0, sc->sc_mems,
	    BUS_SPACE_BARRIER_READ | BUS_SPACE_BARRIER_WRITE);
}

static inline uint32_t
mwx_rmw(struct mwx_softc *sc, uint32_t reg, uint32_t val, uint32_t mask)
{
	reg = mwx_reg_addr(sc, reg);
	val |= bus_space_read_4(sc->sc_st, sc->sc_memh, reg) & ~mask;
	bus_space_write_4(sc->sc_st, sc->sc_memh, reg, val);
	return val;
}

static inline uint32_t
mwx_set(struct mwx_softc *sc, uint32_t reg, uint32_t bits)
{
	return mwx_rmw(sc, reg, bits, 0);
}

static inline uint32_t
mwx_clear(struct mwx_softc *sc, uint32_t reg, uint32_t bits)
{
	return mwx_rmw(sc, reg, 0, bits);
}

static inline uint32_t
mt7921_map_reg_l1(struct mwx_softc *sc, uint32_t reg)
{
	uint32_t offset = MWX_HIF_REG_OFFSET(reg);
	uint32_t base = MWX_HIF_REG_BASE(reg);

	mwx_rmw(sc, MT7921_HIF_REMAP_L1,
	    base << MT7921_HIF_REMAP_L1_SHIFT, MT7921_HIF_REMAP_L1_MASK);
	mwx_barrier(sc);

	return MT7921_HIF_REMAP_BASE_L1 + offset;
}

/*
 * Poll for timeout milliseconds or until register reg read the value val
 * after applying the mask to the value read. Returns 0 on success ETIMEDOUT
 * on failure.
 */
int
mwx_poll(struct mwx_softc *sc, uint32_t reg, uint32_t val, uint32_t mask,
    int timeout)
{
	uint32_t cur;

	reg = mwx_reg_addr(sc, reg);
	timeout *= 100;
	do {
		cur = bus_space_read_4(sc->sc_st, sc->sc_memh, reg) & mask;
		if (cur == val)
			return 0;
		delay(10);
	} while (timeout-- > 0);

	DPRINTF("%s: poll timeout reg %x val %x mask %x cur %x\n",
	    DEVNAME(sc), reg, val, mask, cur);
	return ETIMEDOUT;
}

/*
 * ifp specific functions
 */
int
mwx_init(struct ifnet *ifp)
{
#ifdef AIRPORT_WCL
	/*
	 * The native Wi-Fi interface (AirportMtkWlan) reports the adapter to
	 * macOS as resetting, then available or gone, from these events.
	 */
	struct mwx_softc *sc = (struct mwx_softc *)ifp->if_softc;
	struct ieee80211com *ic = &sc->sc_ic;
	int rv;

	if (ic->ic_event_handler)
		ic->ic_event_handler(ic, IEEE80211_EVT_DRIVER_RESET_BEGIN, NULL);
	rv = mwx_init_hw(ifp);
	if (ic->ic_event_handler)
		ic->ic_event_handler(ic, rv ? IEEE80211_EVT_DRIVER_STOPPED :
		    IEEE80211_EVT_DRIVER_READY, NULL);
	return rv;
#else
	return mwx_init_hw(ifp);
#endif
}

int
mwx_init_hw(struct ifnet *ifp)
{
	struct mwx_softc *sc = (struct mwx_softc *)ifp->if_softc;
	struct ieee80211com *ic = &sc->sc_ic;
	struct mwx_node *mn;
	const uint8_t *lladdr = ((struct arpcom *)ifp)->ac_enaddr;
	int rv;

	if (!sc->sc_fw_loaded) {
		rv = mwx_preinit(sc);
		if (rv) {
			MWX_DEV_LOG(sc, "init preinit failed error=%d\n", rv);
			return rv;
		}
	}

	/*
	 * Use the address the upper layers set (macOS's private Wi-Fi address
	 * per network), like iwx_preinit(): net80211 sends with ic_myaddr and
	 * the firmware's vif (registered below) filters on it. Otherwise DHCP
	 * runs on the private address while the AP knows us by the factory one.
	 */
	if (!IEEE80211_ADDR_EQ(lladdr, etheranyaddr) &&
	    !IEEE80211_ADDR_EQ(lladdr, ic->ic_myaddr)) {
		IEEE80211_ADDR_COPY(ic->ic_myaddr, lladdr);
		MWX_DEV_LOG(sc, "init mac address now %s\n",
		    ether_sprintf(ic->ic_myaddr));
	}

	MWX_DEV_LOG(sc, "init start opmode=%d flags=0x%x ic_state=%d\n",
	    ic->ic_opmode, ifp->if_flags, ic->ic_state);
	rv = mwx_mcu_set_deep_sleep(sc, 0);
	if (rv)
		MWX_DEV_LOG(sc, "init disable deep sleep returned %d\n", rv);
	else
		MWX_DEV_LOG(sc, "init deep sleep disabled\n");

	rv = mt7921_mcu_set_mac_enable(sc, 0, 1);
	if (rv) {
		MWX_DEV_LOG(sc, "init mac enable failed error=%d\n", rv);
		return rv;
	}
	MWX_DEV_LOG(sc, "init mac enable ok\n");

	rv = mt7921_mcu_set_channel_domain(sc);
	if (rv) {
		MWX_DEV_LOG(sc, "init channel domain failed error=%d\n", rv);
		return rv;
	}
	MWX_DEV_LOG(sc, "init channel domain ok\n");

#if 0
	/* XXX no channel available yet */
	rv = mt7921_mcu_set_chan_info(sc, MCU_EXT_CMD_SET_RX_PATH);
	if (rv)
		return rv;
#endif

	rv = mt7921_mcu_set_rate_txpower(sc);
	if (rv) {
		MWX_DEV_LOG(sc, "init rate txpower failed error=%d\n", rv);
		return rv;
	}
	MWX_DEV_LOG(sc, "init rate txpower ok\n");

	mt7921_mac_reset_counters(sc);
	MWX_DEV_LOG(sc, "init counters reset\n");

	mn = &sc->sc_vif.vif_mn;
	MWX_DEV_LOG(sc, "init vif node=%p wcid=%u\n", mn,
	    mn != NULL ? mn->wcid : 0);

	mwx_mac_wtbl_update(sc, mn->wcid);
	MWX_DEV_LOG(sc, "init wtbl updated wcid=%u\n", mn->wcid);

	rv = mt7921_mcu_uni_add_dev(sc, &sc->sc_vif, mn, 1);
	if (rv) {
		MWX_DEV_LOG(sc, "init add dev failed error=%d\n", rv);
		return rv;
	}
	MWX_DEV_LOG(sc, "init add dev ok\n");

	rv = mt7921_mcu_set_tx(sc, &sc->sc_vif);
	if (rv) {
		MWX_DEV_LOG(sc, "init set tx failed error=%d\n", rv);
		return rv;
	}
	MWX_DEV_LOG(sc, "init set tx ok\n");

	if (ic->ic_opmode == IEEE80211_M_MONITOR) {
		rv = mt7921_mcu_set_chan_info(sc, MCU_EXT_CMD_SET_RX_PATH);
		if (rv)
			return rv;
		rv = mt7921_set_channel(sc);
		if (rv)
			return rv;

		rv = mt7921_mcu_set_sniffer(sc, 1);
		MWX_DEV_LOG(sc, "init monitor sniffer enable returned %d\n", rv);
		rv = mt7921_mcu_set_beacon_filter(sc, 0);
		MWX_DEV_LOG(sc, "init monitor beacon filter disable returned %d\n", rv);
		sc->sc_rxfilter = 0;
		mwx_set(sc, MT_DMA_DCR0(0), MT_DMA_DCR0_RXD_G5_EN);
	} else {
		rv = mt7921_mcu_set_sniffer(sc, 0);
		MWX_DEV_LOG(sc, "init sniffer disable returned %d\n", rv);
		sc->sc_rxfilter |= MT_WF_RFCR_DROP_OTHER_UC;
		mwx_clear(sc, MT_DMA_DCR0(0), MT_DMA_DCR0_RXD_G5_EN);
	}
	mwx_write(sc, MT_WF_RFCR(0), sc->sc_rxfilter);
	MWX_DEV_LOG(sc, "init rxfilter set 0x%08x\n", sc->sc_rxfilter);

	ifp->if_flags |= IFF_RUNNING;
	ifq_clr_oactive(&ifp->if_snd);
	MWX_DEV_LOG(sc, "init interface running flags=0x%x\n", ifp->if_flags);

	if (ic->ic_opmode == IEEE80211_M_MONITOR) {
		ic->ic_bss->ni_chan = ic->ic_ibss_chan;
		ieee80211_new_state(ic, IEEE80211_S_RUN, -1);
		MWX_DEV_LOG(sc, "init monitor state run\n");
		return 0;
	}

	MWX_DEV_LOG(sc, "init begin scan\n");
	ieee80211_begin_scan(ifp);
	MWX_DEV_LOG(sc, "init begin scan returned state=%d flags=0x%x sc_flags=0x%x\n",
	    ic->ic_state, ifp->if_flags, sc->sc_flags);

	/*
	 * ieee80211_begin_scan() ends up scheduling mwx_newstate_task().
	 * Wait until the transition to SCAN state has completed.
	 */

	return 0;
}

void
mwx_stop(struct ifnet *ifp)
{
	struct mwx_softc *sc = (struct mwx_softc *)ifp->if_softc;
	struct ieee80211com *ic = &sc->sc_ic;
	int s = splnet();
	int was_running = (ifp->if_flags & IFF_RUNNING) != 0;

	DPRINTF("%s: stop\n", DEVNAME(sc));

	/*
	 * Tell the AP we are leaving (shutdown, interface down). Otherwise it
	 * keeps our session and ignores the first association after reboot.
	 */
	if (was_running && ic->ic_state == IEEE80211_S_RUN &&
	    ic->ic_opmode == IEEE80211_M_STA && ic->ic_bss != NULL) {
		int drv = IEEE80211_SEND_MGMT(ic, ic->ic_bss,
		    IEEE80211_FC0_SUBTYPE_DEAUTH, IEEE80211_REASON_AUTH_LEAVE);
		mwx_start(ifp);
		delay(30 * 1000);
		MWX_DEV_LOG(sc, "stop: deauth sent to AP rv=%d\n", drv);
	}

	/* Cancel scheduled tasks and let any stale tasks finish up. */
	if (sc->sc_nswq != NULL) {
		task_del(sc->sc_nswq, &sc->sc_newstate_task);
		task_del(sc->sc_nswq, &sc->sc_bgscan_done_task);
		task_del(sc->sc_nswq, &sc->sc_setkey_task);
		task_del(sc->sc_nswq, &sc->sc_reset_task);
	}
	task_del(systq, &sc->sc_scan_task);
	timeout_del(&sc->sc_reset_to);

	ifp->if_timer = 0;
	ifp->if_flags &= ~IFF_RUNNING;
	ifq_clr_oactive(&ifp->if_snd);

	if (was_running) {
		struct mwx_node *mn;

		free(sc->sc_bgscan_arg, M_DEVBUF, sc->sc_bgscan_arg_size);
		sc->sc_bgscan_arg = NULL;
		sc->sc_bgscan_arg_size = 0;
		if (sc->sc_flags & MWX_FLAG_SCANNING) {
			mt7921_mcu_hw_scan_cancel(sc);
			sc->sc_flags &= ~MWX_FLAG_SCANNING;
		}

		mn = &sc->sc_vif.vif_mn;
		mt7921_mcu_uni_add_dev(sc, &sc->sc_vif, mn, 0);
		mwx_mcu_set_deep_sleep(sc, 1);
		mt7921_mcu_set_mac_enable(sc, 0, 0);
	}

	sc->sc_newstate(ic, IEEE80211_S_INIT, -1);
	sc->sc_ns_state = IEEE80211_S_INIT;
	ifp->if_timer = 0;

#ifdef AIRPORT_WCL
	/* A stopped firmware scan cannot deliver its completion event. */
	ic->ic_flags &= ~(IEEE80211_F_BGSCAN | IEEE80211_F_ASCAN);
	ic->ic_wcl_scan_requested = false;
	ic->ic_wcl_scan_active = false;
	ic->ic_wcl_scan_ssid_length = 0;
	ic->ic_wcl_scan_idle = false;
	if (ic->ic_event_handler)
		ic->ic_event_handler(ic, IEEE80211_EVT_DRIVER_STOPPED, NULL);
#endif

	splx(s);
}

void
mwx_watchdog(struct ifnet *ifp)
{
	ifp->if_timer = 0;
	ieee80211_watchdog(ifp);
}

static inline int mwx_dma_free_slots(struct mwx_queue *);

/* Free TXWIs and TX ring slots for at least `need` frames. */
static inline int
mwx_tx_has_room(struct mwx_softc *sc, u_int need)
{
	return sc->sc_txwi.mt_nfree >= need &&
	    mwx_dma_free_slots(&sc->sc_txq) >= (int)need;
}

/* Restart output after TX completions freed enough room. */
static void
mwx_tx_kick(struct mwx_softc *sc)
{
	struct ifnet *ifp = &sc->sc_ic.ic_if;

	if (!ifq_is_oactive(&ifp->if_snd) || !mwx_tx_has_room(sc, 32))
		return;
	ifq_clr_oactive(&ifp->if_snd);
	mwx_start(ifp);
#ifdef __PRIVATE_SPI__
	if (ifp->iface != NULL)
		ifp->iface->signalOutputThread();
#endif
}

void
mwx_start(struct ifnet *ifp)
{
	struct mwx_softc *sc = (struct mwx_softc *)ifp->if_softc;
	struct ieee80211com *ic = &sc->sc_ic;
	struct ieee80211_node *ni;
	struct ether_header *eh;
	struct mbuf *m;

	if (!(ifp->if_flags & IFF_RUNNING) || ifq_is_oactive(&ifp->if_snd))
		return;

	for (;;) {
		/*
		 * Stop pulling packets while the TXWI pool or the TX ring is
		 * full instead of dropping them (TCP saw that as loss); the TX
		 * free event restarts output (mwx_tx_kick).
		 */
		if (!mwx_tx_has_room(sc, 1)) {
			ifq_set_oactive(&ifp->if_snd);
			sc->sc_tx_full_cnt++;
			break;
		}

		/* need to send management frames even if we're not RUNning */
		m = mq_dequeue(&ic->ic_mgtq);
		if (m) {
			ni = (struct ieee80211_node *)mbuf_pkthdr_rcvif(m);
			goto sendit;
		}

		if (ic->ic_state != IEEE80211_S_RUN ||
		    (ic->ic_xflags & IEEE80211_F_TX_MGMT_ONLY))
			break;

		m = ifq_dequeue(&ifp->if_snd);
		if (!m)
			break;
		if (mbuf_len(m) < sizeof (*eh) &&
		    (m = m_pullup(m, sizeof (*eh))) == NULL) {
			ifp->if_oerrors++;
			continue;
		}
#if NBPFILTER > 0
		if (ifp->if_bpf != NULL)
			bpf_mtap(ifp->if_bpf, m, BPF_DIRECTION_OUT);
#endif
		if ((m = ieee80211_encap(ifp, m, &ni)) == NULL) {
			ifp->if_oerrors++;
			continue;
		}

 sendit:
#if NBPFILTER > 0
		if (ic->ic_rawbpf != NULL)
			bpf_mtap(ic->ic_rawbpf, m, BPF_DIRECTION_OUT);
#endif
		int rv = mwx_tx(sc, m, ni);
		/* mwx_tx copies node metadata into the descriptor; completion uses
		 * the packet/token only, so release the enqueue reference here. */
		ieee80211_release_node(ic, ni);
		if (rv != 0) {
			ifp->if_oerrors++;
			if (ifp->netStat)
				ifp->netStat->outputErrors++;
			continue;
		}
		if (ifp->netStat)
			ifp->netStat->outputPackets++;

		if (ifp->if_flags & IFF_UP)
			ifp->if_timer = 1;
	}
}

int
mwx_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	int s, err = 0;

	s = splnet();
	switch (cmd) {
	case SIOCSIFADDR:
		ifp->if_flags |= IFF_UP;
		/* FALLTHROUGH */
	case SIOCSIFFLAGS:
		if (ifp->if_flags & IFF_UP) {
			if (!(ifp->if_flags & IFF_RUNNING)) {
				mwx_stop(ifp);
				err = mwx_init(ifp);
			}
		} else {
			if (ifp->if_flags & IFF_RUNNING)
				mwx_stop(ifp);
		}
		break;
	default:
		err = ieee80211_ioctl(ifp, cmd, data);
		break;
	}

	if (err == ENETRESET) {
		err = 0;
		if ((ifp->if_flags & (IFF_UP | IFF_RUNNING)) ==
		    (IFF_UP | IFF_RUNNING)) {
			mwx_stop(ifp);
			err = mwx_init(ifp);
		}
	}
	splx(s);
	return err;
}

int
mwx_media_change(struct ifnet *ifp)
{
	struct mwx_softc *sc = (struct mwx_softc *)ifp->if_softc;
	struct ieee80211com *ic = &sc->sc_ic;
	int err;

	err = ieee80211_media_change(ifp);
	if (err != ENETRESET)
		return err;

	/* TODO lot more handling here */
	if (ic->ic_fixed_mcs != -1) {
		;
	} else if (ic->ic_fixed_rate != -1) {
		;
	}
	if ((ifp->if_flags & (IFF_UP | IFF_RUNNING)) ==
	    (IFF_UP | IFF_RUNNING)) {
		/* XXX could be a bit harsh */
		mwx_stop(ifp);
		err = mwx_init(ifp);
	}
	return err;
}

/*
 * net80211 specific functions.
 */

struct ieee80211_node *
mwx_node_alloc(struct ieee80211com *ic)
{
	/* XXX this is just wrong */
	static uint32_t wcid = 0;
	struct mwx_softc *sc = (struct mwx_softc *)ic->ic_softc;
	struct mwx_node *mn;

	mn = (struct mwx_node *)malloc(sizeof(struct mwx_node), M_DEVBUF, M_NOWAIT | M_ZERO);
	if (mn == NULL)
		return NULL;
	mn->wcid = 1 + wcid++ % (MWX_WTBL_STA - 1);

	/* init WCID table entry */
	mwx_mac_wtbl_update(sc, mn->wcid);

	return &mn->ni;
}

void
mwx_newassoc(struct ieee80211com *ic, struct ieee80211_node *ni, int isnew)
{
	struct mwx_softc *sc = (struct mwx_softc *)ic->ic_softc;
	struct mwx_node *mn = (struct mwx_node *)ni;
	uint16_t wcid = 0;

	if (isnew && ni->ni_associd != 0) {
		/* only interested in true associations */
		wcid = IEEE80211_AID(ni->ni_associd);

	}
	printf("%s: new assoc isnew=%d addr=%s WCID=%d\n", DEVNAME(sc),
	    isnew, ether_sprintf(ni->ni_macaddr), mn->wcid);

	/* XXX TODO rate handling here */
}

#ifndef IEEE80211_STA_ONLY
void
mwx_node_leave(struct ieee80211com *ic, struct ieee80211_node *ni)
{
#if 0
	struct mwx_softc *sc = (struct mwx_softc *)ic->ic_softc;
	struct mwx_node *mn = (struct mwx_node *)ni;
	uint16_t wcid = mn->wcid;

	/* TODO clear WCID */
#endif
}
#endif

int
mwx_scan(struct mwx_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct ifnet *ifp = &ic->ic_if;
	int rv;

	if (sc->sc_flags & MWX_FLAG_BGSCAN) {
		rv = mt7921_mcu_hw_scan_cancel(sc);
		if (rv) {
			printf("%s: could not abort background scan\n",
			    DEVNAME(sc));
			return rv;
		}
	}

	rv = mt7921_mcu_hw_scan(sc, 0);
	if (rv) {
		printf("%s: could not initiate scan\n", DEVNAME(sc));
		return rv;
	}

	/*
	 * The current mode might have been fixed during association.
	 * Ensure all channels get scanned.
	 */
	if (IFM_MODE(ic->ic_media.ifm_cur->ifm_media) != IFM_AUTO)
		ieee80211_setmode(ic, IEEE80211_MODE_AUTO);

	sc->sc_flags |= MWX_FLAG_SCANNING;
	if (ifp->if_flags & IFF_DEBUG)
		printf("%s: %s -> %s\n", ifp->if_xname,
		    ieee80211_state_name[ic->ic_state],
		    ieee80211_state_name[IEEE80211_S_SCAN]);
	if ((sc->sc_flags & MWX_FLAG_BGSCAN) == 0) {
		ieee80211_set_link_state(ic, LINK_STATE_DOWN);
		ieee80211_node_cleanup(ic, ic->ic_bss);
	}
	ic->ic_state = IEEE80211_S_SCAN;

	return 0;
}

int
mwx_newstate(struct ieee80211com *ic, enum ieee80211_state nstate, int arg)
{
	struct mwx_softc *sc = (struct mwx_softc *)ic->ic_softc;

	/*
	 * Prevent attempts to transition towards the same state, unless
	 * we are scanning in which case a SCAN -> SCAN transition
	 * triggers another scan iteration. And AUTH -> AUTH is needed
	 * to support band-steering.
	 */
	if (sc->sc_ns_state == nstate && nstate != IEEE80211_S_SCAN &&
	    nstate != IEEE80211_S_AUTH)
		return 0;

	if (ic->ic_state == IEEE80211_S_RUN) {
		/* cancel other tasks here */
	}

	sc->sc_ns_state = nstate;
	sc->sc_ns_arg = arg;

	task_add(sc->sc_nswq, &sc->sc_newstate_task);
	return 0;
}

void
mwx_newstate_task(void *ptr)
{
	struct mwx_softc *sc = (struct mwx_softc *)ptr;
	struct ieee80211com *ic = &sc->sc_ic;
	enum ieee80211_state ostate = ic->ic_state;
	enum ieee80211_state nstate = sc->sc_ns_state;
	int arg = sc->sc_ns_arg;
	int s = splnet();
	int rv = 0;

	switch (ostate) {
	case IEEE80211_S_RUN:
		if (nstate != ostate)
			mwx_mcu_set_deep_sleep(sc, 1);
		/*
		 * Leaving the BSS: tell the firmware the BSS is gone and remove
		 * the peer station record (like Linux does on disassoc). Without
		 * this the next association reused wcid 1 on top of the stale
		 * record and the chip stopped decrypting RX in hardware.
		 */
		if (nstate < IEEE80211_S_RUN &&
		    ic->ic_opmode == IEEE80211_M_STA) {
			int brv = mt7921_mcu_set_associated_bss(sc, 0);
			int srv = mt7921_mac_sta_update(sc, ic->ic_bss, 0, 0);
			MWX_DEV_LOG(sc, "leave BSS: bss_off=%d sta_remove=%d\n",
			    brv, srv);
			sc->sc_sta_added = 0;
		}
		break;
	case IEEE80211_S_SCAN:
		if (nstate == ostate) {
			if (sc->sc_flags & MWX_FLAG_SCANNING) {
				splx(s);
				return;
			}
		}
		break;
	default:
		break;
	}

	DPRINTF("%s: %s %d -> %d\n", DEVNAME(sc), __func__, ostate, nstate);
	MWX_DEV_LOG(sc, "newstate task %d -> %d arg=%d\n", ostate, nstate, arg);

	switch (nstate) {
	case IEEE80211_S_INIT:
		break;
	case IEEE80211_S_SCAN:
		rv = mwx_scan(sc);
		if (rv)
			break;
		break;
	case IEEE80211_S_AUTH:
		rv = mt7921_set_channel(sc);
		if (rv)
			break;
		mwx_mcu_set_deep_sleep(sc, 0);
		/*
		 * A previous attempt (failed association, or AUTH retry on
		 * another AP) may have left the peer record in firmware; adding
		 * a new peer on top of it breaks hardware decryption.
		 */
		/*
		 * Starting a new connection: send a deauth first so the AP drops
		 * any session it kept from before (e.g. across a reboot); it
		 * otherwise ignored our first association request. An AP that
		 * has no session for us just ignores the frame.
		 */
		if (ostate == IEEE80211_S_SCAN && ic->ic_bss != NULL) {
			IEEE80211_SEND_MGMT(ic, ic->ic_bss,
			    IEEE80211_FC0_SUBTYPE_DEAUTH,
			    IEEE80211_REASON_AUTH_LEAVE);
			mwx_start(&ic->ic_if);
			MWX_DEV_LOG(sc, "AUTH: pre-auth deauth sent to %s\n",
			    ether_sprintf(ic->ic_bss->ni_macaddr));
		}
		if (sc->sc_sta_added) {
			int srv = mt7921_mac_sta_update(sc, sc->sc_ic.ic_bss, 0, 0);
			MWX_DEV_LOG(sc, "AUTH: removed stale peer record rv=%d\n", srv);
			sc->sc_sta_added = 0;
		}
		if (mt7921_mac_sta_update(sc, sc->sc_ic.ic_bss, 1, 1) == 0)
			sc->sc_sta_added = 1;
		break;
	case IEEE80211_S_ASSOC:
		mwx_mcu_set_deep_sleep(sc, 1);
		break;
	case IEEE80211_S_RUN:
		if (ic->ic_opmode == IEEE80211_M_MONITOR)
			break;

		mt7921_mcu_hw_scan_cancel(sc);
		mwx_mcu_set_deep_sleep(sc, 0);
		{
			struct ieee80211_node *bni = ic->ic_bss;
			MWX_DEV_LOG(sc,
			    "RUN peer ht=%d vht=%d chw=%d vht_chanwidth=%u vht_chan1=%u center_freq1=%u htcaps=0x%04x vhtcaps=0x%08x\n",
			    !!(bni->ni_flags & IEEE80211_NODE_HT),
			    !!(bni->ni_flags & IEEE80211_NODE_VHT), bni->ni_chw,
			    bni->ni_vht_chanwidth, bni->ni_vht_chan1,
			    bni->ni_chan->ic_center_freq1, bni->ni_htcaps,
			    bni->ni_vhtcaps);
			uint8_t rbw, rcenter;
			mwx_node_chan_width(bni, &rbw, &rcenter);
			if (rbw != CMD_CBW_20MHZ) {
				int crv = mt7921_mcu_set_chan_info(sc,
				    MCU_EXT_CMD_CHANNEL_SWITCH);
				MWX_DEV_LOG(sc, "RUN switch to %s MHz center=%u rv=%d\n",
				    rbw == CMD_CBW_80MHZ ? "80" : "40", rcenter, crv);
			}
		}
		rv = mt7921_mcu_set_associated_bss(sc, 1);
		if (!rv)
			rv = mt7921_mcu_set_associated_peer(sc);
		if (rv)
			break;
		mt7921_mcu_set_rts_thresh(sc, 0x92b, 0);
		break;
	}

	if (rv)
		mwx_reset(sc);
	else
		sc->sc_newstate(ic, nstate, arg);
	splx(s);
}

int
mwx_bgscan(struct ieee80211com *ic)
{
	struct mwx_softc *sc = (struct mwx_softc *)ic->ic_softc;
	int err;

	if (sc->sc_flags & MWX_FLAG_SCANNING)
		return 0;

	/*
	 * While associated, a full hardware scan keeps the radio off the
	 * home channel for ~11 s. The client asks for one every ~20 s to
	 * refresh its network list, which halved throughput. Allow at most
	 * one background scan per 2 minutes while in RUN.
	 */
	if (ic->ic_state == IEEE80211_S_RUN) {
		static uint64_t last_bgscan_ns;
		uint64_t now_ns, min_ns = 120ULL * 1000000000ULL;

#ifdef AIRPORT_WCL
		/*
		 * macOS asks for a few channels at a time (well under a second
		 * off channel); only full sweeps get the 2 minute limit.
		 */
		if (ic->ic_wcl_scan_requested && ic->ic_wcl_scan_restricted)
			min_ns = 10ULL * 1000000000ULL;
#endif
		absolutetime_to_nanoseconds(mach_absolute_time(), &now_ns);
		if (last_bgscan_ns != 0 && now_ns - last_bgscan_ns < min_ns)
			return EBUSY;
		last_bgscan_ns = now_ns;
	}

	err = mt7921_mcu_hw_scan(sc, 1);
	if (err) {
		printf("%s: could not initiate scan\n", DEVNAME(sc));
		return err;
	}

	sc->sc_flags |= MWX_FLAG_BGSCAN;
	return 0;
}

void
mwx_bgscan_done(struct ieee80211com *ic,
    struct ieee80211_node_switch_bss_arg *arg, size_t arg_size)
{
	struct mwx_softc *sc = (struct mwx_softc *)ic->ic_softc;

	free(sc->sc_bgscan_arg, M_DEVBUF, sc->sc_bgscan_arg_size);
	sc->sc_bgscan_arg = arg;
	sc->sc_bgscan_arg_size = arg_size;
	task_add(sc->sc_nswq, &sc->sc_bgscan_done_task);
}

void
mwx_bgscan_done_task(void *arg)
{
	struct mwx_softc *sc = (struct mwx_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;
	struct ieee80211_node *ni = ic->ic_bss;
	int err = 0;
	int s = splnet();

	if (ic->ic_state != IEEE80211_S_RUN ||
	    (ic->ic_flags & IEEE80211_F_BGSCAN) == 0) {
		err = ENXIO;
		goto done;
	}

	/*
	 * net80211 queued a deauth for the current AP. Push it out on the
	 * current channel before switching; otherwise the AP keeps a stale
	 * session and rejects us (disassoc 8 / deauth 9) when we come back.
	 */
	mwx_start(&ic->ic_if);
	delay(30 * 1000);

	/*
	 * Remove installed crypto keys while we still have access to them.
	 * Once mwx_newstate() is entered ic_bss will already contain
	 * information about our next AP.
	 */
	if (ic->ic_flags & IEEE80211_F_RSNON) {
		struct ieee80211_key *k;

		if (ni->ni_pairwise_key.k_cipher != IEEE80211_CIPHER_NONE)
			(*ic->ic_delete_key)(ic, ni, &ni->ni_pairwise_key);

		if (ic->ic_def_txkey == 1 || ic->ic_def_txkey == 2) {
			k = &ic->ic_nw_keys[ic->ic_def_txkey];
			if ((k->k_flags & IEEE80211_KEY_GROUP) &&
			    k->k_cipher == IEEE80211_CIPHER_CCMP)
				(*ic->ic_delete_key)(ic, ni, k);
		}

		if (ic->ic_igtk_kid == 4 || ic->ic_igtk_kid == 5) {
			k = &ic->ic_nw_keys[ic->ic_igtk_kid];
			if (k->k_flags & IEEE80211_KEY_IGTK)
				(*ic->ic_delete_key)(ic, ni, k);
		}

		ni->ni_port_valid = 0;
		ni->ni_flags &= ~IEEE80211_NODE_TXRXPROT;
		ni->ni_flags &= ~IEEE80211_NODE_TXMGMTPROT;
		ni->ni_flags &= ~IEEE80211_NODE_RXMGMTPROT;
		ni->ni_rsn_supp_state = RSNA_SUPP_INITIALIZE;
	}

	/*
	 * The local net80211 port switches BSS from ni_unref_cb when the
	 * current node's final reference is released. Install the same
	 * callback after the driver has removed hardware keys.
	 */
	ni->ni_unref_arg = sc->sc_bgscan_arg;
	ni->ni_unref_arg_size = sc->sc_bgscan_arg_size;
	ni->ni_unref_cb = ieee80211_node_switch_bss;
	sc->sc_bgscan_arg = NULL;
	sc->sc_bgscan_arg_size = 0;
	if (ni->ni_flags & IEEE80211_NODE_MFP)
		ieee80211_node_switch_bss(ic, ni);

 done:
	if (err) {
		free(sc->sc_bgscan_arg, M_DEVBUF, sc->sc_bgscan_arg_size);
		sc->sc_bgscan_arg = NULL;
		sc->sc_bgscan_arg_size = 0;
	}
	splx(s);
}

int
mwx_set_key(struct ieee80211com *ic, struct ieee80211_node *ni,
    struct ieee80211_key *k)
{
	struct mwx_softc *sc = (struct mwx_softc *)ic->ic_softc;
	struct mwx_setkey_task_arg *a;

	DPRINTF("%s: set_key: ni %p, k_id %d, k_flags %x k_cipher %d\n",
	    DEVNAME(sc), ni, k->k_id, k->k_flags, k->k_cipher);

	/*
	 * MT7921 does not reliably decrypt group-addressed frames with the
	 * GTK installed in hardware; those arrive without RXI_HWDEC and were
	 * dropped as wepfail (broadcast ARP / DHCP never reached the stack).
	 * Also set up the software crypto context for group keys so net80211
	 * can decrypt them itself. Group keys are RX-only for a station.
	 */
	/*
	 * Same fallback for the pairwise key: after a reassociation the chip
	 * sometimes stops decrypting unicast frames too. net80211 never
	 * encrypts TX in software, so this only affects RX.
	 */
	if (!(k->k_flags & IEEE80211_KEY_SWCRYPTO)) {
		int err = ieee80211_set_key(ic, ni, k);
		MWX_DEV_LOG(sc, "%s key id=%d cipher=%d sw crypto setup=%d\n",
		    (k->k_flags & IEEE80211_KEY_GROUP) ? "group" : "pairwise",
		    k->k_id, k->k_cipher, err);
	}

	if ((sc->sc_setkey_cur + 1) % nitems(sc->sc_setkey_arg) ==
	    sc->sc_setkey_tail)
		return ENOSPC;

	a = &sc->sc_setkey_arg[sc->sc_setkey_cur];
	a->ni = ni;
	a->k = k;
	sc->sc_setkey_cur = (sc->sc_setkey_cur + 1) % nitems(sc->sc_setkey_arg);
	task_add(sc->sc_nswq, &sc->sc_setkey_task);
	return EBUSY;
}

void
mwx_delete_key(struct ieee80211com *ic, struct ieee80211_node *ni,
    struct ieee80211_key *k)
{
	struct mwx_softc *sc = (struct mwx_softc *)ic->ic_softc;

	DPRINTF("%s: delete_key: ni %p, k_id %d, k_flags %x k_cipher %d\n",
	    DEVNAME(sc), ni, k->k_id, k->k_flags, k->k_cipher);

	mt7921_mcu_sta_key_delete(sc, ni, k);
	/* release the software crypto context set up in mwx_set_key() */
	if (k->k_flags & IEEE80211_KEY_SWCRYPTO)
		ieee80211_delete_key(ic, ni, k);
}

void
mwx_setkey_task(void *arg)
{
	struct mwx_softc *sc = (struct mwx_softc *)arg;
	struct mwx_setkey_task_arg *a;
	int s = splnet();

	while (sc->sc_setkey_tail != sc->sc_setkey_cur) {
		a = &sc->sc_setkey_arg[sc->sc_setkey_tail];
		mt7921_mcu_sta_key_update(sc, a->ni, a->k);
		a->ni = NULL;
		a->k = NULL;

		sc->sc_setkey_tail = (sc->sc_setkey_tail + 1) %
		    nitems(sc->sc_setkey_arg);
	}

	splx(s);
}

#if NBPFILTER > 0
void
mwx_radiotap_attach(struct mwx_softc *sc)
{
	bpfattach(&sc->sc_drvbpf, &sc->sc_ic.ic_if, DLT_IEEE802_11_RADIO,
	    sizeof(struct ieee80211_frame) + IEEE80211_RADIOTAP_HDRLEN);

	sc->sc_rxtap_len = sizeof sc->sc_rxtapu;
	sc->sc_rxtap.wr_ihdr.it_len = htole16(sc->sc_rxtap_len);
	sc->sc_rxtap.wr_ihdr.it_present = htole32(MWX_RX_RADIOTAP_PRESENT);

	sc->sc_txtap_len = sizeof sc->sc_txtapu;
	sc->sc_txtap.wt_ihdr.it_len = htole16(sc->sc_txtap_len);
	sc->sc_txtap.wt_ihdr.it_present = htole32(MWX_TX_RADIOTAP_PRESENT);
}
#endif

/*
 * Copy a TX frame into one freshly allocated cluster so the firmware sees a
 * single contiguous buffer. Experiment: the WFDMA stalled on the first DHCP
 * frame (a multi-mbuf chain) on MT7921.
 */
static struct mbuf *
mwx_tx_linearize(struct mbuf *m)
{
	size_t len = mbuf_pkthdr_len(m);
	struct mbuf *n;

	if (mbuf_next(m) == NULL || len == 0 || len > MCLBYTES * 2)
		return m;
	{
		static uint32_t lin_log_count;
		if (lin_log_count < 48) {
			struct mbuf *c;
			char chain[96];
			size_t off = 0;

			chain[0] = 0;
			for (c = m; c != NULL && off < sizeof(chain) - 12;
			    c = mbuf_next(c))
				off += snprintf(chain + off, sizeof(chain) - off,
				    "%zu%s@%p,", mbuf_len(c),
				    (mbuf_flags(c) & MBUF_EXT) ? "e" : "",
				    mbuf_data(c));
			MWX_LOG("tx linearize len=%zu chain=%s\n", len, chain);
			lin_log_count++;
		}
	}
	n = MCLGETL(NULL, M_DONTWAIT, len);
	if (n == NULL)
		return m;
	if (mbuf_next(n) != NULL) {
		m_freem(n);
		return m;
	}
	mbuf_setlen(n, len);
	mbuf_pkthdr_setlen(n, len);
	if (mbuf_copydata(m, 0, len, mtod(n, void *)) != 0) {
		m_freem(n);
		return m;
	}
	m_freem(m);
	return n;
}

int
mwx_tx(struct mwx_softc *sc, struct mbuf *m, struct ieee80211_node *ni)
{
	struct mwx_node *mn = (struct mwx_node *)ni;
	struct mwx_txwi *mt;
	struct mt76_txwi *txp;
	int rv;
#ifdef AIRPORT_WCL
	struct ieee80211_frame *wcl_wh;
	bool wcl_data;
	unsigned wcl_ac;
#endif

	if ((mt = mwx_txwi_get(sc)) == NULL) {
		m_freem(m);
		return ENOBUFS;
	}
	m = mwx_tx_linearize(m);
	/* XXX DMA memory access without BUS_DMASYNC_PREWRITE */
	txp = mt->mt_desc;
	memset(txp, 0, sizeof(*txp));
	mt7921_mac_write_txwi(sc, m, ni, txp);

#ifdef AIRPORT_WCL
	/* Per access category data counters for macOS's link quality. */
	wcl_wh = mtod(m, struct ieee80211_frame *);
	wcl_data = (wcl_wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_DATA &&
	    !(wcl_wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_NODATA);
	wcl_ac = ieee80211_has_qos(wcl_wh) ?
	    ieee80211_wcl_ac(ieee80211_get_qos(wcl_wh) & IEEE80211_QOS_TID) : EDCA_AC_BE;
#endif
	rv = mwx_txwi_enqueue(sc, mt, m);
	if (rv != 0) {
		/* Mapping failed before ownership reached the TXWI. */
		m_freem(m);
		mwx_txwi_put(sc, mt);
		return rv;
	}
#ifdef AIRPORT_WCL
	if (wcl_data)
		++sc->sc_ic.ic_wcl_tx_packets[wcl_ac];
#endif

	static uint32_t tx_log_count;
	if (tx_log_count < 32) {
		MWX_DEV_LOG(sc, "tx frame wcid=%u pid=%d len=%zu\n",
		    mn->wcid, mt->mt_idx, mbuf_pkthdr_len(m));
		MWX_DEV_LOG(sc,
		    "txwi %08x %08x %08x %08x %08x %08x %08x %08x\n",
		    txp->txwi[0], txp->txwi[1], txp->txwi[2], txp->txwi[3],
		    txp->txwi[4], txp->txwi[5], txp->txwi[6], txp->txwi[7]);
		MWX_DEV_LOG(sc,
		    "tx desc msdu=%u/%u/%u/%u len=%u/%u/%u/%u\n",
		    txp->msdu_id[0], txp->msdu_id[1], txp->msdu_id[2],
		    txp->msdu_id[3], txp->ptr[0].len0, txp->ptr[0].len1,
		    txp->ptr[1].len0, txp->ptr[1].len1);
		tx_log_count++;
	}

	rv = mwx_dma_txwi_enqueue(sc, &sc->sc_txq, mt);
	if (rv != 0)
		mwx_txwi_put(sc, mt);
	return rv;
}

void
mwx_rx(struct mwx_softc *sc, struct mbuf *m, struct mbuf_list *ml)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct ifnet *ifp = &ic->ic_if;
	struct ieee80211_node *ni;
	struct ieee80211_frame *wh;
	struct ieee80211_rxinfo rxi = { 0 };
	int rv;

	rv = mt7921_mac_fill_rx(sc, m, &rxi);
	if (rv != 0) {
		if (sc->sc_rx_fill_fail < 32) {
			MWX_DEV_LOG(sc,
			    "rx fill failed rv=%d len=%zu fail_count=%u\n",
			    rv, mbuf_len(m), sc->sc_rx_fill_fail + 1);
		}
		sc->sc_rx_fill_fail++;
		ifp->if_ierrors++;
		m_freem(m);
		return;
	}

	wh = mtod(m, struct ieee80211_frame *);
	if (sc->sc_rx_delivered < 32) {
		uint8_t type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
		uint8_t subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

		MWX_DEV_LOG(sc,
		    "rx frame delivered type=0x%02x subtype=0x%02x chan=%u rssi=%d len=%zu\n",
		    type, subtype, rxi.rxi_chan, rxi.rxi_rssi, mbuf_len(m));
	}
	{
		static uint32_t rx_run_log_count;
		uint8_t type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
		uint8_t subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

		if (rx_run_log_count < 48 &&
		    (type == IEEE80211_FC0_TYPE_DATA ||
		    (ic->ic_state == IEEE80211_S_RUN &&
		    (rxi.rxi_flags & IEEE80211_RXI_HWDEC)))) {
			MWX_DEV_LOG(sc,
			    "rx run frame state=%d fc=%02x/%02x type=0x%02x subtype=0x%02x rxi_flags=0x%x chan=%u rssi=%d len=%zu\n",
			    ic->ic_state, wh->i_fc[0], wh->i_fc[1], type, subtype,
			    rxi.rxi_flags, rxi.rxi_chan, rxi.rxi_rssi, mbuf_len(m));
			rx_run_log_count++;
		}
	}
	sc->sc_rx_delivered++;
	if ((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_CTL) {
		mwx_rx_ctl_cnt++;
		if ((wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) ==
		    IEEE80211_FC0_SUBTYPE_BAR)
			mwx_rx_bar_cnt++;
	}
	if (rxi.rxi_flags & IEEE80211_RXI_HWDEC)
		mwx_rx_hwdec_cnt++;
	else if (wh->i_fc[1] & IEEE80211_FC1_PROTECTED)
		mwx_rx_swdec_cnt++;

#if NBPFILTER > 0
	if (__predict_false(sc->sc_drvbpf != NULL)) {
		struct mwx_rx_radiotap_header *tap = &sc->sc_rxtap;
		uint32_t tsf_lo, tsf_hi;
		/* get timestamp (low and high 32 bits) */
		tsf_hi = 0;
		tsf_lo = 0;
		tap->wr_tsft = htole64(((uint64_t)tsf_hi << 32) | tsf_lo);
		tap->wr_flags = 0;
		tap->wr_rate = 2;	/* XXX */
		tap->wr_chan_freq =
		    htole16(ic->ic_channels[rxi.rxi_chan].ic_freq);
		tap->wr_chan_flags =
		    ic->ic_channels[rxi.rxi_chan].ic_flags;
		tap->wr_dbm_antsignal = rxi.rxi_rssi;
		bpf_mtap_hdr(sc->sc_drvbpf, tap, sc->sc_rxtap_len, m,
		    BPF_DIRECTION_IN);
	}
#endif

	/* grab a reference to the source node */
	ni = ieee80211_find_rxnode(ic, wh);

	if (ic->ic_max_rssi && rxi.rxi_rssi < 0)
		rxi.rxi_rssi = mwx_dbm_to_rssi(rxi.rxi_rssi);

	/* send the frame to the 802.11 layer */
	ieee80211_inputm(ifp, m, ni, &rxi, ml);

	/* node is no longer needed */
	ieee80211_release_node(ic, ni);
}

int
mwx_count_nodes(struct ieee80211com *ic)
{
	struct ieee80211_node *ni;
	int count = 0;

	RB_FOREACH(ni, ieee80211_tree, &ic->ic_tree)
		count++;
	return count;
}

/*
 * Driver specific functions.
 */
static uint32_t mwx_intr_calls;

int
mwx_intr(void *arg)
{
	struct mwx_softc *sc = (struct mwx_softc *)arg;
	uint32_t intr, intr_sw;
	uint32_t mask = sc->sc_intr_mask;
	static uint32_t intr_log_count;
	static uint32_t intr_unhandled_log_count;

	mwx_intr_calls++;

	/*
	 * Asleep, or the card is not powered yet after wake: its registers
	 * read all ones and the DMA rings are stale. Touching them panicked
	 * (NULL mbuf in mwx_dma_rx_dequeue) on wake.
	 */
	if (sc->sc_suspended)
		return 0;

	mwx_write(sc, MT_WFDMA0_HOST_INT_ENA, 0);
	intr = mwx_read(sc, MT_WFDMA0_HOST_INT_STA);
	if (intr == 0xffffffff)
		return 0;
	if (intr == 0) {
		mwx_write(sc, MT_WFDMA0_HOST_INT_ENA, mask);
		return 0;
	}

	/* TODO power management */
//	mt76_connac_pm_ref(&dev->mphy, &dev->pm);

	if (intr_log_count < 16) {
		MWX_DEV_LOG(sc, "interrupt status=0x%08x mask=0x%08x\n",
		    intr, mask);
		intr_log_count++;
	}

	if (intr & ~mask && intr_unhandled_log_count < 16) {
		printf("%s: unhandled interrupt %08x\n", DEVNAME(sc),
		    intr & ~mask);
		intr_unhandled_log_count++;
	}
	/* ack interrupts */
	intr &= mask;
	mwx_write(sc, MT_WFDMA0_HOST_INT_STA, intr);

	if (intr & MT_INT_MCU_CMD) {
		intr_sw = mwx_read(sc, MT_MCU_CMD);
		if (intr_log_count < 16)
			MWX_DEV_LOG(sc, "mcu interrupt status=0x%08x\n", intr_sw);
		/* ack MCU2HOST_SW_INT_STA */
		mwx_write(sc, MT_MCU_CMD, intr_sw);
		if (intr_sw & MT_MCU_CMD_WAKE_RX_PCIE)
			intr |= MT_INT_RX_DONE_DATA;
	}

	for (int pass = 0; ; pass++) {
		if (intr & MT_INT_TX_DONE_ALL)
			mwx_dma_tx_done(sc);

		if (intr & MT_INT_RX_DONE_WM)
			mwx_dma_rx_done(sc, &sc->sc_rxfwdlq);
		if (intr & MT_INT_RX_DONE_WM2)
			mwx_dma_rx_done(sc, &sc->sc_rxmcuq);
		if (intr & MT_INT_RX_DONE_DATA)
			mwx_dma_rx_done(sc, &sc->sc_rxq);

		/*
		 * MSI is edge triggered: events that arrived while the host
		 * interrupt enable was cleared do not raise a new message, so
		 * drain them here before re-enabling.
		 */
		if (pass >= 8)
			break;
		intr = mwx_read(sc, MT_WFDMA0_HOST_INT_STA) & mask;
		if (intr == 0)
			break;
		mwx_write(sc, MT_WFDMA0_HOST_INT_STA, intr);
		if (intr & MT_INT_MCU_CMD) {
			intr_sw = mwx_read(sc, MT_MCU_CMD);
			mwx_write(sc, MT_MCU_CMD, intr_sw);
			if (intr_sw & MT_MCU_CMD_WAKE_RX_PCIE)
				intr |= MT_INT_RX_DONE_DATA;
		}
	}

	/* TODO power management */
//	mt76_connac_pm_unref(&dev->mphy, &dev->pm);

	mwx_write(sc, MT_WFDMA0_HOST_INT_ENA, mask);

	return 1;
}

int
mwx_preinit(struct mwx_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct ifnet *ifp = &ic->ic_if;
	int rv, i;
	uint8_t chan;

	MWX_DEV_LOG(sc, "preinit start fw_loaded=%d\n", sc->sc_fw_loaded);

	if ((rv = mwx_init_hardware(sc)) != 0) {
		MWX_DEV_LOG(sc, "preinit hardware init failed error=%d\n", rv);
		return rv;
	}
	MWX_DEV_LOG(sc, "preinit hardware init ok\n");

	if ((rv = mwx_mcu_set_deep_sleep(sc, 1)) != 0) {
		MWX_DEV_LOG(sc, "preinit deep sleep enable failed error=%d\n", rv);
		return rv;
	}
	MWX_DEV_LOG(sc, "preinit deep sleep enabled\n");

	ic->ic_sup_rates[IEEE80211_MODE_11B] = ieee80211_std_rateset_11b;
	ic->ic_sup_rates[IEEE80211_MODE_11G] = ieee80211_std_rateset_11g;
	MWX_DEV_LOG(sc, "preinit capability 2ghz=%d 5ghz=%d 6ghz=%d streams=%u antenna_mask=0x%x\n",
	    sc->sc_capa.has_2ghz, sc->sc_capa.has_5ghz,
	    sc->sc_capa.has_6ghz, sc->sc_capa.num_streams,
	    sc->sc_capa.antenna_mask);

	if (sc->sc_capa.has_2ghz) {
		for (i = 0; i < MWX_NUM_2GHZ_CHANNELS; i++) {
			chan = mwx_channels_2ghz[i];
			ic->ic_channels[chan].ic_freq =
			    ieee80211_ieee2mhz(chan, IEEE80211_CHAN_2GHZ);
			ic->ic_channels[chan].ic_flags =
			    IEEE80211_CHAN_CCK | IEEE80211_CHAN_OFDM |
			    IEEE80211_CHAN_DYN | IEEE80211_CHAN_2GHZ |
			    IEEE80211_CHAN_HT20;
		}

	}
	if (sc->sc_capa.has_5ghz) {
		ic->ic_sup_rates[IEEE80211_MODE_11A] =
		    ieee80211_std_rateset_11a;
		/* set supported .11a channels */
		for (i = 0; i < MWX_NUM_5GHZ_CHANNELS; i++) {
			chan = mwx_channels_5ghz[i];
			ic->ic_channels[chan].ic_freq =
			    ieee80211_ieee2mhz(chan, IEEE80211_CHAN_5GHZ);
			/*
			 * Capability flags only; the operating width comes
			 * from what net80211 negotiates (ni_chw).
			 */
			ic->ic_channels[chan].ic_flags = IEEE80211_CHAN_A |
			    IEEE80211_CHAN_HT20 | IEEE80211_CHAN_HT40 |
			    IEEE80211_CHAN_VHT20 |
			    IEEE80211_CHAN_VHT40 | IEEE80211_CHAN_VHT80;
		}
	}
#ifdef NOTYET
	/* TODO support for 6GHz */
	if (sc->sc_capa.has_6ghz) {
		for (i = 0; i < MWX_NUM_6GHZ_CHANNELS; i++) {
		}
	}
#endif

	/* HT MCS set: MCS 0-7 per spatial stream. */
	memset(ic->ic_sup_mcs, 0, sizeof(ic->ic_sup_mcs));
	ic->ic_sup_mcs[0] = 0xff;
	if (sc->sc_capa.num_streams >= 2)
		ic->ic_sup_mcs[1] = 0xff;
	ic->ic_tx_mcs_set = IEEE80211_TX_MCS_SET_DEFINED;

	/* Configure channel information obtained from firmware. */
	ieee80211_channel_init(ifp);
	/* VHT channels make net80211 claim 11ax too; HE is not supported. */
	ic->ic_modecaps &= ~(1 << IEEE80211_MODE_11AX);
	MWX_DEV_LOG(sc, "preinit channel table ready\n");

	if (IEEE80211_ADDR_EQ(etheranyaddr, sc->sc_ic.ic_myaddr))
		IEEE80211_ADDR_COPY(ic->ic_myaddr, sc->sc_lladdr);

	/* Configure MAC address. */
	rv = if_setlladdr(ifp, ic->ic_myaddr);
	if (rv)
		printf("%s: could not set MAC address (error %d)\n",
		    DEVNAME(sc), rv);
	else
		MWX_DEV_LOG(sc, "preinit mac address=%s\n",
		    ether_sprintf(ic->ic_myaddr));

	ieee80211_media_init(ifp);
	/*
	 * Enable QoS (WMM) directly: ieee80211_configure_ampdu_tx() only does
	 * so together with TX A-MPDU, which the driver does not support yet.
	 */
	ic->ic_flags |= IEEE80211_F_QOS;
	/* media_init does not turn VHT on by itself; never enable HE. */
	ic->ic_flags &= ~IEEE80211_F_HEON;
	if (ic->ic_modecaps & (1 << IEEE80211_MODE_11AC))
		ic->ic_flags |= IEEE80211_F_VHTON;
	MWX_DEV_LOG(sc, "preinit 11n htcaps=0x%04x mcs=%02x%02x hton=%d qos=%d vhton=%d vhtcaps=0x%08x\n",
	    ic->ic_htcaps, ic->ic_sup_mcs[1], ic->ic_sup_mcs[0],
	    !!(ic->ic_flags & IEEE80211_F_HTON),
	    !!(ic->ic_flags & IEEE80211_F_QOS),
	    !!(ic->ic_flags & IEEE80211_F_VHTON), ic->ic_vhtcaps);

	sc->sc_sta_added = 0;	/* fresh firmware has no peer records */
	sc->sc_fw_loaded = 1;
	MWX_DEV_LOG(sc, "preinit complete\n");
	return 0;
}

void
mwx_attach_hook(struct device *self)
{
	struct mwx_softc *sc = (struct mwx_softc *)self;

	MWX_DEV_LOG(sc, "attach hook start\n");
	mwx_preinit(sc);
	MWX_DEV_LOG(sc, "attach hook done fw_loaded=%d\n", sc->sc_fw_loaded);
}

bool
mwx_attach(struct device *parent, struct device *self, void *aux)
{
	struct mwx_softc *sc = (struct mwx_softc *)self;
	struct ieee80211com *ic = &sc->sc_ic;
	struct ifnet *ifp = &ic->ic_if;
	struct pci_attach_args *pa = (struct pci_attach_args *)aux;
	pci_intr_handle_t ih;
	pcireg_t memtype;
	uint32_t hwid, hwrev;
	int error;

	MWX_DEV_LOG(sc, "attach start pci_id=0x%08x vendor=0x%04x product=0x%04x\n",
	    pa->pa_id, PCI_VENDOR(pa->pa_id), PCI_PRODUCT(pa->pa_id));
	sc->sc_pc = pa->pa_pc;
	sc->sc_tag = pa->pa_tag;
	sc->sc_dmat = pa->pa_dmat;
	sc->sc_intr_mask = MT_INT_RX_DONE_ALL | MT_INT_TX_DONE_ALL |
	    MT_INT_MCU_CMD;
	if (PCI_PRODUCT(pa->pa_id) == PCI_PRODUCT_MEDIATEK_MT7922)
		sc->sc_hwtype = MWX_HW_MT7922;
	else
		sc->sc_hwtype = MWX_HW_MT7921;
	MWX_DEV_LOG(sc, "attach hardware type=%s\n",
	    sc->sc_hwtype == MWX_HW_MT7922 ? "MT7922" : "MT7921");

	memtype = pci_mapreg_type(pa->pa_pc, pa->pa_tag, PCI_MAPREG_START);
	if (pci_mapreg_map(pa, PCI_MAPREG_START, memtype, 0,
	    &sc->sc_st, &sc->sc_memh, NULL, &sc->sc_mems, 0)) {
		printf("%s: can't map mem space\n", DEVNAME(sc));
		return false;
	}
	MWX_DEV_LOG(sc, "attach BAR mapped memtype=0x%x size=%zu\n",
	    memtype, (size_t)sc->sc_mems);

	if (pci_intr_map_msix(pa, 0, &ih) &&
	    pci_intr_map_msi(pa, &ih) &&
	    pci_intr_map(pa, &ih)) {
		printf("%s: can't map interrupt\n", DEVNAME(sc));
		/* HAL detach owns the mapping on failure. */
		return false;
	}
	MWX_DEV_LOG(sc, "attach interrupt mapped source=%s\n",
	    pci_intr_string(pa->pa_pc, ih));

	if (mwx_mcu_fw_pmctrl(sc) != 0 ||
	    mwx_mcu_drv_pmctrl(sc) != 0) {
		/*
		 * A warm reboot does not power-cycle the M.2 card, so the chip
		 * can be left wedged by the previous OS session. Try to recover
		 * instead of failing: WFSYS reset first, then a PCIe FLR.
		 */
		MWX_DEV_LOG(sc, "attach MCU power control failed lpctl=0x%08x, "
		    "trying WFSYS reset\n", mwx_read(sc, MT_CONN_ON_LPCTL));
		mwx_wfsys_reset(sc);
		if (mwx_mcu_fw_pmctrl(sc) != 0 ||
		    mwx_mcu_drv_pmctrl(sc) != 0) {
			MWX_DEV_LOG(sc, "still failing lpctl=0x%08x, trying PCIe FLR\n",
			    mwx_read(sc, MT_CONN_ON_LPCTL));
			if (mwx_pci_flr(sc, pa->pa_tag) != 0 ||
			    mwx_mcu_fw_pmctrl(sc) != 0 ||
			    mwx_mcu_drv_pmctrl(sc) != 0) {
				MWX_DEV_LOG(sc, "attach MCU power control failed after "
				    "recovery lpctl=0x%08x\n",
				    mwx_read(sc, MT_CONN_ON_LPCTL));
				goto fail;
			}
		}
		MWX_DEV_LOG(sc, "attach MCU power control recovered\n");
	}
	MWX_DEV_LOG(sc, "attach MCU power control ok\n");

	hwid = mwx_read(sc, MT_HW_CHIPID) & 0xffff;
	hwrev = mwx_read(sc, MT_HW_REV) & 0xff;

	MWX_DEV_LOG(sc, "attach chip id=0x%04x hwrev=0x%02x interrupt=%s\n",
	    hwid, hwrev, pci_intr_string(pa->pa_pc, ih));

	mwx_set(sc, MT_MCU2HOST_SW_INT_ENA, MT_MCU_CMD_WAKE_RX_PCIE);
	if (mwx_wfsys_reset(sc) != 0) {
		MWX_DEV_LOG(sc, "attach WFSYS reset failed\n");
		goto fail;
	}
	MWX_DEV_LOG(sc, "attach WFSYS reset ok\n");

	mwx_write(sc, MT_WFDMA0_HOST_INT_ENA, 0);
	mwx_write(sc, MT_PCIE_MAC_INT_ENABLE, 0xff);

	sc->sc_ih = pci_intr_establish(pa->pa_pc, ih, IPL_NET,
	    mwx_intr, sc, DEVNAME(sc));
	if (sc->sc_ih == NULL) {
		printf("%s: can't establish interrupt\n", DEVNAME(sc));
		goto fail;
	}
	MWX_DEV_LOG(sc, "attach interrupt established handle=%p\n",
	    (void *)sc->sc_ih);

	if ((error = mwx_txwi_alloc(sc, MWX_TXWI_MAX)) != 0) {
		printf("%s: failed to allocate DMA resources %d\n",
		    DEVNAME(sc), error);
		goto fail;
	}

	if ((error = mwx_dma_alloc(sc)) != 0) {
		printf("%s: failed to allocate DMA resources %d\n",
		    DEVNAME(sc), error);
		goto fail;
	}
	MWX_DEV_LOG(sc, "attach DMA resources ready\n");

	/* set regulatory domain to '00' */
	sc->sc_alpha2[0] = '0';
	sc->sc_alpha2[1] = '0';

	ic->ic_phytype = IEEE80211_T_OFDM;	/* not only, but not used */
	ic->ic_opmode = IEEE80211_M_STA;	/* default to BSS mode */
	ic->ic_state = IEEE80211_S_INIT;

	/* Set device capabilities. */
	ic->ic_caps =
#if NOTYET
	    IEEE80211_C_QOS | IEEE80211_C_TX_AMPDU | /* A-MPDU */
	    IEEE80211_C_ADDBA_OFFLOAD | /* device sends ADDBA/DELBA frames */
#endif
	    IEEE80211_C_WEP |		/* WEP */
	    IEEE80211_C_RSN |		/* WPA/RSN */
	    IEEE80211_C_SCANALL |	/* device scans all channels at once */
	    IEEE80211_C_SCANALLBAND |	/* device scans all bands at once */
	    IEEE80211_C_MONITOR |	/* monitor mode supported */
#ifndef IEEE80211_STA_ONLY
	    IEEE80211_C_IBSS |		/* IBSS mode supported */
	    IEEE80211_C_HOSTAP |	/* HostAP mode supported */
	    IEEE80211_C_APPMGT |	/* HostAP power management */
#endif
	    IEEE80211_C_SHSLOT |	/* short slot time supported */
	    IEEE80211_C_SHPREAMBLE |	/* short preamble supported */
	    IEEE80211_C_QOS |		/* WMM, required for 11n */
	    IEEE80211_C_TX_AMPDU;	/* TX A-MPDU, BA set up in firmware */

	/*
	 * Hardware TX A-MSDU (MT_TXD7_HW_AMSDU), like Linux mt7921 and
	 * pengubow's MT7922 port: the MAC packs several MSDUs of a TID with a
	 * Block Ack agreement into one A-MSDU when the AP allows A-MSDU in
	 * A-MPDU. Fewer, larger frames: more upload.
	 */
	{
		int off = 0;
		sc->sc_tx_amsdu = !PE_parse_boot_argn("-mtknoamsdu", &off,
		    sizeof(off));
		if (sc->sc_tx_amsdu)
			ic->ic_caps |= IEEE80211_C_TX_AMSDU_IN_AMPDU;
	}

	/*
	 * 802.11n. 20/40 MHz must be advertised even when only VHT80 is used:
	 * an AP treats a station without the HT "20/40" bit as 20 MHz-only and
	 * never transmits 80 MHz to it. 40 MHz is only actually used on 5 GHz
	 * (2.4 GHz channels are not marked HT40, so net80211 masks the bit).
	 */
	ic->ic_htcaps = IEEE80211_HTCAP_LDPC |
	    IEEE80211_HTCAP_SGI20 | IEEE80211_HTCAP_SGI40 |
	    IEEE80211_HTCAP_CBW20_40 |
	    (1U << IEEE80211_HTCAP_RXSTBC_SHIFT);	/* RX STBC, 1 stream */
	ic->ic_htcaps |=
	    (IEEE80211_HTCAP_SMPS_DIS << IEEE80211_HTCAP_SMPS_SHIFT);
	ic->ic_htxcaps = 0;
	ic->ic_txbfcaps = 0;
	ic->ic_aselcaps = 0;
	ic->ic_ampdu_params = (IEEE80211_AMPDU_PARAM_SS_4 | 0x3 /* 64k */);

	/*
	 * 802.11ac: 80 MHz, SGI80, RX LDPC, MCS 0-9 on 2 streams. MPDUs are
	 * capped at 3895 bytes and A-MPDUs at 64K (RX buffers are 2 KB clusters).
	 */
	/*
	 * SU/MU beamformee with 4 sounding dimensions (STS 3), like Linux
	 * mt7921 and pengubow's MT7922 port: lets the AP beamform toward us,
	 * worth a few dB (higher MCS) on a weak link. The firmware answers the
	 * sounding (NDPA/NDP) by itself.
	 */
	ic->ic_vhtcaps = IEEE80211_VHTCAP_MAX_MPDU_LENGTH_3895 |
	    IEEE80211_VHTCAP_RXLDPC | IEEE80211_VHTCAP_SHORT_GI_80 |
	    IEEE80211_VHTCAP_RXSTBC_1 |
	    IEEE80211_VHTCAP_SU_BEAMFORMEE_CAPABLE |
	    IEEE80211_VHTCAP_MU_BEAMFORMEE_CAPABLE |
	    (3U << IEEE80211_VHTCAP_BEAMFORMEE_STS_SHIFT) |
	    (3U << IEEE80211_VHTCAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT) |
	    IEEE80211_VHTCAP_RX_ANTENNA_PATTERN |
	    IEEE80211_VHTCAP_TX_ANTENNA_PATTERN;
	/* 2 bits per NSS: 2 = MCS 0-9, 3 = not supported */
	ic->ic_vht_rx_mcs_map = 0xfffa;
	ic->ic_vht_tx_mcs_map = 0xfffa;
	ic->ic_vht_rx_highest = 0;
	ic->ic_vht_tx_highest = 0;

#if NOTYET
	ic->ic_vhtcaps = IEEE80211_VHTCAP_MAX_MPDU_LENGTH_11454 |
	    (IEEE80211_VHTCAP_MAX_AMPDU_LEN_64K <<
	    IEEE80211_VHTCAP_MAX_AMPDU_LEN_SHIFT) |
	    (IEEE80211_VHTCAP_CHAN_WIDTH_80 <<
	    IEEE80211_VHTCAP_CHAN_WIDTH_SHIFT) | IEEE80211_VHTCAP_SGI80 |
	    IEEE80211_VHTCAP_RX_ANT_PATTERN | IEEE80211_VHTCAP_TX_ANT_PATTERN;
#endif

	/* IBSS channel undefined for now. */
	ic->ic_ibss_chan = &ic->ic_channels[1];

	/* HW supports up to 288 STAs in HostAP and IBSS modes */
	ic->ic_max_aid = min(IEEE80211_AID_MAX, MWX_WTBL_STA - 1);

	ic->ic_max_rssi = 100;	/* rxi_rssi is normalized for ni_rssi. */

	ifp->if_softc = sc;
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	ifp->if_ioctl = mwx_ioctl;
	ifp->if_start = mwx_start;
	ifp->if_watchdog = mwx_watchdog;
	memcpy(ifp->if_xname, DEVNAME(sc), IFNAMSIZ);

	if_attach(ifp);
	ieee80211_ifattach(ifp, gMwxHal->mwxController());
	sc->sc_net_attached = true;
	ieee80211_media_init(ifp);
	MWX_DEV_LOG(sc, "attach net80211 attached caps=0x%x max_aid=%u\n",
	    ic->ic_caps, ic->ic_max_aid);

#if NBPFILTER > 0
	mwx_radiotap_attach(sc);
#endif

	ic->ic_node_alloc = mwx_node_alloc;
	ic->ic_newassoc = mwx_newassoc;
#ifndef IEEE80211_STA_ONLY
	ic->ic_node_leave = mwx_node_leave;
#endif
	ic->ic_bgscan_start = mwx_bgscan;
	ic->ic_bgscan_done = mwx_bgscan_done;
	ic->ic_set_key = mwx_set_key;
	ic->ic_ampdu_rx_start = mwx_ampdu_rx_start;
	ic->ic_ampdu_rx_stop = mwx_ampdu_rx_stop;
	ic->ic_ampdu_tx_start = mwx_ampdu_tx_start;
	ic->ic_ampdu_tx_stop = mwx_ampdu_tx_stop;
	ic->ic_delete_key = mwx_delete_key;

	/* Override 802.11 state transition machine. */
	sc->sc_newstate = ic->ic_newstate;
	ic->ic_newstate = mwx_newstate;

	sc->sc_nswq = taskq_create("mwxns", 1, IPL_NET, 0);
	if (sc->sc_nswq == NULL) {
		printf("%s: can't create task queue\n", DEVNAME(sc));
		goto fail;
	}

	task_set(&sc->sc_newstate_task, mwx_newstate_task, sc, "mwx_newstate");
	task_set(&sc->sc_bgscan_done_task, mwx_bgscan_done_task, sc, "mwx_bgscan");
	task_set(&sc->sc_setkey_task, mwx_setkey_task, sc, "mwx_setkey");
	task_set(&sc->sc_reset_task, mwx_reset_task, sc, "mwx_reset");
	task_set(&sc->sc_scan_task, mwx_end_scan_task, sc, "mwx_scan");
	timeout_set(&sc->sc_reset_to, mwx_reset_timeo, sc);

	/*
	 * We cannot read the MAC address without loading the
	 * firmware from disk. Postpone until mountroot is done.
	 */
	config_mountroot(self, mwx_attach_hook);

	MWX_DEV_LOG(sc, "attach complete\n");
	return true;

fail:
	/* The HAL caller owns partial-attach cleanup through detach(). */
	return false;
}

int
mwx_activate(struct device *self, int act)
{
	/* XXX TODO */
	return 0;
}

#if 0
/* OpenBSD autoconf metadata is replaced by SimpleMtkWlan's IOKit matching path. */
struct cfdriver mwx_cd = {
	NULL, "mwx", DV_IFNET
};

struct cfattach mwx_ca = {
	sizeof(struct mwx_softc), mwx_match, mwx_attach,
	NULL, mwx_activate
};
#endif

void
mwx_reset(struct mwx_softc *sc)
{
	if (sc->sc_resetting || sc->sc_detaching)
		return;
	sc->sc_resetting = 1;
	task_add(sc->sc_nswq, &sc->sc_reset_task);
}

void
mwx_reset_timeo(void *arg)
{
	mwx_reset((struct mwx_softc *)arg);
}

void
mwx_reset_task(void *arg)
{
	struct mwx_softc *sc = (struct mwx_softc *)arg;
	struct ifnet *ifp = &sc->sc_ic.ic_if;
	int fatal = 0;

	if (ifp->if_flags & IFF_RUNNING)
		mwx_stop(ifp);

	if (sc->sc_hard_reset) {
		/* mwx_init() -> mwx_preinit() does WFSYS reset + firmware load. */
		MWX_DEV_LOG(sc, "hard reset: reloading firmware\n");
		sc->sc_hard_reset = 0;
		sc->sc_fw_loaded = 0;
	}

	if (!fatal && (ifp->if_flags & (IFF_UP | IFF_RUNNING)) == IFF_UP) {
		int rv = mwx_init(ifp);
		MWX_DEV_LOG(sc, "reset done init=%d fw_loaded=%d\n", rv,
		    sc->sc_fw_loaded);
	}
	sc->sc_resetting = 0;
	sc->sc_coredump_cnt = 0;
}

int
mwx_txwi_alloc(struct mwx_softc *sc, int count)
{
	int error, nsegs, i;
	struct mwx_txwi_desc *q = &sc->sc_txwi;
	bus_size_t size = count * sizeof(*q->mt_desc);
	uint32_t addr;

	MWX_DEV_LOG(sc, "txwi alloc start count=%d size=%zu\n",
	    count, (size_t)size);
	LIST_INIT(&q->mt_freelist);
	q->mt_nfree = 0;
	q->mt_count = count;

	error = bus_dmamap_create(sc->sc_dmat, size, 1, size, 0,
	    BUS_DMA_NOWAIT, &q->mt_map);
	if (error != 0) {
		printf("%s: could not create desc TWXI map\n", DEVNAME(sc));
		goto fail;
	}

	error = bus_dmamem_alloc(sc->sc_dmat, size, PAGE_SIZE, 0, &q->mt_seg,
	    1, &nsegs, BUS_DMA_NOWAIT | BUS_DMA_ZERO);
	if (error != 0) {
		printf("%s: could not allocate TWXI memory\n", DEVNAME(sc));
		goto fail;
	}

	error = bus_dmamem_map(sc->sc_dmat, &q->mt_seg, nsegs, size,
	    (void **)&q->mt_desc, BUS_DMA_NOWAIT);
	if (error != 0) {
		printf("%s: can't map desc DMA memory\n", DEVNAME(sc));
		goto fail;
	}

	error = bus_dmamap_load(sc->sc_dmat, q->mt_map, q->mt_desc,
	    size, NULL, BUS_DMA_NOWAIT);
	if (error != 0) {
		printf("%s: could not load desc DMA map\n", DEVNAME(sc));
		goto fail;
	}

	addr = q->mt_map->dm_segs[0].ds_addr;

	q->mt_data = (struct mwx_txwi *)mallocarray(count, sizeof(*q->mt_data),
	    M_DEVBUF, M_NOWAIT | M_ZERO);
	if (q->mt_data == NULL) {
		printf("%s: could not allocate soft data\n", DEVNAME(sc));
		error = ENOMEM;
		goto fail;
	}

	for (i = 0; i < count; i++) {
		q->mt_data[i].mt_idx = i;
		q->mt_data[i].mt_desc = &q->mt_desc[i];
		q->mt_data[i].mt_addr = addr + i * sizeof(*q->mt_desc);
		error = bus_dmamap_create(sc->sc_dmat, MT_TXD_LEN_MASK,
		    MT_MAX_SCATTER, MT_TXD_LEN_MASK, 0, BUS_DMA_NOWAIT,
		    &q->mt_data[i].mt_map);
		if (error != 0) {
			printf("%s: could not create data DMA map\n",
			    DEVNAME(sc));
			goto fail;
		}
	}

	for (i = count - 1; i >= MT_PACKET_ID_FIRST; i--) {
		LIST_INSERT_HEAD(&q->mt_freelist, &q->mt_data[i], mt_entry);
		q->mt_nfree++;
	}

	MWX_DEV_LOG(sc, "txwi alloc ok count=%d dma=0x%08x\n", count, addr);
	return 0;

fail:
	MWX_DEV_LOG(sc, "txwi alloc failed error=%d\n", error);
	mwx_txwi_free(sc);
	return error;
}

void
mwx_txwi_free(struct mwx_softc *sc)
{
	struct mwx_txwi_desc *q = &sc->sc_txwi;

	if (q->mt_data != NULL) {
		int i;
		for (i = 0; i < q->mt_count; i++) {
			struct mwx_txwi *mt = &q->mt_data[i];
			bus_dmamap_destroy(sc->sc_dmat, mt->mt_map);
			m_freem(mt->mt_mbuf);
			if (i >= MT_PACKET_ID_FIRST)
				LIST_REMOVE(mt, mt_entry);
		}
		free(q->mt_data, M_DEVBUF, q->mt_count * sizeof(*q->mt_data));
	}

	if (q->mt_desc != NULL) {
		bus_dmamap_sync(sc->sc_dmat, q->mt_map, 0,
			q->mt_map->dm_mapsize, BUS_DMASYNC_POSTWRITE);
		bus_dmamap_unload(sc->sc_dmat, q->mt_map);
	}

	/*
	 * XXX TODO this is probably not correct as a check, should use
	 * some state variable bitfield to decide which steps need to be run.
	 */
	if (q->mt_seg.ds_len != 0)
		bus_dmamem_unmap(sc->sc_dmat, (caddr_t)q->mt_desc,
			q->mt_count * sizeof(*q->mt_desc));
	if (q->mt_map != NULL)
		bus_dmamem_free(sc->sc_dmat, &q->mt_seg, 1);

	memset(q, 0, sizeof(*q));
}

struct mwx_txwi *
mwx_txwi_get(struct mwx_softc *sc)
{
	struct mwx_txwi *mt;

	mt = LIST_FIRST(&sc->sc_txwi.mt_freelist);
	if (mt == NULL)
		return NULL;
	LIST_REMOVE(mt, mt_entry);
	sc->sc_txwi.mt_nfree--;
	mt->mt_busy = 1;
	return mt;
}

void
mwx_txwi_put(struct mwx_softc *sc, struct mwx_txwi *mt)
{
	if (mt->mt_busy == 0)
		return;

	if (mt->mt_mbuf != NULL) {
		bus_dmamap_sync(sc->sc_dmat, mt->mt_map, 0,
		    mt->mt_map->dm_mapsize, BUS_DMASYNC_POSTWRITE);
		bus_dmamap_unload(sc->sc_dmat, mt->mt_map);
		m_freem(mt->mt_mbuf);
		mt->mt_mbuf = NULL;
	}

	memset(mt->mt_desc, 0, sizeof(*mt->mt_desc));
	mt->mt_busy = 0;

	if (mt->mt_idx < MT_PACKET_ID_FIRST)
		return;
	LIST_INSERT_HEAD(&sc->sc_txwi.mt_freelist, mt, mt_entry);
	sc->sc_txwi.mt_nfree++;
}

int
mwx_txwi_enqueue(struct mwx_softc *sc, struct mwx_txwi *mt, struct mbuf *m)
{
	struct mwx_txwi_desc *q = &sc->sc_txwi;
	struct mt76_txwi *txp = mt->mt_desc;
	struct mt76_connac_txp_ptr *ptr = &txp->ptr[0];
	uint32_t addr;
	uint16_t len;
	int i, nsegs, rv;

	rv = bus_dmamap_load_mbuf(sc->sc_dmat, mt->mt_map, m,
	    BUS_DMA_WRITE | BUS_DMA_NOWAIT);
	if (rv == EFBIG && m_defrag(m, M_DONTWAIT) == 0)
		rv = bus_dmamap_load_mbuf(sc->sc_dmat, mt->mt_map, m,
		    BUS_DMA_WRITE | BUS_DMA_NOWAIT);
	if (rv != 0)
		return rv;

	nsegs = mt->mt_map->dm_nsegs;

	{
		static uint32_t seg_log_count;
		if (seg_log_count < 64) {
			struct mbuf *c;
			int nmb = 0;
			char chain[96];
			size_t off = 0;

			chain[0] = 0;
			for (c = m; c != NULL && off < sizeof(chain) - 12;
			    c = mbuf_next(c), nmb++)
				off += snprintf(chain + off, sizeof(chain) - off,
				    "%zu%s,", mbuf_len(c),
				    (mbuf_flags(c) & MBUF_EXT) ? "e" : "");
			MWX_DEV_LOG(sc,
			    "txseg idx=%u len=%zu nmbuf=%d chain=%s nsegs=%d bounce=%d s0=0x%llx/%llu s1=0x%llx/%llu s2=0x%llx/%llu s3=0x%llx/%llu\n",
			    mt->mt_idx, mbuf_pkthdr_len(m), nmb, chain, nsegs,
			    mt->mt_map->dm_bounce,
			    nsegs > 0 ? (unsigned long long)mt->mt_map->dm_segs[0].ds_addr : 0ULL,
			    nsegs > 0 ? (unsigned long long)mt->mt_map->dm_segs[0].ds_len : 0ULL,
			    nsegs > 1 ? (unsigned long long)mt->mt_map->dm_segs[1].ds_addr : 0ULL,
			    nsegs > 1 ? (unsigned long long)mt->mt_map->dm_segs[1].ds_len : 0ULL,
			    nsegs > 2 ? (unsigned long long)mt->mt_map->dm_segs[2].ds_addr : 0ULL,
			    nsegs > 2 ? (unsigned long long)mt->mt_map->dm_segs[2].ds_len : 0ULL,
			    nsegs > 3 ? (unsigned long long)mt->mt_map->dm_segs[3].ds_addr : 0ULL,
			    nsegs > 3 ? (unsigned long long)mt->mt_map->dm_segs[3].ds_len : 0ULL);
			seg_log_count++;
		}
	}
	if (nsegs > MT_HW_TXP_MAX_BUF_NUM) {
		MWX_DEV_LOG(sc, "txseg idx=%u too many segments %d, dropping\n",
		    mt->mt_idx, nsegs);
		bus_dmamap_unload(sc->sc_dmat, mt->mt_map);
		return EFBIG;
	}

	bus_dmamap_sync(sc->sc_dmat, mt->mt_map, 0, mt->mt_map->dm_mapsize,
	    BUS_DMASYNC_PREWRITE);

	txp->msdu_id[0] = htole16(mt->mt_idx | MT_MSDU_ID_VALID);
	mt->mt_mbuf = m;

	bus_dmamap_sync(sc->sc_dmat, q->mt_map, 0, q->mt_map->dm_mapsize,
	    BUS_DMASYNC_PREWRITE);
	for (i = 0; i < nsegs; i++) {
		KASSERT(mt->mt_map->dm_segs[i].ds_addr <= UINT32_MAX);
		KASSERT(mt->mt_map->dm_segs[i].ds_len <= MT_TXD_LEN_MASK);
		addr = mt->mt_map->dm_segs[i].ds_addr;
		len = mt->mt_map->dm_segs[i].ds_len;

		if (i == nsegs - 1)
			len |= MT_TXD_LEN_LAST;

		if ((i & 1) == 0) {
			ptr->buf0 = htole32(addr);
			ptr->len0 = htole16(len);
		} else {
			ptr->buf1 = htole32(addr);
			ptr->len1 = htole16(len);
			ptr++;
		}
	}
	bus_dmamap_sync(sc->sc_dmat, q->mt_map, 0, q->mt_map->dm_mapsize,
	    BUS_DMASYNC_POSTWRITE);

	return 0;
}

int
mwx_queue_alloc(struct mwx_softc *sc, struct mwx_queue *q, int count,
    uint32_t regbase)
{
	int error, nsegs, i;
	bus_size_t size = count * sizeof(*q->mq_desc);

	MWX_DEV_LOG(sc, "queue alloc start regbase=0x%08x count=%d size=%zu\n",
	    regbase, count, (size_t)size);
	q->mq_regbase = regbase;
	q->mq_count = count;

	error = bus_dmamap_create(sc->sc_dmat, size, 1, size, 0,
	    BUS_DMA_NOWAIT, &q->mq_map);
	if (error != 0) {
		printf("%s: could not create desc DMA map\n", DEVNAME(sc));
		goto fail;
	}

	error = bus_dmamem_alloc(sc->sc_dmat, size, PAGE_SIZE, 0, &q->mq_seg,
	    1, &nsegs, BUS_DMA_NOWAIT | BUS_DMA_ZERO);
	if (error != 0) {
		printf("%s: could not allocate DMA memory\n", DEVNAME(sc));
		goto fail;
	}

	error = bus_dmamem_map(sc->sc_dmat, &q->mq_seg, nsegs, size,
	    (void **)&q->mq_desc, BUS_DMA_NOWAIT);
	if (error != 0) {
		printf("%s: can't map desc DMA memory\n", DEVNAME(sc));
		goto fail;
	}

	error = bus_dmamap_load(sc->sc_dmat, q->mq_map, q->mq_desc,
	    size, NULL, BUS_DMA_NOWAIT);
	if (error != 0) {
		printf("%s: could not load desc DMA map\n", DEVNAME(sc));
		goto fail;
	}

	q->mq_data = (struct mwx_queue_data *)mallocarray(count, sizeof(*q->mq_data),
	    M_DEVBUF, M_NOWAIT | M_ZERO);
	if (q->mq_data == NULL) {
		printf("%s: could not allocate soft data\n", DEVNAME(sc));
		error = ENOMEM;
		goto fail;
	}

	for (i = 0; i < count; i++) {
		error = bus_dmamap_create(sc->sc_dmat, MT_MAX_SIZE,
		    MT_MAX_SCATTER, MT_MAX_SIZE, 0, BUS_DMA_NOWAIT,
		    &q->mq_data[i].md_map);
		if (error != 0) {
			printf("%s: could not create data DMA map\n",
			    DEVNAME(sc));
			goto fail;
		}
	}

	mwx_queue_reset(sc, q);
	MWX_DEV_LOG(sc, "queue alloc ok regbase=0x%08x count=%d dma=0x%llx\n",
	    regbase, count, (unsigned long long)q->mq_map->dm_segs[0].ds_addr);
	return 0;

fail:
	MWX_DEV_LOG(sc, "queue alloc failed regbase=0x%08x error=%d\n",
	    regbase, error);
	mwx_queue_free(sc, q);
	return error;
}

void
mwx_queue_free(struct mwx_softc *sc, struct mwx_queue *q)
{
	if (q->mq_data != NULL) {
		int i;
		for (i = 0; i < q->mq_count; i++) {
			struct mwx_queue_data  *md = &q->mq_data[i];
			bus_dmamap_destroy(sc->sc_dmat, md->md_map);
			m_freem(md->md_mbuf);
		}
		free(q->mq_data, M_DEVBUF, q->mq_count * sizeof(*q->mq_data));
	}

	if (q->mq_desc != NULL) {
		bus_dmamap_sync(sc->sc_dmat, q->mq_map, 0,
			q->mq_map->dm_mapsize, BUS_DMASYNC_POSTWRITE);
		bus_dmamap_unload(sc->sc_dmat, q->mq_map);
	}

	/*
	 * XXX TODO this is probably not correct as a check, should use
	 * some state variable bitfield to decide which steps need to be run.
	 */
	if (q->mq_seg.ds_len != 0)
		bus_dmamem_unmap(sc->sc_dmat, (caddr_t)q->mq_desc,
			q->mq_count * sizeof(*q->mq_desc));
	if (q->mq_map != NULL)
		bus_dmamem_free(sc->sc_dmat, &q->mq_seg, 1);

	memset(q, 0, sizeof(*q));
}

void
mwx_queue_reset(struct mwx_softc *sc, struct mwx_queue *q)
{
	int i;
	uint32_t dmaaddr;
	struct mwx_queue_data *md;

	/* clear descriptors */
	bus_dmamap_sync(sc->sc_dmat, q->mq_map, 0, q->mq_map->dm_mapsize,
	    BUS_DMASYNC_PREWRITE);

	for (i = 0; i < q->mq_count; i++) {
		q->mq_desc[i].buf0 = 0;
		q->mq_desc[i].buf1 = 0;
		q->mq_desc[i].info = 0;
		q->mq_desc[i].ctrl = htole32(MT_DMA_CTL_DMA_DONE);
	}

	bus_dmamap_sync(sc->sc_dmat, q->mq_map, 0, q->mq_map->dm_mapsize,
	    BUS_DMASYNC_POSTWRITE);

	/* reset DMA registers */
	KASSERT(q->mq_map->dm_nsegs == 1);
	KASSERT(q->mq_map->dm_segs[0].ds_addr <= UINT32_MAX);
	dmaaddr	= q->mq_map->dm_segs[0].ds_addr;
	mwx_write(sc, q->mq_regbase + MT_DMA_DESC_BASE, dmaaddr);
	mwx_write(sc, q->mq_regbase + MT_DMA_RING_SIZE, q->mq_count);
	mwx_write(sc, q->mq_regbase + MT_DMA_CPU_IDX, 0);
	mwx_write(sc, q->mq_regbase + MT_DMA_DMA_IDX, 0);
	q->mq_cons = 0;
	q->mq_prod = 0;

	/* free buffers */
	for (i = 0; i < q->mq_count; i++) {
		md = &q->mq_data[i];
		if (md->md_mbuf != NULL) {
			bus_dmamap_sync(sc->sc_dmat, md->md_map, 0,
			    md->md_map->dm_mapsize,
			    BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);
			bus_dmamap_unload(sc->sc_dmat, md->md_map);
			m_freem(md->md_mbuf);
			md->md_mbuf = NULL;
		}
		if (md->md_txwi != NULL) {
			/* return TXWI (and its frame) owned by this slot */
			mwx_txwi_put(sc, md->md_txwi);
			md->md_txwi = NULL;
		}
	}
}

int
mwx_buf_fill(struct mwx_softc *sc, struct mwx_queue_data *md,
    struct mwx_desc *desc)
{
	struct mbuf *m;
	uint32_t buf0, len0, ctrl;
	int rv;

	m = MCLGETL(NULL, M_DONTWAIT, MT_RX_BUF_SIZE);
	if (m == NULL)
		return (ENOMEM);

	mbuf_setlen(m, MT_RX_BUF_SIZE);
	mbuf_pkthdr_setlen(m, MT_RX_BUF_SIZE);

	rv = bus_dmamap_load_mbuf(sc->sc_dmat, md->md_map, m,
	     BUS_DMA_READ | BUS_DMA_NOWAIT);
	if (rv != 0) {
		printf("%s: could not load data, %d\n", DEVNAME(sc), rv);
		m_freem(m);
		return (rv);
	}

	bus_dmamap_sync(sc->sc_dmat, md->md_map, 0,
	    md->md_map->dm_mapsize, BUS_DMASYNC_PREREAD);

	md->md_mbuf = m;

	KASSERT(md->md_map->dm_nsegs == 1);
	KASSERT(md->md_map->dm_segs[0].ds_addr <= UINT32_MAX);
	buf0 = md->md_map->dm_segs[0].ds_addr;
	len0 = md->md_map->dm_segs[0].ds_len;
	ctrl = MT_DMA_CTL_SD_LEN0(len0);
	ctrl |= MT_DMA_CTL_LAST_SEC0;

	desc->buf0 = htole32(buf0);
	desc->buf1 = 0;
	desc->info = 0;
	desc->ctrl = htole32(ctrl);

	return 0;
}

int
mwx_queue_fill(struct mwx_softc *sc, struct mwx_queue *q)
{
	u_int idx, last;
	int rv;

	last = (q->mq_count + q->mq_cons - 1) % q->mq_count;
	idx = q->mq_prod;

	bus_dmamap_sync(sc->sc_dmat, q->mq_map, 0, q->mq_map->dm_mapsize,
	    BUS_DMASYNC_PREWRITE);

	while (idx != last) {
		rv = mwx_buf_fill(sc, &q->mq_data[idx], &q->mq_desc[idx]);
		if (rv != 0) {
			printf("%s: could not fill data, slot %d err %d\n",
			    DEVNAME(sc), idx, rv);
			return rv;
		}
		idx = (idx + 1) % q->mq_count;
	}

	bus_dmamap_sync(sc->sc_dmat, q->mq_map, 0, q->mq_map->dm_mapsize,
	    BUS_DMASYNC_POSTWRITE);

	q->mq_prod = idx;
	mwx_write(sc, q->mq_regbase + MT_DMA_CPU_IDX, q->mq_prod);

	return 0;
}

int
mwx_dma_alloc(struct mwx_softc *sc)
{
	int rv;

	MWX_DEV_LOG(sc, "dma alloc start\n");
	/* TX queues */
	if ((rv = mwx_queue_alloc(sc, &sc->sc_txq, 256,
	    MT_TX_DATA_RING_BASE)) != 0)
		return rv;
	if ((rv = mwx_queue_alloc(sc, &sc->sc_txmcuq, 256,
	    MT_TX_MCU_RING_BASE)) != 0)
		return rv;
	if ((rv = mwx_queue_alloc(sc, &sc->sc_txfwdlq, 16 /* XXX */,
	    MT_TX_FWDL_RING_BASE)) != 0)
		return rv;

	/* RX queues */
	if ((rv = mwx_queue_alloc(sc, &sc->sc_rxq, 256,
	    MT_RX_DATA_RING_BASE)) != 0 ||
	    (rv = mwx_queue_fill(sc, &sc->sc_rxq)) != 0)
		return rv;
	if ((rv = mwx_queue_alloc(sc, &sc->sc_rxmcuq, 256,
	    MT_RX_MCU_RING_BASE)) != 0 ||
	    (rv = mwx_queue_fill(sc, &sc->sc_rxmcuq)) != 0)
		return rv;
	if ((rv = mwx_queue_alloc(sc, &sc->sc_rxfwdlq, 16 /* XXX */,
	    MT_RX_FWDL_RING_BASE)) != 0 ||
	    (rv = mwx_queue_fill(sc, &sc->sc_rxfwdlq)) != 0)
		return rv;

	/* enable DMA engine */
	mwx_dma_enable(sc);

	MWX_DEV_LOG(sc, "dma alloc complete\n");
	return 0;
}

int
mwx_dma_reset(struct mwx_softc *sc, int fullreset)
{
	int rv;

	DPRINTF("%s: DMA reset\n", DEVNAME(sc));

	if ((rv = mwx_dma_disable(sc, fullreset)) != 0)
		return rv;
	if (fullreset)
		if ((rv = mwx_wfsys_reset(sc)) != 0)
			return rv;

	/* TX queues */
	mwx_queue_reset(sc, &sc->sc_txq);
	mwx_queue_reset(sc, &sc->sc_txmcuq);
	mwx_queue_reset(sc, &sc->sc_txfwdlq);

	/* RX queues */
	mwx_queue_reset(sc, &sc->sc_rxq);
	mwx_queue_reset(sc, &sc->sc_rxmcuq);
	mwx_queue_reset(sc, &sc->sc_rxfwdlq);

	/* TDOD mt76_tx_status_check */

	/* refill RX queues */
	if ((rv = mwx_queue_fill(sc, &sc->sc_rxq)) != 0 ||
	    (rv = mwx_queue_fill(sc, &sc->sc_rxmcuq)) != 0 ||
	    (rv = mwx_queue_fill(sc, &sc->sc_rxfwdlq)) != 0)
		return rv;

	/* enable DMA engine */
	mwx_dma_enable(sc);

	return 0;
}

void
mwx_dma_free(struct mwx_softc *sc)
{
	/* TX queues */
	mwx_queue_free(sc, &sc->sc_txq);
	mwx_queue_free(sc, &sc->sc_txmcuq);
	mwx_queue_free(sc, &sc->sc_txfwdlq);

	/* RX queues */
	mwx_queue_free(sc, &sc->sc_rxq);
	mwx_queue_free(sc, &sc->sc_rxmcuq);
	mwx_queue_free(sc, &sc->sc_rxfwdlq);
}

static inline int
mwx_dma_free_slots(struct mwx_queue *q)
{
	int free = q->mq_count - 1;
	free += q->mq_cons;
	free -= q->mq_prod;
	free %= q->mq_count;
	return free;
}

int
mwx_dma_tx_enqueue(struct mwx_softc *sc, struct mwx_queue *q, struct mbuf *m)
{
	struct mwx_queue_data *md;
	struct mwx_desc *desc;
	int i, nsegs, idx, rv;

	idx = q->mq_prod;
	md = &q->mq_data[idx];
	desc = &q->mq_desc[idx];

	rv = bus_dmamap_load_mbuf(sc->sc_dmat, md->md_map, m,
	    BUS_DMA_WRITE | BUS_DMA_NOWAIT);
	if (rv == EFBIG && m_defrag(m, M_DONTWAIT) == 0)
		rv = bus_dmamap_load_mbuf(sc->sc_dmat, md->md_map, m,
		    BUS_DMA_WRITE | BUS_DMA_NOWAIT);
	if (rv != 0)
		return rv;

	nsegs = md->md_map->dm_nsegs;

	/* check if there is enough space */
	if ((nsegs + 1)/2 > mwx_dma_free_slots(q)) {
		bus_dmamap_unload(sc->sc_dmat, md->md_map);
		return EBUSY;
	}

	bus_dmamap_sync(sc->sc_dmat, md->md_map, 0, md->md_map->dm_mapsize,
	    BUS_DMASYNC_PREWRITE);
	md->md_mbuf = m;
	md->md_txwi = NULL;

	bus_dmamap_sync(sc->sc_dmat, q->mq_map, 0, q->mq_map->dm_mapsize,
	    BUS_DMASYNC_PREWRITE);
	for (i = 0; i < nsegs; i += 2) {
		uint32_t	buf0, buf1 = 0;
		uint32_t	len0, len1 = 0, ctrl;

		KASSERT(md->md_map->dm_segs[i].ds_addr <= UINT32_MAX);
		buf0 = md->md_map->dm_segs[i].ds_addr;
		len0 = md->md_map->dm_segs[i].ds_len;
		ctrl = MT_DMA_CTL_SD_LEN0(len0);

		if (i < nsegs - 1) {
			KASSERT(md->md_map->dm_segs[i + 1].ds_addr <=
			    UINT32_MAX);
			buf1 = md->md_map->dm_segs[i + 1].ds_addr;
			len1 = md->md_map->dm_segs[i + 1].ds_len;
			ctrl |= MT_DMA_CTL_SD_LEN1(len1);
		}

		if (i == nsegs - 1)
			ctrl |= MT_DMA_CTL_LAST_SEC0;
		else if (i == nsegs - 2)
			ctrl |= MT_DMA_CTL_LAST_SEC1;

		desc->buf0 = htole32(buf0);
		desc->buf1 = htole32(buf1);
		desc->info = 0;
		desc->ctrl = htole32(ctrl);

		idx = (idx + 1) % q->mq_count;
		KASSERT(idx != q->mq_cons);
		md = &q->mq_data[idx];
		desc = &q->mq_desc[idx];
	}
	bus_dmamap_sync(sc->sc_dmat, q->mq_map, 0, q->mq_map->dm_mapsize,
	    BUS_DMASYNC_POSTWRITE);

	q->mq_prod = idx;

	mwx_write(sc, q->mq_regbase + MT_DMA_CPU_IDX, q->mq_prod);

	return 0;
}

int
mwx_dma_txwi_enqueue(struct mwx_softc *sc, struct mwx_queue *q,
    struct mwx_txwi *mt)
{
	struct mwx_queue_data *md;
	struct mwx_desc *desc;
	uint32_t buf0, len0, ctrl;
	int idx;

	idx = q->mq_prod;
	md = &q->mq_data[idx];
	desc = &q->mq_desc[idx];

	/* check if there is enough space */
	if (1 > mwx_dma_free_slots(q)) {
		bus_dmamap_unload(sc->sc_dmat, md->md_map);
		return EBUSY;
	}

	md->md_txwi = mt;
	md->md_mbuf = NULL;

	bus_dmamap_sync(sc->sc_dmat, q->mq_map, 0, q->mq_map->dm_mapsize,
	    BUS_DMASYNC_PREWRITE);

	buf0 = mt->mt_addr;
	len0 = sizeof(*mt->mt_desc);
	ctrl = MT_DMA_CTL_SD_LEN0(len0);
	ctrl |= MT_DMA_CTL_LAST_SEC0;

	static uint32_t txwi_dma_log_count;
	if (txwi_dma_log_count < 16) {
		MWX_DEV_LOG(sc, "txwi dma idx=%d addr=0x%08x len=%u\n",
		    idx, buf0, len0);
		txwi_dma_log_count++;
	}

	desc->buf0 = htole32(buf0);
	desc->buf1 = 0;
	desc->info = 0;
	desc->ctrl = htole32(ctrl);

	idx = (idx + 1) % q->mq_count;
	KASSERT(idx != q->mq_cons);

	bus_dmamap_sync(sc->sc_dmat, q->mq_map, 0, q->mq_map->dm_mapsize,
	    BUS_DMASYNC_POSTWRITE);

	q->mq_prod = idx;

	mwx_write(sc, q->mq_regbase + MT_DMA_CPU_IDX, q->mq_prod);

	return 0;
}

void
mwx_dma_tx_cleanup(struct mwx_softc *sc, struct mwx_queue *q)
{
	struct mwx_queue_data *md;
	struct mwx_desc *desc;
	int idx, last;

	idx = q->mq_cons;
	last = mwx_read(sc, q->mq_regbase + MT_DMA_DMA_IDX);

	if (idx == last)
		return;

	bus_dmamap_sync(sc->sc_dmat, q->mq_map, 0, q->mq_map->dm_mapsize,
	     BUS_DMASYNC_PREWRITE);

	while (idx != last) {
		md = &q->mq_data[idx];
		desc = &q->mq_desc[idx];

		if (md->md_mbuf != NULL) {
			bus_dmamap_sync(sc->sc_dmat, md->md_map, 0,
			    md->md_map->dm_mapsize, BUS_DMASYNC_POSTWRITE);
			bus_dmamap_unload(sc->sc_dmat, md->md_map);
			m_freem(md->md_mbuf);
			md->md_mbuf = NULL;
		}
		if (md->md_txwi != NULL) {
			static uint32_t txwi_ack_log_count;

			/* TXWI cleanup is driven by the firmware TX free event. */
			md->md_txwi = NULL;
			if (txwi_ack_log_count < 32) {
				MWX_DEV_LOG(sc, "txwi acked idx=%d\n", idx);
				txwi_ack_log_count++;
			}
		}

		/* clear DMA desc just to be sure */
		desc->buf0 = 0;
		desc->buf1 = 0;
		desc->info = 0;
		desc->ctrl = htole32(MT_DMA_CTL_DMA_DONE);

		idx = (idx + 1) % q->mq_count;

		/* check if more data made it in */
		/* XXX should we actually do that? */
		if (idx == last)
			last = mwx_read(sc, q->mq_regbase + MT_DMA_DMA_IDX);
	}

	bus_dmamap_sync(sc->sc_dmat, q->mq_map, 0, q->mq_map->dm_mapsize,
	    BUS_DMASYNC_POSTWRITE);

	q->mq_cons = idx;
	if (q->mq_wakeme) {
		q->mq_wakeme = 0;
		wakeup(q);
	}
}

void
mwx_dma_tx_done(struct mwx_softc *sc)
{
	mwx_dma_tx_cleanup(sc, &sc->sc_txq);
	mwx_dma_tx_cleanup(sc, &sc->sc_txmcuq);
	mwx_dma_tx_cleanup(sc, &sc->sc_txfwdlq);

	/* XXX do we need to wakeup someone */
}

/* XXX wrong place */
void
mwx_dma_rx_process(struct mwx_softc *sc, struct mbuf_list *ml)
{
	struct mbuf_list mlout = MBUF_LIST_INITIALIZER();
	struct mbuf *m;
	uint32_t *data, rxd, type, flag;
	uint32_t event_count = 0, notify_count = 0, normal_mcu_count = 0;
	uint32_t normal_count = 0, unknown_count = 0;
	uint32_t first_unknown_type = 0, first_unknown_flag = 0, first_unknown_rxd = 0;

	while ((m = ml_dequeue(ml)) != NULL) {
		data = mtod(m, uint32_t *);
		rxd = le32toh(data[0]);

		type = MT_RXD0_PKT_TYPE_GET(rxd);
		flag = (rxd & MT_RXD0_PKT_FLAG_MASK) >> MT_RXD0_PKT_FLAG_SHIFT;

		if (type == PKT_TYPE_RX_EVENT && flag == 0x1)
			type = PKT_TYPE_NORMAL_MCU;

		switch (type) {
		case PKT_TYPE_RX_EVENT:
			event_count++;
			mwx_mcu_rx_event(sc, m);
			break;
		case PKT_TYPE_TXRX_NOTIFY:
			notify_count++;
			mwx_mac_tx_free(sc, m);
			break;
		case PKT_TYPE_TXS:
#if TODO
			for (rxd += 2; rxd + 8 <= end; rxd += 8)
				mt7921_mac_add_txs(dev, rxd);
#endif
			m_freem(m);
			break;
		case PKT_TYPE_NORMAL_MCU:
			normal_mcu_count++;
			mwx_rx(sc, m, &mlout);
			break;
		case PKT_TYPE_NORMAL:
			normal_count++;
			mwx_rx(sc, m, &mlout);
			break;
		default:
			if (unknown_count == 0) {
				first_unknown_type = type;
				first_unknown_flag = flag;
				first_unknown_rxd = rxd;
			}
			unknown_count++;
			m_freem(m);
			break;
		}
	}

	if (event_count || notify_count || normal_mcu_count ||
	    normal_count || unknown_count) {
		sc->sc_rx_pkt_event += event_count;
		sc->sc_rx_pkt_txrx_notify += notify_count;
		sc->sc_rx_pkt_normal_mcu += normal_mcu_count;
		sc->sc_rx_pkt_normal += normal_count;
		sc->sc_rx_pkt_unknown += unknown_count;
		if (sc->sc_rx_process_events < 64 || unknown_count != 0) {
			MWX_DEV_LOG(sc,
			    "rx process event=%u notify=%u normal_mcu=%u normal=%u unknown=%u totals e=%u n=%u nmcu=%u norm=%u unk=%u\n",
			    event_count, notify_count, normal_mcu_count,
			    normal_count, unknown_count, sc->sc_rx_pkt_event,
			    sc->sc_rx_pkt_txrx_notify,
			    sc->sc_rx_pkt_normal_mcu, sc->sc_rx_pkt_normal,
			    sc->sc_rx_pkt_unknown);
			if (unknown_count != 0) {
				MWX_DEV_LOG(sc,
				    "rx unknown first type=%u flag=0x%x rxd0=0x%08x\n",
				    first_unknown_type, first_unknown_flag,
				    first_unknown_rxd);
			}
		}
		sc->sc_rx_process_events++;
	}

	if_input(&sc->sc_ic.ic_if, &mlout);
}

void
mwx_dma_rx_dequeue(struct mwx_softc *sc, struct mwx_queue *q,
    struct mbuf_list *ml)
{
	struct mwx_queue_data *md;
	struct mwx_desc *desc;
	struct mbuf *m, *m0 = NULL, *mtail = NULL;
	int idx, last;

	idx = q->mq_cons;
	last = mwx_read(sc, q->mq_regbase + MT_DMA_DMA_IDX);

	if (idx == last)
		return;
	/* card gone or not reinitialized (all-ones read, e.g. after wake) */
	if (last < 0 || last >= q->mq_count)
		return;

	bus_dmamap_sync(sc->sc_dmat, q->mq_map, 0, q->mq_map->dm_mapsize,
	     BUS_DMASYNC_PREREAD);

	while (idx != last) {
		uint32_t ctrl;

		md = &q->mq_data[idx];
		desc = &q->mq_desc[idx];

		bus_dmamap_sync(sc->sc_dmat, md->md_map, 0,
		    md->md_map->dm_mapsize, BUS_DMASYNC_POSTREAD);
		bus_dmamap_unload(sc->sc_dmat, md->md_map);

		/* dequeue mbuf */
		m = md->md_mbuf;
		if (m == NULL) {
			/* ring out of sync with the hardware: let a reset fix it */
			static uint32_t rx_empty_log;
			if (rx_empty_log++ < 8)
				MWX_DEV_LOG(sc, "rx slot %d without buffer (dma idx %d)\n",
				    idx, last);
			mwx_reset(sc);
			break;
		}
		md->md_mbuf = NULL;

		/* only buf0 is used on RX rings */
		ctrl = le32toh(desc->ctrl);
		mbuf_setlen(m, MT_DNA_CTL_SD_GET_LEN0(ctrl));

		if (m0 == NULL) {
			m0 = mtail = m;
			mbuf_pkthdr_setlen(m0, mbuf_len(m));
		} else {
			mbuf_setnext(mtail, m);
			mtail = m;
			mbuf_pkthdr_setlen(m0, mbuf_pkthdr_len(m0) + mbuf_len(m));
		}

		/* TODO handle desc->info */

		/* check if this was the last mbuf of the chain */
		if (ctrl & MT_DMA_CTL_LAST_SEC0) {
			ml_enqueue(ml, m0);
			m0 = NULL;
			mtail = NULL;
		}

		idx = (idx + 1) % q->mq_count;

		/* check if more data made it in */
		/* XXX should we actually do that? */
		if (idx == last) {
			last = mwx_read(sc, q->mq_regbase + MT_DMA_DMA_IDX);
			if (last < 0 || last >= q->mq_count)
				last = idx;
		}
	}

	/* a chain cut short by the out-of-sync check above */
	if (m0 != NULL) {
		m_freem(m0);
		m0 = NULL;
	}
	/* XXX make sure we don't have half processed data */
	KASSERT(m0 == NULL);

	bus_dmamap_sync(sc->sc_dmat, q->mq_map, 0, q->mq_map->dm_mapsize,
	    BUS_DMASYNC_POSTREAD);

	q->mq_cons = idx;
}

void
mwx_dma_rx_done(struct mwx_softc *sc, struct mwx_queue *q)
{
	struct mbuf_list ml = MBUF_LIST_INITIALIZER();

	mwx_dma_rx_dequeue(sc, q, &ml);

	if (ml_empty(&ml))
		return;

	mwx_queue_fill(sc, q);	/* TODO what if it fails, run timer? */

	mwx_dma_rx_process(sc, &ml);
}

struct mbuf *
mwx_mcu_alloc_msg(size_t len)
{
	const int headspace = sizeof(struct mwx_mcu_txd);
	struct mbuf *m;

	/* Allocate mbuf with enough space */
	m = MCLGETL(NULL, M_DONTWAIT, len + headspace);
	if (m == NULL)
		return NULL;
	mbuf_setlen(m, len + headspace);
	mbuf_pkthdr_setlen(m, len + headspace);
	m_adj(m, headspace);

	return m;
}

void
mwx_mcu_set_len(struct mbuf *m, void *end)
{
	uint8_t *start = mtod(m, uint8_t *);
	uint8_t *finish = (uint8_t *)end;
	int len = mbuf_pkthdr_len(m), adj;

	KASSERT(start <= finish && finish - start <= len);
	adj = len - (finish - start);
	m_adj(m, -adj);
}

int
mwx_mcu_send_mbuf(struct mwx_softc *sc, uint32_t cmd, struct mbuf *m, int *seqp)
{
	struct mwx_uni_txd *uni_txd;
	struct mwx_mcu_txd *mcu_txd;
	struct mwx_queue *q;
	uint32_t *txd, val;
	int s, rv, txd_len = 0, mcu_cmd = cmd & MCU_CMD_FIELD_ID_MASK;
	int tot_len, len = mbuf_pkthdr_len(m);
	size_t lead;
	uint8_t seq = 0;

	if (cmd == MCU_CMD_FW_SCATTER) {
		q = &sc->sc_txfwdlq;
		goto enqueue;
	}

	seq = ++sc->sc_mcu_seq & 0x0f;
	if (seq == 0)
		seq = ++sc->sc_mcu_seq & 0x0f;

	KASSERT(seq < nitems(sc->sc_mcu_wait));
	txd_len = cmd & MCU_CMD_FIELD_UNI ? sizeof(*uni_txd) : sizeof(*mcu_txd);
	tot_len = txd_len + len;
	lead = m_leadingspace(m);
	if (lead < (size_t)txd_len) {
		static uint32_t rebuild_log_count;
		struct mbuf *n;

		if (rebuild_log_count < 32) {
			MWX_DEV_LOG(sc,
			    "MCU tx mbuf rebuild cmd=0x%08x len=%d lead=%zu txd_len=%d\n",
			    cmd, len, lead, txd_len);
			rebuild_log_count++;
		}
		n = MCLGETL(NULL, M_DONTWAIT, len + txd_len);
		if (n == NULL) {
			m_freem(m);
			return ENOMEM;
		}
		mbuf_setlen(n, len + txd_len);
		mbuf_pkthdr_setlen(n, len + txd_len);
		if (len != 0 &&
		    mbuf_copydata(m, 0, len, mtod(n, uint8_t *) + txd_len) != 0) {
			m_freem(n);
			m_freem(m);
			return EINVAL;
		}
		m_freem(m);
		m = n;
	} else {
		m = m_prepend(m, txd_len, M_DONTWAIT);
		if (m == NULL)
			return ENOMEM;
	}
	txd = mtod(m, uint32_t *);
	memset(txd, 0, txd_len);

	val = (tot_len & MT_TXD0_TX_BYTES_MASK) |
	    MT_TX_TYPE_CMD | MT_TXD0_Q_IDX(MT_TX_MCU_PORT_RX_Q0);
	txd[0] = htole32(val);

	val = MT_TXD1_LONG_FORMAT | MT_HDR_FORMAT_CMD;
	txd[1] = htole32(val);

	if (cmd & MCU_CMD_FIELD_UNI) {
		uni_txd = (struct mwx_uni_txd *)txd;
		uni_txd->len = htole16(tot_len - sizeof(uni_txd->txd));
		uni_txd->option = MCU_CMD_UNI_EXT_ACK;
		uni_txd->cid = htole16(mcu_cmd);
		uni_txd->s2d_index = CMD_S2D_IDX_H2N;
		uni_txd->pkt_type = MCU_PKT_ID;
		uni_txd->seq = seq;
	} else {
		mcu_txd = (struct mwx_mcu_txd *)txd;
		mcu_txd->len = htole16(tot_len - sizeof(uni_txd->txd));
		mcu_txd->pq_id = htole16(MCU_PQ_ID(MT_TX_PORT_IDX_MCU,
			MT_TX_MCU_PORT_RX_Q0));
		mcu_txd->pkt_type = MCU_PKT_ID;
		mcu_txd->seq = seq;
		mcu_txd->cid = mcu_cmd;
		mcu_txd->s2d_index = CMD_S2D_IDX_H2N;
		mcu_txd->ext_cid = MCU_GET_EXT_CMD(cmd);

		if (mcu_txd->ext_cid || (cmd & MCU_CMD_FIELD_CE)) {
			if (cmd & MCU_CMD_FIELD_QUERY)
				mcu_txd->set_query = MCU_Q_QUERY;
			else
				mcu_txd->set_query = MCU_Q_SET;
			mcu_txd->ext_cid_ack = !!mcu_txd->ext_cid;
		} else {
			mcu_txd->set_query = MCU_Q_NA;
		}
	}

	if (seqp != NULL) {
		memset(&sc->sc_mcu_wait[seq], 0, sizeof(sc->sc_mcu_wait[0]));
		sc->sc_mcu_wait[seq].mcu_cmd = cmd;
		*seqp = seq;
	}
	q = &sc->sc_txmcuq;
enqueue:

	if (cmd != MCU_CMD_FW_SCATTER) {
		static uint32_t mcu_tx_log_count;

		if (mcu_tx_log_count < 96) {
			MWX_DEV_LOG(sc,
			    "mcu tx cmd=0x%08x seq=%u len=%d txd_len=%d q_reg=0x%08x\n",
			    cmd, seq, len, txd_len, q->mq_regbase);
			mcu_tx_log_count++;
		}
#ifdef MWX_PACKET_HEXDUMP
		pkt_hex_dump(m);
#endif
	}

	s = splnet();
	while (1) {
		rv = mwx_dma_tx_enqueue(sc, q, m);
		if (rv != EBUSY)
			break;
		q->mq_wakeme = 1;
		tsleep_nsec(q, 0, "mwxq", MSEC_TO_NSEC(100));
	}
	splx(s);
	if (rv != 0) {
		if (seqp != NULL)
			memset(&sc->sc_mcu_wait[seq], 0,
			    sizeof(sc->sc_mcu_wait[0]));
		m_freem(m);
	}
	return rv;
}

int
mwx_mcu_send_msg(struct mwx_softc *sc, uint32_t cmd, void *data, size_t len,
    int *seqp)
{
	struct mbuf *m;

	m = mwx_mcu_alloc_msg(len);
	if (m == NULL) {
		MWX_LOG("mcu msg alloc failed cmd=0x%08x len=%zu\n", cmd, len);
		return ENOMEM;
	}

	if (len != 0)
		memcpy(mtod(m, caddr_t), data, len);

	return mwx_mcu_send_mbuf(sc, cmd, m, seqp);
}

int
mwx_mcu_send_wait(struct mwx_softc *sc, uint32_t cmd, void *data, size_t len)
{
	int rv, seq;

	rv = mwx_mcu_send_msg(sc, cmd, data, len, &seq);
	if (rv != 0)
		return rv;
	return mwx_mcu_wait_resp_int(sc, cmd, seq, NULL);
}

int
mwx_mcu_send_mbuf_wait(struct mwx_softc *sc, uint32_t cmd, struct mbuf *m)
{
	int rv, seq;

	rv = mwx_mcu_send_mbuf(sc, cmd, m, &seq);
	if (rv != 0)
		return rv;
	return mwx_mcu_wait_resp_int(sc, cmd, seq, NULL);
}

void
mwx_mcu_rx_event(struct mwx_softc *sc, struct mbuf *m)
{
	struct mwx_mcu_rxd *rxd;
	uint32_t cmd, mcu_int = 0;
	uint8_t rxd_eid, rxd_ext_eid, rxd_seq;
	int len, rxd_size;

	rxd_size = MT7921_MCU_RXD_SIZE;
	if ((m = m_pullup(m, sizeof(*rxd) + rxd_size)) == NULL)
		return;
	m_adj(m, rxd_size);
	rxd = mtod(m, struct mwx_mcu_rxd *);

	if (rxd->ext_eid == MCU_EXT_EVENT_RATE_REPORT) {
		printf("%s: MCU_EXT_EVENT_RATE_REPORT COMMAND\n", DEVNAME(sc));
		m_freem(m);
		return;
	}

	len = le16toh(rxd->len);
	/* make sure all the data is in one mbuf */
	if ((m = m_pullup(m, len)) == NULL) {
		printf("%s: mwx_mcu_rx_event m_pullup failed\n", DEVNAME(sc));
		return;
	}
	/* refetch after pullup */
	rxd = mtod(m, struct mwx_mcu_rxd *);
	rxd_eid = rxd->eid;
	rxd_ext_eid = rxd->ext_eid;
	rxd_seq = rxd->seq;
	m_adj(m, sizeof(*rxd));

	switch (rxd_eid) {
	case MCU_EVENT_SCHED_SCAN_DONE:
	case MCU_EVENT_SCAN_DONE:
		mt7921_mcu_scan_event(sc, m);
		break;
#if 0
	case MCU_EVENT_BSS_BEACON_LOSS:
		mt7921_mcu_connection_loss_event(dev, skb);
		break;
	case MCU_EVENT_BSS_ABSENCE:
		mt7921_mcu_bss_event(dev, skb);
		break;
	case MCU_EVENT_DBG_MSG:
		mt7921_mcu_debug_msg_event(dev, skb);
		break;
#endif
	case MCU_EVENT_COREDUMP:
		/* it makes little sense to write the coredump down */
		if (!sc->sc_resetting)
			printf("%s: coredump event\n", DEVNAME(sc));
		mwx_reset(sc);
		break;
	case MCU_EVENT_LP_INFO:
		mt7921_mcu_low_power_event(sc, m);
		break;
	case MCU_EVENT_TX_DONE:
		mt7921_mcu_tx_done_event(sc, m);
		break;
	case 0x6:
		printf("%s: MAGIC COMMAND\n", DEVNAME(sc));
	default:
		if (rxd_seq == 0 || rxd_seq >= nitems(sc->sc_mcu_wait)) {
			printf("%s: mcu rx bad seq %x\n", DEVNAME(sc),
			    rxd_seq);
			break;
		}

		cmd = sc->sc_mcu_wait[rxd_seq].mcu_cmd;

		if (cmd == MCU_CMD_PATCH_SEM_CONTROL ||
		    cmd == MCU_CMD_PATCH_FINISH_REQ) {
			mcu_int = rxd_ext_eid;
			MWX_DEV_LOG(sc, "MCU patch response cmd=0x%08x seq=%u status=0x%x\n",
			    cmd, rxd_seq, mcu_int);
		} else if (cmd == MCU_EXT_CMD_THERMAL_CTRL) {
			if (mbuf_len(m) < sizeof(uint32_t) * 2)
				break;
			mcu_int = le32toh(mtod(m, uint32_t *)[1]);
		} else if (cmd == MCU_EXT_CMD_EFUSE_ACCESS) {
			//ret = mt7921_mcu_parse_eeprom(sc, m);
			printf("%s: mcu resp no handled yet\n", DEVNAME(sc));
		} else if (cmd == MCU_UNI_CMD_DEV_INFO_UPDATE ||
		    cmd == MCU_UNI_CMD_BSS_INFO_UPDATE ||
		    cmd == MCU_UNI_CMD_STA_REC_UPDATE ||
		    cmd == MCU_UNI_CMD_HIF_CTRL ||
		    cmd == MCU_UNI_CMD_OFFLOAD ||
		    cmd == MCU_UNI_CMD_SUSPEND) {
			struct mt7921_mcu_uni_event *event;

			if (mbuf_len(m) < sizeof(*event))
				break;
			event = mtod(m, struct mt7921_mcu_uni_event *);
			mcu_int = le32toh(event->status);
		} else if (cmd == MCU_CE_QUERY_REG_READ) {
			struct mt7921_mcu_reg_event *event;

			if (mbuf_len(m) < sizeof(*event))
				break;
			event = mtod(m, struct mt7921_mcu_reg_event *);
			mcu_int = le32toh(event->val);
		}

		sc->sc_mcu_wait[rxd_seq].mcu_int = mcu_int;
		sc->sc_mcu_wait[rxd_seq].mcu_m = m;
		wakeup(&sc->sc_mcu_wait[rxd_seq]);
		return;
	}

	m_freem(m);
}

int
mwx_mcu_wait_resp_int(struct mwx_softc *sc, uint32_t cmd, int seq,
    uint32_t *val)
{
	int rv;

	KASSERT(seq < nitems(sc->sc_mcu_wait));

	rv = tsleep_nsec(&sc->sc_mcu_wait[seq], 0, "mwxwait", SEC_TO_NSEC(3));
	if (rv != 0) {
		printf("%s: command %x timeout\n", DEVNAME(sc), cmd);
		mwx_reset(sc);
		return rv;
	}

	if (sc->sc_mcu_wait[seq].mcu_m != NULL) {
		m_freem(sc->sc_mcu_wait[seq].mcu_m);
		sc->sc_mcu_wait[seq].mcu_m = NULL;
	}
	if (val != NULL)
		*val = sc->sc_mcu_wait[seq].mcu_int;
	return 0;
}

int
mwx_mcu_wait_resp_msg(struct mwx_softc *sc, uint32_t cmd, int seq,
    struct mbuf **mp)
{
	int rv;

	KASSERT(seq < nitems(sc->sc_mcu_wait));

	rv = tsleep_nsec(&sc->sc_mcu_wait[seq], 0, "mwxwait", SEC_TO_NSEC(3));
	if (rv != 0) {
		printf("%s: command %x timeout\n", DEVNAME(sc), cmd);
		mwx_reset(sc);
		return rv;
	}
	if (sc->sc_mcu_wait[seq].mcu_m == NULL) {
		printf("%s: command response missing\n", DEVNAME(sc));
		return ENOENT;
	}
	if (mp != NULL)
		*mp = sc->sc_mcu_wait[seq].mcu_m;
	else
		m_freem(sc->sc_mcu_wait[seq].mcu_m);
	sc->sc_mcu_wait[seq].mcu_m = NULL;
	return 0;
}

int
mwx_dma_disable(struct mwx_softc *sc, int force)
{
	int rv;

	/* disable WFDMA0 */
	mwx_clear(sc, MT_WFDMA0_GLO_CFG,
	    MT_WFDMA0_GLO_CFG_TX_DMA_EN | MT_WFDMA0_GLO_CFG_RX_DMA_EN |
	    MT_WFDMA0_GLO_CFG_CSR_DISP_BASE_PTR_CHAIN_EN |
	    MT_WFDMA0_GLO_CFG_OMIT_TX_INFO |
	    MT_WFDMA0_GLO_CFG_OMIT_RX_INFO |
	    MT_WFDMA0_GLO_CFG_OMIT_RX_INFO_PFET2);

	rv = mwx_poll(sc, MT_WFDMA0_GLO_CFG, 0,
	    MT_WFDMA0_GLO_CFG_TX_DMA_BUSY | MT_WFDMA0_GLO_CFG_RX_DMA_BUSY, 100);
	if (!force && rv != 0)
		return rv;

	/* disable DMASHDL and set bypass */
	mwx_clear(sc, MT_WFDMA0_GLO_CFG_EXT0, MT_WFDMA0_CSR_TX_DMASHDL_ENABLE);
	mwx_set(sc, MT_DMASHDL_SW_CONTROL, MT_DMASHDL_DMASHDL_BYPASS);

	if (force) {
		/* reset */
		mwx_clear(sc, MT_WFDMA0_RST, MT_WFDMA0_RST_DMASHDL_ALL_RST |
		    MT_WFDMA0_RST_LOGIC_RST);
		mwx_set(sc, MT_WFDMA0_RST, MT_WFDMA0_RST_DMASHDL_ALL_RST |
		    MT_WFDMA0_RST_LOGIC_RST);
		delay(20);
	}

	return 0;
}

void
mwx_dma_enable(struct mwx_softc *sc)
{
#define PREFETCH(base, depth)   ((base) << 16 | (depth))
	/* configure perfetch settings */
	mwx_write(sc, MT_WFDMA0_RX_RING0_EXT_CTRL, PREFETCH(0x0, 0x4));
	mwx_write(sc, MT_WFDMA0_RX_RING2_EXT_CTRL, PREFETCH(0x40, 0x4));
	mwx_write(sc, MT_WFDMA0_RX_RING3_EXT_CTRL, PREFETCH(0x80, 0x4));
	mwx_write(sc, MT_WFDMA0_RX_RING4_EXT_CTRL, PREFETCH(0xc0, 0x4));
	mwx_write(sc, MT_WFDMA0_RX_RING5_EXT_CTRL, PREFETCH(0x100, 0x4));

	mwx_write(sc, MT_WFDMA0_TX_RING0_EXT_CTRL, PREFETCH(0x140, 0x4));
	mwx_write(sc, MT_WFDMA0_TX_RING1_EXT_CTRL, PREFETCH(0x180, 0x4));
	mwx_write(sc, MT_WFDMA0_TX_RING2_EXT_CTRL, PREFETCH(0x1c0, 0x4));
	mwx_write(sc, MT_WFDMA0_TX_RING3_EXT_CTRL, PREFETCH(0x200, 0x4));
	mwx_write(sc, MT_WFDMA0_TX_RING4_EXT_CTRL, PREFETCH(0x240, 0x4));
	mwx_write(sc, MT_WFDMA0_TX_RING5_EXT_CTRL, PREFETCH(0x280, 0x4));
	mwx_write(sc, MT_WFDMA0_TX_RING6_EXT_CTRL, PREFETCH(0x2c0, 0x4));
	mwx_write(sc, MT_WFDMA0_TX_RING16_EXT_CTRL, PREFETCH(0x340, 0x4));
	mwx_write(sc, MT_WFDMA0_TX_RING17_EXT_CTRL, PREFETCH(0x380, 0x4));

	/* reset dma idx */
	mwx_write(sc, MT_WFDMA0_RST_DTX_PTR, ~0);

	/* configure delay interrupt */
	mwx_write(sc, MT_WFDMA0_PRI_DLY_INT_CFG0, 0);

	mwx_set(sc, MT_WFDMA0_GLO_CFG,
	    MT_WFDMA0_GLO_CFG_TX_WB_DDONE |
	    MT_WFDMA0_GLO_CFG_FIFO_LITTLE_ENDIAN |
	    MT_WFDMA0_GLO_CFG_CLK_GAT_DIS |
	    MT_WFDMA0_GLO_CFG_OMIT_TX_INFO |
	    MT_WFDMA0_GLO_CFG_DMA_SIZE(3) |
	    MT_WFDMA0_GLO_CFG_FIFO_DIS_CHECK |
	    MT_WFDMA0_GLO_CFG_RX_WB_DDONE |
	    MT_WFDMA0_GLO_CFG_CSR_DISP_BASE_PTR_CHAIN_EN |
	    MT_WFDMA0_GLO_CFG_OMIT_RX_INFO_PFET2);

	mwx_barrier(sc);
	mwx_set(sc, MT_WFDMA0_GLO_CFG,
	    MT_WFDMA0_GLO_CFG_TX_DMA_EN | MT_WFDMA0_GLO_CFG_RX_DMA_EN);

	mwx_set(sc, MT_WFDMA_DUMMY_CR, MT_WFDMA_NEED_REINIT);

	/* enable interrupts for TX/RX rings */
	mwx_write(sc, MT_WFDMA0_HOST_INT_ENA, sc->sc_intr_mask);
	mwx_set(sc, MT_MCU2HOST_SW_INT_ENA, MT_MCU_CMD_WAKE_RX_PCIE);
	mwx_write(sc, MT_PCIE_MAC_INT_ENABLE, 0xff);
}

/*
 * PCIe Function Level Reset: resets the whole function like a power cycle.
 * Config space (BARs, command, MSI) is saved and restored around it.
 */
int
mwx_pci_flr(struct mwx_softc *sc, IOPCIDevice *dev)
{
	UInt8 cap = 0;
	UInt32 devcap;
	UInt16 devctl;

	if (dev == NULL ||
	    !dev->findPCICapability(kIOPCICapabilityIDPCIExpress, &cap) ||
	    cap == 0) {
		MWX_DEV_LOG(sc, "FLR: no PCIe capability\n");
		return ENODEV;
	}
	devcap = dev->configRead32(cap + 0x04);
	if (!(devcap & (1U << 28))) {
		MWX_DEV_LOG(sc, "FLR: not supported devcap=0x%08x\n", devcap);
		return ENODEV;
	}
	dev->saveDeviceState();
	devctl = dev->configRead16(cap + 0x08);
	dev->configWrite16(cap + 0x08, devctl | (1U << 15));
	IOSleep(150);
	dev->restoreDeviceState();
	dev->setMemoryEnable(true);
	dev->setBusMasterEnable(true);
	MWX_DEV_LOG(sc, "FLR done vendor=0x%04x\n", dev->configRead16(0));
	return 0;
}

int
mwx_mcu_fw_pmctrl(struct mwx_softc *sc)
{
	int i;

	for (i = 0; i < MWX_MCU_INIT_RETRY_COUNT; i++) {
		mwx_write(sc, MT_CONN_ON_LPCTL, PCIE_LPCR_HOST_SET_OWN);
		if (mwx_poll(sc, MT_CONN_ON_LPCTL, PCIE_LPCR_HOST_OWN_SYNC,
		    4, 50) == 0)
			break;
	}

	if (i == MWX_MCU_INIT_RETRY_COUNT) {
		printf("%s: firmware own failed\n", DEVNAME(sc));
		return EIO;
	}

	return 0;
}

int
mwx_mcu_drv_pmctrl(struct mwx_softc *sc)
{
	int i;

	for (i = 0; i < MWX_MCU_INIT_RETRY_COUNT; i++) {
		mwx_write(sc, MT_CONN_ON_LPCTL, PCIE_LPCR_HOST_CLR_OWN);
		delay(3000);
		if (mwx_poll(sc, MT_CONN_ON_LPCTL, 0,
		    PCIE_LPCR_HOST_OWN_SYNC, 50) == 0)
			break;
	}

	if (i == MWX_MCU_INIT_RETRY_COUNT) {
		printf("%s: driver own failed\n", DEVNAME(sc));
		return EIO;
	}

	return 0;
}

int
mwx_wfsys_reset(struct mwx_softc *sc)
{
	DPRINTF("%s: WFSYS reset\n", DEVNAME(sc));

	mwx_clear(sc, MT_WFSYS_SW_RST_B, WFSYS_SW_RST_B);
	delay(50 * 1000);
	mwx_set(sc, MT_WFSYS_SW_RST_B, WFSYS_SW_RST_B);

	return mwx_poll(sc, MT_WFSYS_SW_RST_B, WFSYS_SW_INIT_DONE,
	    WFSYS_SW_INIT_DONE, 500);
}

/*
 * ---------------------------------------------------------------------------
 * MT7927 (MT6639 family, connac3) bring-up: phase 1 (probe/reset) and
 * phase 2 (DMA rings, MSI interrupt, firmware download, first MCU query).
 *
 * Ported from Linux mt76 (BSD-3-Clause-Clear), morrownr/mt76 38f40b4:
 *   mt7925/pci.c        mt7925_pci_probe(), __mt7925_reg_addr(), mt7927 DMA
 *                       layout and IRQ map, mt7925e_mcu_init()
 *   mt792x_core.c       fw/drv own handshake, mt792x_load_firmware()
 *   mt792x_dma.c        mt7927_wfsys_reset(), mt792x_dma_disable/enable(),
 *                       mt7927_dma_prefetch_setup(), mt7927_wfdma_setup()
 *   mt76_connac_mcu.c   mt76_connac2_load_patch/ram(), init_download, ...
 *   mt7925/mcu.c        mt7925_mcu_fill_message(), parse_response(),
 *                       mt7925_mcu_get_nic_capability()
 *   pci.c               mt76_pci_disable_aspm()
 *
 * This code is driven by MtkMt7927Bringup (SimpleMtkWlan.cpp), not by the
 * MT7921 HAL above: it owns its rings, interrupt and register access, and
 * tears everything down (interrupts off, DMA stopped, MCU halted by a WFSYS
 * reset, bus mastering off) before freeing memory. Results go to the log
 * ("MtkDebugLog") and to "MT7927*" properties on the PCI device.
 * ---------------------------------------------------------------------------
 */

#define	MT7927_BAR_MIN_SIZE		0x200000	/* raw window used below */
#define	MT7927_OWN_RETRY_COUNT		10		/* MT792x_DRV_OWN_RETRY_COUNT */
#define	MT7927_ROMCODE_TIMEOUT_MS	200
#define	MT7927_MCU_TIMEOUT_MS		3000		/* mt7925 mcu.timeout 3 * HZ */
#define	MT7927_FW_CHUNK			4096		/* __mt76_mcu_send_firmware max_len */
#define	MT7927_MCU_RXD_LEN		44		/* struct mt7925_mcu_rxd */
#define	MT7927_PKT_TYPE_RX_EVENT	7

/* PCIe capability: Link Control register and its ASPM control field. */
#define	MT7927_PCIE_LNKCTL		0x10
#define	MT7927_PCIE_LNKCTL_ASPMC	0x0003
#define	MT7927_PCIE_LNKCTL_ASPM_L0S	0x0001
#define	MT7927_PCIE_LNKCTL_ASPM_L1	0x0002

/* Patch semaphore results (mt76_connac_mcu.h). */
#define	MT7927_PATCH_SEM_RELEASE	0
#define	MT7927_PATCH_SEM_GET		1
#define	MT7927_PATCH_IS_DL		1
#define	MT7927_PATCH_NOT_DL_SEM_SUCCESS	2
#define	MT7927_PATCH_REL_SEM_SUCCESS	3

#define	MT7927_UNI_CHIP_CONFIG_NIC_CAPA	0x3
#define	MT7927_NIC_CAP_HW_VER		5
#define	MT7927_NIC_CAP_SW_VER		6
#define	MT7927_NIC_CAP_MAC_ADDR		7
#define	MT7927_NIC_CAP_6G		0x18
#define	MT7927_NIC_CAP_CHIP_CAP		0x20

/* Phase 3 (connac3 init): UNI commands and tags (mt76_connac_mcu.h, mt7925/mcu.h). */
#define	MT7927_UNI_CMD(id)		(MCU_CMD_FIELD_UNI | (id))
#define	MT7927_UNI_BAND_CONFIG		MT7927_UNI_CMD(0x08)
#define	MT7927_UNI_SET_DOMAIN_INFO	MT7927_UNI_CMD(0x15)
#define	MT7927_UNI_SET_DBDC_PARMS	MT7927_UNI_CMD(0x28)
#define	MT7927_UNI_THERMAL		MT7927_UNI_CMD(0x35)
#define	MT7927_WM_UNI_QUERY(c)		((c) | MCU_CMD_FIELD_QUERY | MCU_CMD_FIELD_WM)
#define	MT7927_UNI_CHIP_CONFIG_CHIP_CFG	0x2
#define	MT7927_UNI_BAND_CONFIG_RTS	0x08
#define	MT7927_UNI_WSYS_FW_LOG_CTRL	0
#define	MT7927_UNI_EFUSE_ACCESS		1
#define	MT7927_UNI_EFUSE_BUFFER_MODE	2
#define	MT7927_UNI_MBMC_SETTING		0
#define	MT7927_EE_MODE_EFUSE		0
#define	MT7927_EE_FORMAT_WHOLE		1
#define	MT7927_EEPROM_BLOCK		16		/* MT7925_EEPROM_BLOCK_SIZE */
#define	MT7927_EE_HW_TYPE		0xa71
#define	MT7927_EE_HW_TYPE_ENCAP		0x03
#define	MT7927_UNI_EVENT_FW_LOG		0x04		/* MCU_UNI_EVENT_FW_LOG_2_HOST */
#define	MT7927_RXD_OPT_UNSOLICITED	0x04		/* MCU_UNI_CMD_UNSOLICITED_EVENT */
#define	MT7927_FW_FEATURE_NON_DL	0x40
#define	MT7927_FW_TYPE_CLC		2
#define	MT7927_RTS_THRESH		0x92b		/* __mt7925_start */
#define	MT7927_FW_LOG_LINES		64

/* cfg80211 channel flags carried in SET_DOMAIN_INFO (enum ieee80211_channel_flags). */
#define	MT7927_CHAN_NO_IR		(1U << 1)
#define	MT7927_CHAN_RADAR		(1U << 3)
#define	MT7927_CHAN_NO_OFDM		(1U << 6)

/* MAC registers touched by mt7925_mac_init() (mt7925/regs.h, mt792x_regs.h). */
#define	MT7927_MDP_DCR0			0x820cc800
#define	MT7927_MDP_DCR0_DAMSDU_EN	(1U << 15)
#define	MT7927_MDP_DCR1			0x820cc804
#define	MT7927_MAX_RX_LEN_MASK		0x0000fff8	/* GENMASK(15, 3) */
#define	MT7927_MAX_RX_LEN		(1536U << 3)
#define	MT7927_WTBL_UPDATE		0x820d4380	/* MT7925_WTBL_UPDATE */
#define	MT7927_WTBL_UPDATE_IDX_MASK	0x00000fff
#define	MT7927_WTBL_UPDATE_ADM_CLR	(1U << 14)
#define	MT7927_WTBL_UPDATE_BUSY		(1U << 31)
#define	MT7927_WTBL_ITCR		0x820d43b0
#define	MT7927_WTBL_ITCR_WR		(1U << 16)
#define	MT7927_WTBL_ITCR_EXEC		(1U << 31)
#define	MT7927_WTBL_ITDR0		0x820d43b8
#define	MT7927_WTBL_ITDR1		0x820d43bc
#define	MT7927_WTBL_SPE_IDX_SEL		(1U << 6)
#define	MT7927_WTBL_SIZE		20		/* MT792x_WTBL_SIZE */
#define	MT7927_BASIC_RATES_TBL		14		/* MT792x_BASIC_RATES_TBL */
#define	MT7927_TMAC_CTCR0(b)		((b) ? 0x820f40f4U : 0x820e40f4U)
#define	MT7927_CTCR0_REFTIME_MASK	0x0000003f
#define	MT7927_CTCR0_DDLMT_EN		(1U << 17)
#define	MT7927_CTCR0_VHT_SMPDU_EN	(1U << 18)
#define	MT7927_RMAC_MIB_TIME0(b)	((b) ? 0x820f53c4U : 0x820e53c4U)
#define	MT7927_RMAC_MIB_AIRTIME0(b)	((b) ? 0x820f5380U : 0x820e5380U)
#define	MT7927_RMAC_MIB_RXTIME_EN	(1U << 30)
#define	MT7927_MIB_SCR1(b)		((b) ? 0x820fd004U : 0x820ed004U)
#define	MT7927_MIB_TXDUR_EN		(1U << 8)
#define	MT7927_MIB_RXDUR_EN		(1U << 9)
#define	MT7927_DMA_DCR0(b)		((b) ? 0x820f7000U : 0x820e7000U)
#define	MT7927_DMA_DCR0_RXD_G5_EN	(1U << 23)
#define	MT7927_WTBLOFF_RSCR(b)		((b) ? 0x820f9008U : 0x820e9008U)
#define	MT7927_RSCR_RCPI_MASK		0xc3000000	/* RCPI_MODE 31:30, RCPI_PARAM 25:24 */
#define	MT7927_RSCR_RCPI_SET		0x03000000	/* mode 0, param 3 */

struct mt7927_dmamem {
	void		*va;
	uint32_t	pa;
	size_t		size;
	void		*handle;
};

struct mt7927_ring {
	struct mt7927_dmamem	desc_mem;
	struct mt7927_dmamem	buf_mem;
	struct mwx_desc		*desc;
	uint32_t		regbase;
	uint32_t		bufsz;
	uint16_t		count;
	uint16_t		head;
	uint16_t		tail;
	uint8_t			hwidx;
	bool			rx;
	const char		*name;
};

enum { MT7927_TX_BAND0, MT7927_TX_MCU, MT7927_TX_FWDL, MT7927_NTX };
enum { MT7927_RX_BAND0, MT7927_RX_MCU, MT7927_RX_DATA2, MT7927_NRX };

struct mt7927_bringup {
	struct mwx_softc	*sc;
	IOPCIDevice		*pci;
	void			*os;		/* IOWorkLoop, lock, map (kernel) */
	void			*ih_cookie;
	volatile bool		*abort;

	struct mt7927_ring	tx[MT7927_NTX];
	struct mt7927_ring	rx[MT7927_NRX];
	bool			rings_alloc;
	bool			dma_on;
	bool			mcu_touched;	/* firmware download started */

	uint32_t		irq_mask;
	volatile uint32_t	irq_pending;
	volatile uint32_t	intr_seen;	/* union of HOST_INT_STA bits */
	volatile uint32_t	intr_count;
	volatile uint32_t	mcu_sw_seen;

	uint8_t			seq;
	uint8_t			resp[1024];
	uint32_t		resp_len;
	uint8_t			resp_status;
	uint32_t		unsolicited;

	/* results */
	uint32_t		asic;
	uint32_t		romcode;
	uint32_t		fw_state;	/* CONN_ON_MISC after download */
	uint8_t			mac[6];
	bool			mac_valid;
	uint32_t		nic_elements;
	uint64_t		chip_cap;
	bool			chip_cap_valid;

	/* phase 3 */
	uint8_t			txbuf[2048] __attribute__((aligned(8))); /* MCU TXD + payload */
	char			alpha2[2];	/* country for SET_DOMAIN_INFO, 0 = unset */
	uint32_t		mcu_timeouts;
	uint32_t		mcu_max_ms;
	uint32_t		fw_log_events;
	uint32_t		fw_log_lines;
	uint32_t		unsol_events;
	uint8_t			hw_type;
	bool			hw_type_valid;
	uint16_t		ee_chip_id;
	uint8_t			ee_mac[6];
	bool			ee_valid;
	int32_t			temperature;
	bool			temp_valid;
	uint32_t		wtbl_busy;
	uint32_t		p3_fatal;
	uint32_t		p3_warn;
};

static bool mt7927_bar_fault;

/* Raw BAR0 access, bounds checked: a bad offset logs instead of faulting. */
static uint32_t
mt7927_raw_rd(struct mwx_softc *sc, uint32_t off)
{
	if (sc->sc_mems < 4 || off > sc->sc_mems - 4) {
		if (!mt7927_bar_fault)
			MWX_DEV_LOG(sc, "MT7927 read 0x%06x outside BAR0 (size 0x%zx), "
			    "returning 0xffffffff\n", off, (size_t)sc->sc_mems);
		mt7927_bar_fault = true;
		return 0xffffffff;
	}
	return bus_space_read_4(sc->sc_st, sc->sc_memh, off);
}

static void
mt7927_raw_wr(struct mwx_softc *sc, uint32_t off, uint32_t val)
{
	if (sc->sc_mems < 4 || off > sc->sc_mems - 4) {
		if (!mt7927_bar_fault)
			MWX_DEV_LOG(sc, "MT7927 write 0x%06x outside BAR0 (size 0x%zx), "
			    "dropped\n", off, (size_t)sc->sc_mems);
		mt7927_bar_fault = true;
		return;
	}
	bus_space_write_4(sc->sc_st, sc->sc_memh, off, val);
}

/*
 * Linux mt7925 default_fixed_map (also used for MT7927; only MT7928 has its
 * own table). Same first-match lookup, including the upstream "ofs > size"
 * bound.
 */
static const struct {
	uint32_t phys;
	uint32_t mapped;
	uint32_t size;
} mt7927_fixed_map[] = {
	{ 0x830c0000, 0x000000, 0x0001000 }, /* WF_MCU_BUS_CR_REMAP */
	{ 0x54000000, 0x002000, 0x0001000 }, /* WFDMA PCIE0 MCU DMA0 */
	{ 0x55000000, 0x003000, 0x0001000 }, /* WFDMA PCIE0 MCU DMA1 */
	{ 0x56000000, 0x004000, 0x0001000 }, /* WFDMA reserved */
	{ 0x57000000, 0x005000, 0x0001000 }, /* WFDMA MCU wrap CR */
	{ 0x58000000, 0x006000, 0x0001000 }, /* WFDMA PCIE1 MCU DMA0 (MEM_DMA) */
	{ 0x59000000, 0x007000, 0x0001000 }, /* WFDMA PCIE1 MCU DMA1 */
	{ 0x820c0000, 0x008000, 0x0004000 }, /* WF_UMAC_TOP (PLE) */
	{ 0x820c8000, 0x00c000, 0x0002000 }, /* WF_UMAC_TOP (PSE) */
	{ 0x820cc000, 0x00e000, 0x0002000 }, /* WF_UMAC_TOP (PP) */
	{ 0x74030000, 0x010000, 0x0001000 }, /* PCIe MAC */
	{ 0x820e0000, 0x020000, 0x0000400 }, /* WF_LMAC_TOP BN0 (WF_CFG) */
	{ 0x820e1000, 0x020400, 0x0000200 }, /* WF_LMAC_TOP BN0 (WF_TRB) */
	{ 0x820e2000, 0x020800, 0x0000400 }, /* WF_LMAC_TOP BN0 (WF_AGG) */
	{ 0x820e3000, 0x020c00, 0x0000400 }, /* WF_LMAC_TOP BN0 (WF_ARB) */
	{ 0x820e4000, 0x021000, 0x0000400 }, /* WF_LMAC_TOP BN0 (WF_TMAC) */
	{ 0x820e5000, 0x021400, 0x0000800 }, /* WF_LMAC_TOP BN0 (WF_RMAC) */
	{ 0x820ce000, 0x021c00, 0x0000200 }, /* WF_LMAC_TOP (WF_SEC) */
	{ 0x820e7000, 0x021e00, 0x0000200 }, /* WF_LMAC_TOP BN0 (WF_DMA) */
	{ 0x820cf000, 0x022000, 0x0001000 }, /* WF_LMAC_TOP (WF_PF) */
	{ 0x820e9000, 0x023400, 0x0000200 }, /* WF_LMAC_TOP BN0 (WF_WTBLOFF) */
	{ 0x820ea000, 0x024000, 0x0000200 }, /* WF_LMAC_TOP BN0 (WF_ETBF) */
	{ 0x820eb000, 0x024200, 0x0000400 }, /* WF_LMAC_TOP BN0 (WF_LPON) */
	{ 0x820ec000, 0x024600, 0x0000200 }, /* WF_LMAC_TOP BN0 (WF_INT) */
	{ 0x820ed000, 0x024800, 0x0000800 }, /* WF_LMAC_TOP BN0 (WF_MIB) */
	{ 0x820ca000, 0x026000, 0x0002000 }, /* WF_LMAC_TOP BN0 (WF_MUCOP) */
	{ 0x820d0000, 0x030000, 0x0010000 }, /* WF_LMAC_TOP (WF_WTBLON) */
	{ 0x40000000, 0x070000, 0x0010000 }, /* WF_UMAC_SYSRAM */
	{ 0x00400000, 0x080000, 0x0010000 }, /* WF_MCU_SYSRAM */
	{ 0x00410000, 0x090000, 0x0010000 }, /* WF_MCU_SYSRAM (configure register) */
	{ 0x820f0000, 0x0a0000, 0x0000400 }, /* WF_LMAC_TOP BN1 (WF_CFG) */
	{ 0x820f1000, 0x0a0600, 0x0000200 }, /* WF_LMAC_TOP BN1 (WF_TRB) */
	{ 0x820f2000, 0x0a0800, 0x0000400 }, /* WF_LMAC_TOP BN1 (WF_AGG) */
	{ 0x820f3000, 0x0a0c00, 0x0000400 }, /* WF_LMAC_TOP BN1 (WF_ARB) */
	{ 0x820f4000, 0x0a1000, 0x0000400 }, /* WF_LMAC_TOP BN1 (WF_TMAC) */
	{ 0x820f5000, 0x0a1400, 0x0000800 }, /* WF_LMAC_TOP BN1 (WF_RMAC) */
	{ 0x820f7000, 0x0a1e00, 0x0000200 }, /* WF_LMAC_TOP BN1 (WF_DMA) */
	{ 0x820f9000, 0x0a3400, 0x0000200 }, /* WF_LMAC_TOP BN1 (WF_WTBLOFF) */
	{ 0x820fa000, 0x0a4000, 0x0000200 }, /* WF_LMAC_TOP BN1 (WF_ETBF) */
	{ 0x820fb000, 0x0a4200, 0x0000400 }, /* WF_LMAC_TOP BN1 (WF_LPON) */
	{ 0x820fc000, 0x0a4600, 0x0000200 }, /* WF_LMAC_TOP BN1 (WF_INT) */
	{ 0x820fd000, 0x0a4800, 0x0000800 }, /* WF_LMAC_TOP BN1 (WF_MIB) */
	{ 0x820c4000, 0x0a8000, 0x0004000 }, /* WF_LMAC_TOP BN1 (WF_MUCOP) */
	{ 0x820b0000, 0x0ae000, 0x0001000 }, /* [APB2] WFSYS_ON */
	{ 0x80020000, 0x0b0000, 0x0010000 }, /* WF_TOP_MISC_OFF */
	{ 0x81020000, 0x0c0000, 0x0010000 }, /* WF_TOP_MISC_ON */
	{ 0x7c020000, 0x0d0000, 0x0010000 }, /* CONN_INFRA, wfdma */
	{ 0x7c060000, 0x0e0000, 0x0010000 }, /* CONN_INFRA, conn_host_csr_top */
	{ 0x7c000000, 0x0f0000, 0x0010000 }, /* CONN_INFRA */
	{ 0x70020000, 0x1f0000, 0x0010000 }, /* Reserved for CBTOP, can't switch */
	{ 0x7c500000, 0x060000, 0x0200000 }, /* remap */
};

enum mt7927_map_kind { MT7927_MAP_RAW, MT7927_MAP_FIXED, MT7927_MAP_L1,
	MT7927_MAP_NONE };

static enum mt7927_map_kind
mt7927_map(uint32_t addr, uint32_t *off)
{
	size_t i;

	if (addr < MT7927_BAR_MIN_SIZE) {
		*off = addr;
		return MT7927_MAP_RAW;
	}
	for (i = 0; i < nitems(mt7927_fixed_map); i++) {
		uint32_t ofs;

		if (addr < mt7927_fixed_map[i].phys)
			continue;
		ofs = addr - mt7927_fixed_map[i].phys;
		if (ofs > mt7927_fixed_map[i].size)
			continue;
		*off = mt7927_fixed_map[i].mapped + ofs;
		return MT7927_MAP_FIXED;
	}
	if ((addr >= 0x18000000 && addr < 0x18c00000) ||
	    (addr >= 0x70000000 && addr < 0x78000000) ||
	    (addr >= 0x7c000000 && addr < 0x7c400000)) {
		*off = MT7925_HIF_REMAP_BASE_L1 + MWX_HIF_REG_OFFSET(addr);
		return MT7927_MAP_L1;
	}
	/* L2 remap is not used by this code; refuse instead of guessing. */
	return MT7927_MAP_NONE;
}

/*
 * Point the L1 window at addr's 64 KB page and return the previous L1 value.
 * Linux restores it lazily on the next access; we restore right after each
 * access (mt7927_l1_restore), which leaves the hardware in the same state.
 * Only the bring-up thread uses L1; the interrupt handler touches raw
 * registers only.
 */
static uint32_t
mt7927_l1_select(struct mwx_softc *sc, uint32_t addr)
{
	uint32_t old = mt7927_raw_rd(sc, MT7925_HIF_REMAP_L1);

	mt7927_raw_wr(sc, MT7925_HIF_REMAP_L1,
	    (old & ~MT7925_HIF_REMAP_L1_MASK) |
	    (MWX_HIF_REG_BASE(addr) << MT7925_HIF_REMAP_L1_SHIFT));
	(void)mt7927_raw_rd(sc, MT7925_HIF_REMAP_L1);	/* push the write */
	return old;
}

static void
mt7927_l1_restore(struct mwx_softc *sc, uint32_t old)
{
	mt7927_raw_wr(sc, MT7925_HIF_REMAP_L1, old);
	(void)mt7927_raw_rd(sc, MT7925_HIF_REMAP_L1);
}

static uint32_t
mt7927_rr(struct mwx_softc *sc, uint32_t addr)
{
	uint32_t off, old, val;

	switch (mt7927_map(addr, &off)) {
	case MT7927_MAP_RAW:
	case MT7927_MAP_FIXED:
		return mt7927_raw_rd(sc, off);
	case MT7927_MAP_L1:
		old = mt7927_l1_select(sc, addr);
		val = mt7927_raw_rd(sc, off);
		mt7927_l1_restore(sc, old);
		return val;
	default:
		MWX_DEV_LOG(sc, "MT7927 read of unmapped address 0x%08x refused\n",
		    addr);
		return 0xffffffff;
	}
}

static void
mt7927_wr(struct mwx_softc *sc, uint32_t addr, uint32_t val)
{
	uint32_t off, old;

	switch (mt7927_map(addr, &off)) {
	case MT7927_MAP_RAW:
	case MT7927_MAP_FIXED:
		mt7927_raw_wr(sc, off, val);
		return;
	case MT7927_MAP_L1:
		old = mt7927_l1_select(sc, addr);
		mt7927_raw_wr(sc, off, val);
		mt7927_l1_restore(sc, old);
		return;
	default:
		MWX_DEV_LOG(sc, "MT7927 write of unmapped address 0x%08x refused\n",
		    addr);
		return;
	}
}

static uint32_t
mt7927_rmw(struct mwx_softc *sc, uint32_t addr, uint32_t mask, uint32_t val)
{
	uint32_t cur = mt7927_rr(sc, addr);

	cur = (cur & ~mask) | val;
	mt7927_wr(sc, addr, cur);
	return cur;
}

#define	mt7927_set(sc, a, b)	mt7927_rmw((sc), (a), 0, (b))
#define	mt7927_clear(sc, a, b)	mt7927_rmw((sc), (a), (b), 0)

/*
 * Poll every millisecond for up to timeout_ms. With trace, logs each distinct
 * value seen (up to 8). Returns true on match; *last gets the last value.
 */
static bool
mt7927_poll(struct mwx_softc *sc, uint32_t addr, uint32_t mask, uint32_t want,
    int timeout_ms, bool trace, uint32_t *last)
{
	uint32_t cur, prev = 0;
	int i, changes = 0;

	for (i = 0; i <= timeout_ms; i++) {
		cur = mt7927_rr(sc, addr) & mask;
		if (trace && (i == 0 || cur != prev) && changes < 8) {
			MWX_DEV_LOG(sc, "MT7927   poll 0x%08x t=%dms value=0x%08x\n",
			    addr, i, cur);
			changes++;
		}
		prev = cur;
		if (cur == want) {
			if (last)
				*last = cur;
			return true;
		}
		IODelay(1000);
	}
	if (last)
		*last = prev;
	return false;
}

static void
mt7927_publish(IOPCIDevice *dev, const char *key, uint32_t val)
{
	if (dev != NULL)
		dev->setProperty(key, (unsigned long long)val, 32);
}

static void
mt7927_publish_str(IOPCIDevice *dev, const char *key, const char *val)
{
	if (dev != NULL)
		dev->setProperty(key, val);
}

/* Clear ASPM L0s/L1 in one device's PCIe Link Control. Returns the old bits. */
static uint16_t
mt7927_clear_aspm(struct mwx_softc *sc, IOPCIDevice *dev, const char *who)
{
	UInt8 cap = 0;
	uint16_t lnkctl, after;

	if (dev == NULL ||
	    !dev->findPCICapability(kIOPCICapabilityIDPCIExpress, &cap) ||
	    cap == 0) {
		MWX_DEV_LOG(sc, "MT7927 ASPM %s: no PCIe capability\n", who);
		return 0;
	}
	lnkctl = dev->configRead16(cap + MT7927_PCIE_LNKCTL);
	if (lnkctl & MT7927_PCIE_LNKCTL_ASPMC)
		dev->configWrite16(cap + MT7927_PCIE_LNKCTL,
		    lnkctl & ~MT7927_PCIE_LNKCTL_ASPMC);
	after = dev->configRead16(cap + MT7927_PCIE_LNKCTL);
	MWX_DEV_LOG(sc, "MT7927 ASPM %s %04x:%04x lnkctl 0x%04x -> 0x%04x (%s%s)\n",
	    who, dev->configRead16(kIOPCIConfigVendorID),
	    dev->configRead16(kIOPCIConfigDeviceID), lnkctl, after,
	    (lnkctl & MT7927_PCIE_LNKCTL_ASPM_L0S) ? "L0s " : "",
	    (lnkctl & MT7927_PCIE_LNKCTL_ASPM_L1) ? "L1" : "was off");
	return lnkctl & MT7927_PCIE_LNKCTL_ASPMC;
}

/*
 * mt76_pci_disable_aspm(): "ASPM L1 causes unreliable WFDMA register access"
 * on MT7927. Downstream (the card) first, then the upstream port.
 */
static void
mt7927_disable_aspm(struct mwx_softc *sc, IOPCIDevice *dev)
{
	IORegistryEntry *p;
	IOPCIDevice *bridge = NULL;

	mt7927_clear_aspm(sc, dev, "device");
	for (p = dev->getParentEntry(gIOServicePlane); p != NULL;
	    p = p->getParentEntry(gIOServicePlane)) {
		if ((bridge = OSDynamicCast(IOPCIDevice, p)) != NULL)
			break;
	}
	if (bridge != NULL)
		mt7927_clear_aspm(sc, bridge, "upstream");
	else
		MWX_DEV_LOG(sc, "MT7927 ASPM upstream port not found\n");
}

/* mt792xe_mcu_fw_pmctrl(): hand the chip to the firmware. */
static int
mt7927_fw_own(struct mwx_softc *sc)
{
	int i;

	for (i = 0; i < MT7927_OWN_RETRY_COUNT; i++) {
		mt7927_wr(sc, MT_CONN_ON_LPCTL, PCIE_LPCR_HOST_SET_OWN);
		if (mt7927_poll(sc, MT_CONN_ON_LPCTL, PCIE_LPCR_HOST_OWN_SYNC,
		    PCIE_LPCR_HOST_OWN_SYNC, 50, false, NULL))
			return 0;
	}
	MWX_DEV_LOG(sc, "MT7927 firmware own failed lpctl=0x%08x\n",
	    mt7927_rr(sc, MT_CONN_ON_LPCTL));
	return EIO;
}

/* __mt792xe_mcu_drv_pmctrl(): take the chip back for the driver. */
static int
mt7927_drv_own(struct mwx_softc *sc)
{
	int i;

	for (i = 0; i < MT7927_OWN_RETRY_COUNT; i++) {
		mt7927_wr(sc, MT_CONN_ON_LPCTL, PCIE_LPCR_HOST_CLR_OWN);
		IODelay(3000);	/* Linux waits 2-3 ms when ASPM is on; harmless off */
		if (mt7927_poll(sc, MT_CONN_ON_LPCTL, PCIE_LPCR_HOST_OWN_SYNC,
		    0, 50, false, NULL))
			return 0;
	}
	MWX_DEV_LOG(sc, "MT7927 driver own failed lpctl=0x%08x\n",
	    mt7927_rr(sc, MT_CONN_ON_LPCTL));
	return EIO;
}

/* mt7927_sema_status_read(): semaphore reads go through a temporary remap. */
static uint32_t
mt7927_sema_status_read(struct mwx_softc *sc, uint32_t addr)
{
	uint32_t remap, val;

	remap = mt7927_rr(sc, MT7927_PCIE2AP_REMAP_WF_0_54);
	mt7927_wr(sc, MT7927_PCIE2AP_REMAP_WF_0_54,
	    (remap & ~MT7927_PCIE2AP_REMAP_WF_0_54_MASK) |
	    MT7927_PCIE2AP_REMAP_WF_0_54_VAL);
	IODelay(20);
	val = mt7927_rr(sc, addr);
	mt7927_wr(sc, MT7927_PCIE2AP_REMAP_WF_0_54, remap);
	IODelay(20);
	return val;
}

/* mt7927_wfsys_reset(): WFSYS reset through CBINFRA, then wait for ROM idle. */
static int
mt7927_wfsys_reset(struct mwx_softc *sc, uint32_t *romcode)
{
	uint32_t sema;

	sema = mt7927_sema_status_read(sc, MT7927_SEMA_OWN_STA);
	MWX_DEV_LOG(sc, "MT7927 reset: SEMA_OWN_STA=0x%08x rgu=0x%08x "
	    "romcode=0x%08x\n", sema, mt7927_rr(sc, MT7927_CBINFRA_RGU_WF_RST),
	    mt7927_rr(sc, MT7927_ROMCODE_INDEX));

	mt7927_set(sc, MT7927_CBINFRA_RGU_WF_RST,
	    MT7927_CBINFRA_RGU_WF_RST_WF_SUBSYS);
	IOSleep(2);
	mt7927_clear(sc, MT7927_CBINFRA_RGU_WF_RST,
	    MT7927_CBINFRA_RGU_WF_RST_WF_SUBSYS);
	IOSleep(10);
	mt7927_wr(sc, MT7927_CBINFRA_MCU_OWN_SET, 1U << 0);
	MWX_DEV_LOG(sc, "MT7927 reset: pulsed WF_SUBSYS, MCU_OWN_SET=1, "
	    "polling ROMCODE_INDEX for 0x%04x\n", MT7927_MCU_IDLE_VALUE);

	if (!mt7927_poll(sc, MT7927_ROMCODE_INDEX, 0xffff, MT7927_MCU_IDLE_VALUE,
	    MT7927_ROMCODE_TIMEOUT_MS, true, romcode)) {
		MWX_DEV_LOG(sc, "MT7927 WFSYS reset timeout (ROMCODE_INDEX=0x%04x)\n",
		    *romcode & 0xffff);
		return ETIMEDOUT;
	}

	sema = mt7927_sema_status_read(sc, MT7927_SEMA_OWN_STA_REP);
	MWX_DEV_LOG(sc, "MT7927 reset: done, SEMA_OWN_STA_REP=0x%08x\n", sema);
	return 0;
}

static bool
mt7927_aborted(struct mt7927_bringup *b)
{
	return b->abort != NULL && *b->abort;
}

/*
 * Phase 1: ASPM off, own handshake (one FLR fallback), chip ID, EMI sleep
 * protection, CBINFRA WFSYS reset. Order follows mt7925_pci_probe().
 */
static int
mt7927_phase1(struct mt7927_bringup *b)
{
	struct mwx_softc *sc = b->sc;
	IOPCIDevice *dev = b->pci;
	uint32_t lpctl, chipid, rev, val;
	int rv;

	mt7927_bar_fault = false;
	MWX_DEV_LOG(sc, "MT7927 phase 1 start BAR0 size=0x%zx\n",
	    (size_t)sc->sc_mems);
	mt7927_publish(dev, "MT7927ProbeBAR0Size", (uint32_t)sc->sc_mems);
	if (sc->sc_mems < MT7927_BAR_MIN_SIZE) {
		MWX_DEV_LOG(sc, "MT7927 BAR0 smaller than 0x%x, stopping before any "
		    "register access\n", MT7927_BAR_MIN_SIZE);
		return ENXIO;
	}

	mt7927_disable_aspm(sc, dev);

	lpctl = mt7927_rr(sc, MT_CONN_ON_LPCTL);
	MWX_DEV_LOG(sc, "MT7927 before own lpctl=0x%08x\n", lpctl);
	rv = mt7927_fw_own(sc);
	if (rv == 0)
		rv = mt7927_drv_own(sc);
	if (rv != 0) {
		/* Warm reboot from Windows can leave the chip wedged: one FLR. */
		MWX_DEV_LOG(sc, "MT7927 own handshake failed, trying PCIe FLR\n");
		if (mwx_pci_flr(sc, dev) != 0)
			return rv;
		mt7927_disable_aspm(sc, dev);	/* FLR restores config space */
		rv = mt7927_fw_own(sc);
		if (rv == 0)
			rv = mt7927_drv_own(sc);
		if (rv != 0) {
			MWX_DEV_LOG(sc, "MT7927 own handshake failed after FLR\n");
			mt7927_publish(dev, "MT7927ProbeLPCTL",
			    mt7927_rr(sc, MT_CONN_ON_LPCTL));
			return rv;
		}
	}
	lpctl = mt7927_rr(sc, MT_CONN_ON_LPCTL);
	MWX_DEV_LOG(sc, "MT7927 driver own ok lpctl=0x%08x\n", lpctl);
	mt7927_publish(dev, "MT7927ProbeLPCTL", lpctl);

	chipid = mt7927_rr(sc, MT_HW_CHIPID);
	rev = mt7927_rr(sc, MT_HW_REV);
	b->asic = (chipid << 16) | (rev & 0xff);
	MWX_DEV_LOG(sc, "MT7927 ASIC revision: %04x (CHIPID=0x%08x REV=0x%08x)\n",
	    b->asic, chipid, rev);
	mt7927_publish(dev, "MT7927ProbeRawChipID", chipid);
	mt7927_publish(dev, "MT7927ProbeRawRev", rev);
	if ((chipid & 0xffff) != 0x7927) {
		MWX_DEV_LOG(sc, "MT7927 raw CHIPID=0x%04x, forcing chip=0x7927\n",
		    chipid & 0xffff);
		b->asic = (0x7927U << 16) | (rev & 0xff);
	}
	mt7927_publish(dev, "MT7927ProbeASICRev", b->asic);

	val = mt7927_rmw(sc, MT_HW_EMI_CTL, MT_HW_EMI_CTL_SLPPROT_EN,
	    MT_HW_EMI_CTL_SLPPROT_EN);
	MWX_DEV_LOG(sc, "MT7927 EMI sleep protection on, wrote 0x%08x, "
	    "EMI_CTL=0x%08x\n", val, mt7927_rr(sc, MT_HW_EMI_CTL));

	rv = mt7927_wfsys_reset(sc, &b->romcode);
	mt7927_publish(dev, "MT7927ProbeROMCODE", b->romcode);
	mt7927_publish(dev, "MT7927ProbeResetOK", rv == 0);
	if (rv != 0)
		return rv;

	/* The chip ID read before the reset is not valid (raw 0x0000). */
	chipid = mt7927_rr(sc, MT_HW_CHIPID);
	rev = mt7927_rr(sc, MT_HW_REV);
	MWX_DEV_LOG(sc, "MT7927 after reset: CHIPID=0x%08x REV=0x%08x\n",
	    chipid, rev);
	mt7927_publish(dev, "MT7927ProbeChipIDAfterReset", chipid);
	mt7927_publish(dev, "MT7927ProbeRevAfterReset", rev);

	MWX_DEV_LOG(sc, "MT7927 phase 1 PASS: ASIC %04x, 0xc1604=0x%04x\n",
	    b->asic, b->romcode);
	if (mt7927_bar_fault)
		MWX_DEV_LOG(sc, "MT7927 note: a BAR0 bounds check fired; see above\n");
	return 0;
}

/* ---- DMA memory and interrupt plumbing (kernel; host test replaces) ---- */

#ifdef MT7927_HOST_TEST
/* tests/mt7927-probe supplies these after the block. */
static int mt7927_dmamem_alloc(struct mt7927_dmamem *, size_t);
static void mt7927_dmamem_free(struct mt7927_dmamem *);
static void mt7927_signal(struct mt7927_bringup *);
static void mt7927_wait(struct mt7927_bringup *, int);
static int mt7927_irq_setup(struct mt7927_bringup *);
#else
struct mt7927_os {
	IOWorkLoop	*wl;
	IOLock		*lock;
	IOMemoryMap	*bar;
};

static int
mt7927_dmamem_alloc(struct mt7927_dmamem *m, size_t size)
{
	IOBufferMemoryDescriptor *md;
	IOPhysicalAddress pa;

	memset(m, 0, sizeof(*m));
	/* Page aligned, physically contiguous, below 4 GB (32-bit DMA mask). */
	md = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(kernel_task,
	    kIOMemoryPhysicallyContiguous | kIODirectionInOut | kIOMapInhibitCache,
	    size, 0x00000000fffff000ULL);
	if (md == NULL)
		return ENOMEM;
	if (md->prepare() != kIOReturnSuccess) {
		md->release();
		return ENOMEM;
	}
	pa = md->getPhysicalAddress();
	if (pa == 0 || (uint64_t)pa + size > 0x100000000ULL) {
		md->complete();
		md->release();
		return ENOMEM;
	}
	m->va = md->getBytesNoCopy();
	m->pa = (uint32_t)pa;
	m->size = size;
	m->handle = md;
	memset(m->va, 0, size);
	return 0;
}

static void
mt7927_dmamem_free(struct mt7927_dmamem *m)
{
	IOBufferMemoryDescriptor *md = (IOBufferMemoryDescriptor *)m->handle;

	if (md != NULL) {
		md->complete();
		md->release();
	}
	memset(m, 0, sizeof(*m));
}

/* Wake the bring-up thread (interrupt context: work loop thread). */
static void
mt7927_signal(struct mt7927_bringup *b)
{
	struct mt7927_os *os = (struct mt7927_os *)b->os;

	IOLockLock(os->lock);
	b->irq_pending = 1;
	IOLockWakeup(os->lock, (void *)&b->irq_pending, false);
	IOLockUnlock(os->lock);
}

/* Sleep up to ms or until the interrupt handler signals. */
static void
mt7927_wait(struct mt7927_bringup *b, int ms)
{
	struct mt7927_os *os = (struct mt7927_os *)b->os;
	uint64_t deadline;

	IOLockLock(os->lock);
	if (!b->irq_pending) {
		clock_interval_to_deadline(ms, kMillisecondScale, &deadline);
		IOLockSleepDeadline(os->lock, (void *)&b->irq_pending, deadline,
		    THREAD_UNINT);
	}
	b->irq_pending = 0;
	IOLockUnlock(os->lock);
}
#endif /* MT7927_HOST_TEST */

/* ---- Rings ---- */

static int
mt7927_ring_alloc(struct mt7927_bringup *b, struct mt7927_ring *r,
    const char *name, bool rx, uint8_t hwidx, uint16_t count, uint32_t bufsz)
{
	int rv;

	memset(r, 0, sizeof(*r));
	r->name = name;
	r->rx = rx;
	r->hwidx = hwidx;
	r->count = count;
	r->bufsz = bufsz;
	r->regbase = MT7927_RING_REG(rx ? MT7927_RX_RING_BASE :
	    MT7927_TX_RING_BASE, hwidx);
	if ((rv = mt7927_dmamem_alloc(&r->desc_mem,
	    count * sizeof(struct mwx_desc))) != 0)
		return rv;
	if ((rv = mt7927_dmamem_alloc(&r->buf_mem, (size_t)count * bufsz)) != 0)
		return rv;
	r->desc = (struct mwx_desc *)r->desc_mem.va;
	return 0;
}

static void
mt7927_ring_free(struct mt7927_ring *r)
{
	mt7927_dmamem_free(&r->desc_mem);
	mt7927_dmamem_free(&r->buf_mem);
	r->desc = NULL;
}

static inline uint32_t
mt7927_ring_buf_pa(struct mt7927_ring *r, uint16_t idx)
{
	return r->buf_mem.pa + (uint32_t)idx * r->bufsz;
}

static inline uint8_t *
mt7927_ring_buf(struct mt7927_ring *r, uint16_t idx)
{
	return (uint8_t *)r->buf_mem.va + (size_t)idx * r->bufsz;
}

/* mt76_dma_queue_reset + sync_idx: descriptors done, registers programmed. */
static void
mt7927_ring_reset(struct mt7927_bringup *b, struct mt7927_ring *r)
{
	struct mwx_softc *sc = b->sc;
	uint16_t i;

	for (i = 0; i < r->count; i++) {
		r->desc[i].buf0 = 0;
		r->desc[i].buf1 = 0;
		r->desc[i].info = 0;
		r->desc[i].ctrl = htole32(MT_DMA_CTL_DMA_DONE);
	}
	OSSynchronizeIO();
	mt7927_wr(sc, r->regbase + MT_DMA_DESC_BASE, r->desc_mem.pa);
	mt7927_wr(sc, r->regbase + MT_DMA_RING_SIZE, r->count);
	mt7927_wr(sc, r->regbase + MT_DMA_CPU_IDX, 0);
	mt7927_wr(sc, r->regbase + MT_DMA_DMA_IDX, 0);
	r->head = r->tail = 0;
}

static void
mt7927_rx_arm(struct mt7927_ring *r, uint16_t idx)
{
	struct mwx_desc *d = &r->desc[idx];

	d->buf0 = htole32(mt7927_ring_buf_pa(r, idx));
	d->buf1 = 0;
	d->info = 0;
	d->ctrl = htole32(MT_DMA_CTL_SD_LEN0(r->bufsz));	/* DMA_DONE clear */
}

/* mt76_dma_rx_fill: every slot but one, then kick CPU_IDX. */
static void
mt7927_rx_fill(struct mt7927_bringup *b, struct mt7927_ring *r)
{
	uint16_t i;

	for (i = 0; i + 1 < r->count; i++)
		mt7927_rx_arm(r, i);
	r->tail = 0;
	r->head = r->count - 1;
	OSSynchronizeIO();
	mt7927_wr(b->sc, r->regbase + MT_DMA_CPU_IDX, r->head);
}

/* Completed RX slot at tail, or NULL. */
static uint8_t *
mt7927_rx_peek(struct mt7927_ring *r, uint32_t *len)
{
	uint32_t ctrl = le32toh(r->desc[r->tail].ctrl);

	if (!(ctrl & MT_DMA_CTL_DMA_DONE))
		return NULL;
	*len = (ctrl >> MT_DMA_CTL_SD_LEN0_SHIFT) & MT_DMA_CTL_SD_LEN_MASK;
	if (*len > r->bufsz)
		*len = r->bufsz;
	return mt7927_ring_buf(r, r->tail);
}

/* Give the slot back: re-arm the gap slot (head), advance both indices. */
static void
mt7927_rx_release(struct mt7927_bringup *b, struct mt7927_ring *r)
{
	mt7927_rx_arm(r, r->head);
	r->head = (r->head + 1) % r->count;
	r->tail = (r->tail + 1) % r->count;
	OSSynchronizeIO();
	mt7927_wr(b->sc, r->regbase + MT_DMA_CPU_IDX, r->head);
}

/* Reclaim TX slots the hardware has consumed (DMA_IDX). */
static void
mt7927_tx_reap(struct mt7927_bringup *b, struct mt7927_ring *r)
{
	uint32_t dma = mt7927_rr(b->sc, r->regbase + MT_DMA_DMA_IDX);

	if (dma >= r->count)
		return;
	r->tail = (uint16_t)dma;
}

static void mt7927_service(struct mt7927_bringup *, uint8_t, bool *);

static int
mt7927_tx(struct mt7927_bringup *b, struct mt7927_ring *r, const void *data,
    uint32_t len)
{
	struct mwx_desc *d;
	uint16_t next;
	int waited = 0;

	if (len == 0 || len > r->bufsz || len > MT_DMA_CTL_SD_LEN_MASK)
		return EINVAL;
	for (;;) {
		mt7927_tx_reap(b, r);
		next = (r->head + 1) % r->count;
		if (next != r->tail)
			break;
		if (mt7927_aborted(b))
			return ECANCELED;
		if (waited >= MT7927_MCU_TIMEOUT_MS) {
			MWX_DEV_LOG(b->sc, "MT7927 %s ring stuck head=%u tail=%u "
			    "dma_idx=%u\n", r->name, r->head, r->tail,
			    mt7927_rr(b->sc, r->regbase + MT_DMA_DMA_IDX));
			return ETIMEDOUT;
		}
		mt7927_service(b, 0, NULL);
		mt7927_wait(b, 1);
		waited++;
	}
	memcpy(mt7927_ring_buf(r, r->head), data, len);
	d = &r->desc[r->head];
	d->buf0 = htole32(mt7927_ring_buf_pa(r, r->head));
	d->buf1 = 0;
	d->info = 0;
	OSSynchronizeIO();
	d->ctrl = htole32(MT_DMA_CTL_SD_LEN0(len) | MT_DMA_CTL_LAST_SEC0);
	OSSynchronizeIO();
	r->head = next;
	mt7927_wr(b->sc, r->regbase + MT_DMA_CPU_IDX, r->head);
	return 0;
}

/* ---- Interrupt handler (mt792x_irq_handler + tasklet top half) ---- */

static int
mt7927_intr(void *arg)
{
	struct mt7927_bringup *b = (struct mt7927_bringup *)arg;
	struct mwx_softc *sc = b->sc;
	uint32_t sta, sw;

	/* Raw registers only (0xd4xxx): never races the L1 window. */
	mt7927_raw_wr(sc, MT_WFDMA0_HOST_INT_ENA, 0);
	sta = mt7927_raw_rd(sc, MT_WFDMA0_HOST_INT_STA);
	if (sta == 0xffffffff)
		return 0;
	mt7927_raw_wr(sc, MT_WFDMA0_HOST_INT_STA, sta);
	if (sta & MT_INT_MCU_CMD) {
		sw = mt7927_raw_rd(sc, MT_MCU_CMD);
		mt7927_raw_wr(sc, MT_MCU_CMD, sw);	/* ack MCU2HOST_SW_INT_STA */
		OSBitOrAtomic(sw, &b->mcu_sw_seen);
	}
	OSBitOrAtomic(sta, &b->intr_seen);
	OSIncrementAtomic((volatile SInt32 *)&b->intr_count);
	mt7927_signal(b);
	return 1;
}

/* ---- MCU messages ---- */

/*
 * Unsolicited firmware event (rxd option has MCU_UNI_CMD_UNSOLICITED_EVENT),
 * mt7925_mcu_uni_rx_unsolicited_event(). Firmware text log lines (FW_LOG_2_HOST,
 * id 0x28) are copied to the debug log like mt7925_mcu_uni_debug_msg_event();
 * everything else is counted and the first few are logged.
 */
static void
mt7927_unsolicited(struct mt7927_bringup *b, struct mt7927_ring *r,
    const uint8_t *p, uint32_t len)
{
	uint8_t eid = p[32 + 4];

	b->unsol_events++;
	if (eid == MT7927_UNI_EVENT_FW_LOG) {
		/* rxd(44) + rsv(4) + tag(2) len(2) fmt(1) rsv(3), then id */
		const uint32_t id_off = MT7927_MCU_RXD_LEN + 4 + 8;
		char line[161];
		uint32_t i, n;

		b->fw_log_events++;
		if (len <= id_off || p[id_off] != 0x28 ||
		    b->fw_log_lines >= MT7927_FW_LOG_LINES)
			return;
		n = len - id_off;
		if (n > sizeof(line) - 1)
			n = sizeof(line) - 1;
		for (i = 0; i < n; i++) {
			uint8_t c = p[id_off + i];

			if (c == 0)
				break;
			line[i] = (c >= 0x20 && c < 0x7f) ? (char)c : ' ';
		}
		while (i > 0 && line[i - 1] == ' ')
			i--;
		line[i] = '\0';
		if (i == 0)
			return;
		b->fw_log_lines++;
		MWX_DEV_LOG(b->sc, "MT7927 fw: %s\n", line);
		return;
	}
	if (b->unsolicited++ < 16)
		MWX_DEV_LOG(b->sc, "MT7927 unsolicited event on %s: eid=0x%02x "
		    "len=%u\n", r->name, eid, len);
}

/*
 * Drain completed RX descriptors on all three rings. An event whose seq
 * matches want_seq is copied to b->resp (payload after the 44-byte MCU RXD)
 * and *matched is set. Re-enables the host interrupt mask afterwards, like
 * mt792x_poll_rx() / mt76_connac_irq_enable().
 */
static void
mt7927_service(struct mt7927_bringup *b, uint8_t want_seq, bool *matched)
{
	struct mwx_softc *sc = b->sc;
	int i, n;

	for (i = 0; i < MT7927_NRX; i++) {
		struct mt7927_ring *r = &b->rx[i];
		uint8_t *p;
		uint32_t len;

		if (r->desc == NULL)
			continue;
		for (n = 0; n < r->count && (p = mt7927_rx_peek(r, &len)) != NULL;
		    n++) {
			uint32_t rxd0 = len >= 4 ? le32toh(*(uint32_t *)p) : 0;
			uint32_t type = rxd0 >> 27;

			if (len >= MT7927_MCU_RXD_LEN - 4 &&
			    type == MT7927_PKT_TYPE_RX_EVENT) {
				uint8_t eid = p[32 + 4], seq = p[32 + 5];
				uint8_t opt = p[32 + 6], ext_eid = p[32 + 8];

				if (opt & MT7927_RXD_OPT_UNSOLICITED) {
					mt7927_unsolicited(b, r, p, len);
				} else if (want_seq != 0 && seq == want_seq &&
				    matched != NULL && !*matched) {
					b->resp_status = ext_eid;
					b->resp_len = len > MT7927_MCU_RXD_LEN ?
					    len - MT7927_MCU_RXD_LEN : 0;
					if (b->resp_len > sizeof(b->resp))
						b->resp_len = sizeof(b->resp);
					memcpy(b->resp, p + MT7927_MCU_RXD_LEN,
					    b->resp_len);
					*matched = true;
				} else if (b->unsolicited++ < 16) {
					MWX_DEV_LOG(sc, "MT7927 event on %s: eid=0x%02x "
					    "seq=%u ext=0x%02x len=%u (not waited for)\n",
					    r->name, eid, seq, ext_eid, len);
				}
			} else if (b->unsolicited++ < 16) {
				MWX_DEV_LOG(sc, "MT7927 rx on %s: type=%u len=%u "
				    "rxd0=0x%08x\n", r->name, type, len, rxd0);
			}
			mt7927_rx_release(b, r);
		}
	}
	if (b->dma_on)
		mt7927_raw_wr(sc, MT_WFDMA0_HOST_INT_ENA, b->irq_mask);
}

/*
 * mt7925_mcu_fill_message() + send: connac2 MCU TXD layout with the connac3
 * TXD1 header format (no LONG_FORMAT bit). FW_SCATTER goes raw to the FWDL
 * ring. With wait, returns after the event with our seq (3 s timeout).
 */
static int
mt7927_mcu_send(struct mt7927_bringup *b, uint32_t cmd, const void *data,
    uint32_t len, bool wait)
{
	uint8_t *buf = b->txbuf;
	uint32_t txd_len, tot_len, mcu_cmd = cmd & MCU_CMD_FIELD_ID_MASK;
	uint32_t *txd = (uint32_t *)buf;
	bool matched = false;
	uint8_t seq;
	int rv, waited;

	if (cmd == MCU_CMD_FW_SCATTER)
		return mt7927_tx(b, &b->tx[MT7927_TX_FWDL], data, len);

	txd_len = (cmd & MCU_CMD_FIELD_UNI) ? sizeof(struct mwx_uni_txd) :
	    sizeof(struct mwx_mcu_txd);
	if (len > sizeof(b->txbuf) - txd_len)
		return EINVAL;
	tot_len = txd_len + len;

	seq = ++b->seq & 0xf;
	if (seq == 0)
		seq = ++b->seq & 0xf;

	memset(buf, 0, txd_len);
	if (len)
		memcpy(buf + txd_len, data, len);
	txd[0] = htole32((tot_len & MT_TXD0_TX_BYTES_MASK) | MT_TX_TYPE_CMD |
	    MT_TXD0_Q_IDX(MT_TX_MCU_PORT_RX_Q0));
	txd[1] = htole32(MT7925_HDR_FORMAT_CMD);

	if (cmd & MCU_CMD_FIELD_UNI) {
		struct mwx_uni_txd *u = (struct mwx_uni_txd *)buf;

		u->len = htole16(tot_len - sizeof(u->txd));
		u->cid = htole16(mcu_cmd);
		u->s2d_index = CMD_S2D_IDX_H2N;
		u->pkt_type = MCU_PKT_ID;
		u->seq = seq;
		u->option = (cmd & MCU_CMD_FIELD_QUERY) ?
		    (MCU_CMD_ACK | MCU_CMD_UNI) :	/* MCU_CMD_UNI_QUERY_ACK */
		    MCU_CMD_UNI_EXT_ACK;
		if (cmd == MCU_UNI_CMD_CHIP_CONFIG || cmd == MCU_UNI_CMD_HIF_CTRL)
			u->option &= ~MCU_CMD_ACK;
	} else {
		struct mwx_mcu_txd *m = (struct mwx_mcu_txd *)buf;

		m->len = htole16(tot_len - sizeof(m->txd));
		m->pq_id = htole16(MCU_PQ_ID(MT_TX_PORT_IDX_MCU,
		    MT_TX_MCU_PORT_RX_Q0));
		m->pkt_type = MCU_PKT_ID;
		m->seq = seq;
		m->cid = mcu_cmd;
		m->ext_cid = MCU_GET_EXT_CMD(cmd);
		if (m->ext_cid || (cmd & MCU_CMD_FIELD_CE)) {
			m->set_query = (cmd & MCU_CMD_FIELD_QUERY) ? MCU_Q_QUERY :
			    MCU_Q_SET;
			m->ext_cid_ack = !!m->ext_cid;
		} else {
			m->set_query = MCU_Q_NA;
		}
		m->s2d_index = CMD_S2D_IDX_H2N;
	}

	b->resp_len = 0;
	b->resp_status = 0xff;
	if ((rv = mt7927_tx(b, &b->tx[MT7927_TX_MCU], buf, tot_len)) != 0)
		return rv;
	if (!wait)
		return 0;

	for (waited = 0; waited <= MT7927_MCU_TIMEOUT_MS; waited++) {
		mt7927_service(b, seq, &matched);
		if (matched) {
			if ((uint32_t)waited > b->mcu_max_ms)
				b->mcu_max_ms = waited;
			return 0;
		}
		if (mt7927_aborted(b))
			return ECANCELED;
		mt7927_wait(b, 1);
	}
	MWX_DEV_LOG(b->sc, "MT7927 MCU cmd 0x%08x seq %u timeout (intr_count=%u "
	    "intr_seen=0x%08x mcu_tx dma_idx=%u)\n", cmd, seq, b->intr_count,
	    b->intr_seen, mt7927_rr(b->sc,
	    b->tx[MT7927_TX_MCU].regbase + MT_DMA_DMA_IDX));
	b->mcu_timeouts++;
	return ETIMEDOUT;
}

/* ---- DMA bring-up (mt792x_dma_alloc_queues/enable for MT7927) ---- */

/* mt792x_dma_disable(): stop WFDMA, reset pointers, bypass DMASHDL. */
static int
mt7927_dma_disable(struct mt7927_bringup *b, bool force)
{
	struct mwx_softc *sc = b->sc;
	bool idle;

	mt7927_clear(sc, MT_WFDMA0_GLO_CFG,
	    MT_WFDMA0_GLO_CFG_TX_DMA_EN | MT_WFDMA0_GLO_CFG_RX_DMA_EN |
	    MT_WFDMA0_GLO_CFG_CSR_DISP_BASE_PTR_CHAIN_EN |
	    MT_WFDMA0_GLO_CFG_OMIT_TX_INFO | MT_WFDMA0_GLO_CFG_OMIT_RX_INFO |
	    MT_WFDMA0_GLO_CFG_OMIT_RX_INFO_PFET2);
	idle = mt7927_poll(sc, MT_WFDMA0_GLO_CFG,
	    MT_WFDMA0_GLO_CFG_TX_DMA_BUSY | MT_WFDMA0_GLO_CFG_RX_DMA_BUSY, 0,
	    100, false, NULL);
	if (!idle) {
		MWX_DEV_LOG(sc, "MT7927 WFDMA still busy GLO_CFG=0x%08x\n",
		    mt7927_rr(sc, MT_WFDMA0_GLO_CFG));
		if (!force)
			return ETIMEDOUT;
	}
	mt7927_wr(sc, MT_WFDMA0_RST_DTX_PTR, ~0U);
	mt7927_wr(sc, MT_WFDMA0_RST_DRX_PTR, ~0U);

	mt7927_clear(sc, MT_WFDMA0_GLO_CFG_EXT0, MT_WFDMA0_CSR_TX_DMASHDL_ENABLE);
	mt7927_set(sc, MT_DMASHDL_SW_CONTROL, MT_DMASHDL_DMASHDL_BYPASS);
	if (force) {
		mt7927_clear(sc, MT_WFDMA0_RST, MT_WFDMA0_RST_DMASHDL_ALL_RST |
		    MT_WFDMA0_RST_LOGIC_RST);
		mt7927_set(sc, MT_WFDMA0_RST, MT_WFDMA0_RST_DMASHDL_ALL_RST |
		    MT_WFDMA0_RST_LOGIC_RST);
	}
	return idle ? 0 : ETIMEDOUT;
}

#define	MT7927_PREFETCH(base, depth)	((uint32_t)(base) << 16 | (depth))

static void
mt7927_dma_enable(struct mt7927_bringup *b)
{
	struct mwx_softc *sc = b->sc;

	/* mt7927_dma_prefetch_setup() */
	mt7927_wr(sc, MT7927_WFDMA_PREFETCH_CTRL,
	    mt7927_rr(sc, MT7927_WFDMA_PREFETCH_CTRL));
	mt7927_wr(sc, MT7927_WFDMA_PREFETCH_CFG0, 0x660077);
	mt7927_wr(sc, MT7927_WFDMA_PREFETCH_CFG1, 0x1100);
	mt7927_wr(sc, MT7927_WFDMA_PREFETCH_CFG2, 0x30004f);
	mt7927_wr(sc, MT7927_WFDMA_PREFETCH_CFG3, 0x542200);
	mt7927_wr(sc, MT7927_WFDMA0_RX_RING4_EXT_CTRL, MT7927_PREFETCH(0x0000, 0x8));
	mt7927_wr(sc, MT7927_WFDMA0_RX_RING6_EXT_CTRL, MT7927_PREFETCH(0x0080, 0x8));
	mt7927_wr(sc, MT7927_WFDMA0_RX_RING7_EXT_CTRL, MT7927_PREFETCH(0x0100, 0x4));
	mt7927_wr(sc, MT_WFDMA0_TX_RING16_EXT_CTRL, MT7927_PREFETCH(0x0140, 0x4));
	mt7927_wr(sc, MT_WFDMA0_TX_RING15_EXT_CTRL, MT7927_PREFETCH(0x0180, 0x10));
	mt7927_wr(sc, MT_WFDMA0_TX_RING0_EXT_CTRL, MT7927_PREFETCH(0x0280, 0x4));

	/* reset dma idx (TX only for MT7927 here; RX was reset in disable) */
	mt7927_wr(sc, MT_WFDMA0_RST_DTX_PTR, ~0U);
	/* configure delay interrupt */
	mt7927_wr(sc, MT_WFDMA0_PRI_DLY_INT_CFG0, 0);

	mt7927_set(sc, MT_WFDMA0_GLO_CFG,
	    MT_WFDMA0_GLO_CFG_TX_WB_DDONE | MT_WFDMA0_GLO_CFG_FIFO_LITTLE_ENDIAN |
	    MT_WFDMA0_GLO_CFG_CLK_GAT_DIS | MT_WFDMA0_GLO_CFG_OMIT_TX_INFO |
	    MT_WFDMA0_GLO_CFG_DMA_SIZE(3) | MT_WFDMA0_GLO_CFG_FIFO_DIS_CHECK |
	    MT_WFDMA0_GLO_CFG_RX_WB_DDONE |
	    MT_WFDMA0_GLO_CFG_CSR_DISP_BASE_PTR_CHAIN_EN |
	    MT_WFDMA0_GLO_CFG_OMIT_RX_INFO_PFET2);
	mt7927_set(sc, MT_WFDMA0_GLO_CFG,
	    MT_WFDMA0_GLO_CFG_TX_DMA_EN | MT_WFDMA0_GLO_CFG_RX_DMA_EN);

	/* mt7927_wfdma_setup() */
	mt7927_set(sc, MT_WFDMA0_GLO_CFG, MT7927_GLO_CFG_ADDR_EXT_EN |
	    MT7927_GLO_CFG_FW_DWLD_BYPASS_DMASHDL);
	mt7927_clear(sc, MT_WFDMA0_GLO_CFG, MT7927_GLO_CFG_CSR_LBK_RX_Q_SEL_EN);
	mt7927_rmw(sc, MT7927_WFDMA0_GLO_CFG_EXT1, 1U << 28, 1U << 28);
	mt7927_set(sc, MT_WFDMA0_INT_RX_PRI, 0x0f00);
	mt7927_set(sc, MT_WFDMA0_INT_TX_PRI, 0x7f00);

	mt7927_set(sc, MT_WFDMA_DUMMY_CR, MT_WFDMA_NEED_REINIT);

	/* enable interrupts for TX/RX rings (mt76_connac_irq_enable) */
	b->irq_mask = MT7927_INT_TX_DONE_ALL | MT7927_INT_RX_DONE_ALL |
	    MT_INT_MCU_CMD;
	b->dma_on = true;
	mt7927_wr(sc, MT_WFDMA0_HOST_INT_ENA, b->irq_mask);
	mt7927_set(sc, MT_MCU2HOST_SW_INT_ENA, MT_MCU_CMD_WAKE_RX_PCIE);

	MWX_DEV_LOG(sc, "MT7927 DMA on GLO_CFG=0x%08x EXT1=0x%08x INT_ENA=0x%08x\n",
	    mt7927_rr(sc, MT_WFDMA0_GLO_CFG),
	    mt7927_rr(sc, MT7927_WFDMA0_GLO_CFG_EXT1),
	    mt7927_rr(sc, MT_WFDMA0_HOST_INT_ENA));
}

static int
mt7927_dma_init(struct mt7927_bringup *b)
{
	struct mwx_softc *sc = b->sc;
	int rv, i;

	mt7927_dma_disable(b, true);

	b->rings_alloc = true;
	if ((rv = mt7927_ring_alloc(b, &b->tx[MT7927_TX_BAND0], "tx0", false,
	    MT7927_TXQ_BAND0, 16, 2048)) != 0 ||
	    (rv = mt7927_ring_alloc(b, &b->tx[MT7927_TX_MCU], "tx15-mcu", false,
	    MT7927_TXQ_MCU_WM, 32, 2048)) != 0 ||
	    (rv = mt7927_ring_alloc(b, &b->tx[MT7927_TX_FWDL], "tx16-fwdl", false,
	    MT7927_TXQ_FWDL, 32, MT7927_FW_CHUNK)) != 0 ||
	    (rv = mt7927_ring_alloc(b, &b->rx[MT7927_RX_MCU], "rx6-mcu", true,
	    MT7927_RXQ_MCU_WM, 64, MT_RX_BUF_SIZE)) != 0 ||
	    (rv = mt7927_ring_alloc(b, &b->rx[MT7927_RX_BAND0], "rx4-data", true,
	    MT7927_RXQ_BAND0, 32, MT_RX_BUF_SIZE)) != 0 ||
	    (rv = mt7927_ring_alloc(b, &b->rx[MT7927_RX_DATA2], "rx7-data2", true,
	    MT7927_RXQ_DATA2, 32, MT_RX_BUF_SIZE)) != 0) {
		MWX_DEV_LOG(sc, "MT7927 ring allocation failed (%d)\n", rv);
		return rv;
	}

	mt7927_ring_reset(b, &b->tx[MT7927_TX_BAND0]);
	mt7927_wr(sc, MT_WFDMA0_TX_RING0_EXT_CTRL, 0x4);
	mt7927_ring_reset(b, &b->tx[MT7927_TX_MCU]);
	mt7927_ring_reset(b, &b->tx[MT7927_TX_FWDL]);
	for (i = 0; i < MT7927_NRX; i++) {
		mt7927_ring_reset(b, &b->rx[i]);
		mt7927_rx_fill(b, &b->rx[i]);
	}
	for (i = 0; i < MT7927_NTX; i++)
		MWX_DEV_LOG(sc, "MT7927 ring %s reg=0x%05x desc=0x%08x n=%u\n",
		    b->tx[i].name, b->tx[i].regbase, b->tx[i].desc_mem.pa,
		    b->tx[i].count);
	for (i = 0; i < MT7927_NRX; i++)
		MWX_DEV_LOG(sc, "MT7927 ring %s reg=0x%05x desc=0x%08x n=%u cpu=%u\n",
		    b->rx[i].name, b->rx[i].regbase, b->rx[i].desc_mem.pa,
		    b->rx[i].count, mt7927_rr(sc, b->rx[i].regbase + MT_DMA_CPU_IDX));

	mt7927_dma_enable(b);
	return 0;
}

/* ---- Firmware download (mt76_connac2_load_patch/ram, mt792x_load_firmware) ---- */

static uint32_t
mt7927_get_data_mode(uint32_t info)
{
	uint32_t mode = DL_MODE_NEED_RSP;

	if (info == PATCH_SEC_NOT_SUPPORT)
		return mode;
	switch ((info & PATCH_SEC_ENC_TYPE_MASK) >> PATCH_SEC_ENC_TYPE_SHIFT) {
	case 0:	/* plain */
		break;
	case 1:	/* AES */
		mode |= DL_MODE_ENCRYPT;
		mode |= ((info & PATCH_SEC_ENC_AES_KEY_MASK) <<
		    DL_MODE_KEY_IDX_SHIFT) & DL_MODE_KEY_IDX_MASK;
		mode |= DL_MODE_RESET_SEC_IV;
		break;
	case 2:	/* scramble */
		mode |= DL_MODE_ENCRYPT;
		mode |= DL_CONFIG_ENCRY_MODE_SEL;
		mode |= DL_MODE_RESET_SEC_IV;
		break;
	}
	return mode;
}

static uint32_t
mt7927_gen_dl_mode(uint8_t feature_set)
{
	uint32_t ret = DL_MODE_NEED_RSP;

	if (feature_set & FW_FEATURE_SET_ENCRYPT)
		ret |= DL_MODE_ENCRYPT | DL_MODE_RESET_SEC_IV;
	if (feature_set & FW_FEATURE_ENCRY_MODE)
		ret |= DL_CONFIG_ENCRY_MODE_SEL;
	ret |= feature_set & FW_FEATURE_SET_KEY_IDX_MASK;
	return ret;
}

static int
mt7927_init_download(struct mt7927_bringup *b, uint32_t addr, uint32_t len,
    uint32_t mode)
{
	struct {
		uint32_t addr, len, mode;
	} __packed req = { htole32(addr), htole32(len), htole32(mode) };
	uint32_t cmd;

	if (addr == 0x200000 || addr == 0x900000 || addr == 0xe0002800)
		cmd = MCU_CMD_PATCH_START_REQ;
	else
		cmd = MCU_CMD_TARGET_ADDRESS_LEN_REQ;
	return mt7927_mcu_send(b, cmd, &req, sizeof(req), true);
}

static int
mt7927_send_firmware(struct mt7927_bringup *b, const uint8_t *data, uint32_t len)
{
	uint32_t cur;
	int rv;

	while (len > 0) {
		cur = len > MT7927_FW_CHUNK ? MT7927_FW_CHUNK : len;
		if ((rv = mt7927_mcu_send(b, MCU_CMD_FW_SCATTER, data, cur,
		    false)) != 0)
			return rv;
		data += cur;
		len -= cur;
	}
	return 0;
}

static int
mt7927_patch_sem(struct mt7927_bringup *b, bool get, uint8_t *status)
{
	uint32_t req = htole32(get ? MT7927_PATCH_SEM_GET : MT7927_PATCH_SEM_RELEASE);
	int rv;

	rv = mt7927_mcu_send(b, MCU_CMD_PATCH_SEM_CONTROL, &req, sizeof(req), true);
	*status = b->resp_status;
	return rv;
}

/* mt76_connac2_patch_check() */
static int
mt7927_patch_check(const uint8_t *fw, size_t size)
{
	const struct mwx_patch_hdr *hdr = (const struct mwx_patch_hdr *)fw;
	const struct mwx_patch_sec *sec;
	uint32_t i, n;

	if (fw == NULL || size < sizeof(*hdr))
		return EINVAL;
	n = be32toh(hdr->desc.n_region);
	if (n > (size - sizeof(*hdr)) / sizeof(*sec))
		return EINVAL;
	sec = (const struct mwx_patch_sec *)(fw + sizeof(*hdr));
	for (i = 0; i < n; i++) {
		uint32_t offs = be32toh(sec[i].offs);
		uint32_t len = be32toh(sec[i].info.len);

		if (offs > size || len > size - offs)
			return EINVAL;
	}
	return 0;
}

static int
mt7927_load_patch(struct mt7927_bringup *b, const uint8_t *fw, size_t size)
{
	struct mwx_softc *sc = b->sc;
	const struct mwx_patch_hdr *hdr;
	uint8_t sem;
	uint32_t i, n;
	int rv, rv2;

	if ((rv = mt7927_patch_sem(b, true, &sem)) != 0)
		return rv;
	MWX_DEV_LOG(sc, "MT7927 patch semaphore get -> %u\n", sem);
	if (sem == MT7927_PATCH_IS_DL) {
		MWX_DEV_LOG(sc, "MT7927 patch already downloaded\n");
		return 0;
	}
	if (sem != MT7927_PATCH_NOT_DL_SEM_SUCCESS)
		return EAGAIN;

	if (mt7927_patch_check(fw, size) != 0) {
		MWX_DEV_LOG(sc, "MT7927 invalid patch file\n");
		rv = EINVAL;
		goto out;
	}
	hdr = (const struct mwx_patch_hdr *)fw;
	n = be32toh(hdr->desc.n_region);
	MWX_DEV_LOG(sc, "MT7927 patch HW/SW 0x%x build %.16s, %u regions\n",
	    be32toh(hdr->hw_sw_ver), hdr->build_date, n);
	{
		char build[17];

		memcpy(build, hdr->build_date, 16);
		build[16] = 0;
		mt7927_publish_str(b->pci, "MT7927FWPatchBuild", build);
	}

	for (i = 0; i < n; i++) {
		const struct mwx_patch_sec *sec = (const struct mwx_patch_sec *)
		    (fw + sizeof(*hdr) + i * sizeof(*sec));
		uint32_t addr, len, mode;

		if ((be32toh(sec->type) & PATCH_SEC_TYPE_MASK) !=
		    PATCH_SEC_TYPE_INFO) {
			rv = EINVAL;
			goto out;
		}
		addr = be32toh(sec->info.addr);
		len = be32toh(sec->info.len);
		mode = mt7927_get_data_mode(be32toh(sec->info.sec_key_idx));
		MWX_DEV_LOG(sc, "MT7927 patch region %u addr=0x%08x len=%u "
		    "mode=0x%08x\n", i, addr, len, mode);
		if ((rv = mt7927_init_download(b, addr, len, mode)) != 0) {
			MWX_DEV_LOG(sc, "MT7927 patch download request failed (%d)\n",
			    rv);
			goto out;
		}
		if ((rv = mt7927_send_firmware(b, fw + be32toh(sec->offs),
		    len)) != 0) {
			MWX_DEV_LOG(sc, "MT7927 patch send failed (%d)\n", rv);
			goto out;
		}
	}

	{
		uint8_t req[4] = { 0 };		/* check_crc = 0 */

		rv = mt7927_mcu_send(b, MCU_CMD_PATCH_FINISH_REQ, req, sizeof(req),
		    true);
		if (rv == 0 && b->resp_status != 0)
			rv = EIO;
		MWX_DEV_LOG(sc, "MT7927 patch finish -> rv=%d status=%u\n", rv,
		    b->resp_status);
	}
out:
	rv2 = mt7927_patch_sem(b, false, &sem);
	MWX_DEV_LOG(sc, "MT7927 patch semaphore release -> %u\n", sem);
	if (rv == 0 && (rv2 != 0 || sem != MT7927_PATCH_REL_SEM_SUCCESS))
		rv = EAGAIN;
	return rv;
}

/* mt76_connac2_fw_check() */
static int
mt7927_ram_check(const uint8_t *fw, size_t size)
{
	const struct mwx_fw_trailer *hdr;
	const struct mwx_fw_region *region;
	size_t avail, total = 0;
	int i;

	if (fw == NULL || size < sizeof(*hdr))
		return EINVAL;
	hdr = (const struct mwx_fw_trailer *)(fw + size - sizeof(*hdr));
	avail = size - sizeof(*hdr);
	if (hdr->n_region > avail / sizeof(*region))
		return EINVAL;
	avail -= hdr->n_region * sizeof(*region);
	region = (const struct mwx_fw_region *)(fw + avail);
	for (i = 0; i < hdr->n_region; i++) {
		uint32_t len = le32toh(region[i].len);

		if (len > avail - total)
			return EINVAL;
		total += len;
	}
	return 0;
}

static int
mt7927_load_ram(struct mt7927_bringup *b, const uint8_t *fw, size_t size)
{
	struct mwx_softc *sc = b->sc;
	const struct mwx_fw_trailer *hdr;
	uint32_t override = 0, option = 0, offset = 0;
	char ver[11], build[16];
	int i, rv;

	if (mt7927_ram_check(fw, size) != 0) {
		MWX_DEV_LOG(sc, "MT7927 invalid RAM firmware file\n");
		return EINVAL;
	}
	hdr = (const struct mwx_fw_trailer *)(fw + size - sizeof(*hdr));
	memcpy(ver, hdr->fw_ver, 10);
	ver[10] = 0;
	memcpy(build, hdr->build_date, 15);
	build[15] = 0;
	MWX_DEV_LOG(sc, "MT7927 WM firmware version %s build %s, %u regions\n",
	    ver, build, hdr->n_region);
	mt7927_publish_str(b->pci, "MT7927FWVersion", ver);
	mt7927_publish_str(b->pci, "MT7927FWBuild", build);

	for (i = 0; i < hdr->n_region; i++) {
		const struct mwx_fw_region *region = (const struct mwx_fw_region *)
		    ((const uint8_t *)hdr - (hdr->n_region - i) * sizeof(*region));
		uint32_t len = le32toh(region->len), addr = le32toh(region->addr);
		uint32_t mode = mt7927_gen_dl_mode(region->feature_set);

		MWX_DEV_LOG(sc, "MT7927 WM region %d addr=0x%08x len=%u mode=0x%08x "
		    "feature=0x%02x\n", i, addr, len, mode, region->feature_set);
		if (region->feature_set & FW_FEATURE_NON_DL)
			goto next;
		if (region->feature_set & FW_FEATURE_OVERRIDE_ADDR)
			override = addr;
		if ((rv = mt7927_init_download(b, addr, len, mode)) != 0) {
			MWX_DEV_LOG(sc, "MT7927 WM download request failed (%d)\n", rv);
			return rv;
		}
		if ((rv = mt7927_send_firmware(b, fw + offset, len)) != 0) {
			MWX_DEV_LOG(sc, "MT7927 WM send failed (%d)\n", rv);
			return rv;
		}
next:
		offset += len;
	}

	if (override)
		option |= FW_START_OVERRIDE;
	{
		struct {
			uint32_t option, addr;
		} __packed req = { htole32(option), htole32(override) };

		rv = mt7927_mcu_send(b, MCU_CMD_FW_START_REQ, &req, sizeof(req),
		    true);
	}
	MWX_DEV_LOG(sc, "MT7927 WM start override=0x%08x option=0x%x -> %d\n",
	    override, option, rv);
	return rv;
}

/* mt7925e_mcu_init() up to mt792x_load_firmware() completion. */
static int
mt7927_mcu_init(struct mt7927_bringup *b, const uint8_t *patch, size_t patch_len,
    const uint8_t *ram, size_t ram_len)
{
	struct mwx_softc *sc = b->sc;
	uint32_t val;
	int rv;

	if ((rv = mt7927_fw_own(sc)) != 0 || (rv = mt7927_drv_own(sc)) != 0)
		return rv;
	mt7927_rmw(sc, MT_PCIE_MAC_PM, MT_PCIE_MAC_PM_L0S_DIS,
	    MT_PCIE_MAC_PM_L0S_DIS);

	b->mcu_touched = true;
	{
		uint8_t req[4] = { 1, 0, 0, 0 };	/* power_mode = 1 */

		if ((rv = mt7927_mcu_send(b, MCU_CMD_NIC_POWER_CTRL, req,
		    sizeof(req), false)) != 0)
			return rv;
	}
	if (!mt7927_poll(sc, MT_CONN_ON_MISC, MT7927_TOP_MISC_FW_STATE,
	    MT7927_TOP_MISC2_FW_PWR_ON, 1000, true, &val))
		MWX_DEV_LOG(sc, "MT7927 MCU is not ready for firmware download "
		    "(state 0x%x)\n", val);

	if ((rv = mt7927_load_patch(b, patch, patch_len)) != 0)
		return rv;
	if (mt7927_aborted(b))
		return ECANCELED;
	if ((rv = mt7927_load_ram(b, ram, ram_len)) != 0)
		return rv;

	if (!mt7927_poll(sc, MT_CONN_ON_MISC, MT_TOP_MISC2_FW_N9_RDY,
	    MT_TOP_MISC2_FW_N9_RDY, 1500, true, &b->fw_state)) {
		MWX_DEV_LOG(sc, "MT7927 timeout for initializing firmware "
		    "(CONN_ON_MISC=0x%08x)\n", mt7927_rr(sc, MT_CONN_ON_MISC));
		mt7927_publish(b->pci, "MT7927FWReady", 0);
		return EIO;
	}
	mt7927_publish(b->pci, "MT7927FWReady", 1);
	MWX_DEV_LOG(sc, "MT7927 firmware running (FW_N9_RDY)\n");
	return 0;
}

static inline uint16_t
mt7927_le16(const uint8_t *p)
{
	return (uint16_t)(p[0] | (p[1] << 8));
}

/* mt7925_mcu_get_nic_capability(): the first real MCU query. */
static int
mt7927_nic_capability(struct mt7927_bringup *b)
{
	struct mwx_softc *sc = b->sc;
	struct {
		uint8_t rsv[4];
		uint16_t tag, len;
	} __packed req = { { 0 }, htole16(MT7927_UNI_CHIP_CONFIG_NIC_CAPA),
	    htole16(4) };
	const uint8_t *p;
	uint32_t left, i, n;
	int rv;

	if ((rv = mt7927_mcu_send(b, MCU_UNI_CMD_CHIP_CONFIG, &req, sizeof(req),
	    true)) != 0)
		return rv;
	if (b->resp_len < 4) {
		MWX_DEV_LOG(sc, "MT7927 NIC capability reply too short (%u)\n",
		    b->resp_len);
		return EINVAL;
	}
	n = mt7927_le16(b->resp);
	b->nic_elements = n;
	p = b->resp + 4;
	left = b->resp_len - 4;
	MWX_DEV_LOG(sc, "MT7927 NIC capability: %u elements, %u bytes\n", n,
	    b->resp_len);
	for (i = 0; i < n && left >= 4; i++) {
		uint16_t tag = mt7927_le16(p);
		uint16_t len = mt7927_le16(p + 2);
		const uint8_t *data = p + 4;
		uint16_t dlen;

		if (len < 4 || len > left)
			break;
		dlen = len - 4;
		switch (tag) {
		case MT7927_NIC_CAP_MAC_ADDR:
			if (dlen >= 6) {
				memcpy(b->mac, data, 6);
				b->mac_valid = true;
			}
			break;
		case MT7927_NIC_CAP_6G:
			if (dlen)
				mt7927_publish(b->pci, "MT7927NicHas6G", data[0]);
			break;
		case MT7927_NIC_CAP_HW_VER:
		case MT7927_NIC_CAP_SW_VER: {
			char hex[3 * 16 + 1];
			uint16_t k, m = dlen < 16 ? dlen : 16;

			for (k = 0; k < m; k++)
				snprintf(hex + 3 * k, 4, "%02x ", data[k]);
			hex[3 * m] = '\0';
			MWX_DEV_LOG(sc, "MT7927   %s: %s\n",
			    tag == MT7927_NIC_CAP_HW_VER ? "HW_VER" : "SW_VER", hex);
			if (tag == MT7927_NIC_CAP_HW_VER && dlen >= 4)
				mt7927_publish(b->pci, "MT7927NicHwVer",
				    (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
				    ((uint32_t)data[2] << 16) |
				    ((uint32_t)data[3] << 24));
			break;
		}
		case MT7927_NIC_CAP_CHIP_CAP:
			if (dlen >= 8) {
				uint64_t v = 0;
				int k;

				for (k = 7; k >= 0; k--)
					v = (v << 8) | data[k];
				b->chip_cap = v;
				b->chip_cap_valid = true;
				MWX_DEV_LOG(sc, "MT7927   CHIP_CAP: 0x%016llx\n",
				    (unsigned long long)v);
				mt7927_publish(b->pci, "MT7927NicChipCap",
				    (uint32_t)v);
			}
			break;
		default:
			break;
		}
		MWX_DEV_LOG(sc, "MT7927   cap tag=0x%02x len=%u%s\n", tag, dlen,
		    tag == MT7927_NIC_CAP_MAC_ADDR ? " (MAC)" : "");
		p += len;
		left -= len;
	}
	mt7927_publish(b->pci, "MT7927NicCapElements", n);
	if (b->mac_valid) {
		char mac[18];

		snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
		    b->mac[0], b->mac[1], b->mac[2], b->mac[3], b->mac[4],
		    b->mac[5]);
		MWX_DEV_LOG(sc, "MT7927 MAC address from firmware: %s\n", mac);
		mt7927_publish_str(b->pci, "MT7927MACAddress", mac);
	}
	return 0;
}

/* ---- Phase 3: connac3 init (__mt7925_init_hardware and friends) ---- */

static void
mt7927_le32enc(uint8_t *p, uint32_t v)
{
	p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24;
}

static uint32_t
mt7927_le32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
	    ((uint32_t)p[3] << 24);
}

/* Record a phase 3 step result. fatal steps fail the stage, others warn. */
static int
mt7927_p3_step(struct mt7927_bringup *b, const char *what, int rv, bool fatal)
{
	if (rv == 0) {
		MWX_DEV_LOG(b->sc, "MT7927 p3 %-22s ok\n", what);
		return 0;
	}
	MWX_DEV_LOG(b->sc, "MT7927 p3 %-22s FAILED (%d)%s\n", what, rv,
	    fatal ? "" : " - warning only, as in Linux");
	if (fatal)
		b->p3_fatal++;
	else
		b->p3_warn++;
	return rv;
}

/*
 * mt7925_mcu_read_eeprom(): UNI EFUSE_CTRL query, tag ACCESS. Returns the
 * 16-byte block containing offset in blk.
 */
static int
mt7927_efuse_read(struct mt7927_bringup *b, uint32_t offset, uint8_t *blk)
{
	struct {
		uint8_t		rsv[4];
		uint16_t	tag, len;
		uint32_t	addr, valid;
		uint8_t		data[MT7927_EEPROM_BLOCK];
	} __packed req;
	/* event: rsv[4] tag len ver addr valid size magic type rsv1[4x4] data[32] */
	const uint32_t data_off = 4 + 4 + 6 * 4 + 16;
	int rv;

	memset(&req, 0, sizeof(req));
	req.tag = htole16(MT7927_UNI_EFUSE_ACCESS);
	req.len = htole16(sizeof(req) - 4);
	req.addr = htole32(offset & ~(uint32_t)(MT7927_EEPROM_BLOCK - 1));
	if ((rv = mt7927_mcu_send(b, MT7927_WM_UNI_QUERY(MCU_UNI_CMD_EFUSE_CTRL),
	    &req, sizeof(req), true)) != 0)
		return rv;
	if (b->resp_len < data_off + 32) {
		MWX_DEV_LOG(b->sc, "MT7927 EFUSE read reply too short (%u)\n",
		    b->resp_len);
		return EINVAL;
	}
	memcpy(blk, b->resp + data_off, MT7927_EEPROM_BLOCK);
	return 0;
}

/*
 * mt7925_load_clc() front half: HW_TYPE from eFuse, then look for the CLC
 * region (FW_FEATURE_NON_DL, type CLC) in the RAM image. Linux keeps the
 * records for later SET_POWER_LIMIT calls from the regulatory code; here we
 * only report what is there.
 */
static int
mt7927_load_clc(struct mt7927_bringup *b, const uint8_t *fw, size_t size)
{
	const struct mwx_fw_trailer *hdr;
	const struct mwx_fw_region *region;
	uint8_t blk[MT7927_EEPROM_BLOCK];
	size_t offset = 0;
	int i, rv, records = 0;

	if ((rv = mt7927_efuse_read(b, MT7927_EE_HW_TYPE, blk)) != 0)
		return rv;
	b->hw_type = blk[MT7927_EE_HW_TYPE % MT7927_EEPROM_BLOCK];
	b->hw_type_valid = true;
	MWX_DEV_LOG(b->sc, "MT7927 eFuse HW_TYPE 0x%02x (encap %u)\n", b->hw_type,
	    b->hw_type & MT7927_EE_HW_TYPE_ENCAP);
	mt7927_publish(b->pci, "MT7927EfuseHwType", b->hw_type);

	if (fw == NULL || size < sizeof(*hdr))
		return 0;
	hdr = (const struct mwx_fw_trailer *)(fw + size - sizeof(*hdr));
	if (size < sizeof(*hdr) + hdr->n_region * sizeof(*region))
		return 0;
	for (i = 0; i < hdr->n_region; i++) {
		size_t len;

		region = (const struct mwx_fw_region *)((const uint8_t *)hdr -
		    (hdr->n_region - i) * sizeof(*region));
		len = le32toh(region->len);
		if ((region->feature_set & MT7927_FW_FEATURE_NON_DL) &&
		    region->reserved1[0] == MT7927_FW_TYPE_CLC) {	/* type */
			size_t o = 0;

			if (offset + len > size)
				break;
			while (o + 16 <= len) {
				uint32_t clen = mt7927_le32(fw + offset + o);

				if (clen < 16 || clen > len - o)
					break;
				MWX_DEV_LOG(b->sc, "MT7927 CLC record idx %u ver %u "
				    "len %u\n", fw[offset + o + 4],
				    fw[offset + o + 5], clen);
				records++;
				o += clen;
			}
			break;
		}
		offset += len;
	}
	MWX_DEV_LOG(b->sc, "MT7927 CLC: %d record(s) in the RAM image%s\n",
	    records, records ? " (not sent: no regulatory database yet)" :
	    " (Linux then skips CLC and the regdb query)");
	mt7927_publish(b->pci, "MT7927CLCRecords", records);
	return 0;
}

/* mt7925_mcu_fw_log_2_host(): UNI WSYS_CONFIG, tag FW_LOG_CTRL. */
static int
mt7927_fw_log_2_host(struct mt7927_bringup *b, uint8_t ctrl)
{
	struct {
		uint8_t		rsv[4];
		uint16_t	tag, len;
		uint8_t		ctrl, interval, rsv2[2];
	} __packed req;

	memset(&req, 0, sizeof(req));
	req.tag = htole16(MT7927_UNI_WSYS_FW_LOG_CTRL);
	req.len = htole16(sizeof(req) - 4);
	req.ctrl = ctrl;
	return mt7927_mcu_send(b, MCU_UNI_CMD_WSYS_CONFIG, &req, sizeof(req), true);
}

/* mt7925_mcu_set_eeprom(): eFuse mode, whole format, no buffer. */
static int
mt7927_set_eeprom(struct mt7927_bringup *b)
{
	struct {
		uint8_t		rsv[4];
		uint16_t	tag, len;
		uint8_t		buffer_mode, format;
		uint16_t	buf_len;
	} __packed req;

	memset(&req, 0, sizeof(req));
	req.tag = htole16(MT7927_UNI_EFUSE_BUFFER_MODE);
	req.len = htole16(sizeof(req) - 4);
	req.buffer_mode = MT7927_EE_MODE_EFUSE;
	req.format = MT7927_EE_FORMAT_WHOLE;
	return mt7927_mcu_send(b, MCU_UNI_CMD_EFUSE_CTRL, &req, sizeof(req), true);
}

/* mt7925_mcu_chip_config(): text command, sent without waiting. */
static int
mt7927_chip_config(struct mt7927_bringup *b, const char *cmd)
{
	struct {
		uint8_t		rsv[4];
		uint16_t	tag, len;
		uint16_t	id;
		uint8_t		type, resp_type;
		uint16_t	data_size, resv;
		uint8_t		data[320];
	} __packed req;
	size_t n = strlen(cmd) + 1;

	if (n > sizeof(req.data))
		return EINVAL;
	memset(&req, 0, sizeof(req));
	req.tag = htole16(MT7927_UNI_CHIP_CONFIG_CHIP_CFG);
	req.len = htole16(sizeof(req) - 4);
	req.data_size = htole16(n);
	memcpy(req.data, cmd, n);
	MWX_DEV_LOG(b->sc, "MT7927 chip config \"%s\"\n", cmd);
	return mt7927_mcu_send(b, MCU_UNI_CMD_CHIP_CONFIG, &req, sizeof(req), false);
}

/* mt7925_mac_wtbl_update() */
static bool
mt7927_wtbl_update(struct mwx_softc *sc, int idx, uint32_t mask)
{
	mt7927_rmw(sc, MT7927_WTBL_UPDATE, MT7927_WTBL_UPDATE_IDX_MASK,
	    ((uint32_t)idx & MT7927_WTBL_UPDATE_IDX_MASK) | mask);
	return mt7927_poll(sc, MT7927_WTBL_UPDATE, MT7927_WTBL_UPDATE_BUSY, 0, 5,
	    false, NULL);
}

/*
 * mt7925_mac_init(): MDP max RX length and de-aggregation, clear the WTBL
 * admission counters, mt792x_mac_init_band() for both bands, basic rate
 * table. Pure register writes; Linux ignores the WTBL poll result.
 */
static void
mt7927_mac_init(struct mt7927_bringup *b)
{
	/* mt76_rates[] hw_value: (MT_PHY_TYPE_CCK 0 | OFDM 1) << 8 | idx */
	static const uint16_t rates[] = {
		0x000, 0x001, 0x002, 0x003,
		0x10b, 0x10f, 0x10a, 0x10e, 0x109, 0x10d, 0x108, 0x10c,
	};
	struct mwx_softc *sc = b->sc;
	uint32_t i, band;

	mt7927_rmw(sc, MT7927_MDP_DCR1, MT7927_MAX_RX_LEN_MASK, MT7927_MAX_RX_LEN);
	mt7927_set(sc, MT7927_MDP_DCR0, MT7927_MDP_DCR0_DAMSDU_EN);

	b->wtbl_busy = 0;
	for (i = 0; i < MT7927_WTBL_SIZE; i++)
		if (!mt7927_wtbl_update(sc, i, MT7927_WTBL_UPDATE_ADM_CLR))
			b->wtbl_busy++;

	for (band = 0; band < 2; band++) {
		mt7927_rmw(sc, MT7927_TMAC_CTCR0(band), MT7927_CTCR0_REFTIME_MASK,
		    0x3f);
		mt7927_set(sc, MT7927_TMAC_CTCR0(band),
		    MT7927_CTCR0_VHT_SMPDU_EN | MT7927_CTCR0_DDLMT_EN);
		mt7927_set(sc, MT7927_RMAC_MIB_TIME0(band),
		    MT7927_RMAC_MIB_RXTIME_EN);
		mt7927_set(sc, MT7927_RMAC_MIB_AIRTIME0(band),
		    MT7927_RMAC_MIB_RXTIME_EN);
		mt7927_set(sc, MT7927_MIB_SCR1(band), MT7927_MIB_TXDUR_EN);
		mt7927_set(sc, MT7927_MIB_SCR1(band), MT7927_MIB_RXDUR_EN);
		mt7927_rmw(sc, MT7927_DMA_DCR0(band), MT7927_MAX_RX_LEN_MASK,
		    MT7927_MAX_RX_LEN);
		mt7927_clear(sc, MT7927_DMA_DCR0(band), MT7927_DMA_DCR0_RXD_G5_EN);
		mt7927_rmw(sc, MT7927_WTBLOFF_RSCR(band), MT7927_RSCR_RCPI_MASK,
		    MT7927_RSCR_RCPI_SET);
	}

	for (i = 0; i < nitems(rates); i++) {
		uint16_t rate = ((rates[i] >> 8) << 6) | (rates[i] & 0x3f);

		mt7927_wr(sc, MT7927_WTBL_ITDR0, rate);
		mt7927_wr(sc, MT7927_WTBL_ITDR1, MT7927_WTBL_SPE_IDX_SEL);
		mt7927_wr(sc, MT7927_WTBL_ITCR, MT7927_WTBL_ITCR_WR |
		    MT7927_WTBL_ITCR_EXEC | (MT7927_BASIC_RATES_TBL + i));
	}

	MWX_DEV_LOG(sc, "MT7927 mac init: MDP_DCR0 0x%08x MDP_DCR1 0x%08x "
	    "DMA_DCR0 0x%08x/0x%08x TMAC_CTCR0 0x%08x/0x%08x, WTBL busy %u/%u\n",
	    mt7927_rr(sc, MT7927_MDP_DCR0), mt7927_rr(sc, MT7927_MDP_DCR1),
	    mt7927_rr(sc, MT7927_DMA_DCR0(0)), mt7927_rr(sc, MT7927_DMA_DCR0(1)),
	    mt7927_rr(sc, MT7927_TMAC_CTCR0(0)), mt7927_rr(sc, MT7927_TMAC_CTCR0(1)),
	    b->wtbl_busy, MT7927_WTBL_SIZE);
}

/* mt7925_mcu_set_dbdc(): UNI SET_DBDC_PARMS, tag MBMC_SETTING. */
static int
mt7927_set_dbdc(struct mt7927_bringup *b, bool enable)
{
	struct {
		uint8_t		pad[4];
		uint16_t	tag, len;
		uint8_t		mbmc_en, band, pad2[2];
	} __packed req;

	memset(&req, 0, sizeof(req));
	req.tag = htole16(MT7927_UNI_MBMC_SETTING);
	req.len = htole16(sizeof(req) - 4);
	req.mbmc_en = enable;
	return mt7927_mcu_send(b, MT7927_UNI_SET_DBDC_PARMS, &req, sizeof(req), true);
}

/*
 * mt7925_mcu_set_channel_domain() with the mt76 channel lists. There is no
 * cfg80211 here, so channel flags follow the world regulatory domain:
 * active scan only on 2.4 GHz 1-11, everything else passive, DFS marked,
 * 5 GHz 169-177 dropped (disabled).
 */
static int
mt7927_set_channel_domain(struct mt7927_bringup *b)
{
	static const uint8_t ch5[] = {
		36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124,
		128, 132, 136, 140, 144, 149, 153, 157, 161, 165,
	};
	uint32_t n2 = 0, n5 = 0, n6 = 0, len, i;
	uint8_t msg[16 + 8 * (14 + 25 + 59)];
	uint8_t *c = msg + 16;

#define	MT7927_ADD_CH(hw, fl) do {					\
	c[0] = (hw); c[1] = 0; c[2] = 0; c[3] = 0;			\
	mt7927_le32enc(c + 4, (fl));					\
	c += 8;								\
} while (0)
	for (i = 1; i <= 14; i++, n2++)
		MT7927_ADD_CH(i, i <= 11 ? 0 : i <= 13 ? MT7927_CHAN_NO_IR :
		    MT7927_CHAN_NO_IR | MT7927_CHAN_NO_OFDM);
	for (i = 0; i < nitems(ch5); i++, n5++)
		MT7927_ADD_CH(ch5[i], MT7927_CHAN_NO_IR |
		    (ch5[i] >= 52 && ch5[i] <= 144 ? MT7927_CHAN_RADAR : 0));
	for (i = 1; i <= 233; i += 4, n6++)
		MT7927_ADD_CH(i, MT7927_CHAN_NO_IR);
#undef MT7927_ADD_CH

	memset(msg, 0, 16);
	msg[0] = b->alpha2[0];
	msg[1] = b->alpha2[1];
	msg[4] = 0;		/* bw_2g: BW_20_40M */
	msg[5] = 3;		/* bw_5g: BW_20_40_80_160M */
	msg[6] = 3;		/* bw_6g */
	len = 8 + (n2 + n5 + n6) * 8;
	msg[8] = 2;		/* tag */
	msg[9] = 0;
	msg[10] = len & 0xff;
	msg[11] = len >> 8;
	msg[12] = n2;
	msg[13] = n5;
	msg[14] = n6;
	MWX_DEV_LOG(b->sc, "MT7927 channel domain \"%c%c\": %u+%u+%u channels\n",
	    b->alpha2[0] ? b->alpha2[0] : '-', b->alpha2[1] ? b->alpha2[1] : '-',
	    n2, n5, n6);
	return mt7927_mcu_send(b, MT7927_UNI_SET_DOMAIN_INFO, msg,
	    (uint32_t)(c - msg), true);
}

/* mt7925_mcu_set_rts_thresh(): UNI BAND_CONFIG, tag RTS_THRESHOLD, band 0. */
static int
mt7927_set_rts_thresh(struct mt7927_bringup *b, uint32_t val)
{
	struct {
		uint8_t		band_idx, rsv[3];
		uint16_t	tag, len;
		uint32_t	len_thresh, pkt_thresh;
	} __packed req;

	memset(&req, 0, sizeof(req));
	req.tag = htole16(MT7927_UNI_BAND_CONFIG_RTS);
	req.len = htole16(sizeof(req) - 4);
	req.len_thresh = htole32(val);
	req.pkt_thresh = htole32(2);
	return mt7927_mcu_send(b, MT7927_UNI_BAND_CONFIG, &req, sizeof(req), true);
}

/* mt7925_mcu_get_temperature(): UNI THERMAL query, tag 0. */
static int
mt7927_get_temperature(struct mt7927_bringup *b)
{
	struct {
		uint8_t		rsv[4];
		uint16_t	tag, len;
		uint8_t		rsv2[4];
	} __packed req;
	int rv;

	memset(&req, 0, sizeof(req));
	req.len = htole16(sizeof(req) - 4);
	if ((rv = mt7927_mcu_send(b, MT7927_WM_UNI_QUERY(MT7927_UNI_THERMAL),
	    &req, sizeof(req), true)) != 0)
		return rv;
	if (b->resp_len < 4 + 4 + 8)
		return EINVAL;
	b->temperature = (int32_t)mt7927_le32(b->resp + 4 + 4 + 4);
	b->temp_valid = true;
	MWX_DEV_LOG(b->sc, "MT7927 temperature %d C\n", b->temperature);
	mt7927_publish(b->pci, "MT7927TemperatureC", (uint32_t)b->temperature);
	return 0;
}

/*
 * Phase 3, in Linux order:
 *   mt7925_run_firmware tail: load_clc (eFuse HW_TYPE), fw_log_2_host(1)
 *   __mt7925_init_hardware:   set_eeprom, mac_init, set_dbdc(true) (MT7927)
 *   mt7925_init_work:         thermal protect, KeepFullPwr (no deep sleep on MT7927)
 *   __mt7925_start:           channel domain, RTS threshold
 * plus two read-only checks: eFuse block 0 (chip ID, MAC) and temperature.
 * Fatal steps are the ones whose failure fails init in Linux.
 */
static int
mt7927_connac3_init(struct mt7927_bringup *b, const uint8_t *ram, size_t ram_len)
{
	struct mwx_softc *sc = b->sc;
	uint8_t blk[MT7927_EEPROM_BLOCK];
	uint32_t t0 = b->mcu_timeouts;
	int rv, i;

	b->p3_fatal = b->p3_warn = 0;

	mt7927_p3_step(b, "load_clc/eFuse HW_TYPE", mt7927_load_clc(b, ram, ram_len),
	    true);
	rv = mt7927_efuse_read(b, 0, blk);
	if (rv == 0) {
		char mac[18];

		b->ee_chip_id = (uint16_t)(blk[0] | (blk[1] << 8));
		memcpy(b->ee_mac, blk + 4, 6);
		b->ee_valid = true;
		snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
		    blk[4], blk[5], blk[6], blk[7], blk[8], blk[9]);
		MWX_DEV_LOG(sc, "MT7927 eFuse chip id 0x%04x version 0x%04x MAC %s%s\n",
		    b->ee_chip_id, blk[2] | (blk[3] << 8), mac,
		    b->mac_valid && memcmp(b->mac, blk + 4, 6) == 0 ?
		    " (matches firmware)" : "");
		mt7927_publish(b->pci, "MT7927EfuseChipID", b->ee_chip_id);
		mt7927_publish_str(b->pci, "MT7927EfuseMAC", mac);
	}
	mt7927_p3_step(b, "eFuse block 0 (check)", rv, false);
	mt7927_p3_step(b, "fw_log_2_host(1)", mt7927_fw_log_2_host(b, 1), true);
	mt7927_p3_step(b, "set_eeprom", mt7927_set_eeprom(b), true);
	mt7927_mac_init(b);
	mt7927_p3_step(b, "set_dbdc(true)", mt7927_set_dbdc(b, true), false);
	if (mt7927_aborted(b))
		return ECANCELED;
	mt7927_p3_step(b, "thermal protect 2G", mt7927_chip_config(b,
	    "ThermalProtGband 0 100 90 80 30 1 1 115 105 5"), true);
	mt7927_p3_step(b, "thermal protect 5G", mt7927_chip_config(b,
	    "ThermalProtAband 1 100 90 80 30 1 1 115 105 5"), true);
	mt7927_p3_step(b, "KeepFullPwr 1", mt7927_chip_config(b, "KeepFullPwr 1"),
	    false);
	mt7927_p3_step(b, "channel domain", mt7927_set_channel_domain(b), true);
	mt7927_p3_step(b, "RTS threshold", mt7927_set_rts_thresh(b,
	    MT7927_RTS_THRESH), true);
	mt7927_p3_step(b, "temperature (check)", mt7927_get_temperature(b), false);

	/* Let late events (firmware log lines, MBMC) arrive and be counted. */
	for (i = 0; i < 300 && !mt7927_aborted(b); i++) {
		mt7927_service(b, 0, NULL);
		mt7927_wait(b, 1);
	}
	mt7927_service(b, 0, NULL);

	MWX_DEV_LOG(sc, "MT7927 phase 3: %u fatal, %u warnings, %u MCU timeouts, "
	    "slowest reply %u ms, %u unsolicited events (%u firmware log, %u lines)\n",
	    b->p3_fatal, b->p3_warn, b->mcu_timeouts - t0, b->mcu_max_ms,
	    b->unsol_events, b->fw_log_events, b->fw_log_lines);
	mt7927_publish(b->pci, "MT7927P3Fatal", b->p3_fatal);
	mt7927_publish(b->pci, "MT7927P3Warnings", b->p3_warn);
	mt7927_publish(b->pci, "MT7927MCUTimeouts", b->mcu_timeouts);
	mt7927_publish(b->pci, "MT7927MCUSlowestMs", b->mcu_max_ms);
	mt7927_publish(b->pci, "MT7927FwLogEvents", b->fw_log_events);
	mt7927_publish(b->pci, "MT7927WtblBusy", b->wtbl_busy);
	if (b->p3_fatal != 0 || b->mcu_timeouts != t0)
		return EIO;
	return 0;
}

/* ---- Teardown ---- */

static void mt7927_irq_teardown(struct mt7927_bringup *);

static void
mt7927_teardown(struct mt7927_bringup *b)
{
	struct mwx_softc *sc = b->sc;
	uint32_t romcode = 0;
	int i;

	if (sc->sc_memh) {
		mt7927_raw_wr(sc, MT_WFDMA0_HOST_INT_ENA, 0);
		mt7927_raw_wr(sc, MT_PCIE_MAC_INT_ENABLE, 0);
	}
	mt7927_irq_teardown(b);
	if (b->dma_on) {
		mt7927_dma_disable(b, true);
		b->dma_on = false;
	}
	if (b->rings_alloc && sc->sc_memh) {
		/* Halt the MCU so the firmware cannot DMA into freed memory. */
		if (mt7927_wfsys_reset(sc, &romcode) != 0)
			MWX_DEV_LOG(sc, "MT7927 teardown: WFSYS reset did not "
			    "reach ROM idle\n");
	}
	if (b->rings_alloc) {
		if (b->pci != NULL)
			b->pci->setBusMasterEnable(false);
		for (i = 0; i < MT7927_NTX; i++)
			mt7927_ring_free(&b->tx[i]);
		for (i = 0; i < MT7927_NRX; i++)
			mt7927_ring_free(&b->rx[i]);
		b->rings_alloc = false;
	}
	MWX_DEV_LOG(sc, "MT7927 teardown done (interrupts seen %u, bits 0x%08x)\n",
	    b->intr_count, b->intr_seen);
}

/* ---- Kernel-only entry points ---- */

#ifndef MT7927_HOST_TEST
static int
mt7927_irq_setup(struct mt7927_bringup *b)
{
	struct mt7927_os *os = (struct mt7927_os *)b->os;
	struct pci_attach_args pa;
	pci_intr_handle_t ih = NULL;
	struct mwx_softc *sc = b->sc;

	/* mt7925_pci_probe: host interrupts off, PCIe MAC mask open. */
	mt7927_wr(sc, MT_WFDMA0_HOST_INT_ENA, 0);
	mt7927_wr(sc, MT_PCIE_MAC_INT_ENABLE, 0xff);

	memset(&pa, 0, sizeof(pa));
	pa.workloop = os->wl;
	pa.pa_tag = b->pci;
	if (pci_intr_map_msi(&pa, &ih) != 0 || ih == NULL)
		return ENXIO;
	b->ih_cookie = pci_intr_establish(0, ih, IPL_NET, mt7927_intr, b);
	if (b->ih_cookie == NULL) {
		ih->release();
		return ENXIO;
	}
	return 0;
}

static void
mt7927_irq_teardown(struct mt7927_bringup *b)
{
	if (b->ih_cookie != NULL) {
		pci_intr_disestablish(0, b->ih_cookie);
		b->ih_cookie = NULL;
	}
}

static void *
mt7927_zalloc(size_t size)
{
	void *p = IOMalloc(size);

	if (p != NULL)
		bzero(p, size);
	return p;
}

struct mt7927_bringup *
mt7927_bringup_create(IOPCIDevice *dev, IOWorkLoop *wl)
{
	struct mt7927_bringup *b;
	struct mt7927_os *os;
	IOMemoryMap *map;

	b = (struct mt7927_bringup *)mt7927_zalloc(sizeof(*b));
	os = (struct mt7927_os *)mt7927_zalloc(sizeof(*os));
	if (b == NULL || os == NULL)
		goto fail;
	b->sc = (struct mwx_softc *)mt7927_zalloc(sizeof(struct mwx_softc));
	if (b->sc == NULL)
		goto fail;
	os->lock = IOLockAlloc();
	if (os->lock == NULL)
		goto fail;
	map = dev->mapDeviceMemoryWithRegister(kIOPCIConfigBaseAddress0);
	if (map == NULL)
		goto fail;
	os->bar = map;
	os->wl = wl;
	b->os = os;
	b->pci = dev;
	strlcpy(b->sc->sc_dev.dv_xname, "mt7927", sizeof(b->sc->sc_dev.dv_xname));
	b->sc->sc_st = map;
	b->sc->sc_memh = (bus_space_handle_t)map->getVirtualAddress();
	b->sc->sc_mems = (bus_size_t)map->getLength();
	return b;
fail:
	if (os != NULL) {
		if (os->lock != NULL)
			IOLockFree(os->lock);
		IOFree(os, sizeof(*os));
	}
	if (b != NULL) {
		if (b->sc != NULL)
			IOFree(b->sc, sizeof(struct mwx_softc));
		IOFree(b, sizeof(*b));
	}
	return NULL;
}

void
mt7927_bringup_destroy(struct mt7927_bringup *b)
{
	struct mt7927_os *os;

	if (b == NULL)
		return;
	os = (struct mt7927_os *)b->os;
	mt7927_teardown(b);
	if (os != NULL) {
		OSSafeReleaseNULL(os->bar);
		if (os->lock != NULL)
			IOLockFree(os->lock);
		IOFree(os, sizeof(*os));
	}
	IOFree(b->sc, sizeof(struct mwx_softc));
	IOFree(b, sizeof(*b));
}
#endif /* MT7927_HOST_TEST */

/*
 * The bring-up job, run on its own thread. Stages: 1 phase 1 only;
 * 2 + rings, DMA and interrupt; 3 + firmware download; 4 (default) + NIC
 * capability query. Always tears down before returning. Returns the last
 * stage that passed.
 */
/* Country code for SET_DOMAIN_INFO (two letters), NULL or "" for unset. */
void
mt7927_bringup_set_country(struct mt7927_bringup *b, const char *cc)
{
	b->alpha2[0] = b->alpha2[1] = 0;
	if (cc != NULL && cc[0] >= 'A' && cc[0] <= 'Z' && cc[1] >= 'A' &&
	    cc[1] <= 'Z' && cc[2] == '\0') {
		b->alpha2[0] = cc[0];
		b->alpha2[1] = cc[1];
	}
}

int
mt7927_bringup_run(struct mt7927_bringup *b, int stage, const uint8_t *patch,
    size_t patch_len, const uint8_t *ram, size_t ram_len, volatile bool *abort)
{
	struct mwx_softc *sc = b->sc;
	int passed = 0, rv;

	b->abort = abort;
	MWX_DEV_LOG(sc, "MT7927 bring-up start, stage limit %d\n", stage);

	if ((rv = mt7927_phase1(b)) != 0)
		goto done;
	passed = 1;
	if (stage < 2 || mt7927_aborted(b))
		goto done;

	if ((rv = mt7927_irq_setup(b)) != 0) {
		MWX_DEV_LOG(sc, "MT7927 interrupt setup failed (%d)\n", rv);
		goto done;
	}
	if ((rv = mt7927_dma_init(b)) != 0)
		goto done;
	mt7927_service(b, 0, NULL);
	passed = 2;
	MWX_DEV_LOG(sc, "MT7927 phase 2a PASS: rings and DMA up\n");
	if (stage < 3 || mt7927_aborted(b))
		goto done;

	if (patch == NULL || ram == NULL) {
		MWX_DEV_LOG(sc, "MT7927 no firmware files, stopping before download\n");
		goto done;
	}
	if ((rv = mt7927_mcu_init(b, patch, patch_len, ram, ram_len)) != 0) {
		MWX_DEV_LOG(sc, "MT7927 firmware download failed (%d)\n", rv);
		goto done;
	}
	passed = 3;
	if (stage < 4 || mt7927_aborted(b))
		goto done;

	if ((rv = mt7927_nic_capability(b)) != 0) {
		MWX_DEV_LOG(sc, "MT7927 NIC capability query failed (%d)\n", rv);
		goto done;
	}
	passed = 4;
	MWX_DEV_LOG(sc, "MT7927 phase 2 PASS: firmware answers MCU queries\n");
	if (stage < 5 || mt7927_aborted(b))
		goto done;

	if ((rv = mt7927_connac3_init(b, ram, ram_len)) != 0) {
		MWX_DEV_LOG(sc, "MT7927 phase 3 (connac3 init) failed (%d)\n", rv);
		goto done;
	}
	passed = 5;
	MWX_DEV_LOG(sc, "MT7927 phase 3 PASS: connac3 init complete, no MCU "
	    "timeouts\n");
done:
	mt7927_publish(b->pci, "MT7927InterruptCount", b->intr_count);
	mt7927_publish(b->pci, "MT7927InterruptBits", b->intr_seen);
	mt7927_publish(b->pci, "MT7927StagePassed", passed);
	mt7927_teardown(b);
	return passed;
}

/*
 * To be honest this is ridiculous.
 */
uint32_t
mwx_reg_addr(struct mwx_softc *sc, uint32_t reg)
{
	static const struct {
		uint32_t phys;
		uint32_t mapped;
		uint32_t size;
	} fixed_map[] = {
	{ 0x820d0000, 0x30000, 0x10000 }, /* WF_LMAC_TOP (WF_WTBLON) */
	{ 0x820ed000, 0x24800, 0x00800 }, /* WF_LMAC_TOP BN0 (WF_MIB) */
	{ 0x820e4000, 0x21000, 0x00400 }, /* WF_LMAC_TOP BN0 (WF_TMAC) */
	{ 0x820e7000, 0x21e00, 0x00200 }, /* WF_LMAC_TOP BN0 (WF_DMA) */
	{ 0x820eb000, 0x24200, 0x00400 }, /* WF_LMAC_TOP BN0 (WF_LPON) */
	{ 0x820e2000, 0x20800, 0x00400 }, /* WF_LMAC_TOP BN0 (WF_AGG) */
	{ 0x820e3000, 0x20c00, 0x00400 }, /* WF_LMAC_TOP BN0 (WF_ARB) */
	{ 0x820e5000, 0x21400, 0x00800 }, /* WF_LMAC_TOP BN0 (WF_RMAC) */
	{ 0x00400000, 0x80000, 0x10000 }, /* WF_MCU_SYSRAM */
	{ 0x00410000, 0x90000, 0x10000 }, /* WF_MCU_SYSRAM (conf register) */
	{ 0x40000000, 0x70000, 0x10000 }, /* WF_UMAC_SYSRAM */
	{ 0x54000000, 0x02000, 0x01000 }, /* WFDMA PCIE0 MCU DMA0 */
	{ 0x55000000, 0x03000, 0x01000 }, /* WFDMA PCIE0 MCU DMA1 */
	{ 0x58000000, 0x06000, 0x01000 }, /* WFDMA PCIE1 MCU DMA0 (MEM_DMA) */
	{ 0x59000000, 0x07000, 0x01000 }, /* WFDMA PCIE1 MCU DMA1 */
	{ 0x7c000000, 0xf0000, 0x10000 }, /* CONN_INFRA */
	{ 0x7c020000, 0xd0000, 0x10000 }, /* CONN_INFRA, WFDMA */
	{ 0x7c060000, 0xe0000, 0x10000 }, /* CONN_INFRA, conn_host_csr_top */
	{ 0x80020000, 0xb0000, 0x10000 }, /* WF_TOP_MISC_OFF */
	{ 0x81020000, 0xc0000, 0x10000 }, /* WF_TOP_MISC_ON */
	{ 0x820c0000, 0x08000, 0x04000 }, /* WF_UMAC_TOP (PLE) */
	{ 0x820c8000, 0x0c000, 0x02000 }, /* WF_UMAC_TOP (PSE) */
	{ 0x820cc000, 0x0e000, 0x01000 }, /* WF_UMAC_TOP (PP) */
	{ 0x820cd000, 0x0f000, 0x01000 }, /* WF_MDP_TOP */
	{ 0x820ce000, 0x21c00, 0x00200 }, /* WF_LMAC_TOP (WF_SEC) */
	{ 0x820cf000, 0x22000, 0x01000 }, /* WF_LMAC_TOP (WF_PF) */
	{ 0x820e0000, 0x20000, 0x00400 }, /* WF_LMAC_TOP BN0 (WF_CFG) */
	{ 0x820e1000, 0x20400, 0x00200 }, /* WF_LMAC_TOP BN0 (WF_TRB) */
	{ 0x820e9000, 0x23400, 0x00200 }, /* WF_LMAC_TOP BN0 (WF_WTBLOFF) */
	{ 0x820ea000, 0x24000, 0x00200 }, /* WF_LMAC_TOP BN0 (WF_ETBF) */
	{ 0x820ec000, 0x24600, 0x00200 }, /* WF_LMAC_TOP BN0 (WF_INT) */
	{ 0x820f0000, 0xa0000, 0x00400 }, /* WF_LMAC_TOP BN1 (WF_CFG) */
	{ 0x820f1000, 0xa0600, 0x00200 }, /* WF_LMAC_TOP BN1 (WF_TRB) */
	{ 0x820f2000, 0xa0800, 0x00400 }, /* WF_LMAC_TOP BN1 (WF_AGG) */
	{ 0x820f3000, 0xa0c00, 0x00400 }, /* WF_LMAC_TOP BN1 (WF_ARB) */
	{ 0x820f4000, 0xa1000, 0x00400 }, /* WF_LMAC_TOP BN1 (WF_TMAC) */
	{ 0x820f5000, 0xa1400, 0x00800 }, /* WF_LMAC_TOP BN1 (WF_RMAC) */
	{ 0x820f7000, 0xa1e00, 0x00200 }, /* WF_LMAC_TOP BN1 (WF_DMA) */
	{ 0x820f9000, 0xa3400, 0x00200 }, /* WF_LMAC_TOP BN1 (WF_WTBLOFF) */
	{ 0x820fa000, 0xa4000, 0x00200 }, /* WF_LMAC_TOP BN1 (WF_ETBF) */
	{ 0x820fb000, 0xa4200, 0x00400 }, /* WF_LMAC_TOP BN1 (WF_LPON) */
	{ 0x820fc000, 0xa4600, 0x00200 }, /* WF_LMAC_TOP BN1 (WF_INT) */
	{ 0x820fd000, 0xa4800, 0x00800 }, /* WF_LMAC_TOP BN1 (WF_MIB) */
	};
	int i;

	if (reg < 0x100000)
		return reg;

	for (i = 0; i < nitems(fixed_map); i++) {
		uint32_t ofs;

		if (reg < fixed_map[i].phys)
			continue;

		ofs = reg - fixed_map[i].phys;
		if (ofs > fixed_map[i].size)
			continue;

		return fixed_map[i].mapped + ofs;
	}

	if ((reg >= 0x18000000 && reg < 0x18c00000) ||
	    (reg >= 0x70000000 && reg < 0x78000000) ||
	    (reg >= 0x7c000000 && reg < 0x7c400000))
		return mt7921_map_reg_l1(sc, reg);

	panic("%s: Access to currently unsupported address %08x\n",
	    DEVNAME(sc), reg);
}

int
mwx_init_hardware(struct mwx_softc *sc)
{
	int rv;

	MWX_DEV_LOG(sc, "hardware init start\n");
	/* reset dma */
	rv = mwx_dma_reset(sc, 1);
	if (rv != 0) {
		MWX_DEV_LOG(sc, "hardware init dma reset failed error=%d\n", rv);
		return rv;
	}
	MWX_DEV_LOG(sc, "hardware init dma reset ok\n");

	/*
	 * force firmware operation mode into normal state,
	 * which should be set before firmware download stage.
	 */
	mwx_write(sc, MT_SWDEF_MODE, MT_SWDEF_NORMAL_MODE);
	mwx_barrier(sc);
	MWX_DEV_LOG(sc, "hardware init normal firmware mode set\n");

	rv = mt7921_mcu_init(sc);
	if (rv != 0) {
		MWX_DEV_LOG(sc, "hardware init MCU init failed error=%d\n", rv);
		goto fail;
	}
	MWX_DEV_LOG(sc, "hardware init MCU init ok\n");
	/* TODO override eeprom for systems with FDT */
	rv = mt7921_mcu_set_eeprom(sc);
	if (rv != 0) {
		MWX_DEV_LOG(sc, "hardware init EEPROM setup failed error=%d\n", rv);
		goto fail;
	}
	MWX_DEV_LOG(sc, "hardware init EEPROM setup ok\n");
	mwx_mac_init(sc);

	sc->sc_vif.vif_mn.wcid = MWX_WTBL_RESERVED;

	/* MAYBE alloc beacon and mgmt frame wcid 0 here */

	MWX_DEV_LOG(sc, "hardware init complete\n");
	return 0;

 fail:
	/* reset dma */
	MWX_DEV_LOG(sc, "hardware init recovery dma reset start\n");
	rv = mwx_dma_reset(sc, 1);
	if (rv != 0) {
		MWX_DEV_LOG(sc, "hardware init recovery dma reset failed error=%d\n",
		    rv);
		return rv;
	}
	return EAGAIN;
}

int
mt7921_mcu_init(struct mwx_softc *sc)
{
	int rv;

	MWX_DEV_LOG(sc, "MCU init start\n");
	/* this read is needed to make interrupts work */
	(void) mwx_read(sc, MT_TOP_LPCR_HOST_BAND0);
	mwx_write(sc, MT_TOP_LPCR_HOST_BAND0, MT_TOP_LPCR_HOST_DRV_OWN);
	if (mwx_poll(sc, MT_TOP_LPCR_HOST_BAND0, 0, MT_TOP_LPCR_HOST_FW_OWN,
	    5000) != 0) {
	    MWX_DEV_LOG(sc, "MCU init timeout for driver own\n");
	    return EIO;
	}
	MWX_DEV_LOG(sc, "MCU init driver own ok\n");

	mwx_set(sc, MT_PCIE_MAC_PM, MT_PCIE_MAC_PM_L0S_DIS);

	if ((rv = mwx_load_firmware(sc)) != 0) {
		MWX_DEV_LOG(sc, "MCU init firmware load failed error=%d\n", rv);
		return rv;
	}
	MWX_DEV_LOG(sc, "MCU init firmware load ok\n");

	if ((rv = mt7921_mcu_get_nic_capability(sc)) != 0) {
		MWX_DEV_LOG(sc, "MCU init NIC capability failed error=%d\n", rv);
		return rv;
	}
	MWX_DEV_LOG(sc, "MCU init NIC capability ok\n");
	if ((rv = mt7921_mcu_fw_log_2_host(sc, 1)) != 0) {
		MWX_DEV_LOG(sc, "MCU init firmware log enable failed error=%d\n",
		    rv);
		return rv;
	}

	/* TODO mark MCU running */

	MWX_DEV_LOG(sc, "MCU init complete\n");
	return 0;
}

static inline uint32_t
mwx_get_data_mode(struct mwx_softc *sc, uint32_t info)
{
	uint32_t mode = DL_MODE_NEED_RSP;

	if (info == PATCH_SEC_NOT_SUPPORT)
		return mode;
	switch (info & PATCH_SEC_ENC_TYPE_MASK) {
	case PATCH_SEC_ENC_TYPE_PLAIN:
		break;
	case PATCH_SEC_ENC_TYPE_AES:
		mode |= DL_MODE_ENCRYPT;
		mode |= (info << DL_MODE_KEY_IDX_SHIFT) & DL_MODE_KEY_IDX_MASK;
		mode |= DL_MODE_RESET_SEC_IV;
		break;
	case PATCH_SEC_ENC_TYPE_SCRAMBLE:
		mode |= DL_MODE_ENCRYPT;
		mode |= DL_CONFIG_ENCRY_MODE_SEL;
		mode |= DL_MODE_RESET_SEC_IV;
		break;
	default:
		printf("%s: encryption type not supported\n", DEVNAME(sc));
	}
	return mode;
}

static inline uint32_t
mwx_mcu_gen_dl_mode(uint8_t feature_set)
{
	uint32_t ret = DL_MODE_NEED_RSP;

	if (feature_set & FW_FEATURE_SET_ENCRYPT)
		ret |= (DL_MODE_ENCRYPT | DL_MODE_RESET_SEC_IV);
	if (feature_set & FW_FEATURE_ENCRY_MODE)
		ret |= DL_CONFIG_ENCRY_MODE_SEL;

	/* FW_FEATURE_SET_KEY_IDX_MASK == DL_MODE_KEY_IDX_MASK */
	ret |= feature_set & FW_FEATURE_SET_KEY_IDX_MASK;

	return ret;
}


int
mwx_load_firmware(struct mwx_softc *sc)
{
	struct mwx_patch_hdr *hdr;
	struct mwx_fw_trailer *fwhdr;
	const char *rompatch, *fw;
	u_char *buf = NULL, *fwbuf = NULL, *dl;
	size_t buflen = 0, fwlen = 0, offset = 0;
	uint32_t reg, n_region, override = 0, option = 0;
	int i, rv, sem;

	MWX_DEV_LOG(sc, "firmware load start hwtype=%s\n",
	    sc->sc_hwtype == MWX_HW_MT7922 ? "MT7922" : "MT7921");
	reg = mwx_read(sc, MT_CONN_ON_MISC) & MT_TOP_MISC2_FW_N9_RDY;
	if (reg != 0) {
		MWX_DEV_LOG(sc, "firmware already downloaded status=0x%08x\n", reg);
		return 0;
	}

	switch (sc->sc_hwtype) {
	case MWX_HW_MT7921:
		rompatch = MT7921_ROM_PATCH;
		fw = MT7921_FIRMWARE_WM;
		break;
	case MWX_HW_MT7922:
		rompatch = MT7922_ROM_PATCH;
		fw = MT7922_FIRMWARE_WM;
		break;
	}
	MWX_DEV_LOG(sc, "firmware selected patch=%s wm=%s\n", rompatch, fw);

	if ((rv = loadfirmware(rompatch, &buf, &buflen)) != 0) {
		MWX_DEV_LOG(sc, "patch firmware load failed name=%s error=%d\n",
		    rompatch, rv);
		return rv;
	}
	if ((rv = loadfirmware(fw, &fwbuf, &fwlen)) != 0) {
		MWX_DEV_LOG(sc, "WM firmware load failed name=%s error=%d\n",
		    fw, rv);
		free(buf, M_DEVBUF, buflen);
		return rv;
	}
	MWX_DEV_LOG(sc, "firmware blobs loaded patch_size=%zu wm_size=%zu\n",
	    buflen, fwlen);

	rv = mwx_mcu_patch_sem_ctrl(sc, 1);
	if (rv != 0) {
		MWX_DEV_LOG(sc, "patch semaphore acquire failed error=%d\n", rv);
		goto fail;
	}
	MWX_DEV_LOG(sc, "patch semaphore acquired\n");

	if (buflen < sizeof(*hdr)) {
		MWX_DEV_LOG(sc, "invalid patch firmware size=%zu min=%zu\n",
		    buflen, sizeof(*hdr));
		rv = EINVAL;
		goto out;
	}
	hdr = (struct mwx_patch_hdr *)buf;
	n_region = be32toh(hdr->desc.n_region);
	if (buflen < sizeof(*hdr) + n_region * sizeof(struct mwx_patch_sec)) {
		MWX_DEV_LOG(sc, "invalid patch firmware short header size=%zu regions=%u\n",
		    buflen, n_region);
		rv = EINVAL;
		goto out;
	}
	MWX_DEV_LOG(sc, "patch header hw_sw=0x%x patch_ver=0x%x regions=%u build=%.15s\n",
	    be32toh(hdr->hw_sw_ver), be32toh(hdr->patch_ver),
	    n_region, hdr->build_date);

	for (i = 0; i < n_region; i++) {
		struct mwx_patch_sec *sec;
		uint32_t len, addr, mode, sec_info;

		sec = (struct mwx_patch_sec *)(buf + sizeof(*hdr) +
		    i * sizeof(*sec));
		if ((be32toh(sec->type) & PATCH_SEC_TYPE_MASK) !=
		    PATCH_SEC_TYPE_INFO) {
			MWX_DEV_LOG(sc, "invalid patch region index=%d type=0x%x\n",
			    i, be32toh(sec->type));
			rv = EINVAL;
			goto out;
		}

		addr = be32toh(sec->info.addr);
		len = be32toh(sec->info.len);
		dl = buf + be32toh(sec->offs);
		sec_info = be32toh(sec->info.sec_key_idx);
		mode = mwx_get_data_mode(sc, sec_info);
		MWX_DEV_LOG(sc, "patch region index=%d addr=0x%08x len=%u mode=0x%08x sec=0x%08x\n",
		    i, addr, len, mode, sec_info);

		if (dl + len > buf + buflen) {
			MWX_DEV_LOG(sc, "patch region index=%d exceeds payload len=%u\n",
			    i, len);
			rv = EINVAL;
			goto out;
		}

		rv = mwx_mcu_init_download(sc, addr, len, mode);
		if (rv != 0) {
			MWX_DEV_LOG(sc, "patch download request failed index=%d error=%d\n",
			    i, rv);
			goto out;
		}
		rv = mwx_mcu_send_firmware(sc, MCU_CMD_FW_SCATTER,
		    dl, len, MWX_FW_CHUNK_SIZE);
		if (rv != 0) {
			MWX_DEV_LOG(sc, "patch send failed index=%d error=%d\n",
			    i, rv);
			goto out;
		}
	}

	delay(5000);
	rv = mwx_mcu_start_patch(sc);
	if (rv != 0) {
		MWX_DEV_LOG(sc, "patch start failed error=%d\n", rv);
		goto out;
	}
	MWX_DEV_LOG(sc, "patch start ok\n");

out:
	sem = mwx_mcu_patch_sem_ctrl(sc, 0);
	if (sem != 0)
		rv = sem;
	if (rv != 0)
		goto fail;

	if (fwlen < sizeof(*fwhdr)) {
		MWX_DEV_LOG(sc, "invalid WM firmware size=%zu min=%zu\n",
		    fwlen, sizeof(*fwhdr));
		rv = EINVAL;
		goto fail;
	}
	fwhdr = (struct mwx_fw_trailer *)(fwbuf + fwlen - sizeof(*fwhdr));
	MWX_DEV_LOG(sc, "WM header version=%.10s build=%.15s chip=0x%02x eco=0x%02x regions=%u\n",
	    fwhdr->fw_ver, fwhdr->build_date, fwhdr->chip_id,
	    fwhdr->eco_code, fwhdr->n_region);

	if (fwlen < sizeof(*fwhdr) +
	    fwhdr->n_region * sizeof(struct mwx_fw_region)) {
		MWX_DEV_LOG(sc, "invalid WM firmware short header size=%zu regions=%u\n",
		    fwlen, fwhdr->n_region);
		rv = EINVAL;
		goto fail;
	}

	for (i = 0; i < fwhdr->n_region; i++) {
		struct mwx_fw_region *region;
		uint32_t len, addr, mode;

		region = (struct mwx_fw_region *)((u_char *)fwhdr -
		    (fwhdr->n_region - i) * sizeof(*region));

		addr = le32toh(region->addr);
		len = le32toh(region->len);
		mode = mwx_mcu_gen_dl_mode(region->feature_set);

		if (region->feature_set & FW_FEATURE_OVERRIDE_ADDR)
			override = addr;
		MWX_DEV_LOG(sc, "WM region index=%d addr=0x%08x len=%u mode=0x%08x feature=0x%02x offset=%zu\n",
		    i, addr, len, mode, region->feature_set, offset);

		if (offset + len > fwlen - sizeof(*fwhdr) -
		    fwhdr->n_region * sizeof(struct mwx_fw_region)) {
			MWX_DEV_LOG(sc, "WM region index=%d exceeds payload len=%u offset=%zu\n",
			    i, len, offset);
			rv = EINVAL;
			goto fail;
		}

		if (region->feature_set & FW_FEATURE_NON_DL) {
			offset += len;
			continue;
		}

		rv = mwx_mcu_init_download(sc, addr, len, mode);
		if (rv != 0) {
			MWX_DEV_LOG(sc, "WM download request failed index=%d error=%d\n",
			    i, rv);
			goto fail;
		}

		rv = mwx_mcu_send_firmware(sc, MCU_CMD_FW_SCATTER,
		    fwbuf + offset, len, MWX_FW_CHUNK_SIZE);
		if (rv != 0) {
			MWX_DEV_LOG(sc, "WM send failed index=%d error=%d\n",
			    i, rv);
			goto fail;
		}
		offset += len;
	}

	if (override != 0)
		option |= FW_START_OVERRIDE;

	rv = mwx_mcu_start_firmware(sc, override, option);
	if (rv != 0) {
		MWX_DEV_LOG(sc, "firmware start failed override=0x%08x option=0x%08x error=%d\n",
		    override, option, rv);
		goto fail;
	}
	MWX_DEV_LOG(sc, "firmware start ok override=0x%08x option=0x%08x\n",
	    override, option);

	/* XXX should not busy poll here */
	if (mwx_poll(sc, MT_CONN_ON_MISC, MT_TOP_MISC2_FW_N9_RDY,
	    MT_TOP_MISC2_FW_N9_RDY, 1500) != 0) {
		MWX_DEV_LOG(sc, "firmware ready poll timed out\n");
		rv = EIO;
		goto fail;
	}

	MWX_DEV_LOG(sc, "firmware loaded and ready\n");
	rv = 0;

fail:
	if (buf != NULL)
		free(buf, M_DEVBUF, buflen);
	if (fwbuf != NULL)
		free(fwbuf, M_DEVBUF, fwlen);
	return rv;
}

int
mwx_mac_wtbl_update(struct mwx_softc *sc, int idx)
{
	mwx_rmw(sc, MT_WTBL_UPDATE,
	    (idx & MT_WTBL_UPDATE_WLAN_IDX_MASK) | MT_WTBL_UPDATE_ADM_COUNT_CLEAR,
	    MT_WTBL_UPDATE_WLAN_IDX_MASK);

	return mwx_poll(sc, MT_WTBL_UPDATE, 0, MT_WTBL_UPDATE_BUSY, 5000);
}

void
mwx_mac_init_band(struct mwx_softc *sc, uint32_t band)
{
	mwx_rmw(sc, MT_TMAC_CTCR0(band), 0x3f, MT_TMAC_CTCR0_INS_DDLMT_REFTIME);
	mwx_set(sc, MT_TMAC_CTCR0(band),
	    MT_TMAC_CTCR0_INS_DDLMT_VHT_SMPDU_EN |
	    MT_TMAC_CTCR0_INS_DDLMT_EN);

	mwx_set(sc, MT_WF_RMAC_MIB_TIME0(band), MT_WF_RMAC_MIB_RXTIME_EN);
	mwx_set(sc, MT_WF_RMAC_MIB_AIRTIME0(band), MT_WF_RMAC_MIB_RXTIME_EN);

	/* enable MIB tx-rx time reporting */
	mwx_set(sc, MT_MIB_SCR1(band), MT_MIB_TXDUR_EN);
	mwx_set(sc, MT_MIB_SCR1(band), MT_MIB_RXDUR_EN);

	mwx_rmw(sc, MT_DMA_DCR0(band),
	    1536 << MT_DMA_DCR0_MAX_RX_LEN_SHIFT, MT_DMA_DCR0_MAX_RX_LEN_MASK);
	/* disable rx rate report by default due to hw issues */
	mwx_clear(sc, MT_DMA_DCR0(band), MT_DMA_DCR0_RXD_G5_EN);

	/* filter out non-resp frames and get instantaneous signal reporting */
	mwx_rmw(sc, MT_WTBLOFF_TOP_RSCR(band),
	    0 << MT_WTBLOFF_TOP_RSCR_RCPI_MODE_SHIFT |
	    0x3 << MT_WTBLOFF_TOP_RSCR_RCPI_PARAM_SHIFT,
	    MT_WTBLOFF_TOP_RSCR_RCPI_MODE_MASK |
	    MT_WTBLOFF_TOP_RSCR_RCPI_PARAM_MASK);
}

void
mwx_mac_init(struct mwx_softc *sc)
{
	int i;

	mwx_rmw(sc, MT_MDP_DCR1, 1536 << MT_MDP_DCR1_MAX_RX_LEN_SHIFT,
	    MT_MDP_DCR1_MAX_RX_LEN_MASK);

	/* enable hardware de-agg */
	mwx_set(sc, MT_MDP_DCR0, MT_MDP_DCR0_DAMSDU_EN);
#if 0
	/* not enabled since our stack does not handle 802.3 frames */
	/* enable hardware rx header translation */
	mwx_set(sc, MT_MDP_DCR0, MT_MDP_DCR0_RX_HDR_TRANS_EN);
#endif

	for (i = 0; i < MWX_WTBL_SIZE; i++)
		mwx_mac_wtbl_update(sc, i);

	mwx_mac_init_band(sc, 0);
	mwx_mac_init_band(sc, 1);

	sc->sc_rxfilter = mwx_read(sc, MT_WF_RFCR(0));
}

int
mwx_mcu_patch_sem_ctrl(struct mwx_softc *sc, int semget)
{
#define	PATCH_SEM_RELEASE		0
#define PATCH_SEM_GET			1
#define	PATCH_NOT_DL_SEM_FAIL		0
#define	PATCH_IS_DL			1
#define	PATCH_NOT_DL_SEM_SUCCESS	2
#define	PATCH_REL_SEM_SUCCESS		3

	uint32_t op = semget ? PATCH_SEM_GET : PATCH_SEM_RELEASE;
	struct {
		uint32_t op;
	} req = {
		.op = htole32(op),
	};
	int rv, seq;
	uint32_t sem;

	rv = mwx_mcu_send_msg(sc, MCU_CMD_PATCH_SEM_CONTROL,
	    &req, sizeof(req), &seq);
	if (rv != 0)
		return rv;

	rv = mwx_mcu_wait_resp_int(sc, MCU_CMD_PATCH_SEM_CONTROL, seq, &sem);
	if (rv != 0)
		return rv;

	if (semget) {
		switch (sem) {
		case PATCH_IS_DL:
			return -1;
		case PATCH_NOT_DL_SEM_SUCCESS:
			return 0;
		default:
			DPRINTF("%s: failed to %s patch semaphore\n",
			    DEVNAME(sc), "get");
			return EAGAIN;
		}
	} else {
		switch (sem) {
		case PATCH_REL_SEM_SUCCESS:
			return 0;
		default:
			DPRINTF("%s: failed to %s patch semaphore\n",
			    DEVNAME(sc), "release");
			return EAGAIN;
		}
	}
}

int
mwx_mcu_init_download(struct mwx_softc *sc, uint32_t addr,
    uint32_t len, uint32_t mode)
{
	struct {
		uint32_t addr;
		uint32_t len;
		uint32_t mode;
	} req = {
		.addr = htole32(addr),
		.len = htole32(len),
		.mode = htole32(mode),
	};
	int cmd;

	if (addr == 0x200000 || addr == 0x900000)
		cmd = MCU_CMD_PATCH_START_REQ;
	else
		cmd = MCU_CMD_TARGET_ADDRESS_LEN_REQ;

	return mwx_mcu_send_wait(sc, cmd, &req, sizeof(req));
}

int
mwx_mcu_send_firmware(struct mwx_softc *sc, int cmd, u_char *data,
    size_t len, size_t max_len)
{
	size_t cur_len;
	int rv;

	while (len > 0) {
		cur_len = len;
		if (cur_len > max_len)
			cur_len = max_len;

		rv = mwx_mcu_send_msg(sc, cmd, data, cur_len, NULL);
		if (rv != 0)
			return rv;

		data += cur_len;
		len -= cur_len;

		mwx_dma_tx_cleanup(sc, &sc->sc_txfwdlq);
	}

	return 0;
}

int
mwx_mcu_start_patch(struct mwx_softc *sc)
{
	struct {
		uint8_t check_crc;
		uint8_t reserved[3];
	} req = {
		.check_crc = 0,
	};

	return mwx_mcu_send_wait(sc, MCU_CMD_PATCH_FINISH_REQ, &req,
	    sizeof(req));
}

int
mwx_mcu_start_firmware(struct mwx_softc *sc, uint32_t addr, uint32_t option)
{
	struct {
		uint32_t option;
		uint32_t addr;
	} req = {
		.option = htole32(option),
		.addr = htole32(addr),
	};

	return mwx_mcu_send_wait(sc, MCU_CMD_FW_START_REQ, &req, sizeof(req));
}

int
mt7921_mcu_get_nic_capability(struct mwx_softc *sc)
{
	struct mt76_connac_cap_hdr {
		uint16_t	n_elements;
		uint16_t	pad;
	} __packed *hdr;
	struct tlv_hdr {
		uint32_t	type;
		uint32_t	len;
	} __packed *tlv;
	struct mt76_connac_phy_cap {
		uint8_t		ht;
		uint8_t		vht;
		uint8_t		_5g;
		uint8_t		max_bw;
		uint8_t		nss;
		uint8_t		dbdc;
		uint8_t		tx_ldpc;
		uint8_t		rx_ldpc;
		uint8_t		tx_stbc;
		uint8_t		rx_stbc;
		uint8_t		hw_path;
		uint8_t		he;
	} __packed *cap;
	struct mbuf *m;
	int rv, seq, count, i;

	rv = mwx_mcu_send_msg(sc, MCU_CE_CMD_GET_NIC_CAPAB, NULL, 0, &seq);
	if (rv != 0)
		return rv;

	rv = mwx_mcu_wait_resp_msg(sc, MCU_CE_CMD_GET_NIC_CAPAB, seq, &m);
	if (rv != 0)
		return rv;

	/* the message was already pulled up by mwx_mcu_rx_event() */
	if (mbuf_len(m) < sizeof(*hdr)) {
		printf("%s: GET_NIC_CAPAB response size error\n", DEVNAME(sc));
		m_freem(m);
		return EINVAL;
	}
	hdr = mtod(m, struct mt76_connac_cap_hdr *);
	count = le16toh(hdr->n_elements);
	m_adj(m, sizeof(*hdr));

	for (i = 0; i < count; i++) {
		uint32_t type, len;

		if (mbuf_len(m) < sizeof(*tlv)) {
			printf("%s: GET_NIC_CAPAB tlv size error\n",
			    DEVNAME(sc));
			m_freem(m);
			return EINVAL;
		}

		tlv = mtod(m, struct tlv_hdr *);
		type = le32toh(tlv->type);
		len = le32toh(tlv->len);
		m_adj(m, sizeof(*tlv));

		if (mbuf_len(m) < len)
			break;
		switch (type) {
		case MT_NIC_CAP_6G:
			/* TODO 6GHZ SUPPORT */
			sc->sc_capa.has_6ghz = /* XXX 1 */ 0;
			break;
		case MT_NIC_CAP_MAC_ADDR:
			if (len < ETHER_ADDR_LEN)
				break;
			memcpy(sc->sc_lladdr, mtod(m, caddr_t), ETHER_ADDR_LEN);
			break;
		case MT_NIC_CAP_PHY:
			if (len < sizeof(*cap))
				break;
			cap = mtod(m, struct mt76_connac_phy_cap *);

			sc->sc_capa.num_streams = cap->nss;
			sc->sc_capa.antenna_mask = (1U << cap->nss) - 1;
			sc->sc_capa.has_2ghz = cap->hw_path & 0x01;
			sc->sc_capa.has_5ghz = cap->hw_path & 0x02;
			break;
		case MT_NIC_CAP_TX_RESOURCE:
			/* unused on PCIe devices */
			break;
		}
		m_adj(m, len);
	}

	printf("%s: address %s\n", DEVNAME(sc), ether_sprintf(sc->sc_lladdr));

	m_freem(m);
	return 0;
}

int
mt7921_mcu_fw_log_2_host(struct mwx_softc *sc, uint8_t ctrl)
{
	struct {
		uint8_t	ctrl;
		uint8_t	pad[3];
	} req = {
		.ctrl = ctrl,
	};

	return mwx_mcu_send_msg(sc, MCU_CE_CMD_FWLOG_2_HOST, &req,
	    sizeof(req), NULL);
}

int
mt7921_mcu_set_eeprom(struct mwx_softc *sc)
{
	struct req_hdr {
		uint8_t	buffer_mode;
		uint8_t	format;
		uint8_t pad[2];
	} req = {
		.buffer_mode = EE_MODE_EFUSE,
		.format = EE_FORMAT_WHOLE,
	};

	return mwx_mcu_send_wait(sc, MCU_EXT_CMD_EFUSE_BUFFER_MODE, &req,
	    sizeof(req));
}

int
mt7921_mcu_set_rts_thresh(struct mwx_softc *sc, uint32_t val, uint8_t band)
{
	struct {
		uint8_t		prot_idx;
		uint8_t		band;
		uint8_t		rsv[2];
		uint32_t	len_thresh;
		uint32_t	pkt_thresh;
	} __packed req = {
		.prot_idx = 1,
		.band = band,
		.len_thresh = htole32(val),
		.pkt_thresh = htole32(0x2),
	};

	return mwx_mcu_send_wait(sc, MCU_EXT_CMD_PROTECT_CTRL, &req,
	    sizeof(req));
}

int
mwx_mcu_set_deep_sleep(struct mwx_softc *sc, int ena)
{
	struct mwx_connac_config req = {
		.resp_type = 0,
	};

	DPRINTF("%s: %s deep sleep\n", DEVNAME(sc), ena ? "enable" : "disable");
	snprintf((char *)req.data, sizeof(req.data), "KeepFullPwr %d", !ena);
	return mwx_mcu_send_msg(sc, MCU_CE_CMD_CHIP_CONFIG, &req,
	     sizeof(req), NULL);
}

void
mt7921_mcu_low_power_event(struct mwx_softc *sc, struct mbuf *m)
{
	struct mt7921_mcu_lp_event {
		uint8_t state;
		uint8_t reserved[3];
	} __packed *event;

	if (mbuf_len(m) < sizeof(*event))
		return;
	event = mtod(m, struct mt7921_mcu_lp_event *);
	DPRINTF("%s: low power event state %d\n", DEVNAME(sc), event->state);
}

void
mt7921_mcu_tx_done_event(struct mwx_softc *sc, struct mbuf *m)
{
	struct mt7921_mcu_tx_done_event {
		uint8_t		pid;
		uint8_t		status;
		uint16_t	seq;
		uint8_t		wlan_idx;
		uint8_t		tx_cnt;
		uint16_t	tx_rate;
		uint8_t		flag;
		uint8_t		tid;
		uint8_t		rsp_rate;
		uint8_t		mcs;
		uint8_t		bw;
		uint8_t		tx_pwr;
		uint8_t		reason;
		uint8_t		rsv0[1];
		uint32_t	delay;
		uint32_t	timestamp;
		uint32_t	applied_flag;
		uint8_t		txs[28];
		uint8_t		rsv1[32];
	} __packed *event;

	if (mbuf_len(m) < sizeof(*event))
		return;
	event = mtod(m, struct mt7921_mcu_tx_done_event *);
	// TODO mt7921_mac_add_txs(dev, event->txs);
}

int
mt7921_mcu_hw_scan(struct mwx_softc *sc, int bgscan)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct ieee80211_channel *c;
	struct mt76_connac_hw_scan_req	*req;
	struct mbuf *m;
	int n_ssids = 0;
	int rv;
	uint8_t nchan, n_2g = 0, n_5g = 0;

	m = mwx_mcu_alloc_msg(sizeof(*req));
	if (m == NULL)
		return ENOMEM;
	req = mtod(m, struct mt76_connac_hw_scan_req *);
	/* The mbuf payload is not initialized by allocation. */
	memset(req, 0, sizeof(*req));

	sc->sc_flags |= MWX_FLAG_SCANNING;
	sc->sc_scan_seq_num = (sc->sc_scan_seq_num + 1) & 0x7f;

	req->seq_num = sc->sc_scan_seq_num /* | sc->sc_band_idx << 7 */;
	req->bss_idx = /* mvif->idx */ 0;
	req->scan_type = /* sreq->n_ssids ? 1 : */ 0;
	req->probe_req_num = /* sreq->n_ssids ? 2 : */ 0;
	req->version = 1;

#ifdef AIRPORT_WCL
	/*
	 * A scan macOS asked for (AirportMtkWlan): active when it wants probes,
	 * with its SSID (hidden networks), on its channels. Scans the driver
	 * starts itself stay passive over every channel, as with SimpleMtkWlan.
	 * Like Linux mt76: probing with no SSID is the wildcard (ssid_type 1).
	 */
	if (ic->ic_wcl_scan_requested &&
	    AirportWCL::scanUsesProbes(true, ic->ic_wcl_scan_active)) {
		req->scan_type = 1;
		req->probe_req_num = 2;
		if (ic->ic_wcl_scan_ssid_length > 0 &&
		    ic->ic_wcl_scan_ssid_length <= IEEE80211_NWID_LEN) {
			req->ssids[0].ssid_len = htole32(ic->ic_wcl_scan_ssid_length);
			memcpy(req->ssids[0].ssid, ic->ic_wcl_scan_ssid,
			    ic->ic_wcl_scan_ssid_length);
			n_ssids = 1;
		}
	}
#endif

#ifdef NOTYET
	for (i = 0; i < sreq->n_ssids; i++) {
		if (!sreq->ssids[i].ssid_len)
			continue;
		req->ssids[i].ssid_len = htole32(sreq->ssids[i].ssid_len);
		memcpy(req->ssids[i].ssid, sreq->ssids[i].ssid,
		    sreq->ssids[i].ssid_len);
		n_ssids++;
	}
#endif

	req->ssid_type = n_ssids ? 0x4 : 0x1;
	req->ssid_type_ext = n_ssids ? 1 : 0;
	req->ssids_num = n_ssids;

	for (nchan = 0, c = &ic->ic_channels[1];
	    c <= &ic->ic_channels[IEEE80211_CHAN_MAX] &&
	    nchan < 64; c++) {
		struct mt76_connac_mcu_scan_channel *chan;
		uint8_t channel_num;

		if (c->ic_flags == 0)
			continue;
#ifdef AIRPORT_WCL
		if (!AirportWCL::scanChannelSelected(ic->ic_wcl_scan_channels,
		    ic->ic_wcl_scan_requested && ic->ic_wcl_scan_restricted,
		    ieee80211_mhz2ieee(c->ic_freq, 0)))
			continue;
#endif

		if (nchan < 32)
			chan = &req->channels[nchan];
		else
			chan = &req->ext_channels[nchan - 32];

		channel_num = ieee80211_mhz2ieee(c->ic_freq, 0);
		/* TODO IEEE80211_IS_CHAN_6GHZ -> chan->band = 3*/
		if (IEEE80211_IS_CHAN_2GHZ(c)) {
			chan->band = 1;
			n_2g++;
		} else {
			chan->band = 2;
			n_5g++;
		}
		chan->channel_num = channel_num;
		nchan++;
	}

	if (nchan <= 32) {
		req->channels_num = nchan;
	} else {
		req->channels_num = 32;
		req->ext_channels_num = nchan - 32;
	}

	req->channel_type = nchan ? 4 : 0;
	req->timeout_value = htole16(nchan * 120);
	req->channel_min_dwell_time = htole16(120);
	req->channel_dwell_time = htole16(120);


#ifdef NOTYET
	if (sreq->ie_len > 0) {
		memcpy(req->ies, sreq->ie, sreq->ie_len);
		req->ies_len = htole16(sreq->ie_len);
	}
#endif

	req->scan_func |= SCAN_FUNC_SPLIT_SCAN;

	/* wildcard BSSID */
	memset(req->bssid, 0xff, ETHER_ADDR_LEN);
#ifdef NOTYET
	if (sreq->flags & NL80211_SCAN_FLAG_RANDOM_ADDR) {
		get_random_mask_addr(req->random_mac, sreq->mac_addr,
		    sreq->mac_addr_mask);
		req->scan_func |= SCAN_FUNC_RANDOM_MAC;
	}
#endif

	MWX_DEV_LOG(sc,
	    "scan request seq=%u channels=%u 2g=%u 5g=%u primary=%u ext=%u timeout=%u dwell=%u min_dwell=%u scan_func=0x%08x ssid_type=0x%x\n",
	    sc->sc_scan_seq_num, nchan, n_2g, n_5g, req->channels_num,
	    req->ext_channels_num, le16toh(req->timeout_value),
	    le16toh(req->channel_dwell_time),
	    le16toh(req->channel_min_dwell_time),
	    le32toh(req->scan_func), req->ssid_type);

	rv = mwx_mcu_send_mbuf(sc, MCU_CE_CMD_START_HW_SCAN, m, NULL);
	if (rv != 0)
		sc->sc_flags &= ~(MWX_FLAG_SCANNING | MWX_FLAG_BGSCAN);

	return rv;
}

int
mt7921_mcu_hw_scan_cancel(struct mwx_softc *sc)
{
	struct {
		uint8_t		seq_num;
		uint8_t		is_ext_channel;
		uint8_t		rsv[2];
	} __packed req = {
		.seq_num = sc->sc_scan_seq_num,
	};
	int rv;

	rv = mwx_mcu_send_msg(sc, MCU_CE_CMD_CANCEL_HW_SCAN, &req,
	    sizeof(req), NULL);
	if (rv == 0)
		sc->sc_flags &= ~(MWX_FLAG_SCANNING | MWX_FLAG_BGSCAN);
	return rv;
}

void
mwx_end_scan_task(void *arg)
{
	struct mwx_softc *sc = (struct mwx_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;
	int s;

	s = splnet();
	/*
	 * Entering RUN cancels the hardware scan, but the firmware can still
	 * report its completion afterwards. Ending that stale scan made
	 * net80211 choose and re-join the BSS we had just associated to
	 * (without a deauth), which the AP then ignored. Only background
	 * scans may complete while associated.
	 */
	if (ic->ic_state == IEEE80211_S_RUN &&
	    (ic->ic_flags & IEEE80211_F_BGSCAN) == 0) {
		MWX_DEV_LOG(sc, "ignoring stale scan completion in RUN\n");
		splx(s);
		return;
	}
	ieee80211_end_scan(&ic->ic_if);
	splx(s);
}

void
mt7921_mcu_scan_event(struct mwx_softc *sc, struct mbuf *m)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct mt76_connac_hw_scan_done *event;
	uint32_t probe_sum = 0, mdrdy_sum = 0;
	int i, nodes_before;

	sc->sc_scan_done_count++;
	nodes_before = mwx_count_nodes(ic);
	sc->sc_scan_last_ieee80211_nodes = nodes_before;

	if (mbuf_len(m) >= sizeof(*event)) {
		event = mtod(m, struct mt76_connac_hw_scan_done *);
		for (i = 0; i < MT76_HW_SCAN_DONE_MAX_CHANNEL_NUM; i++) {
			probe_sum += event->beacon_probe_num[i];
			mdrdy_sum += event->mdrdy_count[i];
		}
		MWX_DEV_LOG(sc,
		    "scan done #%u seq=%u complete_ch=%u state=%u version=%u beacon_scan=%u probe_sum=%u mdrdy_sum=%u beacon_2g=%u beacon_5g=%u nodes_before=%d rx_norm=%u rx_fail=%u\n",
		    sc->sc_scan_done_count, event->seq_num,
		    event->complete_channel_num, event->current_state,
		    event->version, le32toh(event->beacon_scan_num),
		    probe_sum, mdrdy_sum, le32toh(event->beacon_2g_num),
		    le32toh(event->beacon_5g_num), nodes_before,
		    sc->sc_rx_pkt_normal, sc->sc_rx_fill_fail);
	} else {
		MWX_DEV_LOG(sc,
		    "scan done #%u short event len=%zu nodes_before=%d rx_norm=%u rx_fail=%u\n",
		    sc->sc_scan_done_count, mbuf_len(m), nodes_before,
		    sc->sc_rx_pkt_normal, sc->sc_rx_fill_fail);
	}

	if (mt7921_mcu_hw_scan_cancel(sc) != 0)
		return;
	task_add(systq, &sc->sc_scan_task);
}

int
mt7921_mcu_set_mac_enable(struct mwx_softc *sc, int band, int enable)
{
	struct {
		uint8_t		enable;
		uint8_t		band;
		uint8_t		rsv[2];
	} __packed req = {
		.enable = (uint8_t)enable,
		.band = (uint8_t)band,
	};

	return mwx_mcu_send_wait(sc, MCU_EXT_CMD_MAC_INIT_CTRL, &req,
	    sizeof(req));
}

int
mt7921_mcu_set_channel_domain(struct mwx_softc *sc)
{
	struct {
		uint8_t		alpha2[4]; /* regulatory_request.alpha2 */
		uint8_t		bw_2g;	/* BW_20_40M		0
					 * BW_20M		1
					 * BW_20_40_80M		2
					 * BW_20_40_80_160M	3
					 * BW_20_40_80_8080M	4
					 */
		uint8_t		bw_5g;
		uint8_t		bw_6g;
		uint8_t		pad;
		uint8_t		n_2ch;
		uint8_t		n_5ch;
		uint8_t		n_6ch;
		uint8_t		pad2;
	} __packed *hdr;
	struct {
		uint16_t	hw_value;
		uint16_t	pad;
		uint32_t	flags;
	} __packed *channel;
	struct ieee80211com *ic = &sc->sc_ic;
	struct ieee80211_channel *chan;
	struct mbuf *m;
	int i, len, rv;
	int n_2ch = 0, n_5ch = 0, n_6ch = 0;

	len = sizeof(*hdr) + IEEE80211_CHAN_MAX * sizeof(channel);
	m = mwx_mcu_alloc_msg(len);
	if (m == NULL)
		return ENOMEM;
	hdr = (decltype(hdr))mbuf_data(m);

	hdr->alpha2[0] = '0';
	hdr->alpha2[1] = '0';

	channel = (decltype(channel))(hdr + 1);

	hdr->bw_2g = 0;	/* BW_20_40M */
	for (i = 0; i <= IEEE80211_CHAN_MAX; i++) {
		chan = &ic->ic_channels[i];
		if (!IEEE80211_IS_CHAN_2GHZ(chan))
			continue;

		channel->hw_value = htole16(ieee80211_chan2ieee(ic, chan));
		channel->flags = htole32(0);	/* XXX */

		channel++;
		n_2ch++;
	}
	hdr->bw_5g = 3; /* BW_20_40_80_160M */
	for (i = 0; i <= IEEE80211_CHAN_MAX; i++) {
		chan = &ic->ic_channels[i];
		if (!IEEE80211_IS_CHAN_5GHZ(chan))
			continue;

		channel->hw_value = htole16(ieee80211_chan2ieee(ic, chan));
		channel->flags = htole32(0);	/* XXX */

		channel++;
		n_5ch++;
	}
#ifdef NOTYET
	/* 6GHz handling */
	hdr->bw_6g = 3; /* BW_20_40_80_160M */
	for (i = 0; i <= IEEE80211_CHAN_MAX; i++) {
		chan = &ic->ic_channels[i];
		if (!IEEE80211_IS_CHAN_6GHZ(chan))
			continue;

		channel->hw_value = htole16(ieee80211_chan2ieee(ic, chan));
		channel->flags = htole32(0);	/* XXX */

		channel++;
		n_6ch++;
	}
#endif

	memcpy(hdr->alpha2, sc->sc_alpha2, sizeof(sc->sc_alpha2));
	hdr->n_2ch = n_2ch;
	hdr->n_5ch = n_5ch;
	hdr->n_6ch = n_6ch;

	mwx_mcu_set_len(m, channel);
	rv = mwx_mcu_send_mbuf(sc, MCU_CE_CMD_SET_CHAN_DOMAIN, m, NULL);
	return rv;
}

uint8_t
mt7921_mcu_chan_bw(struct ieee80211_channel *channel)
{
	/*
	 * following modes are not yet supported
	 *  CMD_CBW_5MHZ, CMD_CBW_10MHZ, CMD_CBW_8080MHZ
	 */
	if (channel->ic_flags & IEEE80211_CHAN_VHT160)
		return CMD_CBW_160MHZ;
	if (channel->ic_flags & IEEE80211_CHAN_VHT80)
		return CMD_CBW_80MHZ;
	if (channel->ic_flags & IEEE80211_CHAN_40MHZ)
		return CMD_CBW_40MHZ;
	return CMD_CBW_20MHZ;
}

/*
 * Operating bandwidth and center channel negotiated with the AP: VHT80,
 * HT40 or 20 MHz.
 */
static void
mwx_node_chan_width(struct ieee80211_node *ni, uint8_t *bw, uint8_t *center)
{
	*bw = CMD_CBW_20MHZ;
	*center = ieee80211_mhz2ieee(ni->ni_chan->ic_freq, ni->ni_chan->ic_flags);
	if (ni->ni_chan->ic_center_freq1 == 0)
		return;
	if ((ni->ni_flags & IEEE80211_NODE_VHT) &&
	    ni->ni_chw == IEEE80211_CHAN_WIDTH_80) {
		*bw = CMD_CBW_80MHZ;
		*center = ieee80211_mhz2ieee(ni->ni_chan->ic_center_freq1,
		    ni->ni_chan->ic_flags);
	} else if ((ni->ni_flags & IEEE80211_NODE_HT) &&
	    ni->ni_chw == IEEE80211_CHAN_WIDTH_40) {
		*bw = CMD_CBW_40MHZ;
		*center = ieee80211_mhz2ieee(ni->ni_chan->ic_center_freq1,
		    ni->ni_chan->ic_flags);
	}
}

int
mt7921_mcu_set_chan_info(struct mwx_softc *sc, int cmd)
{
	struct ieee80211_channel *channel;
	struct {
		uint8_t		control_ch;
		uint8_t		center_ch;
		uint8_t		bw;
		uint8_t		tx_streams_num;
		uint8_t		rx_streams;	/* mask or num */
		uint8_t		switch_reason;
		uint8_t		band_idx;
		uint8_t		center_ch2;	/* for 80+80 only */
		uint16_t	cac_case;
		uint8_t		channel_band;
		uint8_t		rsv0;
		uint32_t	outband_freq;
		uint8_t		txpower_drop;
		uint8_t		ap_bw;
		uint8_t		ap_center_ch;
		uint8_t		rsv1[57];
	} __packed req = {
		.tx_streams_num = sc->sc_capa.num_streams,
		.rx_streams = sc->sc_capa.antenna_mask,
		.band_idx = 0,	/* XXX 0 or 1 */
	};

	if (sc->sc_ic.ic_opmode == IEEE80211_M_STA && sc->sc_ic.ic_bss != NULL)
		channel = sc->sc_ic.ic_bss->ni_chan;
	else
		channel = sc->sc_ic.ic_ibss_chan;

	req.control_ch = ieee80211_mhz2ieee(channel->ic_freq,
		    channel->ic_flags);
	req.center_ch = req.control_ch;
	req.bw = CMD_CBW_20MHZ;
	/* Use the negotiated operating width, not the channel capabilities. */
	if (sc->sc_ic.ic_opmode == IEEE80211_M_STA && sc->sc_ic.ic_bss != NULL &&
	    channel == sc->sc_ic.ic_bss->ni_chan)
		mwx_node_chan_width(sc->sc_ic.ic_bss, &req.bw, &req.center_ch);

#ifdef NOTYET
	if (channel->ic_flags & IEEE80211_CHAN_6GHZ)
		req.channel_band = 2;
	else
#endif
	if (channel->ic_flags & IEEE80211_CHAN_5GHZ)
		req.channel_band = 1;
	else
		req.channel_band = 0;

#ifdef NOTYET
	if (dev->mt76.hw->conf.flags & IEEE80211_CONF_OFFCHANNEL)
		req.switch_reason = CH_SWITCH_SCAN_BYPASS_DPD;
	else if ((chandef->chan->flags & IEEE80211_CHAN_RADAR) &&
		 chandef->chan->dfs_state != NL80211_DFS_AVAILABLE)
		req.switch_reason = CH_SWITCH_DFS;
	else
#endif
		req.switch_reason = CH_SWITCH_NORMAL;

	if (cmd == MCU_EXT_CMD_CHANNEL_SWITCH)
		req.rx_streams = sc->sc_capa.num_streams;

#ifdef NOTYET
	if (chandef->width == NL80211_CHAN_WIDTH_80P80) {
		int freq2 = chandef->center_freq2;
		req.center_ch2 = ieee80211_frequency_to_channel(freq2);
	}
#endif

	return mwx_mcu_send_wait(sc, cmd, &req, sizeof(req));
}

/* hardcoded version of what linux does */
void
mt7921_mcu_build_sku(struct mwx_softc *sc, int band, int8_t *sku)
{
	int max_power = 127;
	int i, offset = 4;

	memset(sku, max_power, MT_SKU_POWER_LIMIT);

	if (band == MT_TX_PWR_BAND_2GHZ) {
		/* cck */
		memset(sku, 0x28, 4);
	}

	/* ofdm */
	memset(sku + offset, 0x28, 8);
	offset += 8;

	/* ht */
	for (i = 0; i < 2; i++) {
		memset(sku + offset, 0x28, 8);
		offset += 8;
	}
	sku[offset++] = 0x28;

	/* vht */
	for (i = 0; i < 4; i++) {
		/* this only sets 10 out of 12 bytes on purpose */
		memset(sku + offset, 0x28, 10);
		offset += 12;
	}

	/* he */
	for (i = 0; i < 7; i++) {
		memset(sku + offset, 0x28, 12);
		offset += 12;
	}
}

int
mt7921_mcu_rate_txpower_band(struct mwx_softc *sc, int band,
    const uint8_t *chans, int n_chans, int is_last)
{
	struct mt76_connac_sku_tlv *sku_tlv;
	struct mt76_connac_tx_power_limit_tlv *tx_power_tlv;
	struct mbuf *m;
	int batch_size = 8;
	const int len = sizeof(*tx_power_tlv) + batch_size * sizeof(*sku_tlv);
	int rv = 0, idx, j;

	for (idx = 0; idx < n_chans; ) {
		int num_ch = batch_size;

		m = mwx_mcu_alloc_msg(len);
		if (m == NULL)
			return ENOMEM;
		tx_power_tlv = mtod(m, struct mt76_connac_tx_power_limit_tlv *);
		tx_power_tlv->n_chan = num_ch;
		tx_power_tlv->band = band;
		memcpy(tx_power_tlv->alpha2, sc->sc_alpha2,
		    sizeof(sc->sc_alpha2));

		if (n_chans - idx < batch_size) {
			num_ch = n_chans - idx;
			if (is_last)
				tx_power_tlv->last_msg = 1;
		}

		sku_tlv = (struct mt76_connac_sku_tlv *)(tx_power_tlv + 1);

		for (j = 0; j < num_ch; j++, idx++) {
			sku_tlv->channel = chans[idx];
			mt7921_mcu_build_sku(sc, band, sku_tlv->pwr_limit);
			sku_tlv++;
		}

		mwx_mcu_set_len(m, sku_tlv);
		rv = mwx_mcu_send_mbuf(sc, MCU_CE_CMD_SET_RATE_TX_POWER, m,
		    NULL);
		if (rv != 0)
			break;
	}

	return rv;
}

int
mt7921_mcu_set_rate_txpower(struct mwx_softc *sc)
{
	static const uint8_t chan_list_2ghz[] = {
	    1, 2,  3,  4,  5,  6,  7,
	    8, 9, 10, 11, 12, 13, 14
	};
	static const uint8_t chan_list_5ghz[] = {
	    36,  38,  40,  42,  44,  46,  48,
	    50,  52,  54,  56,  58,  60,  62,
	    64, 100, 102, 104, 106, 108, 110,
	    112, 114, 116, 118, 120, 122, 124,
	    126, 128, 132, 134, 136, 138, 140,
	    142, 144, 149, 151, 153, 155, 157,
	    159, 161, 165
	};
	static const uint8_t chan_list_6ghz[] = {
	    1,   3,   5,   7,   9,  11,  13,
	    15,  17,  19,  21,  23,  25,  27,
	    29,  33,  35,  37,  39,  41,  43,
	    45,  47,  49,  51,  53,  55,  57,
	    59,  61,  65,  67,  69,  71,  73,
	    75,  77,  79,  81,  83,  85,  87,
	    89,  91,  93,  97,  99, 101, 103,
	    105, 107, 109, 111, 113, 115, 117,
	    119, 121, 123, 125, 129, 131, 133,
	    135, 137, 139, 141, 143, 145, 147,
	    149, 151, 153, 155, 157, 161, 163,
	    165, 167, 169, 171, 173, 175, 177,
	    179, 181, 183, 185, 187, 189, 193,
	    195, 197, 199, 201, 203, 205, 207,
	    209, 211, 213, 215, 217, 219, 221,
	    225, 227, 229, 233
	};
	int rv = 0;

	if (sc->sc_capa.has_2ghz)
		rv = mt7921_mcu_rate_txpower_band(sc, MT_TX_PWR_BAND_2GHZ,
		    chan_list_2ghz, nitems(chan_list_2ghz),
		    !(sc->sc_capa.has_5ghz || sc->sc_capa.has_6ghz));
	if (rv == 0 && sc->sc_capa.has_5ghz)
		rv = mt7921_mcu_rate_txpower_band(sc, MT_TX_PWR_BAND_5GHZ,
		    chan_list_5ghz, nitems(chan_list_5ghz),
		    !sc->sc_capa.has_6ghz);
	if (rv == 0 && sc->sc_capa.has_6ghz)
		rv = mt7921_mcu_rate_txpower_band(sc, MT_TX_PWR_BAND_6GHZ,
		    chan_list_6ghz, nitems(chan_list_6ghz), 1);
	return rv;
}

void
mt7921_mac_reset_counters(struct mwx_softc *sc)
{
	int i;

	for (i = 0; i < 4; i++) {
		mwx_read(sc, MT_TX_AGG_CNT(0, i));
		mwx_read(sc, MT_TX_AGG_CNT2(0, i));
	}

	/* XXX TODO stats in softc */

	/* reset airtime counters */
	mwx_read(sc, MT_MIB_SDR9(0));
	mwx_read(sc, MT_MIB_SDR36(0));
	mwx_read(sc, MT_MIB_SDR37(0));
	mwx_set(sc, MT_WF_RMAC_MIB_TIME0(0), MT_WF_RMAC_MIB_RXTIME_CLR);
	mwx_set(sc, MT_WF_RMAC_MIB_AIRTIME0(0), MT_WF_RMAC_MIB_RXTIME_CLR);
}

void
mt7921_mac_set_timing(struct mwx_softc *sc)
{
	uint16_t coverage_class = 0;		/* XXX */
	uint32_t val, reg_offset;
	uint32_t cck = MT_TIMEOUT_CCK_DEF_VAL;
	uint32_t ofdm = MT_TIMEOUT_OFDM_DEF_VAL;
	uint32_t offset;
	int is_2ghz = 1; /* XXX get from ic_bss node */
	uint32_t sifs = is_2ghz ? 10 : 16;
	uint32_t slottime = IEEE80211_DUR_DS_SHSLOT;	/* XXX get from stack */

#ifdef NOTYET
	if (!test_bit(MT76_STATE_RUNNING, &phy->mt76->state))
		return;
#endif

	mwx_set(sc, MT_ARB_SCR(0),
	    MT_ARB_SCR_TX_DISABLE | MT_ARB_SCR_RX_DISABLE);
	delay(1);

	offset = 3 * coverage_class;
	reg_offset = offset | (offset << 16);

	mwx_write(sc, MT_TMAC_CDTR(0), cck + reg_offset);
	mwx_write(sc, MT_TMAC_ODTR(0), ofdm + reg_offset);
	mwx_write(sc, MT_TMAC_ICR0(0),
	    MT_IFS_EIFS_DEF | MT_IFS_RIFS_DEF |
	    (sifs << MT_IFS_SIFS_SHIFT) |
	    (slottime << MT_IFS_SLOT_SHIFT));

	if (slottime < 20 || !is_2ghz)
		val = MT7921_CFEND_RATE_DEFAULT;
	else
		val = MT7921_CFEND_RATE_11B;

	mwx_rmw(sc, MT_AGG_ACR0(0), val, MT_AGG_ACR_CFEND_RATE_MASK);
	mwx_clear(sc, MT_ARB_SCR(0),
	    MT_ARB_SCR_TX_DISABLE | MT_ARB_SCR_RX_DISABLE);
}

int
mt7921_mcu_uni_add_dev(struct mwx_softc *sc, struct mwx_vif *mvif,
    struct mwx_node *mn, int enable)
{
	struct {
		struct {
			uint8_t		omac_idx;
			uint8_t		band_idx;
			uint16_t	pad;
		} __packed hdr;
		struct req_tlv {
			uint16_t	tag;
			uint16_t	len;
			uint8_t		active;
			uint8_t		pad;
			uint8_t		omac_addr[ETHER_ADDR_LEN];
		} __packed tlv;
	} dev_req = {
		.hdr = {
			.omac_idx = mvif->omac_idx,
			.band_idx = mvif->band_idx,
		},
		.tlv = {
			.tag = htole16(DEV_INFO_ACTIVE),
			.len = htole16(sizeof(dev_req.tlv)),
			.active = (uint8_t)enable,
		},
	};
	struct {
		struct {
			uint8_t		bss_idx;
			uint8_t		pad[3];
		} __packed hdr;
		struct mt76_connac_bss_basic_tlv basic;
	} basic_req = {
		.hdr = {
			.bss_idx = mvif->idx,
		},
		.basic = {
			.tag = htole16(UNI_BSS_INFO_BASIC),
			.len = htole16(
			    sizeof(struct mt76_connac_bss_basic_tlv)),
			.omac_idx = mvif->omac_idx,
			.band_idx = mvif->band_idx,
			.wmm_idx = mvif->wmm_idx,
			.active = (uint8_t)enable,
			.bmc_tx_wlan_idx = htole16(mn->wcid),
			.sta_idx = htole16(mn->wcid),
			.conn_state = 1,
		},
	};
	int rv, idx, cmd, len;
	void *data;

	switch (sc->sc_ic.ic_opmode) {
	case IEEE80211_M_MONITOR:
#ifndef IEEE80211_STA_ONLY
	case IEEE80211_M_HOSTAP:
#endif
		basic_req.basic.conn_type =
		    htole32(STA_TYPE_AP | NETWORK_INFRA);
		break;
	case IEEE80211_M_STA:
		basic_req.basic.conn_type =
		    htole32(STA_TYPE_STA | NETWORK_INFRA);
		break;
#ifndef IEEE80211_STA_ONLY
	case IEEE80211_M_IBSS:
		basic_req.basic.conn_type =
		    htole32(STA_TYPE_ADHOC | NETWORK_IBSS);
		break;
#endif
	default:
		panic("%s: unknown operation mode", DEVNAME(sc));
	}

	idx = mvif->omac_idx > EXT_BSSID_START ? HW_BSSID_0 : mvif->omac_idx;
	basic_req.basic.hw_bss_idx = idx;

	/* The address the vif answers to: the current one, not the factory one. */
	memcpy(dev_req.tlv.omac_addr,
	    IEEE80211_ADDR_EQ(sc->sc_ic.ic_myaddr, etheranyaddr) ?
	    sc->sc_lladdr : sc->sc_ic.ic_myaddr, ETHER_ADDR_LEN);

	if (enable) {
		cmd = MCU_UNI_CMD_DEV_INFO_UPDATE;
		data = &dev_req;
		len = sizeof(dev_req);
	} else {
		cmd = MCU_UNI_CMD_BSS_INFO_UPDATE;
		data = &basic_req;
		len = sizeof(basic_req);
	}

printf("%s: %s cmd %x mvif idx %d omac %d band %d wmm %d\n", DEVNAME(sc), __func__, cmd, mvif->idx, mvif->omac_idx, mvif->band_idx, mvif->wmm_idx);
	rv = mwx_mcu_send_wait(sc, cmd, data, len);
	if (rv < 0)
		return rv;

	if (enable) {
		cmd = MCU_UNI_CMD_BSS_INFO_UPDATE;
		data = &basic_req;
		len = sizeof(basic_req);
	} else {
		cmd = MCU_UNI_CMD_DEV_INFO_UPDATE;
		data = &dev_req;
		len = sizeof(dev_req);
	}

printf("%s: %s cmd %x wcid %d\n", DEVNAME(sc), __func__, cmd, mn->wcid);
	return mwx_mcu_send_wait(sc, cmd, data, len);
}

int
mt7921_mcu_set_sniffer(struct mwx_softc *sc, int enable)
{
	struct {
		uint8_t		band_idx;
		uint8_t		pad[3];
		struct sniffer_enable_tlv {
			uint16_t	tag;
			uint16_t	len;
			uint8_t		enable;
			uint8_t		pad[3];
		}		enable;
	} req = {
		.band_idx = 0,
		.enable = {
			.tag = htole16(0),
			.len = htole16(sizeof(req.enable)),
			.enable = (uint8_t)enable,
		},
	};

	return mwx_mcu_send_wait(sc, MCU_UNI_CMD_SNIFFER, &req, sizeof(req));
}

int
mt7921_mcu_set_beacon_filter(struct mwx_softc *sc, int enable)
{
	int rv;

	if (enable) {
#ifdef NOTYET
		rv = mt7921_mcu_uni_bss_bcnft(dev, vif, true);
		if (rv)
			return rv;
#endif
		mwx_set(sc, MT_WF_RFCR(0), MT_WF_RFCR_DROP_OTHER_BEACON);
	} else {
		rv = mt7921_mcu_set_bss_pm(sc, 0);
		if (rv)
			return rv;
		mwx_clear(sc, MT_WF_RFCR(0), MT_WF_RFCR_DROP_OTHER_BEACON);
	}
	return 0;
}

int
mt7921_mcu_set_bss_pm(struct mwx_softc *sc, int enable)
{
#ifdef NOTYET
	struct {
		uint8_t		bss_idx;
		uint8_t		dtim_period;
		uint16_t	aid;
		uint16_t	bcn_interval;
		uint16_t	atim_window;
		uint8_t		uapsd;
		uint8_t		bmc_delivered_ac;
		uint8_t		bmc_triggered_ac;
		uint8_t		pad;
	} req = {
		.bss_idx = mvif->mt76.idx,
		.aid = htole16(vif->cfg.aid),
		.dtim_period = vif->bss_conf.dtim_period,
		.bcn_interval = htole16(vif->bss_conf.beacon_int),
	};
#endif
	struct {
		uint8_t		bss_idx;
		uint8_t		pad[3];
	} req_hdr = {
		.bss_idx = /* mvif->mt76.idx XXX */ 0,
	};
	int rv;

	rv = mwx_mcu_send_msg(sc, MCU_CE_CMD_SET_BSS_ABORT,
		&req_hdr, sizeof(req_hdr), NULL);
#ifdef NOTYET
	if (rv != 0 || !enable)
		return rv;
	rv = mwx_mcu_send_msg(sc, MCU_CE_CMD_SET_BSS_CONNECTED,
		&req, sizeof(req), NULL);
#endif
	return rv;
}

#define IEEE80211_NUM_ACS	4
int
mt7921_mcu_set_tx(struct mwx_softc *sc, struct mwx_vif *mvif)
{
	struct edca {
		uint16_t	cw_min;
		uint16_t	cw_max;
		uint16_t	txop;
		uint16_t	aifs;
		uint8_t		guardtime;
		uint8_t		acm;
	} __packed;
	struct mt7921_mcu_tx {
		struct edca	edca[IEEE80211_NUM_ACS];
		uint8_t		bss_idx;
		uint8_t		qos;
		uint8_t		wmm_idx;
		uint8_t		pad;
	} __packed req = {
		.bss_idx = mvif->idx,
		.qos = /* vif->bss_conf.qos */ 0,
		.wmm_idx = mvif->wmm_idx,
	};
#ifdef NOTYET
	struct mu_edca {
		uint8_t		cw_min;
		uint8_t		cw_max;
		uint8_t		aifsn;
		uint8_t		acm;
		uint8_t		timer;
		uint8_t		padding[3];
	};
	struct mt7921_mcu_mu_tx {
		uint8_t		ver;
		uint8_t		pad0;
		uint16_t	len;
		uint8_t		bss_idx;
		uint8_t		qos;
		uint8_t		wmm_idx;
		uint8_t		pad1;
		struct mu_edca	edca[IEEE80211_NUM_ACS];
		uint8_t		pad3[32];
	} __packed req_mu = {
		.bss_idx = mvif->mt76.idx,
		.qos = vif->bss_conf.qos,
		.wmm_idx = mvif->mt76.wmm_idx,
	};
#endif
	static const int to_aci[] = { 1, 0, 2, 3 };
	int ac, rv;

	for (ac = 0; ac < IEEE80211_NUM_ACS; ac++) {
		//struct ieee80211_tx_queue_params *q = &mvif->queue_params[ac];
		struct edca *e = &req.edca[to_aci[ac]];

		e->aifs = htole16(/* q->aifs */ 2);
		e->txop = htole16(/* q->txop */ 0);

#ifdef NOTYET
		if (q->cw_min)
			e->cw_min = htole16(q->cw_min);
		else
#endif
			e->cw_min = htole16(5);

#ifdef NOTYET
		if ( q->cw_max)
			e->cw_max = htole16(q->cw_max);
		else
#endif
			e->cw_max = htole16(10);
	}

	rv = mwx_mcu_send_msg(sc, MCU_CE_CMD_SET_EDCA_PARMS, &req,
	    sizeof(req), NULL);

#ifdef NOTYET
	if (rv)
		return rv;
	if (!vif->bss_conf.he_support)
		return 0;

	for (ac = 0; ac < IEEE80211_NUM_ACS; ac++) {
		struct ieee80211_he_mu_edca_param_ac_rec *q;
		struct mu_edca *e;

		if (!mvif->queue_params[ac].mu_edca)
			break;

		q = &mvif->queue_params[ac].mu_edca_param_rec;
		e = &(req_mu.edca[to_aci[ac]]);

		e->cw_min = q->ecw_min_max & 0xf;
		e->cw_max = (q->ecw_min_max & 0xf0) >> 4;
		e->aifsn = q->aifsn;
		e->timer = q->mu_edca_timer;
	}

	rv = mt76_mcu_send_msg(&dev->mt76, MCU_CE_CMD(SET_MU_EDCA_PARMS),
	    &req_mu, sizeof(req_mu), false);
#endif
	return rv;
}

int
mt7921_mac_fill_rx(struct mwx_softc *sc, struct mbuf *m,
    struct ieee80211_rxinfo *rxi)
{
	struct ieee80211com *ic = &sc->sc_ic;
	uint32_t *rxd, *rxv = NULL;
	uint32_t rxd0, rxd1, rxd2, rxd3, rxd4;
//	uint32_t mode = 0;
	uint16_t hdr_gap /*, seq_ctrl = 0, fc = 0 */;
	uint8_t chfnum, remove_pad /*, qos_ctl = 0, amsdu_info */;
	int idx, unicast, num_rxd = 6;
	int i;
//	bool insert_ccmp_hdr = false;

	if (mbuf_len(m) < num_rxd * sizeof(uint32_t)) {
		if (sc->sc_rx_fill_fail < 64) {
			MWX_DEV_LOG(sc,
			    "rx drop reason=short-rxd len=%zu need=%zu\n",
			    mbuf_len(m), num_rxd * sizeof(uint32_t));
		}
		return -1;
	}

	rxd = mtod(m, uint32_t *);
	rxd0 = le32toh(rxd[0]);
	rxd1 = le32toh(rxd[1]);
	rxd2 = le32toh(rxd[2]);
	rxd3 = le32toh(rxd[3]);
	rxd4 = le32toh(rxd[4]);

	if (rxd1 & MT_RXD1_NORMAL_BAND_IDX) {
		MWX_RX_DROP_LOG(sc, "band-idx", -1, rxd0, rxd1, rxd2,
		    rxd3, rxd4);
		return -1;
	}

	if (rxd2 & MT_RXD2_NORMAL_AMSDU_ERR) {
		MWX_RX_DROP_LOG(sc, "amsdu-err", -1, rxd0, rxd1, rxd2,
		    rxd3, rxd4);
		return -1;
	}

	if (rxd2 & MT_RXD2_NORMAL_HDR_TRANS) {
		MWX_RX_DROP_LOG(sc, "hdr-trans", -1, rxd0, rxd1, rxd2,
		    rxd3, rxd4);
		return -1;
	}

	/* ICV error or CCMP/BIP/WPI MIC error */
	if (rxd1 & MT_RXD1_NORMAL_ICV_ERR) {
		MWX_RX_DROP_LOG(sc, "icv", -1, rxd0, rxd1, rxd2, rxd3,
		    rxd4);
		ic->ic_stats.is_rx_decryptcrc++;
		return -1;
	}

	if (rxd1 & MT_RXD1_NORMAL_FCS_ERR) {
		MWX_RX_DROP_LOG(sc, "fcs", -1, rxd0, rxd1, rxd2, rxd3,
		    rxd4);
		return -1;
	}

	if (rxd1 & MT_RXD1_NORMAL_TKIP_MIC_ERR) {
		/* report MIC failures to net80211 for TKIP */
		MWX_RX_DROP_LOG(sc, "tkip-mic", -1, rxd0, rxd1, rxd2,
		    rxd3, rxd4);
		ic->ic_stats.is_rx_locmicfail++;
		ieee80211_michael_mic_failure(ic, 0/* XXX */);
		return -1;
	}


	chfnum = (rxd3 & MT_RXD3_NORMAL_CH_NUM_MASK) >>
	    MT_RXD3_NORMAL_CH_NUM_SHIFT;
	unicast = (rxd3 & MT_RXD3_NORMAL_ADDR_TYPE_MASK) == MT_RXD3_NORMAL_U2M;
	idx = rxd1 & MT_RXD1_NORMAL_WLAN_IDX_MASK;

#if 0
	status->wcid = mt7921_rx_get_wcid(dev, idx, unicast);
	if (status->wcid) {
		struct mt7921_sta *msta;

		msta = container_of(status->wcid, struct mt7921_sta, wcid);
		spin_lock_bh(&dev->sta_poll_lock);
		if (list_empty(&msta->poll_list))
			list_add_tail(&msta->poll_list, &dev->sta_poll_list);
		spin_unlock_bh(&dev->sta_poll_lock);
	}
#endif

#if NOTYET
	if ((rxd0 & (MT_RXD0_NORMAL_IP_SUM | MT_RXD0_NORMAL_UDP_TCP_SUM)) ==
	    (MT_RXD0_NORMAL_IP_SUM | MT_RXD0_NORMAL_UDP_TCP_SUM)) {
		m->m_pkthdr.csum_flags = M_IPV4_CSUM_IN_OK |
		    M_TCP_CSUM_IN_OK | M_UDP_CSUM_IN_OK;
	}
#endif

	if ((rxd1 & MT_RXD1_NORMAL_SEC_MODE_MASK) != 0 &&
	    !(rxd1 & (MT_RXD1_NORMAL_CLM | MT_RXD1_NORMAL_CM))) {
		rxi->rxi_flags |= IEEE80211_RXI_HWDEC;
	} else if (ic->ic_state == IEEE80211_S_RUN) {
		/* Diagnose why the chip did not decrypt this frame. */
		static uint32_t nodec_log_count;
		if (nodec_log_count < 24) {
			MWX_DEV_LOG(sc,
			    "rx no-hwdec wlan_idx=%u sec_mode=%u cm=%d clm=%d sec_done=%d unicast=%d rxd=%08x/%08x/%08x/%08x\n",
			    rxd1 & MT_RXD1_NORMAL_WLAN_IDX_MASK,
			    (rxd1 & MT_RXD1_NORMAL_SEC_MODE_MASK) >> 16,
			    !!(rxd1 & MT_RXD1_NORMAL_CM),
			    !!(rxd1 & MT_RXD1_NORMAL_CLM),
			    !!(rxd1 & MT_RXD1_NORMAL_SEC_DONE),
			    (rxd3 & MT_RXD3_NORMAL_ADDR_TYPE_MASK) ==
			    MT_RXD3_NORMAL_U2M, rxd0, rxd1, rxd2, rxd3);
			nodec_log_count++;
		}
	}

	remove_pad = (rxd2 & MT_RXD2_NORMAL_HDR_OFFSET_MASK) >>
	    MT_RXD2_NORMAL_HDR_OFFSET_SHIFT;

	if (rxd2 & MT_RXD2_NORMAL_MAX_LEN_ERROR) {
		MWX_RX_DROP_LOG(sc, "max-len", -EINVAL, rxd0, rxd1, rxd2,
		    rxd3, rxd4);
		return -EINVAL;
	}

	rxd += 6;

	if (rxd1 & MT_RXD1_NORMAL_GROUP_4) {
		num_rxd += 4;
		rxd += 4;
	}
	if (rxd1 & MT_RXD1_NORMAL_GROUP_1) {
		num_rxd += 4;
		rxd += 4;
	}
	if (rxd1 & MT_RXD1_NORMAL_GROUP_2) {
		num_rxd += 2;
		rxd += 2;
	}
	if (rxd1 & MT_RXD1_NORMAL_GROUP_3) {	
		uint32_t v0, v1;
		int8_t chain[4], signal;

		rxv = rxd;
		num_rxd += 2;
		rxd += 2;

		v0 = le32toh(rxv[0]); /* XXX not implemented yet */ 
		v1 = le32toh(rxv[1]);
		if ((rxd3 & MT_RXD3_NORMAL_ADDR_TYPE_MASK) == MT_RXD3_NORMAL_U2M)
			mwx_rx_rate_account(v0);

		if (rxd1 & MT_RXD1_NORMAL_GROUP_5) {
			num_rxd += 18;
			rxd += 6;
			rxv = rxd;
			v1 = le32toh(rxv[0]); 
			rxd += 12;
		}
	

		chain[0] = rcpi_to_rssi(MT_PRXV_RCPI0_SHIFT, v1);
		chain[1] = rcpi_to_rssi(MT_PRXV_RCPI1_SHIFT, v1);
		chain[2] = rcpi_to_rssi(MT_PRXV_RCPI2_SHIFT, v1);
		chain[3] = rcpi_to_rssi(MT_PRXV_RCPI3_SHIFT, v1);

		signal = -128;
		for (i = 0; i < sc->sc_capa.num_streams; i++) {
			if (!(sc->sc_capa.antenna_mask & (1U << i)))
				continue;	
			if (chain[i] >= 0)
				continue;
			signal = MAX(signal, chain[i]);
		}
		rxi->rxi_rssi = signal;
		}

	if (mbuf_len(m) < num_rxd * sizeof(uint32_t)) {
		if (sc->sc_rx_fill_fail < 64) {
			MWX_DEV_LOG(sc,
			    "rx drop reason=short-groups len=%zu need=%zu rxd=%08x/%08x/%08x/%08x/%08x\n",
			    mbuf_len(m), num_rxd * sizeof(uint32_t),
			    rxd0, rxd1, rxd2, rxd3, rxd4);
		}
		return -1;
	}

#if 0
	if (rxd1 & MT_RXD1_NORMAL_GROUP_4) {
		uint32_t v0 = le32toh(rxd[0]);
		uint32_t v2 = le32toh(rxd[2]);

		fc = htole16(FIELD_GET(MT_RXD6_FRAME_CONTROL, v0));
		seq_ctrl = FIELD_GET(MT_RXD8_SEQ_CTRL, v2);
		qos_ctl = FIELD_GET(MT_RXD8_QOS_CTL, v2);

		rxd += 4;
	}

	if (rxd1 & MT_RXD1_NORMAL_GROUP_1) {
		u8 *data = (u8 *)rxd;

		if (status->flag & RX_FLAG_DECRYPTED) {
			switch (FIELD_GET(MT_RXD1_NORMAL_SEC_MODE, rxd1)) {
			case MT_CIPHER_AES_CCMP:
			case MT_CIPHER_CCMP_CCX:
			case MT_CIPHER_CCMP_256:
				insert_ccmp_hdr =
					(rxd2 & MT_RXD2_NORMAL_FRAG);
				/* FALLTHROUGH */
			case MT_CIPHER_TKIP:
			case MT_CIPHER_TKIP_NO_MIC:
			case MT_CIPHER_GCMP:
			case MT_CIPHER_GCMP_256:
				status->iv[0] = data[5];
				status->iv[1] = data[4];
				status->iv[2] = data[3];
				status->iv[3] = data[2];
				status->iv[4] = data[1];
				status->iv[5] = data[0];
				break;
			default:
				break;
			}
		}
		rxd += 4;
	}

	if (rxd1 & MT_RXD1_NORMAL_GROUP_2) {
		status->timestamp = le32_to_cpu(rxd[0]);
		status->flag |= RX_FLAG_MACTIME_START;

		if (!(rxd2 & MT_RXD2_NORMAL_NON_AMPDU)) {
			status->flag |= RX_FLAG_AMPDU_DETAILS;

			/* all subframes of an A-MPDU have the same timestamp */
			if (phy->rx_ampdu_ts != status->timestamp) {
				if (!++phy->ampdu_ref)
					phy->ampdu_ref++;
			}
			phy->rx_ampdu_ts = status->timestamp;

			status->ampdu_ref = phy->ampdu_ref;
		}

		rxd += 2;
	}

	/* RXD Group 3 - P-RXV */
	if (rxd1 & MT_RXD1_NORMAL_GROUP_3) {
		u8 stbc, gi;
		u32 v0, v1;
		bool cck;

		rxv = rxd;
		rxd += 2;

		v0 = le32_to_cpu(rxv[0]);
		v1 = le32_to_cpu(rxv[1]);

		if (v0 & MT_PRXV_HT_AD_CODE)
			status->enc_flags |= RX_ENC_FLAG_LDPC;

		status->chains = mphy->antenna_mask;
		status->chain_signal[0] = to_rssi(MT_PRXV_RCPI0, v1);
		status->chain_signal[1] = to_rssi(MT_PRXV_RCPI1, v1);
		status->chain_signal[2] = to_rssi(MT_PRXV_RCPI2, v1);
		status->chain_signal[3] = to_rssi(MT_PRXV_RCPI3, v1);
		status->signal = -128;
		for (i = 0; i < hweight8(mphy->antenna_mask); i++) {
			if (!(status->chains & BIT(i)) ||
			    status->chain_signal[i] >= 0)
				continue;

			status->signal = max(status->signal,
					     status->chain_signal[i]);
		}

		stbc = FIELD_GET(MT_PRXV_STBC, v0);
		gi = FIELD_GET(MT_PRXV_SGI, v0);
		cck = false;

		idx = i = FIELD_GET(MT_PRXV_TX_RATE, v0);
		mode = FIELD_GET(MT_PRXV_TX_MODE, v0);

		switch (mode) {
		case MT_PHY_TYPE_CCK:
			cck = true;
			fallthrough;
		case MT_PHY_TYPE_OFDM:
			i = mt76_get_rate(&dev->mt76, sband, i, cck);
			break;
		case MT_PHY_TYPE_HT_GF:
		case MT_PHY_TYPE_HT:
			status->encoding = RX_ENC_HT;
			if (i > 31)
				return -EINVAL;
			break;
		case MT_PHY_TYPE_VHT:
			status->nss =
				FIELD_GET(MT_PRXV_NSTS, v0) + 1;
			status->encoding = RX_ENC_VHT;
			if (i > 9)
				return -EINVAL;
			break;
		case MT_PHY_TYPE_HE_MU:
		case MT_PHY_TYPE_HE_SU:
		case MT_PHY_TYPE_HE_EXT_SU:
		case MT_PHY_TYPE_HE_TB:
			status->nss =
				FIELD_GET(MT_PRXV_NSTS, v0) + 1;
			status->encoding = RX_ENC_HE;
			i &= GENMASK(3, 0);

			if (gi <= NL80211_RATE_INFO_HE_GI_3_2)
				status->he_gi = gi;

			status->he_dcm = !!(idx & MT_PRXV_TX_DCM);
			break;
		default:
			return -EINVAL;
		}

		status->rate_idx = i;

		switch (FIELD_GET(MT_PRXV_FRAME_MODE, v0)) {
		case IEEE80211_STA_RX_BW_20:
			break;
		case IEEE80211_STA_RX_BW_40:
			if (mode & MT_PHY_TYPE_HE_EXT_SU &&
			    (idx & MT_PRXV_TX_ER_SU_106T)) {
				status->bw = RATE_INFO_BW_HE_RU;
				status->he_ru =
					NL80211_RATE_INFO_HE_RU_ALLOC_106;
			} else {
				status->bw = RATE_INFO_BW_40;
			}
			break;
		case IEEE80211_STA_RX_BW_80:
			status->bw = RATE_INFO_BW_80;
			break;
		case IEEE80211_STA_RX_BW_160:
			status->bw = RATE_INFO_BW_160;
			break;
		default:
			return -EINVAL;
		}

		status->enc_flags |= RX_ENC_FLAG_STBC_MASK * stbc;
		if (mode < MT_PHY_TYPE_HE_SU && gi)
			status->enc_flags |= RX_ENC_FLAG_SHORT_GI;

		if (rxd1 & MT_RXD1_NORMAL_GROUP_5) {
			rxd += 18;
		}
	}

	amsdu_info = FIELD_GET(MT_RXD4_NORMAL_PAYLOAD_FORMAT, rxd4);
	status->amsdu = !!amsdu_info;
	if (status->amsdu) {
		status->first_amsdu = amsdu_info == MT_RXD4_FIRST_AMSDU_FRAME;
		status->last_amsdu = amsdu_info == MT_RXD4_LAST_AMSDU_FRAME;
	}
#endif

	hdr_gap = num_rxd * sizeof(uint32_t) + 2 * remove_pad;
	if (mbuf_len(m) < hdr_gap + sizeof(struct ieee80211_frame_min)) {
		if (sc->sc_rx_fill_fail < 64) {
			MWX_DEV_LOG(sc,
			    "rx drop reason=short-80211 len=%zu hdr_gap=%u rxd=%08x/%08x/%08x/%08x/%08x\n",
			    mbuf_len(m), hdr_gap, rxd0, rxd1, rxd2, rxd3,
			    rxd4);
		}
		return -1;
	}
	m_adj(m, hdr_gap);
#if 0
	if (status->amsdu) {
		memmove(skb->data + 2, skb->data,
			ieee80211_get_hdrlen_from_skb(skb));
		skb_pull(skb, 2);
	}

	struct ieee80211_hdr *hdr;

	if (insert_ccmp_hdr) {
		u8 key_id = FIELD_GET(MT_RXD1_NORMAL_KEY_ID, rxd1);

		mt76_insert_ccmp_hdr(skb, key_id);
	}

	hdr = mt76_skb_get_hdr(skb);
	fc = hdr->frame_control;
	if (ieee80211_is_data_qos(fc)) {
		seq_ctrl = le16_to_cpu(hdr->seq_ctrl);
		qos_ctl = *ieee80211_get_qos_ctl(hdr);
	}

	if (!status->wcid || !ieee80211_is_data_qos(fc))
		return 0;

	status->aggr = unicast && !ieee80211_is_qos_nullfunc(fc);
	status->seqno = IEEE80211_SEQ_TO_SN(seq_ctrl);
	status->qos_ctl = qos_ctl;
#endif
	rxi->rxi_chan = chfnum;

	if (rxi->rxi_flags & IEEE80211_RXI_HWDEC) {
		/*
		 * MT7921/MT7922 firmware decrypts and removes CCMP IV/MIC.
		 * Leave the protected bit clear so net80211 does not try to
		 * strip an IV which is no longer present.
		 */
		struct ieee80211_frame *wh;

		wh = mtod(m, struct ieee80211_frame *);
		wh->i_fc[1] &= ~IEEE80211_FC1_PROTECTED;
	}

	return 0;
}

uint32_t
mt7921_mac_tx_rate_val(struct mwx_softc *sc)
{
	int rateidx = 0, offset = 4;
	uint32_t rate, mode;

	/* XXX TODO basic_rates
	rateidx = ffs(vif->bss_conf.basic_rates) - 1;
	*/

	if (IEEE80211_IS_CHAN_2GHZ(sc->sc_ic.ic_bss->ni_chan))
		offset = 0;
	/* pick the lowest rate for hidden nodes */
	if (rateidx < 0)
		rateidx = 0;

	rateidx += offset;

	if (rateidx >= nitems(mt76_rates))
		rateidx = offset;

	rate =  mt76_rates[rateidx].hw_value;
	mode = (rate >> 8) << MT_TX_RATE_MODE_SHIFT;
	rate &= 0xff;

	return (rate & MT_TX_RATE_IDX_MASK) | (mode & MT_TX_RATE_MODE_MASK);
}

void
mt7921_mac_write_txwi_80211(struct mwx_softc *sc, struct mbuf *m,
    struct ieee80211_node *ni, struct mt76_txwi *txp)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct ieee80211_frame *wh;
	uint32_t val;
	uint8_t type, subtype, tid = 0;
	u_int hdrlen;
	int multicast;


	wh = mtod(m, struct ieee80211_frame *);
	type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
	type >>= IEEE80211_FC0_TYPE_SHIFT;
	subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
	subtype >>= IEEE80211_FC0_SUBTYPE_SHIFT;
	multicast = IEEE80211_IS_MULTICAST(wh->i_addr1);

	if (type == IEEE80211_FC0_TYPE_CTL)
		hdrlen = sizeof(struct ieee80211_frame_min);
	else
		hdrlen = ieee80211_get_hdrlen(wh);

	/* Put QoS frames on the data queue which maps to their TID. */
	if (ieee80211_has_qos(wh)) {
		uint16_t qos = ieee80211_get_qos(wh);

		tid = qos & IEEE80211_QOS_TID;
	}

	/*
	 * Like Linux: aggregate only TIDs with a TX Block Ack agreement, and
	 * let the MAC build A-MSDUs where the AP allowed A-MSDU in A-MPDU.
	 */
	if (type == (IEEE80211_FC0_TYPE_DATA >> IEEE80211_FC0_TYPE_SHIFT) &&
	    !multicast) {
		struct ieee80211_tx_ba *ba = ieee80211_has_qos(wh) && tid < 8 ?
		    &ni->ni_tx_ba[tid] : NULL;

		if (ba == NULL || ba->ba_state != IEEE80211_BA_AGREED)
			txp->txwi[3] |= htole32(MT_TXD3_BA_DISABLE);
		else if (sc->sc_tx_amsdu &&
		    (ba->ba_params & IEEE80211_ADDBA_AMSDU))
			txp->txwi[7] |= htole32(MT_TXD7_HW_AMSDU);
	}

#ifdef NOTYET
	if (ieee80211_is_action(fc) &&
	    mgmt->u.action.category == WLAN_CATEGORY_BACK &&
	    mgmt->u.action.u.addba_req.action_code == WLAN_ACTION_ADDBA_REQ) {
		u16 capab = le16_to_cpu(mgmt->u.action.u.addba_req.capab);

		txp->txwi[5] |= htole32(MT_TXD5_ADD_BA);
		tid = (capab >> 2) & IEEE80211_QOS_CTL_TID_MASK;
	} else if (ieee80211_is_back_req(hdr->frame_control)) {
		struct ieee80211_bar *bar = (struct ieee80211_bar *)hdr;
		u16 control = le16_to_cpu(bar->control);

		tid = FIELD_GET(IEEE80211_BAR_CTRL_TID_INFO_MASK, control);
	}
#endif

	/* Let the firmware know about our ADDBA requests (as Linux does). */
	if (type == (IEEE80211_FC0_TYPE_MGT >> IEEE80211_FC0_TYPE_SHIFT) &&
	    subtype == (IEEE80211_FC0_SUBTYPE_ACTION >>
	    IEEE80211_FC0_SUBTYPE_SHIFT) &&
	    mbuf_len(m) >= hdrlen + 5) {
		uint8_t *act = mtod(m, uint8_t *) + hdrlen;
		if (act[0] == IEEE80211_CATEG_BA &&
		    act[1] == IEEE80211_ACTION_ADDBA_REQ) {
			uint16_t capab = act[3] | (act[4] << 8);
			txp->txwi[5] |= htole32(MT_TXD5_ADD_BA);
			tid = (capab >> 2) & 0xf;
		}
	}

	val = MT_HDR_FORMAT_802_11 | MT_TXD1_HDR_INFO(hdrlen / 2) |
	    MT_TXD1_TID(tid);
	txp->txwi[1] |= htole32(val);

	val = MT_TXD2_FRAME_TYPE(type) | MT_TXD2_SUB_TYPE(subtype);
	if (multicast)
		val |= MT_TXD2_MULTICAST;

#ifdef NOTYET
	if (key && multicast && ieee80211_is_robust_mgmt_frame(skb) &&
	    key->cipher == WLAN_CIPHER_SUITE_AES_CMAC) {
		val |= MT_TXD2_BIP;
		txp->txwi[3] &= ~htole32(MT_TXD3_PROTECT_FRAME);
	}
#endif

	if (multicast || type != IEEE80211_FC0_TYPE_DATA) {
		/* Fixed rata is available just for 802.11 txd */
		uint32_t rate, val6;

		val |= MT_TXD2_FIX_RATE;
		/* hardware won't add HTC for mgmt/ctrl frame */
		val |= htole32(MT_TXD2_HTC_VLD);

		rate = mt7921_mac_tx_rate_val(sc);

		val6 = MT_TXD6_FIXED_BW;
		val6 |= (rate << MT_TXD6_TX_RATE_SHIFT) & MT_TXD6_TX_RATE_MASK;
		txp->txwi[6] |= htole32(val6);
		txp->txwi[3] |= htole32(MT_TXD3_BA_DISABLE);
	}

	txp->txwi[2] |= htole32(val);

#ifdef NOTYET
	if (ieee80211_is_beacon(fc)) {
		txp->txwi[3] &= ~htole32(MT_TXD3_SW_POWER_MGMT);
		txp->txwi[3] |= htole32(MT_TXD3_REM_TX_COUNT);
	}

	if (info->flags & IEEE80211_TX_CTL_INJECTED) {
		u16 seqno = le16_to_cpu(hdr->seq_ctrl);

		if (ieee80211_is_back_req(hdr->frame_control)) {
			struct ieee80211_bar *bar;

			bar = (struct ieee80211_bar *)skb->data;
			seqno = le16_to_cpu(bar->start_seq_num);
		}

		val = MT_TXD3_SN_VALID |
			FIELD_PREP(MT_TXD3_SEQ, IEEE80211_SEQ_TO_SN(seqno));
		txp->txwi[3] |= htole32(val);
		txp->txwi[7] &= ~htole32(MT_TXD7_HW_AMSDU);
	}
#endif

	val = MT_TXD7_TYPE(type) | MT_TXD7_SUB_TYPE(subtype);
	txp->txwi[7] |= htole32(val);

#if NBPFILTER > 0
	if (__predict_false(sc->sc_drvbpf != NULL)) {
		struct mwx_tx_radiotap_header *tap = &sc->sc_txtap;
		uint16_t chan_flags;

		tap->wt_flags = 0;
		tap->wt_chan_freq = htole16(ni->ni_chan->ic_freq);
		chan_flags = ni->ni_chan->ic_flags;
		if (ic->ic_curmode != IEEE80211_MODE_11N &&
			ic->ic_curmode != IEEE80211_MODE_11AC) {
			chan_flags &= ~IEEE80211_CHAN_HT;
			chan_flags &= ~IEEE80211_CHAN_40MHZ;
		}
		if (ic->ic_curmode != IEEE80211_MODE_11AC)
			chan_flags &= ~IEEE80211_CHAN_VHT;
		tap->wt_chan_flags = htole16(chan_flags);
#ifdef NOTYET
		if ((ni->ni_flags & IEEE80211_NODE_HT) &&
		    !IEEE80211_IS_MULTICAST(wh->i_addr1) &&
		    type == IEEE80211_FC0_TYPE_DATA &&
		    rinfo->ht_plcp != MWX_RATE_HT_SISO_MCS_INV_PLCP) {
			tap->wt_rate = (0x80 | rinfo->ht_plcp);
		} else
			tap->wt_rate = rinfo->rate;
#endif
		tap->wt_rate = 2;
		if ((ic->ic_flags & IEEE80211_F_WEPON) &&
		    (wh->i_fc[1] & IEEE80211_FC1_PROTECTED))
			tap->wt_flags |= IEEE80211_RADIOTAP_F_WEP;

		bpf_mtap_hdr(sc->sc_drvbpf, tap, sc->sc_txtap_len,
		    m, BPF_DIRECTION_OUT);
	}
#endif

}

static inline uint8_t
mt7921_lmac_mapping(uint8_t ac)
{
	/* LMAC uses the reverse order of mac80211 AC indexes */
	return 3 - ac;
}

void
mt7921_mac_write_txwi(struct mwx_softc *sc, struct mbuf *m,
    struct ieee80211_node *ni, struct mt76_txwi *txp)
{
	struct mwx_node *mn = (struct mwx_node *)ni;
	struct ieee80211_frame *wh;
	uint32_t val, p_fmt, omac_idx;
	uint8_t q_idx, wmm_idx, band_idx;
	uint8_t phy_idx = 0;
	/*
	 * No per-frame TX status: TXWIs are released by the TX free event,
	 * and a TXS event for every frame only loaded the RX ring (Linux
	 * asks for status only when mac80211 needs it).
	 */
	int pid = MT_PACKET_ID_NO_SKB;
	enum mt76_txq_id qid = MT_TXQ_BE;
	/* mac80211 AC index (VO=0, VI=1, BE=2, BK=3) of the hardware queue */
	uint8_t ac = 0;

	wh = mtod(m, struct ieee80211_frame *);
	/*
	 * Data goes to the queue of its access category; management and
	 * control frames stay on VO, like mac80211. Everything used to go to
	 * VO, where the hardware does not aggregate best-effort traffic well.
	 */
	if ((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_DATA) {
		static const uint8_t tid_to_ac[8] = { 2, 3, 3, 2, 1, 1, 0, 0 };

		ac = ieee80211_has_qos(wh) ?
		    tid_to_ac[ieee80211_get_qos(wh) & IEEE80211_QOS_TID & 7] : 2;
	}
	omac_idx = sc->sc_vif.omac_idx << MT_TXD1_OWN_MAC_SHIFT;
	wmm_idx = sc->sc_vif.wmm_idx;
	band_idx = sc->sc_vif.band_idx;

	if (qid >= MT_TXQ_PSD) {
		p_fmt = MT_TX_TYPE_CT;
		q_idx = MT_LMAC_ALTX0;
	} else {
		p_fmt = MT_TX_TYPE_CT;
		q_idx = wmm_idx * MWX_MAX_WMM_SETS + mt7921_lmac_mapping(ac);

#ifdef NOTYET
		/* counting non-offloading skbs */
		wcid->stats.tx_bytes += skb->len;
		wcid->stats.tx_packets++;
#endif
	}

	val = ((mbuf_pkthdr_len(m) + MT_TXD_SIZE) & MT_TXD0_TX_BYTES_MASK) |
		p_fmt | MT_TXD0_Q_IDX(q_idx);
	txp->txwi[0] = htole32(val);

	val = MT_TXD1_LONG_FORMAT | (mn->wcid & MT_TXD1_WLAN_IDX_MASK) |
	    (omac_idx & MT_TXD1_OWN_MAC_MASK);
	if (phy_idx || band_idx)
		val |= MT_TXD1_TGID;
	txp->txwi[1] = htole32(val);
	txp->txwi[2] = 0;

	val = 15 << MT_TXD3_REM_TX_COUNT_SHIFT;
	if (wh->i_fc[1] & IEEE80211_FC1_PROTECTED)
		val |= MT_TXD3_PROTECT_FRAME;
#ifdef NOTYET
	if (info->flags & IEEE80211_TX_CTL_NO_ACK)
		val |= MT_TXD3_NO_ACK;
#endif
	txp->txwi[3] = htole32(val);
	txp->txwi[4] = 0;

	val = pid & MT_TXD5_PID;
	if (pid >= MT_PACKET_ID_FIRST)
		val |= MT_TXD5_TX_STATUS_HOST;
	txp->txwi[5] = htole32(val);
	txp->txwi[6] = 0;
	txp->txwi[7] = /* XXX wcid->amsdu ? htole32(MT_TXD7_HW_AMSDU) : */ 0;

#ifdef NOTYET
	if (is_8023)
		mt76_connac2_mac_write_txwi_8023(txp, m, wcid);
	else
#endif
		mt7921_mac_write_txwi_80211(sc, m, ni, txp);
}

void
mwx_mac_tx_free(struct mwx_softc *sc, struct mbuf *m)
{
	struct mwx_txwi *mt;
	uint32_t *txfree;
	uint32_t txval;
	int count, i;

	mwx_dma_tx_cleanup(sc, &sc->sc_txq);

	/* Both the event header and each PAIR/MSDU word must be present. */
	if (mbuf_pkthdr_len(m) < 2 * sizeof(txval))
		goto out;

	if ((m = m_pullup(m, mbuf_pkthdr_len(m))) == NULL)
		return;

	txfree = mtod(m, uint32_t *);
	txval = le32toh(txfree[0]);
	m_adj(m, 2 * sizeof(txval));

	count = MT_TX_FREE0_MSDU_CNT_GET(txval);

	if (count * sizeof(txval) > mbuf_len(m))
		goto out;

	txfree = mtod(m, uint32_t *);
	for (i = 0; i < count; i++) {
		uint16_t msdu;

		/* PAIR words extend count, but never the received payload. */
		if ((size_t)i >= mbuf_len(m) / sizeof(*txfree))
			break;
		txval = le32toh(txfree[i]);
		if (txval & MT_TX_FREE_PAIR) {
			count++;
			continue;
		}

		msdu = MT_TX_FREE_MSDU_ID_GET(txval);
		if (msdu >= sc->sc_txwi.mt_count)
			continue;
		mt = &sc->sc_txwi.mt_data[msdu];
		if (mt->mt_busy == 0)
			continue;
		mwx_txwi_put(sc, mt);
	}

out:
	m_freem(m);
	mwx_tx_kick(sc);
}

int
mt7921_set_channel(struct mwx_softc *sc)
{
	int rv;

	/* stop queues, block other configs (MT76_RESET) */
	// XXX NOTYET mt76_set_channel(sc);

	rv = mt7921_mcu_set_chan_info(sc, MCU_EXT_CMD_CHANNEL_SWITCH);
	if (rv)
		return rv;
	mt7921_mac_set_timing(sc);
	mt7921_mac_reset_counters(sc);

	/* restart queues */
	return 0;
}

uint8_t
mt7921_get_phy_mode_v2(struct mwx_softc *sc, struct ieee80211_node *ni)
{
	uint8_t mode = 0;

	if (ni == NULL)
		ni = sc->sc_ic.ic_bss;

	if (IEEE80211_IS_CHAN_2GHZ(ni->ni_chan)) {
		mode |= PHY_TYPE_BIT_HR_DSSS | PHY_TYPE_BIT_ERP;
		if (ieee80211_node_supports_ht(ni))
			mode |= PHY_TYPE_BIT_HT;
#ifdef NOTYET
		if (ieee80211_node_supports_he(ni))
			mode |= PHY_TYPE_BIT_HE;
#endif
	} else if (IEEE80211_IS_CHAN_5GHZ(ni->ni_chan) /* || CHAN_6GHZ */) {
		mode |= PHY_TYPE_BIT_OFDM;
		if (ieee80211_node_supports_ht(ni))
			mode |= PHY_TYPE_BIT_HT;
		/* only once VHT is actually negotiated (not just supported) */
		if (ni->ni_flags & IEEE80211_NODE_VHT)
			mode |= PHY_TYPE_BIT_VHT;
#ifdef NOTYET
		if (ieee80211_node_supports_he(ni))
			mode |= PHY_TYPE_BIT_HE;
#endif
	}
	return mode;
}

struct mbuf *
mwx_alloc_sta_req_tlv(int len)
{
	struct mbuf *m;

	/* Allocate mbuf cluster with enough space */
	m = MCLGETL(NULL, M_DONTWAIT, MCLBYTES);
	if (m == NULL)
		return NULL;

	/* align to have space for the mcu header */
	mbuf_setdata(m, (uint8_t *)mbuf_data(m) + sizeof(struct mwx_mcu_txd) + len, 0);
	mbuf_setlen(m, 0);
	mbuf_pkthdr_setlen(m, 0);

	return m;
}

void *
mwx_append_len(struct mbuf *m, int len)
{
	caddr_t p;
	size_t oldlen;

	KASSERT(m_trailingspace(m) >= len);

	oldlen = mbuf_len(m);
	p = mtod(m, caddr_t) + oldlen;
	mbuf_setlen(m, oldlen + len);
	mbuf_pkthdr_setlen(m, mbuf_len(m));
	memset(p, 0, len);

	return p;
}

/*
 * Reserve len bytes at the end of mbuf m, return to start of that area
 * after initializing the data. It also sets the tag and len hdr.
 */
void *
mwx_append_tlv(struct mbuf *m, uint16_t *tlvnum, int tag, int len)
{
	struct {
		uint16_t	tag;
		uint16_t	len;
	} tlv = {
		.tag = htole16(tag),
		.len = htole16(len),
	};
	caddr_t p;

	p = (caddr_t)mwx_append_len(m, len);
	memcpy(p, &tlv, sizeof(tlv));

	*tlvnum += 1;

	return p;
}

struct mbuf *
mwx_fill_sta_req_hdr(struct mbuf *m, struct mwx_vif *mvif,
    uint8_t muar_idx, uint16_t wcid, uint16_t tlvnum)
{
	struct sta_req_hdr *hdr;

	KASSERT(m_leadingspace(m) >= sizeof(struct sta_req_hdr));
	m = m_prepend(m, sizeof(struct sta_req_hdr), M_DONTWAIT);
	if (m == NULL)
		return NULL;
	hdr = mtod(m, struct sta_req_hdr *);
	memset(hdr, 0, sizeof(struct sta_req_hdr));

	hdr->bss_idx = mvif->idx;
	hdr->wlan_idx_lo = wcid & 0xff;
	hdr->wlan_idx_hi = wcid >> 8;
	hdr->muar_idx = muar_idx;
	hdr->is_tlv_append = 1;
	hdr->tlv_num = htole16(tlvnum);
	return m;
}

void
mt7921_mcu_add_basic_tlv(struct mbuf *m, uint16_t *tlvnum, struct mwx_softc *sc,
    struct ieee80211_node *ni, int add, int isnew)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct sta_rec_basic *basic;

	basic = (struct sta_rec_basic *)mwx_append_tlv(m, tlvnum,
	    STA_REC_BASIC, sizeof(*basic));

	basic->extra_info = htole16(EXTRA_INFO_VER);
	if (add) {
		if (isnew)
			basic->extra_info |= htole16(EXTRA_INFO_NEW);
		basic->conn_state = CONN_STATE_PORT_SECURE;
	} else {
		basic->conn_state = CONN_STATE_DISCONNECT;
	}

	if (ni == NULL) {
		basic->conn_type = htole32(STA_TYPE_BC | NETWORK_INFRA);
		memset(basic->peer_addr, 0xff, sizeof(basic->peer_addr));
		return;
	}

	switch (ic->ic_opmode) {
#ifndef IEEE80211_STA_ONLY
	case IEEE80211_M_HOSTAP:
		basic->conn_type = htole32(STA_TYPE_STA | NETWORK_INFRA);
		break;
#endif
	case IEEE80211_M_STA:
		basic->conn_type = htole32(STA_TYPE_AP | NETWORK_INFRA);
		break;
#ifndef IEEE80211_STA_ONLY
	case IEEE80211_M_IBSS:
	case IEEE80211_M_AHDEMO:
		basic->conn_type = htole32(STA_TYPE_ADHOC | NETWORK_IBSS);
		break;
#endif
	case IEEE80211_M_MONITOR:
		panic("mt7921_mcu_sta_basic_tlv unexpected operation mode");
	}

	basic->aid = htole16(IEEE80211_AID(ni->ni_associd));
	memcpy(basic->peer_addr, ni->ni_macaddr, IEEE80211_ADDR_LEN);
	basic->qos = (ni->ni_flags & IEEE80211_NODE_QOS) != 0;
}

void
mt7921_mcu_add_sta_tlv(struct mbuf *m, uint16_t *tlvnum, struct mwx_softc *sc,
    struct ieee80211_node *ni, int add, int isnew)
{
	//struct ieee80211com *ic = &sc->sc_ic;
	struct sta_rec_ra_info *ra_info;
	struct sta_rec_state *state;
	struct sta_rec_phy *phy;
	uint16_t supp_rates;

#ifdef NOTYET
	/* sta rec ht */
	if (sta->deflink.ht_cap.ht_supported) {
		struct sta_rec_ht *ht;

		ht = mwx_append_tlv(m, tlvnum, STA_REC_HT, sizeof(*ht));
		ht->ht_cap = htole16(sta->deflink.ht_cap.cap);
	}

	/* sta rec vht */
	if (sta->deflink.vht_cap.vht_supported) {
		struct sta_rec_vht *vht;

		vht = mwx_append_tlv(m, tlvnum, STA_REC_VHT,
		    sizeof(*vht));
		vht->vht_cap = htole32(sta->deflink.vht_cap.cap);
		vht->vht_rx_mcs_map = sta->deflink.vht_cap.vht_mcs.rx_mcs_map;
		vht->vht_tx_mcs_map = sta->deflink.vht_cap.vht_mcs.tx_mcs_map;
	}

	/* sta rec uapsd */
	/* from function:
		if (vif->type != NL80211_IFTYPE_AP || !sta->wme)
			return;
	*/
	mt7921_mcu_sta_uapsd(m, tlvnum, vif, ni);
#endif

#ifdef NOTYET
	if (sta->deflink.ht_cap.ht_supported || sta->deflink.he_cap.has_he)
		mt76_connac_mcu_sta_amsdu_tlv(skb, sta, vif);

	/* sta rec he */
	if (sta->deflink.he_cap.has_he) {
		mt76_connac_mcu_sta_he_tlv(skb, sta);
		if (band == NL80211_BAND_6GHZ &&
		    sta_state == MT76_STA_INFO_STATE_ASSOC) {
			struct sta_rec_he_6g_capa *he_6g_capa;

			he_6g_capa = mwx_append_tlv(m, tlvnum,
			    STA_REC_HE_6G, sizeof(*he_6g_capa));
			he_6g_capa->capa = sta->deflink.he_6ghz_capa.capa;
		}
	}
#endif

	phy = (struct sta_rec_phy *)mwx_append_tlv(m, tlvnum, STA_REC_PHY,
	    sizeof(*phy));
	/* XXX basic_rates: bitmap of basic rates, each bit stands for an
	 *      index into the rate table configured by the driver in
	 *      the current band.
	 */
	phy->basic_rate = htole16(0x0150); /* XXX */
	phy->phy_type = mt7921_get_phy_mode_v2(sc, ni);
#ifdef NOTYET
	phy->ampdu = FIELD_PREP(IEEE80211_HT_AMPDU_PARM_FACTOR,
	    sta->deflink.ht_cap.ampdu_factor) |
	    FIELD_PREP(IEEE80211_HT_AMPDU_PARM_DENSITY,
	    sta->deflink.ht_cap.ampdu_density);
#endif
	// XXX phy->rcpi = rssi_to_rcpi(-ewma_rssi_read(&sc->sc_vif.rssi));
	phy->rcpi = 0xdc;	/* XXX STOLEN FROM LINUX DUMP */

#ifdef HACK
	supp_rates = sta->deflink.supp_rates[band];
	if (band == NL80211_BAND_2GHZ)
		supp_rates = FIELD_PREP(RA_LEGACY_OFDM, supp_rates >> 4) |
		FIELD_PREP(RA_LEGACY_CCK, supp_rates & 0xf);
	else
		supp_rates = FIELD_PREP(RA_LEGACY_OFDM, supp_rates);
#else
	supp_rates = RA_LEGACY_OFDM;
#endif

	ra_info = (struct sta_rec_ra_info *)mwx_append_tlv(m, tlvnum,
	    STA_REC_RA, sizeof(*ra_info));
	ra_info->legacy = htole16(supp_rates);
#ifdef NOTYET
	if (sta->deflink.ht_cap.ht_supported)
		memcpy(ra_info->rx_mcs_bitmask,
			sta->deflink.ht_cap.mcs.rx_mask,
			HT_MCS_MASK_NUM);
#endif

	state = (struct sta_rec_state *)mwx_append_tlv(m, tlvnum,
	    STA_REC_STATE, sizeof(*state));
	state->state = /* XXX sta_state */ 0;
#ifdef NOTYET
	if (sta->deflink.vht_cap.vht_supported) {
		state->vht_opmode = sta->deflink.bandwidth;
		state->vht_opmode |= (sta->deflink.rx_nss - 1) <<
			IEEE80211_OPMODE_NOTIF_RX_NSS_SHIFT;
	}
#endif
}

int
mt7921_mcu_wtbl_generic_tlv(struct mbuf *m, uint16_t *tlvnum,
    struct mwx_softc *sc, struct ieee80211_node *ni)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct wtbl_generic *generic;
	struct wtbl_rx *rx;

	generic = (struct wtbl_generic *)mwx_append_tlv(m, tlvnum,
	    WTBL_GENERIC, sizeof(*generic));

	if (ni) {
		generic->partial_aid = htole16(IEEE80211_AID(ni->ni_associd));
		memcpy(generic->peer_addr, ni->ni_macaddr, IEEE80211_ADDR_LEN);
		generic->muar_idx = sc->sc_vif.omac_idx;
		generic->qos = (ni->ni_flags & IEEE80211_NODE_QOS) != 0;
	} else {
		memset(generic->peer_addr, 0xff, IEEE80211_ADDR_LEN);
		generic->muar_idx = 0xe;
	}

	rx = (struct wtbl_rx *)mwx_append_tlv(m, tlvnum, WTBL_RX,
	    sizeof(*rx));
#ifndef IEEE80211_STA_ONLY
	rx->rca1 = ni ? ic->ic_opmode != IEEE80211_M_HOSTAP : 1;
#else
	rx->rca1 = 1;
#endif
	rx->rca2 = 1;
	rx->rv = 1;

	return sizeof(*generic) + sizeof(*rx);
}

int
mt7921_mcu_wtbl_hdr_trans_tlv(struct mbuf *m, uint16_t *tlvnum,
    struct mwx_softc *sc, struct ieee80211_node *ni)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct wtbl_hdr_trans *htr;

	htr = (struct wtbl_hdr_trans *)mwx_append_tlv(m, tlvnum,
	    WTBL_HDR_TRANS, sizeof(*htr));

	/* no hdr decapsulation offload */
	htr->no_rx_trans = 1;

	if (ic->ic_opmode == IEEE80211_M_STA)
		htr->to_ds = 1;
	else
		htr->from_ds = 1;

	return sizeof(*htr);
}

int
mt7921_mcu_wtbl_ht_tlv(struct mbuf *m, uint16_t *tlvnum,
    struct mwx_softc *sc, struct ieee80211_node *ni)
{
	struct wtbl_smps *smps;

	/* XXX lots missing here */

	smps = (struct wtbl_smps *)mwx_append_tlv(m, tlvnum, WTBL_SMPS,
	    sizeof(*smps));
	/* spatial multiplexing power save mode, off for now */
	//smps->smps = (sta->deflink.smps_mode == IEEE80211_SMPS_DYNAMIC);

	return sizeof(*smps);
}

int
mt7921_mac_sta_update(struct mwx_softc *sc, struct ieee80211_node *ni,
    int add, int isnew)
{
	struct mwx_node *mw = (struct mwx_node *)ni;
	struct mwx_vif *mvif = &sc->sc_vif;
	struct sta_rec_wtbl *wtbl;
	struct mbuf *m = NULL;
	uint16_t tlvnum = 0, wnum = 0;
	int wlen = 0;

	m = mwx_alloc_sta_req_tlv(sizeof(struct sta_req_hdr));
	if (m == NULL)
		return ENOBUFS;

	if (ni != NULL)
		mt7921_mcu_add_basic_tlv(m, &tlvnum, sc, ni, add, isnew);

	if (ni != NULL && add)
		mt7921_mcu_add_sta_tlv(m, &tlvnum, sc, ni, add, isnew);

	wtbl = (struct sta_rec_wtbl *)mwx_append_tlv(m, &tlvnum,
	    STA_REC_WTBL, sizeof(*wtbl));
	wtbl->wlan_idx_lo = mw ? mw->wcid & 0xff : 0;
	wtbl->wlan_idx_hi = mw ? mw->wcid >> 8 : 0;
	wtbl->operation = WTBL_RESET_AND_SET;

	if (add) {
		wlen += mt7921_mcu_wtbl_generic_tlv(m, &wnum, sc, ni);
		wlen += mt7921_mcu_wtbl_hdr_trans_tlv(m, &wnum, sc, ni);

		if (ni)
			wlen += mt7921_mcu_wtbl_ht_tlv(m, &wnum, sc, ni);
	}

	wtbl->tlv_num = htole16(wnum);
	wtbl->len = htole16(le16toh(wtbl->len) + wlen);

	m = mwx_fill_sta_req_hdr(m, mvif, ni ? mvif->omac_idx : 0,
	    mw ? mw->wcid : 0, tlvnum);
	if (m == NULL)
		return ENOBUFS;

	{
		int rv = mwx_mcu_send_mbuf_wait(sc, MCU_UNI_CMD_STA_REC_UPDATE, m);
		MWX_DEV_LOG(sc, "sta_update add=%d new=%d wcid=%u peer=%s rv=%d\n",
		    add, isnew, mw ? mw->wcid : 0,
		    ni ? ether_sprintf(ni->ni_macaddr) : "-", rv);
		return rv;
	}
}

static int
mt7921_key_to_cipher_id(struct ieee80211_key *k)
{
	switch (k->k_cipher) {
	case IEEE80211_CIPHER_CCMP:
		 return MCU_CIPHER_AES_CCMP;
	case IEEE80211_CIPHER_TKIP:
		return MCU_CIPHER_TKIP;
	case IEEE80211_CIPHER_WEP40:
		return MCU_CIPHER_WEP40;
	case IEEE80211_CIPHER_WEP104:
		 return MCU_CIPHER_WEP104;
	case IEEE80211_CIPHER_BIP:
		return MCU_CIPHER_BIP_CMAC_128;
	default:
		return MCU_CIPHER_NONE;
	}
}

void
mt7921_mcu_add_key_tlv(struct mbuf *m, uint16_t *tlvnum,
    struct ieee80211_key *k, int add)
{
	struct sta_rec_sec *sec;
	struct sta_rec_sec_key *key;

	sec = (struct sta_rec_sec *)mwx_append_tlv(m, tlvnum, STA_REC_KEY,
	    sizeof(*sec));

	if (add) {
		sec->n_cipher = 1;
		sec->add = 0;	/* connac2 has inverted logic */
		sec->len = htole16(sizeof(*sec) + sizeof(*key));

		key = (struct sta_rec_sec_key *)mwx_append_len(m, sizeof(*key));
		key->cipher_id = mt7921_key_to_cipher_id(k);
		key->cipher_len = sizeof(*key);
		key->key_id = k->k_id;
		key->key_len = k->k_len;

		KASSERT(k->k_len <= sizeof(key->key));
		memcpy(key->key, k->k_key, k->k_len);

		if (key->cipher_id == MCU_CIPHER_TKIP &&
		    k->k_len == sizeof(key->key)) {
			/* Rx/Tx MIC keys are swapped. */
			memcpy(key->key + 16, k->k_key + 24, 8);
			memcpy(key->key + 24, k->k_key + 16, 8);
		}
	} else {
		sec->add = 1;
		sec->n_cipher = 0;
	}
}

int
mt7921_mcu_sta_key_update(struct mwx_softc *sc, struct ieee80211_node *ni,
    struct ieee80211_key *k)
{
	struct mwx_vif *mvif = &sc->sc_vif;
	struct mwx_node *mn = (struct mwx_node *)ni;
	struct mbuf *m;
	int want_keymask = (MWX_NODE_FLAG_HAVE_PAIRWISE_KEY |
	    MWX_NODE_FLAG_HAVE_GROUP_KEY);
	int rv;
	uint16_t tlvnum = 0, wcid = 0;
	uint8_t muar_idx = 0;

	if (ni == NULL) {
		ni = sc->sc_ic.ic_bss;
		mn = (struct mwx_node *)ni;
	}
	if (ni == NULL)
		return ENXIO;

	if ((k->k_flags & IEEE80211_KEY_GROUP) != 0) {
		wcid = mvif->vif_mn.wcid;
		muar_idx = 0x0e;
	} else {
		wcid = mn->wcid;
	}

	m = mwx_alloc_sta_req_tlv(sizeof(struct sta_req_hdr));
	if (m == NULL)
		return ENOBUFS;

	DPRINTF("%s: %s: ni %p, k_id %d, k_flags %x k_cipher %d wcid %d\n",
	    DEVNAME(sc), "add key", ni, k->k_id, k->k_flags, k->k_cipher, wcid);
	MWX_DEV_LOG(sc,
	    "key add request id=%d flags=0x%x cipher=%d len=%d wcid=%u muar=%u ni=%p\n",
	    k->k_id, k->k_flags, k->k_cipher, k->k_len, wcid, muar_idx, ni);

	mt7921_mcu_add_key_tlv(m, &tlvnum, k, 1);
	m = mwx_fill_sta_req_hdr(m, mvif, muar_idx, wcid, tlvnum);
	if (m == NULL)
		return ENOBUFS;

	rv = mwx_mcu_send_mbuf_wait(sc, MCU_UNI_CMD_STA_REC_UPDATE, m);
	if (rv != 0)
		return rv;
	MWX_DEV_LOG(sc,
	    "key add done id=%d flags=0x%x cipher=%d wcid=%u node_flags_before=0x%x\n",
	    k->k_id, k->k_flags, k->k_cipher, wcid, mn->flags);

	/* Keep track of added keys to trigger link up when all are done. */
	if ((k->k_flags & IEEE80211_KEY_GROUP) != 0)
		mn->flags |= MWX_NODE_FLAG_HAVE_GROUP_KEY;
	else
		mn->flags |= MWX_NODE_FLAG_HAVE_PAIRWISE_KEY;

	if ((mn->flags & want_keymask) == want_keymask) {
		DPRINTF("marking port %s valid\n", ether_sprintf(ni->ni_macaddr));
		MWX_DEV_LOG(sc,
		    "key add complete port valid mac=%s node_flags=0x%x\n",
		    ether_sprintf(ni->ni_macaddr), mn->flags);
		if (ni->ni_flags & IEEE80211_NODE_MFP)
			ni->ni_flags |= IEEE80211_NODE_TXMGMTPROT;
		ni->ni_port_valid = 1;
		ieee80211_set_link_state(&sc->sc_ic, LINK_STATE_UP);
	}

	return 0;
}

void
mt7921_mcu_sta_key_delete(struct mwx_softc *sc, struct ieee80211_node *ni,
    struct ieee80211_key *k)
{
	struct mwx_vif *mvif = &sc->sc_vif;
	struct mwx_node *mn = (struct mwx_node *)ni;
	struct mbuf *m;
	uint16_t tlvnum = 0, wcid = 0;
	uint8_t muar_idx = 0;

	if (ni == NULL) {
		ni = sc->sc_ic.ic_bss;
		mn = (struct mwx_node *)ni;
	}
	if (ni == NULL)
		return;

	if ((k->k_flags & IEEE80211_KEY_GROUP) != 0) {
		wcid = mvif->vif_mn.wcid;
		muar_idx = 0x0e;
		mn->flags &= ~MWX_NODE_FLAG_HAVE_GROUP_KEY;
	} else {
		wcid = mn->wcid;
		mn->flags &= ~MWX_NODE_FLAG_HAVE_PAIRWISE_KEY;
	}

	m = mwx_alloc_sta_req_tlv(sizeof(struct sta_req_hdr));
	if (m == NULL)
		return;

	DPRINTF("%s: %s: ni %p, k_id %d, k_flags %x k_cipher %d wcid %d\n",
	    DEVNAME(sc), "delete key", ni, k->k_id, k->k_flags, k->k_cipher,
	    wcid);

	mt7921_mcu_add_key_tlv(m, &tlvnum, k, 0);
	m = mwx_fill_sta_req_hdr(m, mvif, muar_idx, wcid, tlvnum);
	if (m == NULL)
		return;

	mwx_mcu_send_mbuf(sc, MCU_UNI_CMD_STA_REC_UPDATE, m, NULL);
}

#undef free

bool
MtkMwx::mwx_match(IOPCIDevice *device)
{
	if (device == NULL) {
		MWX_LOG("probe skipped: null PCI device\n");
		return false;
	}
	uint16_t vendor = device->configRead16(kIOPCIConfigVendorID);
	uint16_t product = device->configRead16(kIOPCIConfigDeviceID);
	bool matched = pci_matchbyid(vendor, product, mwx_devices,
	    nitems(mwx_devices)) != 0;
	MWX_LOG("probe vendor=0x%04x product=0x%04x matched=%d\n",
	    vendor, product, matched);
	return matched;
}

bool
MtkMwx::attach(IOPCIDevice *device)
{
	MWX_LOG("HAL attach begin device=%p\n", (void *)device);
	if (com == NULL)
		com = (struct mwx_softc *)malloc(sizeof(*com), M_DEVBUF, M_WAITOK | M_ZERO);
	if (pci == NULL)
		pci = (struct pci_attach_args *)malloc(sizeof(*pci), M_DEVBUF, M_WAITOK | M_ZERO);
	if (com == NULL || pci == NULL) {
		MWX_LOG("HAL attach allocation failed com=%p pci=%p\n",
		    (void *)com, (void *)pci);
		releaseAll();
		return false;
	}
	MWX_LOG("HAL attach allocated com=%p pci=%p\n",
	    (void *)com, (void *)pci);

	if (!taskq_init()) {
		releaseAll();
		return false;
	}
	taskQueueOwned = true;
	gMwxHal = this;
	pci->pa_tag = device;
	pci->workloop = getMainWorkLoop();
	pci->pa_id = ((pcireg_t)device->configRead16(kIOPCIConfigDeviceID) << 16) |
	    device->configRead16(kIOPCIConfigVendorID);
	strlcpy(com->sc_dev.dv_xname, "mwx0", sizeof(com->sc_dev.dv_xname));
	MWX_LOG("HAL attach pci_id=0x%08x workloop=%p\n",
	    pci->pa_id, (void *)pci->workloop);
	if (!mwx_attach(NULL, (struct device *)com, pci)) {
		MWX_LOG("HAL attach failed inside mwx_attach\n");
		detach(device);
		return false;
	}
	MWX_LOG("HAL attach complete\n");
	return true;
}

void
MtkMwx::detach(IOPCIDevice *device)
{
    MWX_LOG("HAL detach begin device=%p com=%p\n", (void *)device, (void *)com);
    if (com == NULL) {
        if (taskQueueOwned) { taskq_destroy(systq); taskQueueOwned = false; }
        releaseAll();
        return;
    }
    struct ifnet *ifp = &com->sc_ic.ic_if;
    com->sc_detaching = true;
    timeout_del(&com->sc_reset_to);
    /* Keep interrupts alive while in-flight MCU requests finish. */
    taskq_quiesce(com->sc_nswq);
    if (taskQueueOwned) taskq_quiesce(systq);
    if (ifp->if_flags & IFF_RUNNING) mwx_stop(ifp);
    timeout_free(&com->sc_reset_to);
    /* No interrupt callback may access buffers during their destruction. */
    if (com->sc_ih) {
        pci_intr_disestablish(pci->pa_pc, com->sc_ih);
        com->sc_ih = NULL;
    }
    if (com->sc_memh) {
        mwx_write(com, MT_WFDMA0_HOST_INT_ENA, 0);
        mwx_dma_disable(com, 1);
    }
    if (com->sc_net_attached) {
        ieee80211_ifdetach(ifp);
        com->sc_net_attached = false;
    }
    taskq_destroy(com->sc_nswq);
    com->sc_nswq = NULL;
    if (taskQueueOwned) { taskq_destroy(systq); taskQueueOwned = false; }
    mwx_txwi_free(com);
    mwx_dma_free(com);
    if (com->sc_memh) {
        bus_space_unmap(com->sc_st, com->sc_memh, com->sc_mems);
        com->sc_memh = 0;
    }
    releaseAll();
    MWX_LOG("HAL detach complete\n");
}

IOReturn
MtkMwx::enable(IONetworkInterface *interface)
{
	MWX_LOG("HAL enable begin interface=%p com=%p\n",
	    (void *)interface, (void *)com);
	if (com == NULL) {
		MWX_LOG("HAL enable failed: not attached\n");
		return kIOReturnNotAttached;
	}
	struct ifnet *ifp = &com->sc_ic.ic_if;
	if (ifp->if_flags & IFF_UP) {
		MWX_DEV_LOG(com, "HAL enable skipped: already up flags=0x%x\n",
		    ifp->if_flags);
		return kIOReturnSuccess;
	}
	ifp->if_flags |= IFF_UP;
	int rv = mwx_init(ifp);
	MWX_DEV_LOG(com, "HAL enable done mwx_init=%d flags=0x%x\n",
	    rv, ifp->if_flags);
	return rv == 0 ? kIOReturnSuccess : kIOReturnError;
}

IOReturn
MtkMwx::disable(IONetworkInterface *interface)
{
	MWX_LOG("HAL disable begin interface=%p com=%p\n",
	    (void *)interface, (void *)com);
	if (com == NULL)
		return kIOReturnSuccess;
	struct ifnet *ifp = &com->sc_ic.ic_if;
	if (!(ifp->if_flags & IFF_UP)) {
		MWX_DEV_LOG(com, "HAL disable skipped: already down flags=0x%x\n",
		    ifp->if_flags);
		return kIOReturnSuccess;
	}
	ifp->if_flags &= ~IFF_UP;
	if (ifp->if_flags & IFF_RUNNING)
		mwx_stop(ifp);
	MWX_DEV_LOG(com, "HAL disable complete flags=0x%x\n", ifp->if_flags);
	return kIOReturnSuccess;
}

struct ieee80211com *
MtkMwx::get80211Controller()
{
	if (com == NULL)
		com = (struct mwx_softc *)malloc(sizeof(*com), M_DEVBUF, M_WAITOK | M_ZERO);
	return com == NULL ? NULL : &com->sc_ic;
}

MtkDriverInfo *
MtkMwx::getDriverInfo()
{
	return this;
}

MtkDriverController *
MtkMwx::getDriverController()
{
	return this;
}

IOEthernetController *
MtkMwx::mwxController()
{
	return getController();
}

int
MtkMwx::mwxSleepNsec(void *ident, int priority, const char *wmesg,
    uint64_t timo)
{
	return MtkHalService::tsleep_nsec(ident, priority, wmesg, timo);
}

void
MtkMwx::mwxWakeup(void *ident)
{
	wakeupOn(ident);
}

const char *
MtkMwx::getFirmwareVersion()
{
	if (com == NULL)
		return "MT792x";
	return com->sc_hwtype == MWX_HW_MT7922 ? "MT7922" : "MT7921";
}

int16_t
MtkMwx::getBSSNoise()
{
	return 0;
}

bool
MtkMwx::is5GBandSupport()
{
	return com != NULL && com->sc_capa.has_5ghz;
}

int
MtkMwx::getTxNSS()
{
	return (com != NULL && com->sc_capa.num_streams > 0) ? com->sc_capa.num_streams : 1;
}

const char *
MtkMwx::getFirmwareName()
{
	if (com == NULL || com->sc_hwtype == MWX_HW_MT7922)
		return MT7922_FIRMWARE_WM;
	return MT7921_FIRMWARE_WM;
}

UInt32
MtkMwx::supportedFeatures()
{
	return kIONetworkFeatureMultiPages;
}

const char *
MtkMwx::getFirmwareCountryCode()
{
	static char alpha2[3] = "00";
	if (com != NULL) {
		alpha2[0] = com->sc_alpha2[0];
		alpha2[1] = com->sc_alpha2[1];
		alpha2[2] = '\0';
	}
	return alpha2;
}

uint32_t
MtkMwx::getTxQueueSize()
{
	return 256;
}

uint32_t
MtkMwx::getRxRateKbps()
{
	return mwx_rxr_last_kbps;
}

int
MtkMwx::getRxRateMcs()
{
	return mwx_rxr_last_mcs;
}

void
MtkMwx::clearScanningFlags()
{
	if (com)
		com->sc_flags &= ~(MWX_FLAG_SCANNING | MWX_FLAG_BGSCAN);
}

IOReturn
MtkMwx::setMulticastList(IOEthernetAddress *addr, int count)
{
	return kIOReturnSuccess;
}

void
MtkMwx::releaseAll()
{
	MWX_LOG("HAL releaseAll com=%p pci=%p\n", (void *)com, (void *)pci);
	if (com) {
		mwx_free_mem(com);
		com = NULL;
	}
	if (pci) {
		mwx_free_mem(pci);
		pci = NULL;
	}
	if (gMwxHal == this)
		gMwxHal = NULL;
}

void
MtkMwx::free()
	{
		MWX_LOG("HAL free\n");
		releaseAll();
		MtkHalService::free();
	}

static int mwx_send_assoc_status(struct mwx_softc *sc, uint32_t cmd, void *data, size_t len)
{
    int seq, rv;
    uint32_t status = 0;
    rv = mwx_mcu_send_msg(sc, cmd, data, len, &seq);
    if (rv) return rv;
    rv = mwx_mcu_wait_resp_int(sc, cmd, seq, &status);
    MWX_DEV_LOG(sc, "assoc_status cmd=%x transport=%d firmware=%u\n", cmd, rv, status);
    return rv ? rv : (status ? EIO : 0);
}

/* Publish the associated peer without resetting WTBL or key state. */
int mt7921_mcu_set_associated_peer(struct mwx_softc *sc)
{
    struct ieee80211_node *ni = sc->sc_ic.ic_bss;
    if (!ni || IEEE80211_AID(ni->ni_associd) == 0) return EINVAL;
    struct mbuf *m = mwx_alloc_sta_req_tlv(sizeof(struct sta_req_hdr));
    if (!m) return ENOBUFS;
    uint16_t tlvnum = 0;
    mt7921_mcu_add_basic_tlv(m, &tlvnum, sc, ni, 1, 0);
    if (ni->ni_flags & IEEE80211_NODE_HT) {
        /* 802.11n: peer HT caps, PHY type/A-MPDU params, RA MCS mask. */
        struct sta_rec_ht_v1 *ht = (struct sta_rec_ht_v1 *)mwx_append_tlv(m,
            &tlvnum, STA_REC_HT, sizeof(*ht));
        ht->ht_cap = htole16(ni->ni_htcaps);
        struct sta_rec_phy *phy = (struct sta_rec_phy *)mwx_append_tlv(m,
            &tlvnum, STA_REC_PHY, sizeof(*phy));
        phy->basic_rate = htole16(0x0150);
        phy->phy_type = mt7921_get_phy_mode_v2(sc, ni);
        phy->ampdu = ni->ni_ampdu_param & 0x1f;
        phy->rcpi = 0xdc;
        struct sta_rec_ra_info *ra = (struct sta_rec_ra_info *)mwx_append_tlv(m,
            &tlvnum, STA_REC_RA, sizeof(*ra));
        ra->legacy = htole16(RA_LEGACY_OFDM);
        for (int i = 0; i < HT_MCS_MASK_NUM; i++)
            ra->rx_mcs_bitmask[i] = ni->ni_rxmcs[i] &
                (i < 2 ? sc->sc_ic.ic_sup_mcs[i] : 0);
        MWX_DEV_LOG(sc, "assoc_peer HT htcaps=0x%04x ampdu=0x%02x phy=0x%02x mcs=%02x%02x\n",
            ni->ni_htcaps, ni->ni_ampdu_param, phy->phy_type,
            ra->rx_mcs_bitmask[1], ra->rx_mcs_bitmask[0]);
    }
    if ((ni->ni_flags & IEEE80211_NODE_HT) && sc->sc_tx_amsdu) {
        /* Hardware TX A-MSDU (Linux mt76_connac_mcu_sta_amsdu_tlv). */
        struct sta_rec_amsdu *amsdu = (struct sta_rec_amsdu *)mwx_append_tlv(m,
            &tlvnum, STA_REC_HW_AMSDU, sizeof(*amsdu));
        amsdu->max_amsdu_num = 8;
        amsdu->amsdu_en = 1;
        amsdu->max_mpdu_size = 0;	/* A-MSDUs up to 3839 bytes */
    }
    if (ni->ni_flags & IEEE80211_NODE_VHT) {
        struct sta_rec_vht_v1 *vht = (struct sta_rec_vht_v1 *)mwx_append_tlv(m,
            &tlvnum, STA_REC_VHT, sizeof(*vht));
        /* peer capabilities without 160/80+80 (we only do 80 MHz) */
        vht->vht_cap = htole32(ni->ni_vhtcaps &
            ~IEEE80211_VHTCAP_SUPP_CHAN_WIDTH_MASK);
        vht->vht_rx_mcs_map = htole16(ni->ni_vht_mcsinfo.rx_mcs_map);
        vht->vht_tx_mcs_map = htole16(ni->ni_vht_mcsinfo.tx_mcs_map);
    }
    struct sta_rec_state *state = (struct sta_rec_state *)mwx_append_tlv(m, &tlvnum, STA_REC_STATE, sizeof(*state));
    state->state = 2; /* MT76_STA_INFO_STATE_ASSOC: NONE=0, AUTH=1, ASSOC=2. */
    if (ni->ni_flags & IEEE80211_NODE_VHT) {
        /* bandwidth (0=20, 2=80) | (rx nss - 1) << 4 */
        uint8_t bw, center;
        mwx_node_chan_width(ni, &bw, &center);
        state->vht_opmode = (bw == CMD_CBW_80MHZ ? 2 :
            bw == CMD_CBW_40MHZ ? 1 : 0) |
            ((sc->sc_capa.num_streams > 1 ? 1 : 0) << 4);
        MWX_DEV_LOG(sc, "assoc_peer VHT vhtcaps=0x%08x rxmcs=0x%04x txmcs=0x%04x chw=%d center=%u opmode=0x%02x\n",
            ni->ni_vhtcaps, ni->ni_vht_mcsinfo.rx_mcs_map,
            ni->ni_vht_mcsinfo.tx_mcs_map, ni->ni_chw, center,
            state->vht_opmode);
    }
    m = mwx_fill_sta_req_hdr(m, &sc->sc_vif, sc->sc_vif.omac_idx, ((struct mwx_node *)ni)->wcid, tlvnum);
    if (!m) return ENOBUFS;
    int seq, rv = mwx_mcu_send_mbuf(sc, MCU_UNI_CMD_STA_REC_UPDATE, m, &seq);
    uint32_t status = 0;
    if (!rv) rv = mwx_mcu_wait_resp_int(sc, MCU_UNI_CMD_STA_REC_UPDATE, seq, &status);
    MWX_DEV_LOG(sc, "assoc_peer aid=%u state=2 transport=%d firmware=%u\n", IEEE80211_AID(ni->ni_associd), rv, status);
    return rv ? rv : (status ? EIO : 0);
}

/*
 * RX Block Ack session (we are the recipient). The firmware must know about
 * it to answer the AP's A-MPDUs with BlockAck; net80211 reorders in software.
 * Called from RX processing, so do not wait for the MCU response here.
 */
static int
mwx_mcu_sta_ba(struct mwx_softc *sc, struct ieee80211_node *ni, uint8_t tid,
    uint16_t ssn, uint16_t winsize, int enable, int tx, int amsdu)
{
	struct mwx_node *mn = (struct mwx_node *)ni;
	struct sta_rec_ba *ba;
	struct mbuf *m;
	uint16_t tlvnum = 0;

	m = mwx_alloc_sta_req_tlv(sizeof(struct sta_req_hdr));
	if (m == NULL)
		return ENOBUFS;
	ba = (struct sta_rec_ba *)mwx_append_tlv(m, &tlvnum, STA_REC_BA,
	    sizeof(*ba));
	ba->tid = tid;
	ba->ba_type = tx ? MT_BA_TYPE_ORIGINATOR : MT_BA_TYPE_RECIPIENT;
	ba->amsdu = amsdu ? 1 : 0;
	ba->ba_en = enable ? (1U << tid) : 0;
	ba->ssn = htole16(ssn);
	ba->winsize = htole16(winsize);
	m = mwx_fill_sta_req_hdr(m, &sc->sc_vif, sc->sc_vif.omac_idx,
	    mn->wcid, tlvnum);
	if (m == NULL)
		return ENOBUFS;
	return mwx_mcu_send_mbuf(sc, MCU_UNI_CMD_STA_REC_UPDATE, m, NULL);
}

int
mwx_ampdu_rx_start(struct ieee80211com *ic, struct ieee80211_node *ni,
    uint8_t tid)
{
	struct mwx_softc *sc = (struct mwx_softc *)ic->ic_softc;
	struct ieee80211_rx_ba *ba = &ni->ni_rx_ba[tid];
	int rv;

	rv = mwx_mcu_sta_ba(sc, ni, tid, ba->ba_winstart, ba->ba_winsize, 1, 0, 0);
	MWX_DEV_LOG(sc, "rx BA start tid=%u ssn=%u win=%u rv=%d\n", tid,
	    ba->ba_winstart, ba->ba_winsize, rv);
	return rv;
}

void
mwx_ampdu_rx_stop(struct ieee80211com *ic, struct ieee80211_node *ni,
    uint8_t tid)
{
	struct mwx_softc *sc = (struct mwx_softc *)ic->ic_softc;
	int rv;

	rv = mwx_mcu_sta_ba(sc, ni, tid, 0, 0, 0, 0, 0);
	MWX_DEV_LOG(sc, "rx BA stop tid=%u rv=%d\n", tid, rv);
}

/*
 * TX Block Ack session (we are the originator): the firmware aggregates the
 * TID into A-MPDUs and syncs its hardware sequence number to the SSN we sent
 * in the ADDBA request.
 */
int
mwx_ampdu_tx_start(struct ieee80211com *ic, struct ieee80211_node *ni,
    uint8_t tid)
{
	struct mwx_softc *sc = (struct mwx_softc *)ic->ic_softc;
	struct ieee80211_tx_ba *ba = &ni->ni_tx_ba[tid];
	uint16_t win = ba->ba_winsize;
	int amsdu, rv;

	if (win == 0 || win > 64)
		win = 64;
	amsdu = sc->sc_tx_amsdu && (ba->ba_params & IEEE80211_ADDBA_AMSDU);
	rv = mwx_mcu_sta_ba(sc, ni, tid, ba->ba_winstart, win, 1, 1, amsdu);
	MWX_DEV_LOG(sc, "tx BA start tid=%u ssn=%u win=%u amsdu=%d rv=%d\n",
	    tid, ba->ba_winstart, win, amsdu, rv);
	return rv;
}

void
mwx_ampdu_tx_stop(struct ieee80211com *ic, struct ieee80211_node *ni,
    uint8_t tid)
{
	struct mwx_softc *sc = (struct mwx_softc *)ic->ic_softc;
	int rv;

	rv = mwx_mcu_sta_ba(sc, ni, tid, 0, 0, 0, 1, 0);
	MWX_DEV_LOG(sc, "tx BA stop tid=%u rv=%d\n", tid, rv);
}

int
mt7921_mcu_set_associated_bss(struct mwx_softc *sc, int associated)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct ieee80211_node *ni = ic->ic_bss;
	struct mwx_vif *mvif = &sc->sc_vif;
	struct {
		uint8_t bss_idx;
		uint8_t pad[3];
		struct mt76_connac_bss_basic_tlv basic;
	} __packed bss = {};
	struct {
		uint8_t bss_idx;
		uint8_t pad[3];
		struct {
			uint16_t tag, len;
			uint8_t control_channel, center_chan, center_chan2, bw;
			uint8_t tx_streams, rx_streams, short_st, ht_op_info;
			uint8_t sco, band, pad[2];
		} __packed rlm;
	} __packed channel = {};
	int rv, is_2g;

	if (ic->ic_opmode != IEEE80211_M_STA)
		return 0;
	if (ni == NULL || ni->ni_chan == NULL ||
	    ni->ni_chan == IEEE80211_CHAN_ANYC)
		return EINVAL;
	uint8_t op_bw, op_center;
	mwx_node_chan_width(ni, &op_bw, &op_center);
	is_2g = IEEE80211_IS_CHAN_2GHZ(ni->ni_chan);
	bss.bss_idx = mvif->idx;
	bss.basic.tag = htole16(UNI_BSS_INFO_BASIC);
	bss.basic.len = htole16(sizeof(bss.basic));
	bss.basic.active = 1;
	bss.basic.omac_idx = mvif->omac_idx;
	bss.basic.hw_bss_idx = mvif->omac_idx > EXT_BSSID_START ?
	    HW_BSSID_0 : mvif->omac_idx;
	bss.basic.band_idx = mvif->band_idx;
	bss.basic.conn_type = htole32(STA_TYPE_STA | NETWORK_INFRA);
	bss.basic.conn_state = associated ? 0 : 1;
	bss.basic.wmm_idx = mvif->wmm_idx;
	memcpy(bss.basic.bssid, ni->ni_bssid, ETHER_ADDR_LEN);
	bss.basic.bmc_tx_wlan_idx = htole16(mvif->vif_mn.wcid);
	bss.basic.sta_idx = htole16(mvif->vif_mn.wcid);
	bss.basic.bcn_interval = htole16(ni->ni_intval);
	bss.basic.dtim_period = ni->ni_dtimperiod;
	/* BSS phymode uses A/B/G bits; nonht_basic_phy uses PHY_TYPE bits. */
	bss.basic.phymode = is_2g ? ((1U << 1) | (1U << 2)) : (1U << 0);
	if (ni->ni_flags & IEEE80211_NODE_HT)
		bss.basic.phymode |= is_2g ? (1U << 3) /* GN */ :
		    (1U << 4) /* AN */;
	if (ni->ni_flags & IEEE80211_NODE_VHT)
		bss.basic.phymode |= (1U << 5); /* AC */
	bss.basic.nonht_basic_phy = htole16(is_2g ?
	    PHY_TYPE_BIT_HR_DSSS | PHY_TYPE_BIT_ERP : PHY_TYPE_BIT_OFDM);
	rv = mwx_send_assoc_status(sc, MCU_UNI_CMD_BSS_INFO_UPDATE, &bss, sizeof(bss));
	MWX_DEV_LOG(sc, "associated BSS enable=%d channel=%u beacon=%u dtim=%u rv=%d\n",
	    associated, ieee80211_mhz2ieee(ni->ni_chan->ic_freq, 0), ni->ni_intval, ni->ni_dtimperiod, rv);
	if (rv != 0 || !associated)
		return rv;

	channel.bss_idx = mvif->idx;
	channel.rlm.tag = htole16(UNI_BSS_INFO_RLM);
	channel.rlm.len = htole16(sizeof(channel.rlm));
	channel.rlm.control_channel = ieee80211_mhz2ieee(ni->ni_chan->ic_freq, 0);
	channel.rlm.center_chan = op_center;
	channel.rlm.bw = op_bw;
	if (op_bw != CMD_CBW_20MHZ) {
		channel.rlm.ht_op_info = 4;	/* 40 MHz+ allowed */
		if (channel.rlm.control_channel < channel.rlm.center_chan)
			channel.rlm.sco = 1;	/* SCA */
		else if (channel.rlm.control_channel > channel.rlm.center_chan)
			channel.rlm.sco = 3;	/* SCB */
	}
	channel.rlm.tx_streams = sc->sc_capa.num_streams;
	channel.rlm.rx_streams = sc->sc_capa.antenna_mask;
	channel.rlm.short_st = 1;
	channel.rlm.band = is_2g ? 0 : 1;
	rv = mwx_send_assoc_status(sc, MCU_UNI_CMD_BSS_INFO_UPDATE,
	    &channel, sizeof(channel));
	MWX_DEV_LOG(sc, "associated BSS RLM channel=%u band=%u rv=%d\n",
	    channel.rlm.control_channel, channel.rlm.band, rv);
	return rv;
}

/*
 * System sleep. The M.2 card is powered off in S3, so the firmware, the
 * DMA ring registers and the MSI state are gone on wake. Leave the network
 * (deauth while the radio still works), mask interrupts and ignore the
 * hardware until resume().
 */
void
MtkMwx::suspend()
{
	struct mwx_softc *sc = com;
	struct ifnet *ifp;

	if (sc == NULL || sc->sc_suspended)
		return;
	ifp = &sc->sc_ic.ic_if;
	MWX_DEV_LOG(sc, "suspend flags=0x%x fw_loaded=%d\n", ifp->if_flags,
	    sc->sc_fw_loaded);
	if (ifp->if_flags & IFF_RUNNING)
		mwx_stop(ifp);
	mwx_write(sc, MT_WFDMA0_HOST_INT_ENA, 0);
	sc->sc_suspended = 1;
}

/*
 * System wake: take the chip back from the firmware (with the same WFSYS
 * reset / PCIe FLR fallback as attach), then reload the firmware through
 * the hard reset task (the DMA stall recovery path). An interface that was
 * up is brought up again by that task; one the front end took down (the
 * native Wi-Fi interface) is initialized when it is enabled again.
 */
void
MtkMwx::resume()
{
	struct mwx_softc *sc = com;

	if (sc == NULL || !sc->sc_suspended)
		return;
	MWX_DEV_LOG(sc, "resume lpctl=0x%08x\n", mwx_read(sc, MT_CONN_ON_LPCTL));
	if (mwx_mcu_fw_pmctrl(sc) != 0 || mwx_mcu_drv_pmctrl(sc) != 0) {
		MWX_DEV_LOG(sc, "resume: driver own failed, trying WFSYS reset\n");
		mwx_wfsys_reset(sc);
		if ((mwx_mcu_fw_pmctrl(sc) != 0 || mwx_mcu_drv_pmctrl(sc) != 0) &&
		    pci != NULL && pci->pa_tag != NULL) {
			MWX_DEV_LOG(sc, "resume: trying PCIe FLR\n");
			if (mwx_pci_flr(sc, pci->pa_tag) == 0) {
				mwx_mcu_fw_pmctrl(sc);
				mwx_mcu_drv_pmctrl(sc);
			}
		}
	}
	mwx_set(sc, MT_MCU2HOST_SW_INT_ENA, MT_MCU_CMD_WAKE_RX_PCIE);
	mwx_write(sc, MT_WFDMA0_HOST_INT_ENA, 0);
	mwx_write(sc, MT_PCIE_MAC_INT_ENABLE, 0xff);
	sc->sc_fw_loaded = 0;
	sc->sc_suspended = 0;
	sc->sc_hard_reset = 1;
	mwx_reset(sc);
	MWX_DEV_LOG(sc, "resume: firmware reload scheduled\n");
}

void
MtkMwx::debugPoll()
{
	struct mwx_softc *sc = com;
	struct ieee80211com *ic;
	static uint32_t polls, last_intr_calls;
	static uint32_t last_txq_dma = 0xffffffff, last_mcu_dma = 0xffffffff;
	static uint32_t txq_stuck, mcu_stuck, last_reset_poll;
	static int stall_dumped;
	uint32_t sta, ena, lp, mcu;
	uint32_t tq_cpu, tq_dma, mq_cpu, mq_dma;
	int verbose;

	if (sc == NULL || !sc->sc_fw_loaded || sc->sc_resetting ||
	    sc->sc_suspended)
		return;
	ic = &sc->sc_ic;
	polls++;

	/*
	 * net80211 sends AUTH / ASSOC_REQ once and then waits the whole 5 s
	 * management timer before rescanning every channel. A single lost
	 * frame (seen on 2.4 GHz: AUTH answered, ASSOC response never came)
	 * thus cost ~20 s at boot. Retransmit like mac80211 does, once per
	 * poll, up to three times.
	 */
	{
		static int retry_state = -1, retries;

		if (ic->ic_opmode == IEEE80211_M_STA && ic->ic_mgt_timer != 0 &&
		    (ic->ic_state == IEEE80211_S_AUTH ||
		    ic->ic_state == IEEE80211_S_ASSOC)) {
			if (retry_state != ic->ic_state) {
				retry_state = ic->ic_state;
				retries = 0;
			} else if (retries < 3) {
				retries++;
				MWX_DEV_LOG(sc, "%s retry %d to %s\n",
				    ic->ic_state == IEEE80211_S_AUTH ?
				    "AUTH" : "ASSOC", retries,
				    ether_sprintf(ic->ic_bss->ni_macaddr));
				if (ic->ic_state == IEEE80211_S_AUTH)
					IEEE80211_SEND_MGMT(ic, ic->ic_bss,
					    IEEE80211_FC0_SUBTYPE_AUTH, 1);
				else
					IEEE80211_SEND_MGMT(ic, ic->ic_bss,
					    IEEE80211_FC0_SUBTYPE_ASSOC_REQ, 0);
			}
		} else
			retry_state = -1;
	}

	sta = mwx_read(sc, MT_WFDMA0_HOST_INT_STA);
	ena = mwx_read(sc, MT_WFDMA0_HOST_INT_ENA);
	lp = mwx_read(sc, MT_CONN_ON_LPCTL);
	mcu = mwx_read(sc, MT_MCU_CMD);
	tq_cpu = mwx_read(sc, sc->sc_txq.mq_regbase + MT_DMA_CPU_IDX);
	tq_dma = mwx_read(sc, sc->sc_txq.mq_regbase + MT_DMA_DMA_IDX);
	mq_cpu = mwx_read(sc, sc->sc_txmcuq.mq_regbase + MT_DMA_CPU_IDX);
	mq_dma = mwx_read(sc, sc->sc_txmcuq.mq_regbase + MT_DMA_DMA_IDX);

	txq_stuck = (tq_cpu != tq_dma && tq_dma == last_txq_dma) ?
	    txq_stuck + 1 : 0;
	mcu_stuck = (mq_cpu != mq_dma && mq_dma == last_mcu_dma) ?
	    mcu_stuck + 1 : 0;
	last_txq_dma = tq_dma;
	last_mcu_dma = mq_dma;

	verbose = (sta & sc->sc_intr_mask) != 0 || polls % 30 == 0 ||
	    txq_stuck == 2 || mcu_stuck == 2;
	if (verbose) {
		struct ifnet *ifp = &ic->ic_if;
		char drops[160];
		size_t off = 0;
		int i;

		MWX_DEV_LOG(sc,
		    "poll state=%d chan=%u intr_calls=%u sta=0x%08x ena=0x%08x lpctl=0x%08x mcu_cmd=0x%08x\n",
		    ic->ic_state,
		    ic->ic_bss ? ieee80211_chan2ieee(ic, ic->ic_bss->ni_chan) : 0,
		    mwx_intr_calls, sta, ena, lp, mcu);
		MWX_DEV_LOG(sc,
		    "poll txq cpu=%u dma=%u | txmcu cpu=%u dma=%u | rxq cpu=%u dma=%u cons=%u | rxmcu cpu=%u dma=%u cons=%u\n",
		    tq_cpu, tq_dma, mq_cpu, mq_dma,
		    mwx_read(sc, sc->sc_rxq.mq_regbase + MT_DMA_CPU_IDX),
		    mwx_read(sc, sc->sc_rxq.mq_regbase + MT_DMA_DMA_IDX),
		    sc->sc_rxq.mq_cons,
		    mwx_read(sc, sc->sc_rxmcuq.mq_regbase + MT_DMA_CPU_IDX),
		    mwx_read(sc, sc->sc_rxmcuq.mq_regbase + MT_DMA_DMA_IDX),
		    sc->sc_rxmcuq.mq_cons);
		drops[0] = 0;
		for (i = 0; i < MWX_RX_DROP_REASONS &&
		    mwx_rx_drop_name[i] != NULL && off < sizeof(drops) - 24; i++)
			off += snprintf(drops + off, sizeof(drops) - off,
			    "%s=%u ", mwx_rx_drop_name[i], mwx_rx_drop_cnt[i]);
		MWX_DEV_LOG(sc,
		    "stats rx_hwdec=%u rx_swdec=%u ipkts=%llu ierr=%llu opkts=%llu oerr=%llu hwdrop[%s] dup=%u wrongbss=%u wrongdir=%u notassoc=%u unenc=%u wepfail=%u decap=%u decryptcrc=%u ccmp_replay=%u ccmp_dec=%u tooshort=%u nombuf=%u ba_below=%u ba_above=%u\n",
		    mwx_rx_hwdec_cnt, mwx_rx_swdec_cnt,
		    (unsigned long long)(ifp->netStat ? ifp->netStat->inputPackets : 0),
		    (unsigned long long)(ifp->netStat ? ifp->netStat->inputErrors : 0),
		    (unsigned long long)(ifp->netStat ? ifp->netStat->outputPackets : 0),
		    (unsigned long long)(ifp->netStat ? ifp->netStat->outputErrors : 0), drops,
		    ic->ic_stats.is_rx_dup, ic->ic_stats.is_rx_wrongbss,
		    ic->ic_stats.is_rx_wrongdir, ic->ic_stats.is_rx_notassoc,
		    ic->ic_stats.is_rx_unencrypted, ic->ic_stats.is_rx_wepfail,
		    ic->ic_stats.is_rx_decap, ic->ic_stats.is_rx_decryptcrc,
		    ic->ic_stats.is_ccmp_replays, ic->ic_stats.is_ccmp_dec_errs,
		    ic->ic_stats.is_rx_tooshort, ic->ic_stats.is_rx_nombuf,
		    ic->ic_stats.is_ht_rx_frame_below_ba_winstart,
		    ic->ic_stats.is_ht_rx_frame_above_ba_winend);
	}
	if (verbose)
		MWX_DEV_LOG(sc,
		    "ba gap_timeout=%u frame_lost=%u slide=%u jump=%u below=%u bar_rx=%u rx_agreements=%u drv_ctl=%u drv_bar=%u\n",
		    ic->ic_stats.is_ht_rx_ba_window_gap_timeout,
		    ic->ic_stats.is_ht_rx_ba_frame_lost,
		    ic->ic_stats.is_ht_rx_ba_window_slide,
		    ic->ic_stats.is_ht_rx_ba_window_jump,
		    ic->ic_stats.is_ht_rx_frame_below_ba_winstart,
		    ieee80211_bar_rx_count,
		    ic->ic_stats.is_ht_rx_ba_agreements, mwx_rx_ctl_cnt,
		    mwx_rx_bar_cnt);
	if (verbose)
		MWX_DEV_LOG(sc,
		    "tx txwi_free=%u ring_free=%d full=%u oactive=%d tx_ba=%u amsdu=%d\n",
		    sc->sc_txwi.mt_nfree, mwx_dma_free_slots(&sc->sc_txq),
		    sc->sc_tx_full_cnt, ifq_is_oactive(&ic->ic_if.if_snd) ? 1 : 0,
		    ic->ic_stats.is_ht_tx_ba_agreements, sc->sc_tx_amsdu);
	if (verbose && mwx_rxr_total != 0) {
		MWX_DEV_LOG(sc,
		    "rxrate n=%u mode[cck=%u ofdm=%u ht=%u vht=%u he=%u] bw[20=%u 40=%u 80=%u 160=%u] nss[1=%u 2=%u] "
		    "mcs[0=%u 1=%u 2=%u 3=%u 4=%u 5=%u 6=%u 7=%u 8=%u 9=%u] sgi=%u stbc=%u ldpc=%u\n",
		    mwx_rxr_total, mwx_rxr_mode[0], mwx_rxr_mode[1],
		    mwx_rxr_mode[2] + mwx_rxr_mode[3], mwx_rxr_mode[4],
		    mwx_rxr_mode[8] + mwx_rxr_mode[9] + mwx_rxr_mode[10] +
		    mwx_rxr_mode[11],
		    mwx_rxr_bw[0], mwx_rxr_bw[1], mwx_rxr_bw[2], mwx_rxr_bw[3],
		    mwx_rxr_nss[0], mwx_rxr_nss[1],
		    mwx_rxr_mcs[0], mwx_rxr_mcs[1], mwx_rxr_mcs[2], mwx_rxr_mcs[3],
		    mwx_rxr_mcs[4], mwx_rxr_mcs[5], mwx_rxr_mcs[6], mwx_rxr_mcs[7],
		    mwx_rxr_mcs[8], mwx_rxr_mcs[9], mwx_rxr_sgi, mwx_rxr_stbc,
		    mwx_rxr_ldpc);
		/* per-interval histogram */
		memset(mwx_rxr_mode, 0, sizeof(mwx_rxr_mode));
		memset(mwx_rxr_bw, 0, sizeof(mwx_rxr_bw));
		memset(mwx_rxr_nss, 0, sizeof(mwx_rxr_nss));
		memset(mwx_rxr_mcs, 0, sizeof(mwx_rxr_mcs));
		mwx_rxr_sgi = mwx_rxr_stbc = mwx_rxr_ldpc = mwx_rxr_total = 0;
	}
	last_intr_calls = mwx_intr_calls;

	if (txq_stuck == 2 && !stall_dumped && tq_dma < sc->sc_txq.mq_count) {
		struct mwx_desc *d = &sc->sc_txq.mq_desc[tq_dma];
		struct mwx_txwi *mt = sc->sc_txq.mq_data[tq_dma].md_txwi;

		stall_dumped = 1;
		MWX_DEV_LOG(sc,
		    "TX STALL ring idx=%u desc buf0=0x%08x ctrl=0x%08x buf1=0x%08x info=0x%08x\n",
		    tq_dma, le32toh(d->buf0), le32toh(d->ctrl),
		    le32toh(d->buf1), le32toh(d->info));
		if (mt != NULL && mt->mt_desc != NULL) {
			struct mt76_txwi *t = mt->mt_desc;
			MWX_DEV_LOG(sc,
			    "TX STALL txwi idx=%u addr=0x%08x w=%08x %08x %08x %08x %08x %08x %08x %08x msdu=%04x ptr0=0x%08x/%04x/%04x/0x%08x ptr1=0x%08x/%04x/%04x/0x%08x\n",
			    mt->mt_idx, mt->mt_addr,
			    t->txwi[0], t->txwi[1], t->txwi[2], t->txwi[3],
			    t->txwi[4], t->txwi[5], t->txwi[6], t->txwi[7],
			    t->msdu_id[0],
			    t->ptr[0].buf0, t->ptr[0].len0, t->ptr[0].len1,
			    t->ptr[0].buf1,
			    t->ptr[1].buf0, t->ptr[1].len0, t->ptr[1].len1,
			    t->ptr[1].buf1);
		}
	}

	/*
	 * Auto recovery: if the TX data or MCU ring has not moved for 4
	 * seconds while work is pending, the WFDMA/firmware is wedged and
	 * only a WFSYS reset with firmware reload brings it back.
	 * Rate limited to once per 30 seconds.
	 */
	uint32_t stuck_limit = (sc->sc_flags &
	    (MWX_FLAG_SCANNING | MWX_FLAG_BGSCAN)) ? 10 : 4;
	if ((txq_stuck >= stuck_limit || mcu_stuck >= stuck_limit) &&
	    polls - last_reset_poll >= 30) {
		MWX_DEV_LOG(sc,
		    "DMA stall detected (txq_stuck=%u mcu_stuck=%u), hard reset\n",
		    txq_stuck, mcu_stuck);
		last_reset_poll = polls;
		txq_stuck = mcu_stuck = 0;
		last_txq_dma = last_mcu_dma = 0xffffffff;
		stall_dumped = 0;
		sc->sc_hard_reset = 1;
		mwx_reset(sc);
		return;
	}

	/* Recover from a lost MSI: process anything left pending. */
	if ((sta & sc->sc_intr_mask) != 0) {
		MWX_DEV_LOG(sc, "poll found pending intr 0x%08x, servicing\n",
		    sta & sc->sc_intr_mask);
		mwx_intr(sc);
	}
}
