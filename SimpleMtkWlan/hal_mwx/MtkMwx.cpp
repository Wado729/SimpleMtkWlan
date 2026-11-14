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
	MWX_HW_MT7927,		/* connac3; runs on the MT7927 engine below */
};

struct mt7927_bringup;

struct mwx_setkey_task_arg {
	struct ieee80211_node	*ni;
	struct ieee80211_key	*k;
};

#include "mt7927_types.h"

/* MT7927 phase 4c: Block Ack setup queued from RX context. */
struct mt7927_ba_op {
	struct ieee80211_node	*ni;
	uint8_t			tid;
	uint8_t			kind;		/* MT7927_BA_*, MT7927_KEY_SET */
	/* MT7927_KEY_SET: a copy of the key, wiped after use */
	bool			key_pairwise;
	uint8_t			key_id;
	uint8_t			key_len;
	uint8_t			key[32];
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

	/* MWX_HW_MT7927 */
	struct mt7927_bringup	*sc_7927;
	IOLock			*sc_7927_lock;
	IOLock			*sc_7927_txlock;	/* mt7927_hal_output() */
	volatile bool		sc_7927_abort;
	bool			sc_7927_thread;		/* init thread started */
	volatile bool		sc_7927_thread_done;
	bool			sc_7927_dead;		/* stopped for sleep */
	int			sc_7927_scan_ticks;
	uint32_t		sc_7927_join_refused;
	uint32_t		sc_7927_poll;
	uint32_t		sc_7927_rx_drop[8];
	/* phase 4e.1: 6 GHz scanning (heard, not yet given to net80211) */
	bool			sc_7927_scan6g;		/* off: -mtk7927no6g */
	bool			sc_7927_nobgscan;	/* -mtk7927nobgscan */
	uint32_t		sc_7927_rx_6g;		/* 6 GHz frames received */
	uint8_t			sc_7927_6g_bssid[32][6];
	uint32_t		sc_7927_6g_n;
	uint32_t		sc_7927_bgscans, sc_7927_bgscan_busy;	/* phase 4e.3 */
	/* phase 4b: join */
	bool			sc_7927_joined;		/* BSS_INFO + STA_REC set */
	bool			sc_7927_assoc;
	uint32_t		sc_7927_assoc_polls;
	/* phase 4c.2: CCMP keys in the chip */
	bool			sc_7927_hwcrypto;	/* off: -mtk7927swcrypto */
	uint8_t			sc_7927_hwkeys;		/* MT7927_HWKEY_* installed */
	volatile bool		sc_7927_ptk_pending;	/* hold data TX until set */
	uint32_t		sc_7927_hwkey_fail;
	uint32_t		sc_7927_tx_hwenc;
	uint32_t		sc_7927_tx_swenc;
	/* phase 4c.3: hardware A-MSDU, TX status samples */
	bool			sc_7927_amsdu_ok;	/* on: -mtk7927amsdu */
	/* phase 4d: 802.11ax */
	bool			sc_7927_he;		/* off: -mtk7927nohe */
	uint32_t		sc_7927_tx_amsdu;
	uint32_t		sc_7927_txs_tick;
	/* link watchdog: the radio stopped hearing the AP */
	uint32_t		sc_7927_run_polls;	/* seconds associated, authorized */
	uint32_t		sc_7927_bcn_loss_seen;
	uint32_t		sc_7927_mib_seen;
	uint32_t		sc_7927_recoveries;
	uint32_t		sc_7927_last_recovery;	/* poll tick */
	uint32_t		sc_7927_tx_held;	/* frames held back: no token */
	volatile bool		sc_7927_edca_dirty;	/* AP changed WMM parameters */
	struct mbuf_list	sc_7927_rxml;		/* RX batch for if_input */
	uint32_t		sc_7927_rxml_frames;	/* 802.11 frames in it */
	uint32_t		sc_7927_rx_batches, sc_7927_rx_batched;
	uint32_t		sc_7927_rx_csum;	/* frames with chip-checked checksums */
	/* phase 4c.10: RX header translation (decap offload) */
	bool			sc_7927_rx_decap;	/* on unless -mtk7927nodecap */
	struct mt7927_reorder	sc_7927_reorder[8];	/* per TID, BA sessions */
	mbuf_t			sc_7927_amsdu_head;	/* A-MSDU being gathered */
	mbuf_t			sc_7927_amsdu_tail;
	struct mt7927_rxunit	sc_7927_amsdu_meta;
	uint32_t		sc_7927_amsdu_when;	/* ms, first subframe */
	uint8_t			sc_7927_pn_uc[17][6];	/* last CCMP PN per TID */
	uint8_t			sc_7927_pn_mc[17][6];
	volatile bool		sc_7927_pn_reset_uc;	/* new keys: start over */
	volatile bool		sc_7927_pn_reset_mc;
	CTimeout		*sc_7927_reorder_to;
	bool			sc_7927_reorder_armed;
	struct mt7927_rxu	sc_7927_rxu[4 * MT7927_REORDER_WIN];
	struct mt7927_rxu	*sc_7927_rxu_free;
	bool			sc_7927_rxu_init;
	uint32_t		sc_7927_rx8023, sc_7927_rx8023_drop;
	uint32_t		sc_7927_rx_replay, sc_7927_rx_late;
	uint32_t		sc_7927_rx_nog4, sc_7927_rx_untrans_amsdu;
	uint32_t		sc_7927_depth_tok;	/* max tokens out, last 5 s */
	uint32_t		sc_7927_tf_ev, sc_7927_tf_ms, sc_7927_tf_re;
	uint32_t		sc_7927_depth_ring;	/* max undone descriptors */
	uint32_t		sc_7927_tx_encfail;
	uint32_t		sc_7927_rx_bcn;		/* beacons from our BSS */
	uint32_t		sc_7927_rx_mcast;	/* group-addressed data */
	uint32_t		sc_7927_rx_ucast;	/* unicast data */
	uint32_t		sc_7927_rx_hwdec;	/* decrypted by the chip */
	uint32_t		sc_7927_rx_hwdec_nopn;
	struct mt7927_bss	sc_7927_bss;
	uint8_t			sc_7927_txbuf[2304];
	/* phase 4c */
	uint8_t			*sc_7927_fw_patch;	/* kept for wake */
	size_t			sc_7927_fw_plen;
	uint8_t			*sc_7927_fw_ram;
	size_t			sc_7927_fw_rlen;
	uint32_t		sc_7927_wakes;
	struct mt7927_ba_op	sc_7927_baq[16];
	uint32_t		sc_7927_baq_head;
	uint32_t		sc_7927_baq_tail;
	struct task		sc_7927_ba_task;
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

/* MT7927 glue (defined after the MT7927 engine block). */
static int	mt7927_hal_attach(struct mwx_softc *, struct pci_attach_args *);
static void	mt7927_hal_start(struct mwx_softc *);
static void	mt7927_hal_detach(struct mwx_softc *);
static int	mt7927_hal_preinit(struct mwx_softc *);
static int	mt7927_hal_init_hw(struct mwx_softc *);
static void	mt7927_hal_stop(struct mwx_softc *);
static int	mt7927_hal_scan(struct mwx_softc *);
static void	mt7927_hal_suspend(struct mwx_softc *);
static void	mt7927_hal_poll(struct mwx_softc *);
static void	mt7927_hal_end_scan(struct mwx_softc *);
static void	mt7927_hal_output(struct mwx_softc *, struct ifnet *);
static void	mt7927_newstate(struct mwx_softc *, enum ieee80211_state,
		    enum ieee80211_state, int);
static int	mt7927_set_key(struct ieee80211com *, struct ieee80211_node *,
		    struct ieee80211_key *);
static void	mt7927_delete_key(struct ieee80211com *, struct ieee80211_node *,
		    struct ieee80211_key *);
static void	mt7927_join_poll(struct mwx_softc *);
static void	mt7927_join_teardown(struct mwx_softc *, const char *);
static int	mt7927_ampdu_rx_start(struct ieee80211com *,
		    struct ieee80211_node *, uint8_t);
static void	mt7927_ampdu_rx_stop(struct ieee80211com *,
		    struct ieee80211_node *, uint8_t);
static int	mt7927_ampdu_tx_start(struct ieee80211com *,
		    struct ieee80211_node *, uint8_t);
static void	mt7927_ampdu_tx_stop(struct ieee80211com *,
		    struct ieee80211_node *, uint8_t);
static void	mt7927_ba_task(void *);
struct mt7927_edca;
static void	mt7927_updateedca(struct ieee80211com *);
static void	mt7927_edca_fill(struct mwx_softc *, struct mt7927_edca *);
struct mt7927_ba_op;
static void	mt7927_key_install(struct mwx_softc *, struct mt7927_ba_op *);
static void	mt7927_hal_txroom(void *);
static void	mt7927_rx_bar(struct mwx_softc *, const uint8_t *, size_t);
static int	mt7927_mac_fill_rx(struct mwx_softc *, struct mbuf *,
		    struct ieee80211_rxinfo *);
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

	if (sc->sc_hwtype == MWX_HW_MT7927)
		return mt7927_hal_init_hw(sc);

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
		if (sc->sc_hwtype == MWX_HW_MT7927) {
			mt7927_hal_stop(sc);
		} else {
		if (sc->sc_flags & MWX_FLAG_SCANNING) {
			mt7921_mcu_hw_scan_cancel(sc);
			sc->sc_flags &= ~MWX_FLAG_SCANNING;
		}

		mn = &sc->sc_vif.vif_mn;
		mt7921_mcu_uni_add_dev(sc, &sc->sc_vif, mn, 0);
		mwx_mcu_set_deep_sleep(sc, 1);
		mt7921_mcu_set_mac_enable(sc, 0, 0);
		}
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

	if (sc->sc_hwtype == MWX_HW_MT7927) {
		mt7927_hal_output(sc, ifp);
		return;
	}

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

	if (sc->sc_hwtype == MWX_HW_MT7927) {
		rv = mt7927_hal_scan(sc);
		goto started;
	}
	if (sc->sc_flags & MWX_FLAG_BGSCAN) {
		rv = mt7921_mcu_hw_scan_cancel(sc);
		if (rv) {
			printf("%s: could not abort background scan\n",
			    DEVNAME(sc));
			return rv;
		}
	}

	rv = mt7921_mcu_hw_scan(sc, 0);
started:
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

	if (sc->sc_hwtype == MWX_HW_MT7927) {
		mt7927_newstate(sc, ostate, nstate, arg);
		splx(s);
		return;
	}

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

	if (sc->sc_hwtype == MWX_HW_MT7927) {
		/*
		 * Phase 4e.3: scans while associated, as Linux mt7925 does
		 * them (split scan: the firmware returns to the home channel).
		 * macOS's channel subsets go straight through; a full sweep
		 * (no channel list) at most every 2 minutes.
		 */
		static uint64_t last_full_ns, last_ns;
		uint64_t now_ns, min_ns = 120ULL * 1000000000ULL;

		if (sc->sc_7927_nobgscan)
			return EBUSY;	/* as before phase 4e.3 */
		if (sc->sc_flags & MWX_FLAG_SCANNING) {
			sc->sc_7927_bgscan_busy++;
			return EBUSY;
		}
		absolutetime_to_nanoseconds(mach_absolute_time(), &now_ns);
#ifdef AIRPORT_WCL
		/* macOS's few-channel subsets: at most one per 10 s (as MT7922) */
		if (ic->ic_wcl_scan_requested && ic->ic_wcl_scan_restricted) {
			if (last_ns != 0 &&
			    now_ns - last_ns < 10ULL * 1000000000ULL) {
				sc->sc_7927_bgscan_busy++;
				return EBUSY;
			}
			min_ns = 0;
		}
#endif
		if (min_ns != 0) {
			if (last_full_ns != 0 && now_ns - last_full_ns < min_ns) {
				sc->sc_7927_bgscan_busy++;
				return EBUSY;
			}
			last_full_ns = now_ns;
		}
		err = mt7927_hal_scan(sc);
		if (err != 0) {
			sc->sc_7927_bgscan_busy++;
			return err;
		}
		last_ns = now_ns;
		sc->sc_flags |= MWX_FLAG_BGSCAN;
		sc->sc_7927_bgscans++;
		return 0;
	}
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

	if (sc->sc_hwtype == MWX_HW_MT7927)
		rv = mt7927_mac_fill_rx(sc, m, &rxi);
	else
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
	if (sc->sc_hwtype == MWX_HW_MT7927 && ic->ic_bss != NULL &&
	    ic->ic_state >= IEEE80211_S_ASSOC &&
	    mbuf_len(m) >= sizeof(struct ieee80211_frame) &&
	    IEEE80211_ADDR_EQ(wh->i_addr2, ic->ic_bss->ni_bssid)) {
		uint8_t t = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;

		if (t == IEEE80211_FC0_TYPE_MGT &&
		    (wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) ==
		    IEEE80211_FC0_SUBTYPE_BEACON)
			sc->sc_7927_rx_bcn++;
		else if (t == IEEE80211_FC0_TYPE_DATA &&
		    IEEE80211_IS_MULTICAST(wh->i_addr1))
			sc->sc_7927_rx_mcast++;
		else if (t == IEEE80211_FC0_TYPE_DATA)
			sc->sc_7927_rx_ucast++;
	}
	if ((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_CTL) {
		mwx_rx_ctl_cnt++;
		if ((wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) ==
		    IEEE80211_FC0_SUBTYPE_BAR) {
			mwx_rx_bar_cnt++;
			if (sc->sc_hwtype == MWX_HW_MT7927)
				mt7927_rx_bar(sc, mtod(m, const uint8_t *),
				    mbuf_len(m));
		}
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

	if (sc->sc_hwtype == MWX_HW_MT7927) {
		/* Firmware, connac3 init and MAC come from the MT7927 engine. */
		if ((rv = mt7927_hal_preinit(sc)) != 0)
			return rv;
	} else {
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
	}

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
	/*
	 * VHT channels make net80211 claim 11ax too. Only the MT7927 does HE
	 * (phase 4d; -mtk7927nohe turns it off); the MT7921/22 do not here.
	 */
	if (sc->sc_hwtype != MWX_HW_MT7927 || !sc->sc_7927_he)
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
	/* media_init does not turn VHT on by itself; HE only where 11ax stays */
	if (ic->ic_modecaps & (1 << IEEE80211_MODE_11AX))
		ic->ic_flags |= IEEE80211_F_HEON;
	else
		ic->ic_flags &= ~IEEE80211_F_HEON;
	if (ic->ic_modecaps & (1 << IEEE80211_MODE_11AC))
		ic->ic_flags |= IEEE80211_F_VHTON;
	MWX_DEV_LOG(sc, "preinit 11n htcaps=0x%04x mcs=%02x%02x hton=%d qos=%d vhton=%d vhtcaps=0x%08x heon=%d\n",
	    ic->ic_htcaps, ic->ic_sup_mcs[1], ic->ic_sup_mcs[0],
	    !!(ic->ic_flags & IEEE80211_F_HTON),
	    !!(ic->ic_flags & IEEE80211_F_QOS),
	    !!(ic->ic_flags & IEEE80211_F_VHTON), ic->ic_vhtcaps,
	    !!(ic->ic_flags & IEEE80211_F_HEON));

	sc->sc_sta_added = 0;	/* fresh firmware has no peer records */
	sc->sc_fw_loaded = 1;
	MWX_DEV_LOG(sc, "preinit complete\n");
	return 0;
}

/*
 * mt7925_init_he_caps() for a station (NL80211_IFTYPE_STATION) with two
 * streams: the HE Capabilities element net80211 puts in association requests
 * (ieee80211_add_hecaps) and we put in probe requests. 2.4 and 5 GHz differ
 * in the channel width set and the PPE thresholds, so this is redone for the
 * band before each association and for each band's probe-request IEs.
 */
static void
mt7927_he_caps(struct ieee80211com *ic, bool five)
{
	struct ieee80211_he_cap_elem *e = &ic->ic_he_cap_elem;
	static const uint8_t ppet16_ppet8_ru3_ru0[] = { 0x1c, 0xc7, 0x71 };
	const int nss = 2;
	uint8_t ru = five ? 0xf : 0x3, nru = five ? 4 : 2, bits, size, i;
	uint16_t map = 0;

	for (i = 0; i < 8; i++)
		map |= (uint16_t)((i < nss ? IEEE80211_HE_MCS_SUPPORT_0_11 :
		    IEEE80211_HE_MCS_NOT_SUPPORTED) << (i * 2));
	memset(e, 0, sizeof(*e));
	e->mac_cap_info[0] = IEEE80211_HE_MAC_CAP0_HTC_HE;
	e->mac_cap_info[1] = IEEE80211_HE_MAC_CAP1_TF_MAC_PAD_DUR_16US;
	e->mac_cap_info[3] = IEEE80211_HE_MAC_CAP3_OMI_CONTROL |
	    0x18;					/* MAX_AMPDU_LEN_EXP_EXT_3 */
	e->mac_cap_info[4] = IEEE80211_HE_MAC_CAP4_AMDSU_IN_AMPDU;
	e->phy_cap_info[0] = five ?
	    (IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_40MHZ_80MHZ_IN_5G |
	    IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_160MHZ_IN_5G |
	    IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_RU_MAPPING_IN_5G) :
	    (IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_40MHZ_IN_2G |
	    IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_RU_MAPPING_IN_2G);
	e->phy_cap_info[1] = IEEE80211_HE_PHY_CAP1_LDPC_CODING_IN_PAYLOAD |
	    IEEE80211_HE_PHY_CAP1_DEVICE_CLASS_A |
	    IEEE80211_HE_PHY_CAP1_HE_LTF_AND_GI_FOR_HE_PPDUS_0_8US;
	e->phy_cap_info[2] = IEEE80211_HE_PHY_CAP2_NDP_4x_LTF_AND_3_2US |
	    IEEE80211_HE_PHY_CAP2_STBC_TX_UNDER_80MHZ |
	    IEEE80211_HE_PHY_CAP2_STBC_RX_UNDER_80MHZ |
	    IEEE80211_HE_PHY_CAP2_UL_MU_FULL_MU_MIMO |
	    IEEE80211_HE_PHY_CAP2_UL_MU_PARTIAL_MU_MIMO;
	e->phy_cap_info[3] = IEEE80211_HE_PHY_CAP3_DCM_MAX_CONST_TX_QPSK |
	    IEEE80211_HE_PHY_CAP3_DCM_MAX_CONST_RX_QPSK;
	e->phy_cap_info[4] = IEEE80211_HE_PHY_CAP4_SU_BEAMFORMEE |
	    IEEE80211_HE_PHY_CAP4_BEAMFORMEE_MAX_STS_UNDER_80MHZ_4 |
	    IEEE80211_HE_PHY_CAP4_BEAMFORMEE_MAX_STS_ABOVE_80MHZ_4;
	e->phy_cap_info[5] = IEEE80211_HE_PHY_CAP5_NG16_SU_FEEDBACK |
	    IEEE80211_HE_PHY_CAP5_NG16_MU_FEEDBACK;
	e->phy_cap_info[6] = IEEE80211_HE_PHY_CAP6_CODEBOOK_SIZE_42_SU |
	    IEEE80211_HE_PHY_CAP6_CODEBOOK_SIZE_75_MU |
	    IEEE80211_HE_PHY_CAP6_TRIG_CQI_FB |
	    IEEE80211_HE_PHY_CAP6_PARTIAL_BW_EXT_RANGE |
	    IEEE80211_HE_PHY_CAP6_PPE_THRESHOLD_PRESENT;
	e->phy_cap_info[7] = 0x02 |			/* POWER_BOOST_FACTOR_SUPP */
	    IEEE80211_HE_PHY_CAP7_HE_SU_MU_PPDU_4XLTF_AND_08_US_GI;
	e->phy_cap_info[8] = IEEE80211_HE_PHY_CAP8_20MHZ_IN_40MHZ_HE_PPDU_IN_2G |
	    IEEE80211_HE_PHY_CAP8_20MHZ_IN_160MHZ_HE_PPDU |
	    IEEE80211_HE_PHY_CAP8_80MHZ_IN_160MHZ_HE_PPDU |
	    IEEE80211_HE_PHY_CAP8_DCM_MAX_RU_484;
	e->phy_cap_info[9] = IEEE80211_HE_PHY_CAP9_LONGER_THAN_16_SIGB_OFDM_SYM |
	    IEEE80211_HE_PHY_CAP9_NON_TRIGGERED_CQI_FEEDBACK |
	    IEEE80211_HE_PHY_CAP9_TX_1024_QAM_LESS_THAN_242_TONE_RU |
	    IEEE80211_HE_PHY_CAP9_RX_1024_QAM_LESS_THAN_242_TONE_RU |
	    IEEE80211_HE_PHY_CAP9_RX_FULL_BW_SU_USING_MU_WITH_COMP_SIGB |
	    IEEE80211_HE_PHY_CAP9_RX_FULL_BW_SU_USING_MU_WITH_NON_COMP_SIGB;
	memset(&ic->ic_he_mcs_nss_supp, 0, sizeof(ic->ic_he_mcs_nss_supp));
	ic->ic_he_mcs_nss_supp.rx_mcs_80 = htole16(map);
	ic->ic_he_mcs_nss_supp.tx_mcs_80 = htole16(map);
	ic->ic_he_mcs_nss_supp.rx_mcs_160 = htole16(map);
	ic->ic_he_mcs_nss_supp.tx_mcs_160 = htole16(map);
	/* mt76_connac_gen_ppe_thresh() */
	memset(ic->ic_ppe_thres, 0, sizeof(ic->ic_ppe_thres));
	ic->ic_ppe_thres[0] = (uint8_t)((nss - 1) |
	    (ru << IEEE80211_PPE_THRES_RU_INDEX_BITMASK_POS));
	bits = (uint8_t)(IEEE80211_PPE_THRES_INFO_PPET_SIZE * nss * nru * 2);
	size = (uint8_t)((bits + 7) / 8);
	for (i = 0; i < size - 1; i++)
		ic->ic_ppe_thres[i + 1] = ppet16_ppet8_ru3_ru0[i % 3];
	ic->ic_ppe_thres[i + 1] = ppet16_ppet8_ru3_ru0[i % 3] &
	    (0xff >> (8 - (bits - 1) % 8));
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
	if (PCI_PRODUCT(pa->pa_id) == 0x7927)
		sc->sc_hwtype = MWX_HW_MT7927;
	else if (PCI_PRODUCT(pa->pa_id) == PCI_PRODUCT_MEDIATEK_MT7922)
		sc->sc_hwtype = MWX_HW_MT7922;
	else
		sc->sc_hwtype = MWX_HW_MT7921;
	MWX_DEV_LOG(sc, "attach hardware type=%s\n",
	    sc->sc_hwtype == MWX_HW_MT7927 ? "MT7927" :
	    sc->sc_hwtype == MWX_HW_MT7922 ? "MT7922" : "MT7921");

	memtype = pci_mapreg_type(pa->pa_pc, pa->pa_tag, PCI_MAPREG_START);
	if (pci_mapreg_map(pa, PCI_MAPREG_START, memtype, 0,
	    &sc->sc_st, &sc->sc_memh, NULL, &sc->sc_mems, 0)) {
		printf("%s: can't map mem space\n", DEVNAME(sc));
		return false;
	}
	MWX_DEV_LOG(sc, "attach BAR mapped memtype=0x%x size=%zu\n",
	    memtype, (size_t)sc->sc_mems);

	if (sc->sc_hwtype == MWX_HW_MT7927) {
		/* Own reset, rings and MSI; firmware comes later from disk. */
		if (mt7927_hal_attach(sc, pa) != 0)
			goto fail;
		goto common;
	}

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

common:
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
	if (sc->sc_hwtype == MWX_HW_MT7927) {
		int off = 0;

		/* mt7925_init_hardware(): VHT 160 MHz with short GI */
		ic->ic_vhtcaps |= IEEE80211_VHTCAP_SUPP_CHAN_WIDTH_160MHZ |
		    IEEE80211_VHTCAP_SHORT_GI_160;
		/*
		 * With the chip splitting A-MSDUs (RX decap, phase 4c.10) the
		 * MPDU size is not bound by our buffers: 11454-byte MPDUs and
		 * 1 MB A-MPDUs (exponent 7), as mt7925 advertises.
		 */
		if (!PE_parse_boot_argn("-mtk7927nodecap", &off, sizeof(off))) {
			ic->ic_vhtcaps &= ~(IEEE80211_VHTCAP_MAX_MPDU_MASK |
			    IEEE80211_VHTCAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK);
			ic->ic_vhtcaps |= IEEE80211_VHTCAP_MAX_MPDU_LENGTH_11454 |
			    IEEE80211_VHTCAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK;
		}
		/* phase 4d: 802.11ax station caps as mt7925 (5 GHz set) */
		sc->sc_7927_he = !PE_parse_boot_argn("-mtk7927nohe", &off,
		    sizeof(off));
		mt7927_he_caps(ic, true);
		/*
		 * The front end reports HE to macOS from this (card
		 * capabilities byte 17 bit 7, WCLDeviceConfiguration::
		 * isHeSupported); without it the menu says 802.11ac.
		 */
		if (sc->sc_7927_he)
			ic->ic_caps |= IEEE80211_C_HE;
		/*
		 * RX Block Ack windows up to 256 MPDUs, as mt792x sets
		 * max_rx_aggregation_subframes (IEEE80211_MAX_AMPDU_BUF_HE):
		 * longer A-MPDUs between Block Acks, both ways (TX: the AP's ADDBA
		 * response may give less).
		 */
		ic->ic_rx_ba_max_winsz = MT7927_REORDER_WIN;
		ic->ic_tx_ba_max_winsz = MT7927_REORDER_WIN;
	}

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
	if (sc->sc_hwtype == MWX_HW_MT7927) {
		/*
		 * Keys in software (net80211 CCMP): the hardware cannot build
		 * A-MSDUs of frames it does not encrypt, so no TX A-MSDU.
		 */
		int sw = 0;

		ic->ic_set_key = mt7927_set_key;
		ic->ic_delete_key = mt7927_delete_key;
		ic->ic_updateedca = mt7927_updateedca;
		ic->ic_caps &= ~IEEE80211_C_TX_AMSDU_IN_AMPDU;
		sc->sc_7927_hwcrypto = !PE_parse_boot_argn("-mtk7927swcrypto",
		    &sw, sizeof(sw));
		/*
		 * With keys in the chip the MAC can build A-MSDUs itself
		 * (MT_TXD3_HW_AMSDU), as Linux mt7925 does. Opt-in with
		 * -mtk7927amsdu until the TX path is understood.
		 */
		sc->sc_7927_amsdu_ok = sc->sc_7927_hwcrypto &&
		    PE_parse_boot_argn("-mtk7927amsdu", &sw, sizeof(sw));
		if (sc->sc_7927_amsdu_ok)
			ic->ic_caps |= IEEE80211_C_TX_AMSDU_IN_AMPDU;
		ic->ic_ampdu_rx_start = mt7927_ampdu_rx_start;
		ic->ic_ampdu_rx_stop = mt7927_ampdu_rx_stop;
		ic->ic_ampdu_tx_start = mt7927_ampdu_tx_start;
		ic->ic_ampdu_tx_stop = mt7927_ampdu_tx_stop;
		task_set(&sc->sc_7927_ba_task, mt7927_ba_task, sc, "mt7927_ba");
	}

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
	if (sc->sc_hwtype == MWX_HW_MT7927)
		mt7927_hal_start(sc);	/* waits for the Data volume */
	else
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
#define	MT7927_PKT_TYPE_NORMAL_MCU	8

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
#define	MT7927_UNI_EDCA_UPDATE		MT7927_UNI_CMD(0x04)
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

/* Phase 4 (mt7925/mcu.h, mt76_connac_mcu.h). */
#define	MT7927_UNI_SCAN_REQ_CMD		MT7927_UNI_CMD(0x16)
#define	MT7927_SCAN_IE_MAX		200	/* probe-request IEs per band */
#define	MT7927_UNI_SCAN_REQ		1
#define	MT7927_UNI_SCAN_CANCEL		2
#define	MT7927_UNI_SCAN_SSID		10
#define	MT7927_UNI_SCAN_BSSID		11
#define	MT7927_UNI_SCAN_CHANNEL		12
#define	MT7927_UNI_SCAN_IE		13
#define	MT7927_UNI_SCAN_MISC		14
#define	MT7927_SCAN_FUNC_SPLIT_SCAN	(1U << 5)
#define	MT7927_UNI_EVENT_SCAN_DONE	0x0e
#define	MT7927_UNI_EVENT_COREDUMP	0x0a
#define	MT7927_UNI_EVENT_BSS_BEACON_LOSS 0x0c
#define	MT7927_UNI_EVENT_SCAN_DONE_BASIC 0
#define	MT7927_UNI_BAND_CONFIG_RX_FILTER 0x0c
#define	MT7927_FILTER_ENABLE		(1U << 31)
#define	MT7927_CONNECTION_INFRA_STA	0x00010001	/* STA_TYPE_STA | NETWORK_INFRA */
#define	MT7927_WTBL_RESERVED		(MT7927_WTBL_SIZE - 1)
#define	MT7927_UNI_SET_POWER_LIMIT	MT7927_UNI_CMD(0x2c)
#define	MT7927_TXPWR_HDR		52	/* struct mt7925_tx_power_limit_tlv */
#define	MT7927_SKU_LEN			450	/* channel + MT_CONNAC3_SKU_POWER_LIMIT */
#define	MT7927_MIB(b, ofs)		(((b) ? 0x820fd000U : 0x820ed000U) + (ofs))

/* Phase 4b: join, data TX (mt7925/mcu.h, mt76_connac_mcu.h, mt76_connac3_mac.h). */
#define	MT7927_UNI_ROC			MT7927_UNI_CMD(0x27)
#define	MT7927_UNI_EVENT_ROC		0x27
#define	MT7927_UNI_ROC_ACQUIRE		0
#define	MT7927_UNI_ROC_ABORT		1
#define	MT7927_UNI_EVENT_ROC_GRANT	0
#define	MT7927_ROC_REQ_JOIN		0
#define	MT7927_ROC_WAIT_MS		4000		/* 4 * HZ */

#define	MT7927_BSS_TAG_BASIC		0
#define	MT7927_BSS_TAG_RLM		2
#define	MT7927_BSS_TAG_MBSSID		6
#define	MT7927_BSS_TAG_RATE		11
#define	MT7927_BSS_TAG_QBSS		15
#define	MT7927_BSS_TAG_SEC		16
#define	MT7927_BSS_TAG_IFS_TIME		23
#define	MT7927_BSS_TAG_PS		21	/* UNI_BSS_INFO_PS */
#define	MT7927_BSS_TAG_MLD		26
#define	MT7927_BSS_TAG_BSS_COLOR	4	/* UNI_BSS_INFO_BSS_COLOR */
#define	MT7927_BSS_TAG_HE_BASIC		5	/* UNI_BSS_INFO_HE_BASIC */
#define	MT7927_STA_TAG_HE_V2		0x19	/* STA_REC_HE_V2 */
#define	MT7927_STA_TAG_BASIC		0
#define	MT7927_STA_TAG_RA		1
#define	MT7927_STA_TAG_BA		6
#define	MT7927_STA_TAG_STATE		7
#define	MT7927_STA_TAG_HT		9
#define	MT7927_STA_TAG_VHT		10
#define	MT7927_BA_TYPE_ORIGINATOR	1
#define	MT7927_BA_TYPE_RECIPIENT	2
#define	MT7927_STA_TAG_PHY		0x15
#define	MT7927_STA_TAG_MLD_OFF		0x23
#define	MT7927_STA_TAG_REMOVE		0x25
#define	MT7927_STA_TAG_HDR_TRANS	0x2b
#define	MT7927_STA_TAG_KEY_V3		0x27
#define	MT7927_STA_TAG_HW_AMSDU		0x0f
#define	MT7927_CIPHER_AES_CCMP		4
#define	MT7927_BSS_MODE_WPA2_PSK	7
#define	MT7927_HWKEY_PAIRWISE		0x01	/* sc_7927_hwkeys */
#define	MT7927_HWKEY_GROUP		0x02
#define	MT7927_CONNECTION_INFRA_AP	0x00010002	/* STA_TYPE_AP | NETWORK_INFRA */
#define	MT7927_CONNECTION_INFRA_BC	0x00010020	/* STA_TYPE_BC | NETWORK_INFRA */
#define	MT7927_CONN_STATE_PORT_SECURE	2
#define	MT7927_EXTRA_INFO_VER		(1U << 0)
#define	MT7927_EXTRA_INFO_NEW		(1U << 1)
#define	MT7927_PHY_TYPE_ERP_INDEX	1
#define	MT7927_PHY_TYPE_OFDM_INDEX	3
#define	MT7927_BASIC_RATES_IDX(band)	(MT7927_BASIC_RATES_TBL + ((band) == 1 ? 0 : 4))

/* connac3 TXD (mt76_connac3_mac.h) */
#define	MT7927_TXD_SIZE			32
#define	MT7927_TXP_SIZE			32	/* struct mt76_connac_hw_txp */
#define	MT7927_TXD0_TX_BYTES(x)		((x) & 0xffff)
#define	MT7927_TXD0_PKT_FMT_CT		(0U << 23)
#define	MT7927_TXD0_Q_IDX(x)		((uint32_t)(x) << 25)
#define	MT7927_TXD1_WLAN_IDX(x)		((x) & 0xfff)
#define	MT7927_TXD1_TGID(x)		(((uint32_t)(x) & 3) << 12)
#define	MT7927_TXD1_HDR_FORMAT_80211	(2U << 14)
#define	MT7927_TXD1_HDR_INFO(x)		(((uint32_t)(x) & 0x1f) << 16)
#define	MT7927_TXD1_TID(x)		(((uint32_t)(x) & 0xf) << 21)
#define	MT7927_TXD1_OWN_MAC(x)		(((uint32_t)(x) & 0x3f) << 25)
#define	MT7927_TXD1_FIXED_RATE		(1U << 31)
#define	MT7927_TXD2_SUB_TYPE(x)		((x) & 0xf)
#define	MT7927_TXD2_FRAME_TYPE(x)	(((uint32_t)(x) & 3) << 4)
#define	MT7927_TXD3_NO_ACK		(1U << 0)
#define	MT7927_TXD3_PROTECT_FRAME	(1U << 1)
#define	MT7927_TXD3_BCM			(1U << 4)
#define	MT7927_TXD3_HW_AMSDU		(1U << 5)
#define	MT7927_TXD5_PID(x)		((uint32_t)(x) & 0xff)
#define	MT7927_TXD5_TX_STATUS_HOST	(1U << 10)
#define	MT7927_TXS_PID			0x40	/* sampled TX status (< 0x7f) */
#define	MT7927_PKT_TYPE_TXS		0
#define	MT7927_TXD3_REM_TX_COUNT(x)	(((uint32_t)(x) & 0x1f) << 11)
#define	MT7927_TXD3_BA_DISABLE		(1U << 28)
#define	MT7927_TXD6_DAS			(1U << 2)
#define	MT7927_TXD6_DIS_MAT		(1U << 3)
#define	MT7927_TXD6_MSDU_CNT(x)		(((uint32_t)(x) & 0x3f) << 4)
#define	MT7927_TXD6_TX_RATE(x)		(((uint32_t)(x) & 0x3f) << 16)
#define	MT7927_TXP_MSDU_VALID		(1U << 15)	/* MT_MSDU_ID_VALID */
#define	MT7927_TXP_LEN_LAST		(1U << 15)	/* MT_TXD_LEN_LAST */
#define	MT7927_LMAC_ALTX0		0x10
#define	MT7927_PKT_TYPE_TXRX_NOTIFY	6
#define	MT7927_TXFREE_INFO_PAIR		(1U << 31)
#define	MT7927_TXFREE_INFO_HEADER	(1U << 30)
#define	MT7927_TXFREE_MSDU_MASK		0x7fff

/* cfg80211 channel flags carried in SET_DOMAIN_INFO (enum ieee80211_channel_flags). */
#define	MT7927_CHAN_NO_IR		(1U << 1)
#define	MT7927_CHAN_RADAR		(1U << 3)
#define	MT7927_CHAN_NO_OFDM		(1U << 6)

/* MAC registers touched by mt7925_mac_init() (mt7925/regs.h, mt792x_regs.h). */
#define	MT7927_MDP_DCR0			0x820cc800
#define	MT7927_MDP_DCR0_DAMSDU_EN	(1U << 15)
#define	MT7927_MDP_DCR1			0x820cc804
#define	MT7927_MAX_RX_LEN_MASK		0x0000fff8	/* GENMASK(15, 3) */
#define	MT7927_MAX_RX_LEN		(3968U << 3)
/*
 * Phase 4c: keys stay in software, so the chip cannot open an A-MSDU (its
 * subframe headers are encrypted). A-MSDUs arrive whole (up to the 3895-byte
 * VHT MPDU we advertise) in 4 KB buffers and net80211 decaps them after
 * decrypting; hardware de-A-MSDU stays off. Linux (keys in hardware) uses
 * 1536 + DAMSDU with 2 KB buffers.
 */
#define	MT7927_RX_BUF_SIZE		4096
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

/* Phase 4 interface to the main driver. */
enum {
	MT7927_RX_SHORT = 1,
	MT7927_RX_AMSDU_ERR,
	MT7927_RX_LEN_ERR,
	MT7927_RX_FCS_ERR,
	MT7927_RX_ICV_ERR,
	MT7927_RX_HDR_TRANS,
};

struct mt7927_rxi {
	uint32_t	hdr_off;	/* offset of the 802.11 header */
	uint32_t	frame_len;
	uint8_t		chan;		/* IEEE channel number */
	uint8_t		band;		/* 2, 5 or 6 (GHz) */
	uint8_t		band_idx;
	int8_t		rssi;		/* dBm, -127 when unknown */
	bool		decrypted;
	bool		unicast;
	uint16_t	wlan_idx;
	uint8_t		sec_mode;	/* CONNAC3_CIPHER_* the frame used */
	uint8_t		key_id;
	bool		has_pn;		/* group 1 present: pn[] valid */
	uint8_t		pn[6];		/* PN0 (least significant) first */
	/* header translation (RX decap offload): payload is 802.3 */
	bool		hdr_trans;
	bool		hdr_trans_err;	/* 2-byte length after the type */
	bool		frag;
	uint8_t		amsdu;		/* RXD4: 0 none, 3 first, 2 middle, 1 last */
	bool		has_g4;		/* group 4: fc, seq_ctrl, qos_ctl valid */
	uint16_t	fc;
	uint16_t	seq_ctrl;
	uint16_t	qos_ctl;
};



struct mt7927_vif {
	uint8_t		idx;		/* bss_idx */
	uint8_t		omac_idx;
	uint8_t		band_idx;
	uint8_t		wmm_idx;
	uint16_t	wcid;
	uint8_t		addr[6];
};

struct mt7927_scan_chan {
	uint8_t		band;		/* 1: 2.4 GHz, 2: 5 GHz, 3: 6 GHz */
	uint8_t		chan;
};

struct mt7927_dmamem {
	void		*va;
	uint32_t	pa;
	size_t		size;
	void		*handle;
};

/*
 * Ring buffers come in 64 KB physically contiguous chunks, so rings as large
 * as Linux's (1536 RX buffers) need no multi-megabyte contiguous block.
 */
#define	MT7927_CHUNK_SZ		65536
#define	MT7927_RING_CHUNKS	96

struct mt7927_ring {
	struct mt7927_dmamem	desc_mem;
	struct mt7927_dmamem	buf_chunk[MT7927_RING_CHUNKS];
	uint16_t		per_chunk;	/* buffers per chunk */
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
#define MT7927_STAGE_N		64	/* rx6 frame staging slots */
#define MT7927_RX_BATCH		64	/* 802.11 frames per if_input() */
/*
 * Data TX payload buffers (msdu ids). Linux allows 8192 and limits latency
 * with mac80211's airtime queue limit, which we do not have: 1024 is about
 * 15 ms of 2x2 VHT80 airtime.
 */
#define MT7927_TX_TOKENS	1024
#define MT7927_TOK_PER_CHUNK	(MT7927_CHUNK_SZ / MT7927_TX_TOKEN_SZ)
#define MT7927_TOK_CHUNKS	((MT7927_TX_TOKENS + MT7927_TOK_PER_CHUNK - 1) / \
				    MT7927_TOK_PER_CHUNK)
#define MT7927_TX_TOKEN_SZ	2304
/* no TX free event for this many watchdog seconds: tokens may be reclaimed */
#define MT7927_RECLAIM_TICKS	3
#define MT7927_STAGE_SZ		4096

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

	/* phase 4: kept running under the main driver */
	volatile bool		running;	/* firmware up, hardware kept */
	bool			owns_sc;	/* sc allocated by bringup_create */
	volatile uint8_t	wait_seq;	/* MCU reply being waited for */
	volatile bool		wait_done;
	void			*cb_arg;
	void			(*cb_rx)(void *, const uint8_t *, uint32_t);
	void			(*cb_rx_done)(void *);	/* end of an RX batch */
	uint32_t		rx_cur_info;	/* DMA descriptor info of the frame in cb_rx */
	bool			rx_decap;	/* header translation + de-A-MSDU */
	void			(*cb_event)(void *, uint8_t, const uint8_t *,
				    uint32_t);
	void			(*cb_txroom)(void *);
	volatile bool		tx_blocked;
	uint32_t		rx_frames;	/* handed to cb_rx */
	uint32_t		rx_other;	/* data-ring packets not delivered */
	uint32_t		isr_runs;
	uint8_t			scan_seq;
	/* phase 4a diagnostics */
	uint32_t		ring_pkts[MT7927_NRX];
	uint32_t		ring_types[MT7927_NRX][16];
	uint32_t		other_logged;
	uint32_t		scan_done_logged;
	/*
	 * phase 4a.3: the firmware routes 802.11 frames to the MCU event
	 * ring (rx6) too. That ring is drained under the svc lock, from the
	 * interrupt handler or from a thread waiting on a command, where
	 * calling into net80211 could deadlock. Frames are copied here
	 * under the lock and handed to cb_rx from the interrupt handler
	 * once it is released. Producers hold the svc lock; the work loop
	 * is the only consumer, and stage_tail moves only after a slot
	 * has been delivered, so a slot is never rewritten while read.
	 */
	uint32_t		stage_head;	/* written under svc lock */
	uint32_t		stage_tail;	/* advanced under svc lock */
	uint32_t		stage_drops;
	uint32_t		stage_frames;	/* rx6 frames delivered */
	uint16_t		stage_len[MT7927_STAGE_N];
	uint8_t			stage[MT7927_STAGE_N][MT7927_STAGE_SZ]
				    __attribute__((aligned(8)));
	/* phase 4b: join ROC */
	volatile bool		roc_granted;
	bool			roc_active;
	uint8_t			roc_token;
	uint8_t			roc_status;
	uint8_t			roc_chan;
	uint32_t		roc_grant_ms;
	uint32_t		roc_events;
	/* phase 4b: data TX tokens (payload buffers named by msdu id) */
	struct mt7927_dmamem	tok_chunk[MT7927_TOK_CHUNKS];
	volatile uint8_t	tok_busy[MT7927_TX_TOKENS];
	uint32_t		tok_when[MT7927_TX_TOKENS];
	uint32_t		tok_seq;
	uint32_t		tok_next;
	uint32_t		tx_queued;
	uint32_t		tx_done;
	uint32_t		tx_failed;
	uint32_t		tx_free_events;
	uint32_t		tx_free_badver;
	uint32_t		tx_no_token;
	uint32_t		tx_reclaimed;
	uint32_t		tx_ring_full;
	uint32_t		tx_logged;
	uint32_t		tok_free_seq;	/* tok_seq at the last TX free event */
	uint32_t		wd_ticks;	/* watchdog seconds (engine_tick) */
	uint32_t		tok_free_tick;	/* ticks at the last TX free event */
	uint32_t		tx_retries;	/* free event headers: tx count - 1 */
	uint32_t		tx_free_msdus;	/* MSDUs in TX free events */
	uint32_t		tx_free_max;	/* most MSDUs in one free event */
	/* phase 4c.3: sampled TX status (rate the firmware picked) */
	uint32_t		txs_count;
	uint32_t		txs_ack_err;
	uint32_t		txs_last;	/* TXS0: rate, bw, ampdu, errors */
	uint32_t		txs_last1;	/* TXS1: tx power */
	/* unsolicited firmware events by ID; beacon loss / coredump logged */
	uint16_t		eid_count[256];
	uint32_t		bcn_loss;
	uint32_t		coredumps;
	uint32_t		eid_logged;
	/* last 30 s MIB window (the counters clear on read) */
	uint32_t		mib_rx_time[2];
	uint32_t		mib_tx_time[2];
	uint32_t		mib_windows;
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
static int mt7927_dmamem_alloc(struct mt7927_dmamem *, size_t, bool);
static void mt7927_dmamem_free(struct mt7927_dmamem *);
static void mt7927_signal(struct mt7927_bringup *);
static void mt7927_wait(struct mt7927_bringup *, int);
static int mt7927_irq_setup(struct mt7927_bringup *);
static void mt7927_svc_lock(struct mt7927_bringup *);
static void mt7927_svc_unlock(struct mt7927_bringup *);
static void mt7927_op_lock(struct mt7927_bringup *);
static void mt7927_op_unlock(struct mt7927_bringup *);
#else
struct mt7927_os {
	IOWorkLoop	*wl;
	IOLock		*lock;
	IOMemoryMap	*bar;		/* NULL when the main driver owns BAR0 */
	IOLock		*svc;		/* RX MCU ring: ISR vs. MCU waiter */
	IORecursiveLock	*op;		/* one MCU exchange at a time */
};

static int
mt7927_dmamem_alloc(struct mt7927_dmamem *m, size_t size, bool cached)
{
	IOBufferMemoryDescriptor *md;
	IOPhysicalAddress pa;

	memset(m, 0, sizeof(*m));
	/*
	 * Page aligned, physically contiguous, below 4 GB (32-bit DMA mask).
	 * Frame buffers are cached, like Linux's page_pool / coherent memory
	 * on x86, where PCIe DMA snoops the CPU caches: copying a frame out
	 * of uncached memory costs a bus read per word. Descriptors stay
	 * uncached.
	 */
	md = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(kernel_task,
	    kIOMemoryPhysicallyContiguous | kIODirectionInOut |
	    (cached ? 0 : kIOMapInhibitCache), size, 0x00000000fffff000ULL);
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

static void
mt7927_svc_lock(struct mt7927_bringup *b)
{
	IOLockLock(((struct mt7927_os *)b->os)->svc);
}

static void
mt7927_svc_unlock(struct mt7927_bringup *b)
{
	IOLockUnlock(((struct mt7927_os *)b->os)->svc);
}

static void
mt7927_op_lock(struct mt7927_bringup *b)
{
	IORecursiveLockLock(((struct mt7927_os *)b->os)->op);
}

static void
mt7927_op_unlock(struct mt7927_bringup *b)
{
	IORecursiveLockUnlock(((struct mt7927_os *)b->os)->op);
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
	    count * sizeof(struct mwx_desc), false)) != 0)
		return rv;
	r->per_chunk = bufsz >= MT7927_CHUNK_SZ ? 1 :
	    (uint16_t)(MT7927_CHUNK_SZ / bufsz);
	for (uint32_t i = 0, done = 0; done < count; i++) {
		uint32_t n = count - done < r->per_chunk ? count - done :
		    r->per_chunk;

		if (i >= MT7927_RING_CHUNKS)
			return EINVAL;
		if ((rv = mt7927_dmamem_alloc(&r->buf_chunk[i], (size_t)n * bufsz,
		    true)) != 0)
			return rv;
		done += n;
	}
	r->desc = (struct mwx_desc *)r->desc_mem.va;
	return 0;
}

static void
mt7927_ring_free(struct mt7927_ring *r)
{
	mt7927_dmamem_free(&r->desc_mem);
	for (int i = 0; i < MT7927_RING_CHUNKS; i++)
		if (r->buf_chunk[i].va != NULL)
			mt7927_dmamem_free(&r->buf_chunk[i]);
	r->desc = NULL;
}

static inline uint32_t
mt7927_ring_buf_pa(struct mt7927_ring *r, uint16_t idx)
{
	return r->buf_chunk[idx / r->per_chunk].pa +
	    (uint32_t)(idx % r->per_chunk) * r->bufsz;
}

static inline uint8_t *
mt7927_ring_buf(struct mt7927_ring *r, uint16_t idx)
{
	return (uint8_t *)r->buf_chunk[idx / r->per_chunk].va +
	    (size_t)(idx % r->per_chunk) * r->bufsz;
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

static void mt7927_service(struct mt7927_bringup *);
static void mt7927_isr_running(struct mt7927_bringup *);
static void mt7927_roc_event(struct mt7927_bringup *, const uint8_t *, uint32_t);
static void mt7927_tx_free_event(struct mt7927_bringup *, const uint8_t *,
    uint32_t);
static void mt7927_txs_event(struct mt7927_bringup *, const uint8_t *,
    uint32_t);
static uint32_t mt7927_le32(const uint8_t *);

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
		mt7927_service(b);
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
	if (b->running)
		mt7927_isr_running(b);
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
	if (eid == MT7927_UNI_EVENT_ROC) {
		if (len > MT7927_MCU_RXD_LEN)
			mt7927_roc_event(b, p + MT7927_MCU_RXD_LEN,
			    len - MT7927_MCU_RXD_LEN);
		return;
	}
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
	if (b->eid_count[eid] < 0xffff)
		b->eid_count[eid]++;
	if (eid == MT7927_UNI_EVENT_BSS_BEACON_LOSS ||
	    eid == MT7927_UNI_EVENT_COREDUMP) {
		char hex[3 * 24 + 1];
		uint32_t k, m = len > MT7927_MCU_RXD_LEN ?
		    len - MT7927_MCU_RXD_LEN : 0;

		if (eid == MT7927_UNI_EVENT_BSS_BEACON_LOSS)
			b->bcn_loss++;
		else
			b->coredumps++;
		if (m > 24)
			m = 24;
		for (k = 0; k < m; k++)
			snprintf(hex + 3 * k, 4, "%02x ", p[MT7927_MCU_RXD_LEN + k]);
		hex[3 * m] = '\0';
		if (b->eid_logged++ < 32)
			MWX_DEV_LOG(b->sc, "MT7927 firmware %s event (len %u): %s\n",
			    eid == MT7927_UNI_EVENT_COREDUMP ? "COREDUMP" :
			    "BEACON LOSS", len, hex);
		return;
	}
	if (b->unsolicited++ < 16 || b->eid_count[eid] == 1)
		MWX_DEV_LOG(b->sc, "MT7927 unsolicited event on %s: eid=0x%02x "
		    "len=%u%s\n", r->name, eid, len,
		    b->eid_count[eid] == 1 ? " (first of this id)" : "");
	if (eid == MT7927_UNI_EVENT_SCAN_DONE && b->scan_done_logged++ < 3) {
		char hex[3 * 32 + 1];
		uint32_t k, m = len > MT7927_MCU_RXD_LEN ? len - MT7927_MCU_RXD_LEN : 0;

		if (m > 32)
			m = 32;
		for (k = 0; k < m; k++)
			snprintf(hex + 3 * k, 4, "%02x ", p[MT7927_MCU_RXD_LEN + k]);
		hex[3 * m] = '\0';
		MWX_DEV_LOG(b->sc, "MT7927 scan-done event len %u: %s\n", len, hex);
	}
	if (b->running && b->cb_event != NULL)
		b->cb_event(b->cb_arg, eid, p + MT7927_MCU_RXD_LEN,
		    len > MT7927_MCU_RXD_LEN ? len - MT7927_MCU_RXD_LEN : 0);
}

/* connac3 RXD0 packet type, with the SW frame and NORMAL_MCU remaps of
 * mt7925_queue_rx_skb(). */
static uint32_t
mt7927_rx_type(uint32_t rxd0)
{
	uint32_t type = rxd0 >> 27, flag = (rxd0 >> 16) & 0xf;

	if (type != PKT_TYPE_NORMAL && ((rxd0 >> 16) & 0x380f) == 0x3801)
		return PKT_TYPE_NORMAL;
	if (type == MT7927_PKT_TYPE_RX_EVENT && flag == 0x1)
		return MT7927_PKT_TYPE_NORMAL_MCU;
	return type;
}

/*
 * Drain one RX ring. MCU replies whose seq matches the command being waited
 * for (b->wait_seq) are copied to b->resp; unsolicited events go to
 * mt7927_unsolicited(); with deliver, 802.11 frames go to cb_rx.
 */
static bool
mt7927_drain(struct mt7927_bringup *b, struct mt7927_ring *r, bool deliver,
    bool stop_when_full)
{
	struct mwx_softc *sc = b->sc;
	uint8_t *p;
	uint32_t len;
	int n;

	if (r->desc == NULL)
		return false;
	for (n = 0; n < r->count && (p = mt7927_rx_peek(r, &len)) != NULL; n++) {
		uint32_t rxd0 = len >= 4 ? le32toh(*(uint32_t *)p) : 0;
		uint32_t type = mt7927_rx_type(rxd0);
		int ri = (int)(r - b->rx);

		if (stop_when_full && !deliver &&
		    b->stage_head - b->stage_tail >= MT7927_STAGE_N &&
		    (type == PKT_TYPE_NORMAL ||
		    type == MT7927_PKT_TYPE_NORMAL_MCU))
			return true;	/* deliver the stage, then come back */

		if (ri >= 0 && ri < MT7927_NRX) {
			b->ring_pkts[ri]++;
			b->ring_types[ri][type & 0xf]++;
		}

		if (len >= MT7927_MCU_RXD_LEN - 4 &&
		    type == MT7927_PKT_TYPE_RX_EVENT) {
			uint8_t eid = p[32 + 4], seq = p[32 + 5];
			uint8_t opt = p[32 + 6], ext_eid = p[32 + 8];

			if (opt & MT7927_RXD_OPT_UNSOLICITED) {
				mt7927_unsolicited(b, r, p, len);
			} else if (b->wait_seq != 0 && seq == b->wait_seq &&
			    !b->wait_done) {
				b->resp_status = ext_eid;
				b->resp_len = len > MT7927_MCU_RXD_LEN ?
				    len - MT7927_MCU_RXD_LEN : 0;
				if (b->resp_len > sizeof(b->resp))
					b->resp_len = sizeof(b->resp);
				memcpy(b->resp, p + MT7927_MCU_RXD_LEN,
				    b->resp_len);
				OSSynchronizeIO();
				b->wait_done = true;
			} else if (eid == MT7927_UNI_EVENT_ROC) {
				if (len > MT7927_MCU_RXD_LEN)
					mt7927_roc_event(b, p + MT7927_MCU_RXD_LEN,
					    len - MT7927_MCU_RXD_LEN);
			} else if (b->unsolicited++ < 16) {
				MWX_DEV_LOG(sc, "MT7927 event on %s: eid=0x%02x "
				    "seq=%u ext=0x%02x len=%u (not waited for)\n",
				    r->name, eid, seq, ext_eid, len);
			}
		} else if (type == MT7927_PKT_TYPE_TXRX_NOTIFY && b->running) {
			mt7927_tx_free_event(b, p, len);
		} else if (type == MT7927_PKT_TYPE_TXS && b->running) {
			mt7927_txs_event(b, p, len);
		} else if (deliver && b->cb_rx != NULL &&
		    (type == PKT_TYPE_NORMAL ||
		    type == MT7927_PKT_TYPE_NORMAL_MCU)) {
			b->rx_frames++;
			/* checksum status (mt76_dma_get_buf: desc->info) */
			b->rx_cur_info = le32toh(r->desc[r->tail].info);
			b->cb_rx(b->cb_arg, p, len);
			b->rx_cur_info = 0;
		} else if (!deliver && b->running && b->cb_rx != NULL &&
		    (type == PKT_TYPE_NORMAL ||
		    type == MT7927_PKT_TYPE_NORMAL_MCU)) {
			/* caller holds the svc lock (running mode) */
			if (b->stage_head - b->stage_tail < MT7927_STAGE_N &&
			    len <= MT7927_STAGE_SZ) {
				uint32_t slot = b->stage_head % MT7927_STAGE_N;

				memcpy(b->stage[slot], p, len);
				b->stage_len[slot] = (uint16_t)len;
				OSSynchronizeIO();
				b->stage_head++;
			} else {
				b->stage_drops++;
			}
		} else {
			b->rx_other++;
			if (b->other_logged++ < 12)
				MWX_DEV_LOG(sc, "MT7927 rx on %s: type=%u len=%u "
				    "rxd0-3 %08x %08x %08x %08x (%s)\n", r->name,
				    type, len, rxd0,
				    len >= 8 ? mt7927_le32(p + 4) : 0,
				    len >= 12 ? mt7927_le32(p + 8) : 0,
				    len >= 16 ? mt7927_le32(p + 12) : 0,
				    b->running ? "running" : "bring-up");
		}
		mt7927_rx_release(b, r);
	}
	return false;
}

/*
 * Poll for MCU traffic from the thread waiting on a command. During
 * bring-up every ring is drained (nothing else runs); once running, only
 * the MCU event ring, under the lock shared with the interrupt handler,
 * which owns the data rings. Re-enables the host interrupt mask afterwards,
 * like mt792x_poll_rx() / mt76_connac_irq_enable().
 */
static void
mt7927_service(struct mt7927_bringup *b)
{
	int i;

	if (!b->running) {
		for (i = 0; i < MT7927_NRX; i++)
			mt7927_drain(b, &b->rx[i], false, false);
	} else {
		mt7927_svc_lock(b);
		mt7927_drain(b, &b->rx[MT7927_RX_MCU], false, false);
		mt7927_svc_unlock(b);
	}
	if (b->dma_on)
		mt7927_raw_wr(b->sc, MT_WFDMA0_HOST_INT_ENA, b->irq_mask);
}

/*
 * Hand frames staged from rx6 to cb_rx (work loop thread, svc lock not
 * held). The tail moves only after the slot has been delivered.
 */
static void
mt7927_deliver_staged(struct mt7927_bringup *b)
{
	uint32_t head, tail;

	mt7927_svc_lock(b);
	head = b->stage_head;
	tail = b->stage_tail;
	mt7927_svc_unlock(b);
	while (tail != head) {
		uint32_t slot = tail % MT7927_STAGE_N;

		if (b->cb_rx != NULL && b->running) {
			b->rx_frames++;
			b->stage_frames++;
			b->cb_rx(b->cb_arg, b->stage[slot], b->stage_len[slot]);
		}
		tail++;
		mt7927_svc_lock(b);
		b->stage_tail = tail;
		mt7927_svc_unlock(b);
	}
}

/*
 * Output was refused for lack of TX tokens or ring slots: once TX free events
 * gave enough back, let the driver restart it (work loop thread).
 */
static void
mt7927_tx_room_check(struct mt7927_bringup *b)
{
	uint32_t i, freed = 0;

	if (!b->tx_blocked || b->cb_txroom == NULL)
		return;
	for (i = 0; i < MT7927_TX_TOKENS && freed < 32; i++)
		if (!b->tok_busy[i])
			freed++;
	if (freed < 32)
		return;
	b->tx_blocked = false;
	b->cb_txroom(b->cb_arg);
}

/*
 * Interrupt work once running (work loop thread): the MCU ring under the
 * lock, then the data rings with frames handed to cb_rx. MSI is edge
 * triggered, so status that arrived meanwhile is drained before the mask
 * is restored (as mwx_intr does).
 */
static void
mt7927_isr_running(struct mt7927_bringup *b)
{
	struct mwx_softc *sc = b->sc;
	uint32_t sta;
	int pass;

	b->isr_runs++;
	for (pass = 0; pass < 8; pass++) {
		bool full;
		int batch = 0;

		do {
			mt7927_svc_lock(b);
			full = mt7927_drain(b, &b->rx[MT7927_RX_MCU], false, true);
			mt7927_svc_unlock(b);
			mt7927_deliver_staged(b);
		} while (full && ++batch < 64);
		mt7927_drain(b, &b->rx[MT7927_RX_BAND0], true, false);
		mt7927_drain(b, &b->rx[MT7927_RX_DATA2], true, false);
		if (b->cb_rx_done != NULL)
			b->cb_rx_done(b->cb_arg);
		mt7927_tx_room_check(b);
		sta = mt7927_raw_rd(sc, MT_WFDMA0_HOST_INT_STA) & b->irq_mask;
		if (sta == 0 || sta == (0xffffffff & b->irq_mask))
			break;
		mt7927_raw_wr(sc, MT_WFDMA0_HOST_INT_STA, sta);
		if (sta & MT_INT_MCU_CMD) {
			uint32_t sw = mt7927_raw_rd(sc, MT_MCU_CMD);

			mt7927_raw_wr(sc, MT_MCU_CMD, sw);
			OSBitOrAtomic(sw, &b->mcu_sw_seen);
		}
		OSBitOrAtomic(sta, &b->intr_seen);
	}
	if (b->dma_on && b->running)
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
	mt7927_svc_lock(b);
	b->wait_done = false;
	b->wait_seq = wait ? seq : 0;
	mt7927_svc_unlock(b);
	if ((rv = mt7927_tx(b, &b->tx[MT7927_TX_MCU], buf, tot_len)) != 0) {
		b->wait_seq = 0;
		return rv;
	}
	if (!wait)
		return 0;

	for (waited = 0; waited <= MT7927_MCU_TIMEOUT_MS; waited++) {
		mt7927_service(b);
		if (b->wait_done) {
			b->wait_seq = 0;
			if ((uint32_t)waited > b->mcu_max_ms)
				b->mcu_max_ms = waited;
			return 0;
		}
		if (mt7927_aborted(b)) {
			b->wait_seq = 0;
			return ECANCELED;
		}
		mt7927_wait(b, 1);
	}
	b->wait_seq = 0;
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
	    MT7927_TXQ_BAND0, MT7927_TX_TOKENS, 128)) != 0 ||
	    (rv = mt7927_ring_alloc(b, &b->tx[MT7927_TX_MCU], "tx15-mcu", false,
	    MT7927_TXQ_MCU_WM, 32, 2048)) != 0 ||
	    (rv = mt7927_ring_alloc(b, &b->tx[MT7927_TX_FWDL], "tx16-fwdl", false,
	    MT7927_TXQ_FWDL, 32, MT7927_FW_CHUNK)) != 0 ||
	    (rv = mt7927_ring_alloc(b, &b->rx[MT7927_RX_MCU], "rx6-mcu", true,
	    MT7927_RXQ_MCU_WM, 512, MT7927_RX_BUF_SIZE)) != 0 ||
	    (rv = mt7927_ring_alloc(b, &b->rx[MT7927_RX_BAND0], "rx4-data", true,
	    MT7927_RXQ_BAND0, 1536, MT7927_RX_BUF_SIZE)) != 0 ||
	    (rv = mt7927_ring_alloc(b, &b->rx[MT7927_RX_DATA2], "rx7-data2", true,
	    MT7927_RXQ_DATA2, 512, MT7927_RX_BUF_SIZE)) != 0) {
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

	/*
	 * With header translation (rx_decap) the chip splits A-MSDUs and
	 * translates each subframe, as mt7925_mac_init() sets it up: 1536 and
	 * de-A-MSDU on. Otherwise whole A-MSDUs for net80211.
	 */
	mt7927_rmw(sc, MT7927_MDP_DCR1, MT7927_MAX_RX_LEN_MASK,
	    b->rx_decap ? 1536U << 3 : MT7927_MAX_RX_LEN);
	if (b->rx_decap)
		mt7927_set(sc, MT7927_MDP_DCR0, MT7927_MDP_DCR0_DAMSDU_EN);
	else
		mt7927_clear(sc, MT7927_MDP_DCR0, MT7927_MDP_DCR0_DAMSDU_EN);

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
		    b->rx_decap ? 1536U << 3 : MT7927_MAX_RX_LEN);
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
		mt7927_service(b);
		mt7927_wait(b, 1);
	}
	mt7927_service(b);

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

/* ---- Phase 4: runtime (RX descriptors, interface, scan) ---- */

/*
 * connac3 RX descriptor of an 802.11 frame (mt7925_mac_fill_rx subset):
 * 8-dword RXD, optional groups 4/1/2/3 (4 dwords each) and 5 (24 dwords),
 * then 2 * HDR_OFFSET pad bytes. With header translation the payload at
 * hdr_off is an 802.3 frame (DA, SA, type) and group 4 has the original
 * frame control, sequence and QoS control.
 */
int
mt7927_rx_parse(const uint8_t *p, uint32_t len, uint8_t antenna_mask,
    struct mt7927_rxi *ri)
{
	uint32_t rxd1, rxd2, rxd3, off = 32, sec;
	uint8_t chfreq, pad;
	int i;

	memset(ri, 0, sizeof(*ri));
	ri->rssi = -127;
	if (len < 32)
		return MT7927_RX_SHORT;
	rxd1 = mt7927_le32(p + 4);
	rxd2 = mt7927_le32(p + 8);
	rxd3 = mt7927_le32(p + 12);

	if (rxd2 & (1U << 23))			/* AMSDU_ERR */
		return MT7927_RX_AMSDU_ERR;
	if (rxd2 & (1U << 24))			/* MAX_LEN_ERROR */
		return MT7927_RX_LEN_ERR;
	if (rxd3 & (1U << 24))			/* FCS_ERR */
		return MT7927_RX_FCS_ERR;
	if (rxd1 & (1U << 25))			/* ICV_ERR */
		return MT7927_RX_ICV_ERR;
	ri->hdr_trans = (rxd2 & (1U << 7)) != 0;
	ri->hdr_trans_err = (rxd2 & (1U << 25)) != 0;
	ri->frag = (rxd2 & (1U << 27)) != 0;
	ri->amsdu = mt7927_le32(p + 16) & 0x3;	/* RXD4 PAYLOAD_FORMAT */
	if (ri->hdr_trans && (rxd1 & (1U << 23)))	/* CM: not decrypted */
		return MT7927_RX_HDR_TRANS;

	chfreq = (rxd3 >> 8) & 0xff;
	if (chfreq > 180) {
		ri->band = 6;
		ri->chan = (uint8_t)((chfreq - 181) * 4 + 1);
	} else if (chfreq > 14) {
		ri->band = 5;
		ri->chan = chfreq;
	} else {
		ri->band = 2;
		ri->chan = chfreq;
	}
	ri->band_idx = (rxd1 >> 27) & 0x3;
	ri->unicast = ((rxd3 >> 16) & 0x3) == 1;
	ri->wlan_idx = rxd1 & 0xfff;
	sec = (rxd2 >> 16) & 0x1f;
	ri->decrypted = sec != 0 && !(rxd1 & ((1U << 23) | (1U << 24)));

	ri->sec_mode = (uint8_t)sec;
	ri->key_id = (rxd1 >> 21) & 0x3;

	if (rxd1 & (1U << 19)) {		/* group 4 */
		if (off + 16 > len)
			return MT7927_RX_SHORT;
		ri->has_g4 = true;
		ri->fc = (uint16_t)(mt7927_le32(p + off) & 0xffff);
		ri->seq_ctrl = (uint16_t)(mt7927_le32(p + off + 8) & 0xffff);
		ri->qos_ctl = (uint16_t)(mt7927_le32(p + off + 8) >> 16);
		off += 16;
	}
	if (rxd1 & (1U << 16)) {		/* group 1: IV/PN */
		if (off + 16 > len)
			return MT7927_RX_SHORT;
		memcpy(ri->pn, p + off, 6);
		ri->has_pn = true;
		off += 16;
	}
	if (rxd1 & (1U << 17))			/* group 2 */
		off += 16;
	if (rxd1 & (1U << 18)) {		/* group 3: P-RXV */
		uint32_t v3;

		if (off + 16 > len)
			return MT7927_RX_SHORT;
		v3 = mt7927_le32(p + off + 12);
		for (i = 0; i < 4; i++) {
			int rssi = ((int)((v3 >> (8 * i)) & 0xff) - 220) / 2;

			if (!(antenna_mask & (1U << i)) || rssi >= 0)
				continue;
			if (rssi > ri->rssi)
				ri->rssi = (int8_t)rssi;
		}
		off += 16;
		if (rxd1 & (1U << 20))		/* group 5: C-RXV */
			off += 96;
	}
	pad = (rxd2 >> 13) & 0x7;
	off += 2 * pad;
	if (off + (ri->hdr_trans ? 14 : 16) > len)	/* 802.3 / 802.11 min */
		return MT7927_RX_SHORT;
	ri->hdr_off = off;
	ri->frame_len = len - off;
	return 0;
}

/* ---- Block Ack reorder (mt76 agg-rx.c) ---- */

static inline bool
mt7927_sn_less(uint16_t a, uint16_t b)
{
	return ((a - b) & 0xfff) > 0x800;
}

void
mt7927_reorder_start(struct mt7927_reorder *r, uint16_t ssn, uint16_t size)
{
	memset(r, 0, sizeof(*r));
	r->active = true;
	r->head = ssn & 0xfff;
	r->size = size == 0 || size > MT7927_REORDER_WIN ? MT7927_REORDER_WIN :
	    size;
}

static void
mt7927_reorder_release(struct mt7927_reorder *r, mt7927_release_fn fn,
    void *arg)
{
	uint16_t idx = r->head % r->size;
	void *u = r->buf[idx];

	r->head = (r->head + 1) & 0xfff;
	if (u == NULL)
		return;
	r->buf[idx] = NULL;
	r->n--;
	fn(arg, u, true);
}

/* everything before sequence number head (mt76_rx_aggr_release_frames) */
static void
mt7927_reorder_release_to(struct mt7927_reorder *r, uint16_t head,
    mt7927_release_fn fn, void *arg)
{
	while (mt7927_sn_less(r->head, head))
		mt7927_reorder_release(r, fn, arg);
}

/* the in-order run at the head (mt76_rx_aggr_release_head) */
static void
mt7927_reorder_release_head(struct mt7927_reorder *r, mt7927_release_fn fn,
    void *arg)
{
	while (r->buf[r->head % r->size] != NULL)
		mt7927_reorder_release(r, fn, arg);
}

/* Window stops (DELBA, leaving): what is buffered goes up in order. */
void
mt7927_reorder_stop(struct mt7927_reorder *r, mt7927_release_fn fn, void *arg)
{
	uint32_t i;

	if (!r->active)
		return;
	for (i = 0; i < r->size && r->n != 0; i++)
		mt7927_reorder_release(r, fn, arg);
	r->active = false;
}

/* A Block Ack Request moves the window to ssn. */
void
mt7927_reorder_bar(struct mt7927_reorder *r, uint16_t ssn,
    mt7927_release_fn fn, void *arg)
{
	if (!r->active)
		return;
	r->started = true;
	mt7927_reorder_release_to(r, ssn & 0xfff, fn, arg);
	mt7927_reorder_release_head(r, fn, arg);
}

/* mt76_rx_aggr_reorder() for one unit with sequence number seq. */
void
mt7927_reorder_add(struct mt7927_reorder *r, uint16_t seq, void *unit,
    uint32_t now, mt7927_release_fn fn, void *arg)
{
	uint16_t idx;

	seq &= 0xfff;
	if (!r->active) {
		fn(arg, unit, true);
		return;
	}
	if (!r->started) {
		if (mt7927_sn_less(seq, r->head)) {
			fn(arg, unit, true);	/* before the window began */
			return;
		}
		r->started = true;
	}
	if (mt7927_sn_less(seq, r->head)) {
		fn(arg, unit, false);		/* late or duplicate */
		return;
	}
	if (seq == r->head) {
		r->head = (r->head + 1) & 0xfff;
		fn(arg, unit, true);
		if (r->n != 0)
			mt7927_reorder_release_head(r, fn, arg);
		return;
	}
	/* beyond the window: release older frames to make room */
	if (!mt7927_sn_less(seq, (r->head + r->size) & 0xfff))
		mt7927_reorder_release_to(r,
		    (uint16_t)((seq - r->size + 1) & 0xfff), fn, arg);
	idx = seq % r->size;
	if (r->buf[idx] != NULL) {
		fn(arg, unit, false);		/* duplicate */
		return;
	}
	r->buf[idx] = unit;
	r->when[idx] = now;
	r->n++;
	mt7927_reorder_release_head(r, fn, arg);
}

/*
 * Frames held longer than timeo_ms go up with the gap before them given up
 * (mt76_rx_aggr_check_release). Returns whether frames are still held.
 */
bool
mt7927_reorder_check(struct mt7927_reorder *r, uint32_t now,
    uint32_t timeo_ms, mt7927_release_fn fn, void *arg)
{
	uint32_t i;

	if (!r->active || r->n == 0)
		return false;
	mt7927_reorder_release_head(r, fn, arg);
	for (i = 1; i < r->size && r->n != 0; i++) {
		uint16_t seq = (uint16_t)((r->head + i) & 0xfff);
		uint16_t idx = seq % r->size;

		if (r->buf[idx] == NULL)
			continue;
		if (now - r->when[idx] < timeo_ms)
			break;
		mt7927_reorder_release_to(r, seq, fn, arg);
		mt7927_reorder_release_head(r, fn, arg);
		i = 0;
	}
	return r->n != 0;
}

/* Scan-done event payload (after the MCU RXD): rsv[4], then TLVs. */
bool
mt7927_scan_event_done(const uint8_t *p, uint32_t len)
{
	uint32_t off = 4;

	while (off + 4 <= len) {
		uint16_t tag = mt7927_le16(p + off);
		uint16_t tl = mt7927_le16(p + off + 2);

		if (tag == MT7927_UNI_EVENT_SCAN_DONE_BASIC)
			return true;
		if (tl < 4 || tl > len - off)
			break;
		off += tl;
	}
	return false;
}

/* mt76_connac_mcu_uni_add_dev(): DEV_INFO then BSS_INFO basic (reversed on remove). */
int
mt7927_dev_add(struct mt7927_bringup *b, const struct mt7927_vif *v, bool enable)
{
	struct {
		uint8_t		omac_idx, band_idx;
		uint16_t	pad;
		uint16_t	tag, len;
		uint8_t		active, link_idx, omac_addr[6];
	} __packed dev;
	struct {
		uint8_t		bss_idx, pad[3];
		uint16_t	tag, len;
		uint8_t		active, omac_idx, hw_bss_idx, band_idx;
		uint32_t	conn_type;
		uint8_t		conn_state, wmm_idx, bssid[6];
		uint16_t	bmc_tx_wlan_idx, bcn_interval;
		uint8_t		dtim_period, phymode;
		uint16_t	sta_idx, nonht_basic_phy;
		uint8_t		phymode_ext, link_idx;
	} __packed bss;
	int rv;
	uint32_t st_dev = 0xffffffff, st_bss = 0xffffffff;

	memset(&dev, 0, sizeof(dev));
	dev.omac_idx = v->omac_idx;
	dev.band_idx = v->band_idx;
	dev.tag = htole16(0);			/* DEV_INFO_ACTIVE */
	dev.len = htole16(12);
	dev.active = enable;
	memcpy(dev.omac_addr, v->addr, 6);

	memset(&bss, 0, sizeof(bss));
	bss.bss_idx = v->idx;
	bss.tag = htole16(0);			/* UNI_BSS_INFO_BASIC */
	bss.len = htole16(sizeof(bss) - 4);
	bss.active = enable;
	bss.omac_idx = v->omac_idx;
	bss.hw_bss_idx = v->omac_idx > 0x10 ? 0 : v->omac_idx;
	bss.band_idx = v->band_idx;
	bss.conn_type = htole32(MT7927_CONNECTION_INFRA_STA);
	bss.conn_state = 1;
	bss.wmm_idx = v->wmm_idx;
	bss.bmc_tx_wlan_idx = htole16(v->wcid);
	bss.sta_idx = htole16(v->wcid);

	mt7927_op_lock(b);
	if (enable) {
		/* mt7925_mcu_parse_response(): { u8 cid; pad[3]; le32 status } */
		rv = mt7927_mcu_send(b, MCU_UNI_CMD_DEV_INFO_UPDATE, &dev,
		    sizeof(dev), true);
		if (rv == 0 && b->resp_len >= 8)
			st_dev = mt7927_le32(b->resp + 4);
		if (rv == 0)
			rv = mt7927_mcu_send(b, MCU_UNI_CMD_BSS_INFO_UPDATE, &bss,
			    sizeof(bss), true);
		if (rv == 0 && b->resp_len >= 8)
			st_bss = mt7927_le32(b->resp + 4);
	} else {
		rv = mt7927_mcu_send(b, MCU_UNI_CMD_BSS_INFO_UPDATE, &bss,
		    sizeof(bss), true);
		if (rv == 0)
			rv = mt7927_mcu_send(b, MCU_UNI_CMD_DEV_INFO_UPDATE, &dev,
			    sizeof(dev), true);
	}
	mt7927_op_unlock(b);
	MWX_DEV_LOG(b->sc, "MT7927 %s interface bss %u omac %u band %u wcid %u "
	    "-> %d (fw status dev 0x%x bss 0x%x)\n", enable ? "add" : "remove",
	    v->idx, v->omac_idx, v->band_idx, v->wcid, rv, st_dev, st_bss);
	return rv;
}

/* mt7925_mcu_set_rxfilter(): UNI BAND_CONFIG, tag SET_MAC80211_RX_FILTER. */
int
mt7927_set_rxfilter(struct mt7927_bringup *b, uint8_t band_idx, uint32_t fif)
{
	struct {
		uint8_t		band_idx, rsv1[3];
		uint16_t	tag, len;
		uint8_t		mode, rsv2[3];
		uint32_t	fif, bit_map;
		uint8_t		bit_op, pad[51];
	} __packed req;
	int rv;

	memset(&req, 0, sizeof(req));
	req.band_idx = band_idx;
	req.tag = htole16(MT7927_UNI_BAND_CONFIG_RX_FILTER);
	req.len = htole16(sizeof(req) - 4);
	req.mode = fif ? 0 : 1;
	req.fif = htole32(fif);
	mt7927_op_lock(b);
	rv = mt7927_mcu_send(b, MT7927_UNI_BAND_CONFIG, &req, sizeof(req), true);
	mt7927_op_unlock(b);
	return rv;
}

/*
 * mt7925_mcu_hw_scan(): UNI SCAN_REQ with REQ, SSID, BSSID, CHANNEL and MISC
 * TLVs. Passive (no probe requests, so no probe IEs) unless an SSID is
 * given; wildcard BSSID; split scan; firmware default dwell times.
 */
int
mt7927_scan_start_ex(struct mt7927_bringup *b, const struct mt7927_vif *v,
    const struct mt7927_scan_chan *ch, int nch, const uint8_t *ssid,
    int ssid_len, bool active, const uint8_t *const ie[2],
    const uint16_t ie_len[2])
{
	struct {
		uint8_t		seq_num, bss_idx, pad[2];
		struct {
			uint16_t tag, len;
			uint8_t	scan_type, probe_req_num, scan_func, src_mask;
			uint16_t min_dwell, dwell, timeout, probe_delay;
			uint32_t func_mask_ext;
		} __packed req;
		struct {
			uint16_t tag, len;
			uint8_t	ssid_type, ssids_num, is_short_ssid, pad;
			struct {
				uint32_t len;
				uint8_t	ssid[32];
			} __packed ssids[10];
		} __packed ssid;
		struct {
			uint16_t tag, len;
			uint8_t	bssid[6], match_ch, match_ssid_ind, rcpi;
			uint8_t	match_short_ssid_ind, pad[2];
		} __packed bssid;
		struct {
			uint16_t tag, len;
			uint8_t	channel_type, channels_num, pad[2];
			struct {
				uint8_t band, channel_num;
			} __packed channels[64];
		} __packed chan;
		struct {
			uint16_t tag, len;
			uint8_t	random_mac[6], rsv[2];
		} __packed misc;
	} __packed msg;
	/* the message, then a probe-request IE TLV per band (2.4, 5 GHz) */
	uint8_t buf[sizeof(msg) + 2 * (8 + MT7927_SCAN_IE_MAX)];
	uint32_t blen;
	int i, rv;

	if (nch > 64)
		nch = 64;
	if (ssid_len > 0)
		active = true;
	memset(&msg, 0, sizeof(msg));
	b->scan_seq = (b->scan_seq + 1) & 0x7f;
	msg.seq_num = b->scan_seq | (uint8_t)(v->band_idx << 7);
	msg.bss_idx = v->idx;

	msg.req.tag = htole16(MT7927_UNI_SCAN_REQ);
	msg.req.len = htole16(sizeof(msg.req));
	/*
	 * mt7925_mcu_hw_scan() with cfg80211's usual wildcard SSID: an active
	 * scan (2 probe requests per channel; the firmware stays passive where
	 * the regulatory domain requires). A passive scan can miss an AP whose
	 * beacon does not fall in the dwell.
	 */
	msg.req.scan_type = active ? 1 : 0;
	msg.req.probe_req_num = active ? 2 : 0;
	msg.req.scan_func = MT7927_SCAN_FUNC_SPLIT_SCAN;

	msg.ssid.tag = htole16(MT7927_UNI_SCAN_SSID);
	msg.ssid.len = htole16(sizeof(msg.ssid));
	if (ssid != NULL && ssid_len > 0 && ssid_len <= 32) {
		msg.ssid.ssids[0].len = htole32(ssid_len);
		memcpy(msg.ssid.ssids[0].ssid, ssid, ssid_len);
		msg.ssid.ssids_num = 1;
		msg.ssid.ssid_type = 1U << 2;
	} else {
		msg.ssid.ssid_type = 1U << 0;	/* wildcard */
	}

	msg.bssid.tag = htole16(MT7927_UNI_SCAN_BSSID);
	msg.bssid.len = htole16(sizeof(msg.bssid));
	memset(msg.bssid.bssid, 0xff, 6);

	msg.chan.tag = htole16(MT7927_UNI_SCAN_CHANNEL);
	msg.chan.len = htole16(sizeof(msg.chan));
	for (i = 0; i < nch; i++) {
		msg.chan.channels[i].band = ch[i].band;
		msg.chan.channels[i].channel_num = ch[i].chan;
	}
	msg.chan.channels_num = (uint8_t)nch;
	msg.chan.channel_type = nch ? 4 : 0;

	msg.misc.tag = htole16(MT7927_UNI_SCAN_MISC);
	msg.misc.len = htole16(sizeof(msg.misc));

	memcpy(buf, &msg, sizeof(msg));
	blen = sizeof(msg);
	/* mt7925_mcu_build_scan_ie_tlv(): the IEs of our probe requests */
	for (i = 0; active && ie != NULL && i < 2; i++) {
		uint8_t *t = buf + blen;

		if (ie[i] == NULL || ie_len[i] == 0 ||
		    ie_len[i] > MT7927_SCAN_IE_MAX)
			continue;
		t[0] = MT7927_UNI_SCAN_IE;
		t[1] = 0;
		t[2] = (uint8_t)(8 + ie_len[i]);
		t[3] = (uint8_t)((8 + ie_len[i]) >> 8);
		t[4] = (uint8_t)ie_len[i];
		t[5] = (uint8_t)(ie_len[i] >> 8);
		t[6] = (uint8_t)(i + 1);		/* band: 1 2.4, 2 5 GHz */
		t[7] = 0;
		memcpy(t + 8, ie[i], ie_len[i]);
		blen += 8 + ie_len[i];
	}

	mt7927_op_lock(b);
	rv = mt7927_mcu_send(b, MT7927_UNI_SCAN_REQ_CMD, buf, blen, true);
	mt7927_op_unlock(b);
	MWX_DEV_LOG(b->sc, "MT7927 scan request seq %u bss %u band %u: %d "
	    "channels, %s -> %d\n", b->scan_seq, v->idx, v->band_idx, nch,
	    active ? "active" : "passive", rv);
	return rv;
}

int
mt7927_scan_start(struct mt7927_bringup *b, const struct mt7927_vif *v,
    const struct mt7927_scan_chan *ch, int nch, const uint8_t *ssid,
    int ssid_len)
{
	return mt7927_scan_start_ex(b, v, ch, nch, ssid, ssid_len, false,
	    NULL, NULL);
}

/* mt7925_mcu_cancel_hw_scan() */
int
mt7927_scan_cancel(struct mt7927_bringup *b, const struct mt7927_vif *v)
{
	struct {
		uint8_t		seq_num, bss_idx, pad[2];
		uint16_t	tag, len;
		uint8_t		is_ext_channel, rsv[3];
	} __packed req;
	int rv;

	memset(&req, 0, sizeof(req));
	req.seq_num = b->scan_seq;
	req.bss_idx = v->idx;
	req.tag = htole16(MT7927_UNI_SCAN_CANCEL);
	req.len = htole16(8);
	mt7927_op_lock(b);
	rv = mt7927_mcu_send(b, MT7927_UNI_SCAN_REQ_CMD, &req, sizeof(req), true);
	mt7927_op_unlock(b);
	return rv;
}

/*
 * ---- Phase 4b: joining a BSS (mt7925 main.c, mcu.c, mac.c, pci_mac.c) ----
 *
 * mac80211 order for a station on the MT7927, non-MLO, 20 MHz:
 *   assign_vif_chanctx  -> mt7927_reconfig_band(): DEV_INFO off/on with the
 *                          band of the BSS (5 GHz = band 1)
 *   sta_add (NONE)      -> WTBL ADM clear, BSS_INFO (basic, sec, rate, qos,
 *                          mld, ifs, rlm, mbssid), STA_REC (basic, phy, ra,
 *                          state NONE, hdr_trans)
 *   mgd_prepare_tx      -> UNI ROC acquire (JOIN), wait for the grant event
 *   auth / assoc frames -> data ring 0, connac3 TXD + hw TXP (cut-through)
 *   sta_state ASSOC     -> BSS_INFO, STA_REC (state ASSOC)
 *   BSS_CHANGED_ASSOC   -> STA_REC for the BSS's broadcast entry (ASSOC)
 *   authorized          -> ROC abort
 * Keys stay in software (net80211 CCMP) for now, so nothing here installs
 * them in the WTBL.
 */

/* A message being built: UNI header, then TLVs; the header's second
 * 16-bit word counts the TLVs (mt76_connac_mcu_add_nested_tlv()). */
struct mt7927_msg {
	uint8_t		buf[384];
	uint32_t	len;
};

static void
mt7927_msg_init(struct mt7927_msg *m, const void *hdr, uint32_t hlen)
{
	memset(m->buf, 0, sizeof(m->buf));
	memcpy(m->buf, hdr, hlen);
	m->len = hlen;
}

static uint8_t *
mt7927_msg_tlv(struct mt7927_msg *m, uint16_t tag, uint16_t len)
{
	uint8_t *p = m->buf + m->len;
	uint16_t n;

	if (m->len + len > sizeof(m->buf))
		return NULL;
	p[0] = tag & 0xff;
	p[1] = tag >> 8;
	p[2] = len & 0xff;
	p[3] = len >> 8;
	m->len += len;
	n = (uint16_t)(m->buf[2] | (m->buf[3] << 8)) + 1;
	m->buf[2] = n & 0xff;
	m->buf[3] = n >> 8;
	return p;
}

static void
mt7927_put16(uint8_t *p, uint16_t v)
{
	p[0] = v & 0xff;
	p[1] = v >> 8;
}

static void
mt7927_put32(uint8_t *p, uint32_t v)
{
	p[0] = v & 0xff;
	p[1] = (v >> 8) & 0xff;
	p[2] = (v >> 16) & 0xff;
	p[3] = v >> 24;
}

/* Send with the op lock; the UNI reply's status word (after cid, pad[3]). */
static int
mt7927_uni_send_status(struct mt7927_bringup *b, uint32_t cmd,
    const struct mt7927_msg *m, uint32_t *status)
{
	int rv;

	mt7927_op_lock(b);
	rv = mt7927_mcu_send(b, cmd, m->buf, m->len, true);
	if (status != NULL)
		*status = (rv == 0 && b->resp_len >= 8) ?
		    mt7927_le32(b->resp + 4) : 0xffffffff;
	mt7927_op_unlock(b);
	return rv;
}

/* mt7925_mac_wtbl_update(MT_WTBL_UPDATE_ADM_COUNT_CLEAR) for a new peer. */
void
mt7927_wtbl_clear(struct mt7927_bringup *b, uint16_t idx)
{
	if (!mt7927_wtbl_update(b->sc, idx, MT7927_WTBL_UPDATE_ADM_CLR))
		MWX_DEV_LOG(b->sc, "MT7927 WTBL %u: ADM clear busy\n", idx);
}

/* mt7927_reconfig_band(): DEV_INFO off, new band index, DEV_INFO on. */
int
mt7927_band_reconfig(struct mt7927_bringup *b, struct mt7927_vif *v,
    uint8_t band_idx)
{
	int rv;

	if (v->band_idx == band_idx)
		return 0;
	rv = mt7927_dev_add(b, v, false);
	v->band_idx = band_idx;
	if (rv == 0)
		rv = mt7927_dev_add(b, v, true);
	MWX_DEV_LOG(b->sc, "MT7927 band reconfig -> band %u: %d\n", band_idx, rv);
	return rv;
}

/* mt7925_mcu_add_bss_info_sta(): BSS_INFO for the BSS we join. */
int
mt7927_bss_info(struct mt7927_bringup *b, const struct mt7927_vif *v,
    const struct mt7927_bss *bss, bool enable)
{
	struct mt7927_msg m;
	uint8_t hdr[4] = { v->idx, 0, 0, 0 };
	uint8_t *t;
	uint32_t status;
	int rv;

	mt7927_msg_init(&m, hdr, sizeof(hdr));

	t = mt7927_msg_tlv(&m, MT7927_BSS_TAG_BASIC, 32);	/* bss_basic first */
	t[4] = 1;						/* active (STA) */
	t[5] = v->omac_idx;
	t[6] = v->omac_idx > 0x10 ? 0 : v->omac_idx;		/* hw_bss_idx */
	t[7] = v->band_idx;
	mt7927_put32(t + 8, MT7927_CONNECTION_INFRA_STA);
	t[12] = !enable;					/* conn_state */
	t[13] = v->wmm_idx;
	memcpy(t + 14, bss->bssid, 6);
	mt7927_put16(t + 20, v->wcid);				/* bmc_tx_wlan_idx */
	mt7927_put16(t + 22, bss->bcn_int);
	t[24] = bss->dtim;
	t[25] = bss->phymode;
	mt7927_put16(t + 26, bss->peer_wcid);			/* sta_idx */
	mt7927_put16(t + 28, bss->band == 1 ? MT7927_PHY_TYPE_ERP_INDEX :
	    MT7927_PHY_TYPE_OFDM_INDEX);			/* nonht_basic_phy */
	t[30] = 0;						/* phymode_ext */
	t[31] = v->idx;						/* link_idx */

	t = mt7927_msg_tlv(&m, MT7927_BSS_TAG_SEC, 8);	/* mt7925_mcu_bss_sec_tlv */
	if (bss->cipher == MT7927_CIPHER_AES_CCMP) {
		t[4] = MT7927_BSS_MODE_WPA2_PSK;
		t[5] = 6;
	} else {
		t[4] = 0;					/* MODE_OPEN */
		t[5] = 1;
	}
	t[6] = bss->cipher;					/* 0: no hw cipher */

	t = mt7927_msg_tlv(&m, MT7927_BSS_TAG_RATE, 16);
	mt7927_put16(t + 6, bss->band == 1 ? 0x000f :		/* HR_DSSS_ERP */
	    ((1U << 6) | (1U << 8) | (1U << 10)));		/* OFDM_BASIC_RATE */
	t[12] = bss->band == 1;					/* short_preamble */
	t[13] = MT7927_BASIC_RATES_IDX(bss->band);		/* bc_fixed_rate */
	t[14] = MT7927_BASIC_RATES_IDX(bss->band);		/* mc_fixed_rate */

	t = mt7927_msg_tlv(&m, MT7927_BSS_TAG_QBSS, 8);
	t[4] = bss->qos;

	t = mt7927_msg_tlv(&m, MT7927_BSS_TAG_MLD, 20);
	t[4] = 0xff;						/* group_mld_id */
	t[5] = v->idx + 32;					/* own_mld_id */
	memcpy(t + 6, v->addr, 6);
	t[12] = 0xff;						/* remap_idx */
	t[13] = 0xff;						/* link_id */

	t = mt7927_msg_tlv(&m, MT7927_BSS_TAG_IFS_TIME, 20);
	t[4] = 1;						/* slot_valid */
	mt7927_put16(t + 8, bss->band == 1 ? 20 : 9);		/* slot_time */

	if (bss->he) {						/* link_conf->he_support */
		/* mt7925_mcu_bss_he_tlv(): defaults when the AP gives 0 */
		t = mt7927_msg_tlv(&m, MT7927_BSS_TAG_HE_BASIC, 16);
		mt7927_put16(t + 4, bss->he_rts ? bss->he_rts : 1023);
		t[6] = bss->he_pe ? bss->he_pe : 4;		/* he_pe_duration */
		mt7927_put16(t + 8, bss->he_own_tx[0]);		/* max_nss_mcs: BW80 */
		mt7927_put16(t + 10, bss->he_own_tx[1]);	/* BW160 */
		mt7927_put16(t + 12, bss->he_own_tx[2]);	/* BW8080 */
		/* mt7925_mcu_bss_color_tlv() */
		t = mt7927_msg_tlv(&m, MT7927_BSS_TAG_BSS_COLOR, 8);
		t[4] = enable ? bss->he_color_en : 0;
		t[5] = enable ? bss->he_color : 0;
	}

	if (enable) {
		uint8_t center = bss->center_chan ? bss->center_chan : bss->chan;

		/* mt7925_mcu_bss_rlm_tlv() */
		t = mt7927_msg_tlv(&m, MT7927_BSS_TAG_RLM, 16);
		t[4] = bss->chan;				/* control_channel */
		t[5] = center;
		t[7] = bss->bw;					/* CMD_CBW_* */
		t[8] = 2;					/* tx_streams */
		t[9] = 2;					/* rx_streams */
		t[10] = bss->bw ? 4 : 0;			/* ht_op_info: 40M allowed */
		t[11] = bss->chan < center ? 1 : bss->chan > center ? 3 : 0;	/* sco */
		t[12] = bss->band;				/* 1: 2.4, 2: 5 GHz */

		t = mt7927_msg_tlv(&m, MT7927_BSS_TAG_MBSSID, 8);
	}
	rv = mt7927_uni_send_status(b, MCU_UNI_CMD_BSS_INFO_UPDATE, &m, &status);
	MWX_DEV_LOG(b->sc, "MT7927 BSS_INFO %s %02x:%02x:%02x:%02x:%02x:%02x ch %u "
	    "band %u (idx %u) phymode 0x%02x sta %u -> %d (fw status 0x%x)\n",
	    enable ? "join" : "leave", bss->bssid[0], bss->bssid[1], bss->bssid[2],
	    bss->bssid[3], bss->bssid[4], bss->bssid[5], bss->chan, bss->band,
	    v->band_idx, bss->phymode, bss->peer_wcid, rv, status);
	return rv;
}

/*
 * mt7925_mcu_sta_cmd(): STA_REC for the AP (peer) or for the BSS's broadcast
 * entry (the vif's own WCID, as mac80211 passes link_sta == NULL).
 */
int
mt7927_sta_rec(struct mt7927_bringup *b, const struct mt7927_vif *v,
    const struct mt7927_bss *bss, bool peer, bool enable, uint8_t state,
    bool newly)
{
	struct mt7927_msg m;
	uint16_t wcid = peer ? bss->peer_wcid : v->wcid;
	uint8_t hdr[8];
	uint8_t *t;
	uint32_t status;
	int rv;

	hdr[0] = v->idx;
	hdr[1] = wcid & 0xff;					/* wlan_idx_lo */
	hdr[2] = hdr[3] = 0;					/* tlv_num */
	hdr[4] = 1;						/* is_tlv_append */
	hdr[5] = peer ? v->omac_idx : 0xe;			/* muar_idx */
	hdr[6] = wcid >> 8;					/* wlan_idx_hi */
	hdr[7] = 0;
	mt7927_msg_init(&m, hdr, sizeof(hdr));

	if (enable) {
		t = mt7927_msg_tlv(&m, MT7927_STA_TAG_BASIC, 20);
		mt7927_put32(t + 4, peer ? MT7927_CONNECTION_INFRA_AP :
		    MT7927_CONNECTION_INFRA_BC);
		t[8] = MT7927_CONN_STATE_PORT_SECURE;
		t[9] = peer ? bss->qos : 0;
		mt7927_put16(t + 10, bss->aid);
		memcpy(t + 12, bss->bssid, 6);
		mt7927_put16(t + 18, MT7927_EXTRA_INFO_VER |
		    (newly ? MT7927_EXTRA_INFO_NEW : 0));
		if (peer) {
			t = mt7927_msg_tlv(&m, MT7927_STA_TAG_PHY, 12);
			mt7927_put16(t + 4, bss->basic_rates);
			t[6] = bss->phy_type;
			t[7] = bss->ampdu;
			t[10] = bss->max_ampdu_len;

			if (bss->ht_cap) {			/* sta_rec_ht */
				t = mt7927_msg_tlv(&m, MT7927_STA_TAG_HT, 8);
				mt7927_put16(t + 4, bss->ht_cap);
			}
			if (bss->vht_cap) {			/* sta_rec_vht */
				t = mt7927_msg_tlv(&m, MT7927_STA_TAG_VHT, 16);
				mt7927_put32(t + 4, bss->vht_cap);
				mt7927_put16(t + 8, bss->vht_rx_mcs);
				mt7927_put16(t + 10, bss->vht_tx_mcs);
			}
			if (bss->amsdu) {			/* mt7925_mcu_sta_amsdu_tlv */
				t = mt7927_msg_tlv(&m, MT7927_STA_TAG_HW_AMSDU, 8);
				t[4] = 8;			/* max_amsdu_num */
				t[5] = bss->amsdu - 1;		/* max_mpdu_size */
				t[6] = 1;			/* amsdu_en */
			}
			if (bss->he) {				/* mt76_connac_mcu_sta_he_tlv_v2 */
				t = mt7927_msg_tlv(&m, MT7927_STA_TAG_HE_V2, 28);
				memcpy(t + 4, bss->he_mac, 6);
				memcpy(t + 10, bss->he_phy, 11);
				t[21] = 2;			/* pkt_ext: 16 us nominal padding */
				mt7927_put16(t + 22, bss->he_mcs[0]);	/* BW80 */
				mt7927_put16(t + 24, bss->he_mcs[1]);	/* BW160 */
				mt7927_put16(t + 26, bss->he_mcs[2]);	/* BW8080 */
			}

			t = mt7927_msg_tlv(&m, MT7927_STA_TAG_RA, 16);
			mt7927_put16(t + 4, bss->ra_legacy);
			memcpy(t + 6, bss->ht_mcs, 10);

			t = mt7927_msg_tlv(&m, MT7927_STA_TAG_STATE, 16);
			t[4] = state;
			if (bss->vht_cap)
				t[12] = bss->vht_opmode;
		}
		t = mt7927_msg_tlv(&m, MT7927_STA_TAG_HDR_TRANS, 8);
		t[4] = 0;					/* from_ds */
		t[5] = 1;					/* to_ds (station) */
		/* dis_rx_hdr_tran (mt7925_mcu_sta_hdr_trans_tlv): on only for
		 * the peer with decap offload, never the broadcast entry */
		t[6] = peer && bss->rx_hdr_trans ? 0 : 1;
	} else {
		t = mt7927_msg_tlv(&m, MT7927_STA_TAG_REMOVE, 8);
		t = mt7927_msg_tlv(&m, MT7927_STA_TAG_MLD_OFF, 4);
	}
	rv = mt7927_uni_send_status(b, MCU_UNI_CMD_STA_REC_UPDATE, &m, &status);
	MWX_DEV_LOG(b->sc, "MT7927 STA_REC %s wcid %u %s state %u%s -> %d (fw "
	    "status 0x%x)\n", peer ? "peer" : "bss-bc", wcid,
	    enable ? "add" : "remove", state, newly ? " new" : "", rv, status);
	return rv;
}

int mt7927_roc_abort(struct mt7927_bringup *, const struct mt7927_vif *);

/* mt7925_mcu_sta_ba(): a Block Ack agreement for one TID with the AP. */
int
mt7927_sta_ba(struct mt7927_bringup *b, const struct mt7927_vif *v,
    const struct mt7927_bss *bss, uint8_t tid, bool tx, bool enable,
    uint16_t ssn, uint16_t winsize, bool amsdu)
{
	struct mt7927_msg m;
	uint8_t hdr[8];
	uint8_t *t;
	uint32_t status;
	int rv;

	hdr[0] = v->idx;
	hdr[1] = bss->peer_wcid & 0xff;
	hdr[2] = hdr[3] = 0;
	hdr[4] = 1;						/* is_tlv_append */
	hdr[5] = v->omac_idx;					/* muar_idx */
	hdr[6] = bss->peer_wcid >> 8;
	hdr[7] = 0;
	mt7927_msg_init(&m, hdr, sizeof(hdr));
	t = mt7927_msg_tlv(&m, MT7927_STA_TAG_BA, 16);
	t[4] = tid;
	t[5] = tx ? MT7927_BA_TYPE_ORIGINATOR : MT7927_BA_TYPE_RECIPIENT;
	t[6] = amsdu;
	t[7] = (uint8_t)((enable ? 1U : 0U) << tid);		/* ba_en */
	mt7927_put16(t + 8, ssn);
	mt7927_put16(t + 10, winsize);
	rv = mt7927_uni_send_status(b, MCU_UNI_CMD_STA_REC_UPDATE, &m, &status);
	MWX_DEV_LOG(b->sc, "MT7927 %s BA tid %u %s ssn %u win %u%s -> %d (fw status "
	    "0x%x)\n", tx ? "TX" : "RX", tid, enable ? "on" : "off", ssn, winsize,
	    amsdu ? " amsdu" : "", rv, status);
	return rv;
}

/*
 * mt7925_mcu_uni_bss_ps(): the BSS's power save state, 0 = stay awake (what
 * Linux sends with power save off). Without it the firmware picks its own,
 * and the AP then holds our frames until a beacon.
 */
int
mt7927_bss_ps(struct mt7927_bringup *b, const struct mt7927_vif *v,
    uint8_t ps_state)
{
	struct mt7927_msg m;
	uint8_t hdr[4] = { v->idx, 0, 0, 0 };
	uint32_t status;
	uint8_t *t;
	int rv;

	mt7927_msg_init(&m, hdr, sizeof(hdr));
	t = mt7927_msg_tlv(&m, MT7927_BSS_TAG_PS, 8);
	t[4] = ps_state;
	m.buf[2] = m.buf[3] = 0;			/* pad in mt7925's header */
	rv = mt7927_uni_send_status(b, MCU_UNI_CMD_BSS_INFO_UPDATE, &m, &status);
	MWX_DEV_LOG(b->sc, "MT7927 power save state %u (0 = awake) -> %d "
	    "(fw status 0x%x)\n", ps_state, rv, status);
	return rv;
}

/*
 * mt7925_mcu_set_tx(): WMM/EDCA parameters of the BSS, one TLV per access
 * category in mac80211 order (VO, VI, BE, BK; queue = that index). Without
 * them the firmware's TX queues run on whatever it defaults to.
 */
int
mt7927_set_edca(struct mt7927_bringup *b, const struct mt7927_vif *v,
    const struct mt7927_edca *e)
{
	struct mt7927_msg m;
	uint8_t hdr[4] = { v->idx, 0, 0, 0 };
	uint32_t status;
	uint8_t *t;
	int ac, rv;

	mt7927_msg_init(&m, hdr, sizeof(hdr));
	for (ac = 0; ac < 4; ac++) {
		t = mt7927_msg_tlv(&m, 0, 12);		/* MCU_EDCA_AC_PARAM */
		t[4] = (uint8_t)ac;			/* queue */
		t[5] = 0x0f;				/* WMM_PARAM_SET */
		t[6] = e[ac].ecw_min;
		t[7] = e[ac].ecw_max;
		mt7927_put16(t + 8, e[ac].txop);
		t[10] = e[ac].aifs;
	}
	m.buf[2] = m.buf[3] = 0;			/* reserved, not a TLV count */
	rv = mt7927_uni_send_status(b, MT7927_UNI_EDCA_UPDATE, &m, &status);
	MWX_DEV_LOG(b->sc, "MT7927 EDCA (aifs/cwmin/cwmax/txop) VO %u/%u/%u/%u "
	    "VI %u/%u/%u/%u BE %u/%u/%u/%u BK %u/%u/%u/%u -> %d (fw status 0x%x)\n",
	    e[0].aifs, e[0].ecw_min, e[0].ecw_max, e[0].txop,
	    e[1].aifs, e[1].ecw_min, e[1].ecw_max, e[1].txop,
	    e[2].aifs, e[2].ecw_min, e[2].ecw_max, e[2].txop,
	    e[3].aifs, e[3].ecw_min, e[3].ecw_max, e[3].txop, rv, status);
	return rv;
}

/*
 * mt7925_mcu_sta_key_tlv(): install (or remove) a key in the firmware. The
 * pairwise key goes on the AP's WCID, a group key on the BSS's broadcast
 * entry, as mac80211 passes sta == NULL for it.
 */
int
mt7927_sta_key(struct mt7927_bringup *b, const struct mt7927_vif *v,
    const struct mt7927_bss *bss, bool pairwise, bool add, uint8_t cipher,
    uint8_t key_id, const uint8_t *key, uint8_t key_len)
{
	struct mt7927_msg m;
	uint16_t wcid = pairwise ? bss->peer_wcid : v->wcid;
	uint8_t hdr[8];
	uint8_t *t;
	uint32_t status;
	int rv;

	if (key_len > 32)
		return EINVAL;
	hdr[0] = v->idx;
	hdr[1] = wcid & 0xff;
	hdr[2] = hdr[3] = 0;
	hdr[4] = 1;						/* is_tlv_append */
	hdr[5] = pairwise ? v->omac_idx : 0xe;			/* muar_idx */
	hdr[6] = wcid >> 8;
	hdr[7] = 0;
	mt7927_msg_init(&m, hdr, sizeof(hdr));
	t = mt7927_msg_tlv(&m, MT7927_STA_TAG_KEY_V3, 68);	/* sta_rec_sec_uni */
	t[4] = add;
	t[5] = pairwise;					/* tx_key */
	t[6] = pairwise;					/* key_type */
	t[7] = 0;						/* is_authenticator */
	memcpy(t + 8, bss->bssid, 6);				/* peer_addr */
	t[14] = v->idx;						/* bss_idx */
	if (add) {
		t[15] = cipher;
		t[16] = key_id;
		t[17] = key_len;
		memcpy(t + 20, key, key_len);
	}
	t[18] = wcid & 0xff;					/* wlan_idx */
	t[19] = 1;						/* mgmt_prot */
	rv = mt7927_uni_send_status(b, MCU_UNI_CMD_STA_REC_UPDATE, &m, &status);
	explicit_bzero(m.buf, sizeof(m.buf));
	if (rv == 0 && status != 0)
		rv = EIO;		/* not in the chip: stay in software */
	MWX_DEV_LOG(b->sc, "MT7927 %s key id %u cipher %u %s on wcid %u -> %d (fw "
	    "status 0x%x)\n", pairwise ? "pairwise" : "group", key_id, cipher,
	    add ? "installed" : "removed", wcid, rv, status);
	return rv;
}

/* mt7925_mcu_set_roc() + mt7925_set_roc(): acquire and wait for the grant. */
int
mt7927_roc(struct mt7927_bringup *b, const struct mt7927_vif *v,
    uint8_t chan, uint8_t band, uint32_t duration_ms)
{
	struct mt7927_msg m;
	uint8_t hdr[4] = { 0, 0, 0, 0 };
	uint8_t *t, token;
	int rv, waited;

	if (b->roc_active)
		return EBUSY;
	token = ++b->roc_token;
	b->roc_granted = false;
	b->roc_grant_ms = 0;
	mt7927_msg_init(&m, hdr, sizeof(hdr));
	/* a plain header: rsv[4] carries no TLV count here */
	t = m.buf + m.len;
	memset(t, 0, 24);
	mt7927_put16(t, MT7927_UNI_ROC_ACQUIRE);
	mt7927_put16(t + 2, 24);
	t[4] = v->idx;						/* bss_idx */
	t[5] = token;
	t[6] = chan;						/* control_channel */
	t[7] = 0;						/* sco */
	t[8] = band;
	t[9] = 0;						/* CMD_CBW_20MHZ */
	t[10] = chan;						/* center_chan */
	t[12] = 0;						/* bw_from_ap */
	t[13] = chan;						/* center_chan_from_ap */
	t[15] = MT7927_ROC_REQ_JOIN;
	mt7927_put32(t + 16, duration_ms);			/* maxinterval */
	t[20] = 0xff;						/* dbdcband: auto */
	m.len += 24;

	mt7927_op_lock(b);
	rv = mt7927_mcu_send(b, MT7927_UNI_ROC, m.buf, m.len, true);
	mt7927_op_unlock(b);
	if (rv != 0) {
		MWX_DEV_LOG(b->sc, "MT7927 ROC acquire ch %u -> %d\n", chan, rv);
		return rv;
	}
	b->roc_active = true;
	for (waited = 0; !b->roc_granted && waited < MT7927_ROC_WAIT_MS;
	    waited++) {
		if (mt7927_aborted(b))
			break;
		mt7927_service(b);
		if (b->roc_granted)
			break;
		mt7927_wait(b, 1);
	}
	if (!b->roc_granted) {
		MWX_DEV_LOG(b->sc, "MT7927 ROC ch %u token %u: no grant after %d ms\n",
		    chan, token, waited);
		mt7927_roc_abort(b, v);
		return ETIMEDOUT;
	}
	MWX_DEV_LOG(b->sc, "MT7927 ROC ch %u token %u granted after %d ms "
	    "(status %u, ch %u, %u ms)\n", chan, token, waited, b->roc_status,
	    b->roc_chan, b->roc_grant_ms);
	return 0;
}

int
mt7927_roc_abort(struct mt7927_bringup *b, const struct mt7927_vif *v)
{
	uint8_t req[4 + 12];
	int rv;

	if (!b->roc_active)
		return 0;
	memset(req, 0, sizeof(req));
	mt7927_put16(req + 4, MT7927_UNI_ROC_ABORT);
	mt7927_put16(req + 6, 12);
	req[8] = v->idx;
	req[9] = b->roc_token;
	req[10] = 0xff;						/* dbdcband */
	mt7927_op_lock(b);
	rv = mt7927_mcu_send(b, MT7927_UNI_ROC, req, sizeof(req), true);
	mt7927_op_unlock(b);
	b->roc_active = false;
	b->roc_granted = false;
	MWX_DEV_LOG(b->sc, "MT7927 ROC abort token %u -> %d\n", b->roc_token, rv);
	return rv;
}

bool
mt7927_roc_state(struct mt7927_bringup *b, uint32_t *grant_ms)
{
	if (grant_ms != NULL)
		*grant_ms = b->roc_grant_ms;
	return b->roc_active;
}

/* UNI ROC event (unsolicited): rsv[4], then the grant TLV. */
static void
mt7927_roc_event(struct mt7927_bringup *b, const uint8_t *p, uint32_t len)
{
	const uint8_t *t = p + 4;

	if (len < 4 + 16 || mt7927_le16(t) != MT7927_UNI_EVENT_ROC_GRANT ||
	    mt7927_le16(t + 2) < 16)
		return;
	b->roc_events++;
	if (t[5] != b->roc_token)			/* tokenid */
		return;
	b->roc_status = t[6];
	b->roc_chan = t[7];				/* primarychannel */
	b->roc_grant_ms = (mt7927_le16(t + 2) >= 20 && len >= 4 + 20) ?
	    mt7927_le32(t + 16) : 0;			/* max_interval */
	OSSynchronizeIO();
	b->roc_granted = true;
}

/* ---- data TX: connac3 TXD + hw TXP on ring 0, payload in a token buffer ---- */

static void mt7927_tx_free_mem(struct mt7927_bringup *);

static int
mt7927_tx_alloc(struct mt7927_bringup *b)
{
	int rv;

	if (b->tok_chunk[0].va != NULL)
		return 0;
	rv = 0;
	for (uint32_t i = 0; i < MT7927_TOK_CHUNKS && rv == 0; i++) {
		uint32_t n = MT7927_TX_TOKENS - i * MT7927_TOK_PER_CHUNK;

		if (n > MT7927_TOK_PER_CHUNK)
			n = MT7927_TOK_PER_CHUNK;
		rv = mt7927_dmamem_alloc(&b->tok_chunk[i],
		    (size_t)n * MT7927_TX_TOKEN_SZ, true);
	}
	if (rv != 0) {
		mt7927_tx_free_mem(b);
	} else {
		memset((void *)b->tok_busy, 0, sizeof(b->tok_busy));
		b->tok_seq = 0;
	}
	return rv;
}

static void
mt7927_tx_free_mem(struct mt7927_bringup *b)
{
	for (uint32_t i = 0; i < MT7927_TOK_CHUNKS; i++)
		if (b->tok_chunk[i].va != NULL)
			mt7927_dmamem_free(&b->tok_chunk[i]);
	memset((void *)b->tok_busy, 0, sizeof(b->tok_busy));
}

/* PKT_TYPE_TXRX_NOTIFY (mt7925_mac_tx_free()): give the tokens back. */
static void
mt7927_tx_free_event(struct mt7927_bringup *b, const uint8_t *p, uint32_t len)
{
	uint32_t total, count = 0, off, ver;

	b->tx_free_events++;
	b->tok_free_seq = b->tok_seq;
	b->tok_free_tick = b->wd_ticks;
	if (len < 8)
		return;
	total = (mt7927_le32(p) >> 16) & 0x3ff;			/* MSDU_CNT */
	ver = (mt7927_le32(p + 4) >> 16) & 0xf;
	if (ver < 4 && b->tx_free_badver++ < 4)
		MWX_DEV_LOG(b->sc, "MT7927 TX free event version %u\n", ver);
	for (off = 8; count < total && off + 4 <= len; off += 4) {
		uint32_t info = mt7927_le32(p + off);
		int i;

		if (info & (MT7927_TXFREE_INFO_PAIR | MT7927_TXFREE_INFO_HEADER)) {
			if (info & MT7927_TXFREE_INFO_HEADER) {
				/* MT_TXFREE_INFO_COUNT / _STAT (mt7925_mac_tx_free) */
				uint32_t cnt = (info >> 24) & 0xf;

				if (cnt > 1)
					b->tx_retries += cnt - 1;
				if (((info >> 28) & 3) != 0)
					b->tx_failed++;
			}
			continue;
		}
		for (i = 0; i < 2; i++) {
			uint32_t msdu = (info >> (15 * i)) & MT7927_TXFREE_MSDU_MASK;

			if (msdu == MT7927_TXFREE_MSDU_MASK)
				continue;
			count++;
			if (msdu < MT7927_TX_TOKENS && b->tok_busy[msdu]) {
				OSSynchronizeIO();
				b->tok_busy[msdu] = 0;
				b->tx_done++;
			}
		}
	}
	b->tx_free_msdus += count;
	if (count > b->tx_free_max)
		b->tx_free_max = count;
}

/* Watchdog second (1 s): the clock for reclaiming tokens. */
void
mt7927_engine_tick(struct mt7927_bringup *b)
{
	b->wd_ticks++;
}

/* Retries and aggregation as TX free events report them, since the last call. */
void
mt7927_engine_txfree_stats(struct mt7927_bringup *b, uint32_t *events,
    uint32_t *msdus, uint32_t *max, uint32_t *retries, uint32_t *failed)
{
	mt7927_svc_lock(b);
	*events = b->tx_free_events;
	*msdus = b->tx_free_msdus;
	*max = b->tx_free_max;
	*retries = b->tx_retries;
	*failed = b->tx_failed;
	b->tx_free_max = 0;
	mt7927_svc_unlock(b);
}

/*
 * mt7925_mac_add_txs(): TX status entries (8 dwords each, from dword 2)
 * for the frames we asked one for (MT7927_TXS_PID). Only the latest is
 * kept, for the log: the rate the firmware's rate control picked.
 */
static void
mt7927_txs_event(struct mt7927_bringup *b, const uint8_t *p, uint32_t len)
{
	uint32_t off;

	/* the PCI path, mt7925_rx_check(): 4 dword header, 12 dword records */
	for (off = 16; off + 48 <= len; off += 48) {
		uint32_t t0 = mt7927_le32(p + off);
		uint32_t t3 = mt7927_le32(p + off + 12);

		if (((t0 >> 23) & 3) > 1 || (t3 >> 24) != MT7927_TXS_PID)
			continue;
		b->txs_count++;
		if (t0 & (7U << 16))			/* ACK/RTS/queue timeout */
			b->txs_ack_err++;
		b->txs_last = t0;
		b->txs_last1 = mt7927_le32(p + off + 4);
	}
}

void
mt7927_engine_link(struct mt7927_bringup *b, uint8_t band, uint32_t *bcn_loss,
    uint32_t *coredumps, uint32_t *rx_time, uint32_t *tx_time,
    uint32_t *windows)
{
	*bcn_loss = b->bcn_loss;
	*coredumps = b->coredumps;
	*rx_time = b->mib_rx_time[band & 1];
	*tx_time = b->mib_tx_time[band & 1];
	*windows = b->mib_windows;
}

/*
 * Is there a token for one more frame? Checked before a frame is taken off
 * the send queue, so a full chip holds frames back instead of dropping
 * them. If not, TX is marked blocked: the next TX free events with room
 * call cb_txroom.
 */
bool
mt7927_engine_tx_room(struct mt7927_bringup *b)
{
	uint32_t i, tok;
	bool room = false;

	mt7927_svc_lock(b);
	for (i = 0; i < MT7927_TX_TOKENS; i++) {
		tok = (b->tok_next + i) % MT7927_TX_TOKENS;
		if (!b->tok_busy[tok]) {
			room = true;
			break;
		}
	}
	/* while free events have stopped, mt7927_tx_frame() may reclaim */
	if (!room && b->tok_seq - b->tok_free_seq >= MT7927_TX_TOKENS &&
	    b->wd_ticks - b->tok_free_tick >= MT7927_RECLAIM_TICKS)
		room = true;
	if (!room)
		b->tx_blocked = true;
	mt7927_svc_unlock(b);
	return room;
}

/* Frames in the chip (tokens out) and descriptors the DMA has not fetched. */
void
mt7927_engine_tx_depth(struct mt7927_bringup *b, uint32_t *inflight,
    uint32_t *ring_pending)
{
	struct mt7927_ring *r = &b->tx[MT7927_TX_BAND0];
	uint32_t i, n = 0, cpu, dma;

	for (i = 0; i < MT7927_TX_TOKENS; i++)
		n += b->tok_busy[i] != 0;
	*inflight = n;
	*ring_pending = 0;
	if (r->count != 0 && b->sc->sc_memh) {
		cpu = mt7927_raw_rd(b->sc, r->regbase + MT_DMA_CPU_IDX);
		dma = mt7927_raw_rd(b->sc, r->regbase + MT_DMA_DMA_IDX);
		*ring_pending = (cpu + r->count - dma) % r->count;
	}
}

void
mt7927_engine_txs(struct mt7927_bringup *b, uint32_t *count, uint32_t *errs,
    uint32_t *txs0, uint32_t *txs1)
{
	*count = b->txs_count;
	*errs = b->txs_ack_err;
	*txs0 = b->txs_last;
	*txs1 = b->txs_last1;
}

/*
 * Queue one 802.11 frame (already encrypted if it needs to be). Takes the
 * svc lock: callers must not hold it. Never waits.
 */
int
mt7927_tx_frame(struct mt7927_bringup *b, const struct mt7927_txinfo *ti,
    const uint8_t *frame, uint32_t len)
{
	struct mt7927_ring *r = &b->tx[MT7927_TX_BAND0];
	uint8_t txw[MT7927_TXD_SIZE + MT7927_TXP_SIZE];
	uint32_t w[8], i, best = MT7927_TX_TOKENS, tok = MT7927_TX_TOKENS;
	uint32_t pa;
	uint16_t next;
	struct mwx_desc *d;
	uint8_t fc0;

	if (!b->running || b->tok_chunk[0].va == NULL || r->desc == NULL)
		return ENXIO;
	if (len < 10 || len > MT7927_TX_TOKEN_SZ)
		return EINVAL;
	fc0 = frame[0];

	mt7927_svc_lock(b);
	mt7927_tx_reap(b, r);
	next = (r->head + 1) % r->count;
	if (next == r->tail) {
		mt7927_svc_unlock(b);
		b->tx_ring_full++;
		b->tx_blocked = true;
		return ENOBUFS;
	}
	for (i = 0; i < MT7927_TX_TOKENS; i++) {
		uint32_t t = (b->tok_next + i) % MT7927_TX_TOKENS;

		if (!b->tok_busy[t]) {
			tok = t;
			break;
		}
		if (best == MT7927_TX_TOKENS ||
		    (int32_t)(b->tok_when[t] - b->tok_when[best]) < 0)
			best = t;
	}
	if (tok == MT7927_TX_TOKENS) {
		/*
		 * No TX free event came back for these: take the oldest once
		 * enough newer frames went out after it, but only while free
		 * events have stopped altogether. While they flow, the frames
		 * are still queued in the chip: wait for room instead of
		 * overwriting one.
		 */
		if (best == MT7927_TX_TOKENS ||
		    b->tok_seq - b->tok_free_seq < MT7927_TX_TOKENS ||
		    b->wd_ticks - b->tok_free_tick < MT7927_RECLAIM_TICKS ||
		    b->tok_seq - b->tok_when[best] < MT7927_TX_TOKENS / 2) {
			mt7927_svc_unlock(b);
			b->tx_no_token++;
			b->tx_blocked = true;
			return ENOBUFS;
		}
		tok = best;
		b->tx_reclaimed++;
	}
	b->tok_busy[tok] = 1;
	b->tok_when[tok] = ++b->tok_seq;
	b->tok_next = (tok + 1) % MT7927_TX_TOKENS;
	{
		const struct mt7927_dmamem *c =
		    &b->tok_chunk[tok / MT7927_TOK_PER_CHUNK];
		uint32_t off = (tok % MT7927_TOK_PER_CHUNK) * MT7927_TX_TOKEN_SZ;

		memcpy((uint8_t *)c->va + off, frame, len);
		pa = c->pa + off;
	}

	/* mt7925_mac_write_txwi() + _80211() */
	w[0] = MT7927_TXD0_TX_BYTES(len + MT7927_TXD_SIZE) |
	    MT7927_TXD0_PKT_FMT_CT | MT7927_TXD0_Q_IDX(ti->q_idx);
	w[1] = MT7927_TXD1_WLAN_IDX(ti->wcid) |
	    MT7927_TXD1_OWN_MAC(ti->omac_idx) |
	    (ti->band_idx && ti->band_idx != 0xff ?
	    MT7927_TXD1_TGID(ti->band_idx) : 0) |
	    MT7927_TXD1_HDR_FORMAT_80211 |
	    MT7927_TXD1_HDR_INFO(ti->hdrlen / 2) | MT7927_TXD1_TID(ti->tid) |
	    (ti->fixed_rate ? MT7927_TXD1_FIXED_RATE : 0);
	w[2] = MT7927_TXD2_FRAME_TYPE((fc0 >> 2) & 3) |
	    MT7927_TXD2_SUB_TYPE(fc0 >> 4);
	w[3] = MT7927_TXD3_REM_TX_COUNT(15) |
	    (ti->protect ? MT7927_TXD3_PROTECT_FRAME : 0) |
	    (ti->multicast ? MT7927_TXD3_BCM | MT7927_TXD3_NO_ACK : 0) |
	    (ti->fixed_rate ? MT7927_TXD3_BA_DISABLE : 0) |
	    (ti->amsdu ? MT7927_TXD3_HW_AMSDU : 0);
	w[4] = 0;
	w[5] = 0;						/* PID 0: no TXS */
	if (ti->txs) {
		/* as mt7925_mac_write_txwi() for a status request */
		w[5] = MT7927_TXD5_TX_STATUS_HOST | MT7927_TXD5_PID(MT7927_TXS_PID);
		w[3] |= MT7927_TXD3_BA_DISABLE;
		w[3] &= ~MT7927_TXD3_HW_AMSDU;
	}
	w[6] = MT7927_TXD6_DAS | MT7927_TXD6_MSDU_CNT(1) | MT7927_TXD6_DIS_MAT |
	    (ti->fixed_rate ? MT7927_TXD6_TX_RATE(ti->rate_idx) : 0);
	w[7] = 0;
	for (i = 0; i < 8; i++)
		mt7927_put32(txw + 4 * i, w[i]);
	/* mt76_connac_write_hw_txp(): one MSDU, one buffer */
	memset(txw + MT7927_TXD_SIZE, 0, MT7927_TXP_SIZE);
	mt7927_put16(txw + MT7927_TXD_SIZE, tok | MT7927_TXP_MSDU_VALID);
	mt7927_put16(txw + MT7927_TXD_SIZE + 2, 0xffff);	/* unused ids */
	mt7927_put16(txw + MT7927_TXD_SIZE + 4, 0xffff);
	mt7927_put16(txw + MT7927_TXD_SIZE + 6, 0xffff);
	mt7927_put32(txw + MT7927_TXD_SIZE + 8, pa);		/* ptr[0].buf0 */
	mt7927_put16(txw + MT7927_TXD_SIZE + 12, len | MT7927_TXP_LEN_LAST);

	memcpy(mt7927_ring_buf(r, r->head), txw, sizeof(txw));
	d = &r->desc[r->head];
	d->buf0 = htole32(mt7927_ring_buf_pa(r, r->head));
	d->buf1 = 0;
	d->info = 0;
	OSSynchronizeIO();
	d->ctrl = htole32(MT_DMA_CTL_SD_LEN0(sizeof(txw)) | MT_DMA_CTL_LAST_SEC0);
	OSSynchronizeIO();
	r->head = next;
	mt7927_wr(b->sc, r->regbase + MT_DMA_CPU_IDX, r->head);
	b->tx_queued++;
	if (b->tx_logged < 24) {
		b->tx_logged++;
		MWX_DEV_LOG(b->sc, "MT7927 tx fc %02x len %u wcid %u q 0x%02x tok %u "
		    "%s txd %08x %08x %08x %08x %08x %08x %08x\n", fc0, len,
		    ti->wcid, ti->q_idx, tok, ti->fixed_rate ? "fixed" : "ra",
		    w[0], w[1], w[2], w[3], w[5], w[6], w[7]);
	}
	mt7927_svc_unlock(b);
	return 0;
}

void
mt7927_engine_tx_counters(struct mt7927_bringup *b, uint32_t *queued,
    uint32_t *done, uint32_t *free_events, uint32_t *no_token,
    uint32_t *reclaimed, uint32_t *ring_full)
{
	*queued = b->tx_queued;
	*done = b->tx_done;
	*free_events = b->tx_free_events;
	*no_token = b->tx_no_token;
	*reclaimed = b->tx_reclaimed;
	*ring_full = b->tx_ring_full;
}

/*
 * mt7925_mcu_set_rate_txpower() as mac80211 triggers it when the first
 * interface opens (IEEE80211_CONF_CHANGE_POWER): UNI SET_POWER_LIMIT, three
 * channels per message, 2.4 then 5 GHz. With no device-tree limits Linux
 * fills every rate with the channel's regulatory power (2 * max_reg_power,
 * half-dB units) or 127 for channels outside the band's table; here the
 * world-domain 20 dBm is used for the channels net80211 knows.
 */
static int
mt7927_txpower_band(struct mt7927_bringup *b, int band)
{
	static const uint8_t ch2[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
	    14 };
	static const uint8_t ch5[] = { 36, 38, 40, 42, 44, 46, 48, 50, 52, 54,
	    56, 58, 60, 62, 64, 100, 102, 104, 106, 108, 110, 112, 114, 116, 118,
	    120, 122, 124, 126, 128, 132, 134, 136, 138, 140, 142, 144, 149, 151,
	    153, 155, 157, 159, 161, 165, 167 };
	const uint8_t *list = band == 2 ? ch2 : ch5;
	int n = band == 2 ? (int)nitems(ch2) : (int)nitems(ch5);
	int i, j, idx = 0, batches = (n + 2) / 3, rv = 0;
	uint8_t last = list[n - 1];
	for (i = 0; i < batches && rv == 0; i++) {
		/* Linux's batch count (n % 3 for the last one, 0 if n % 3 == 0) */
		int nch = i == batches - 1 ? n % 3 : 3;
		uint32_t mlen = MT7927_TXPWR_HDR + nch * MT7927_SKU_LEN;
		uint8_t tmp[MT7927_TXPWR_HDR + 3 * MT7927_SKU_LEN];

		memset(tmp, 0, MT7927_TXPWR_HDR);
		tmp[4] = 1;			/* tag */
		tmp[6] = (mlen - 4) & 0xff;
		tmp[7] = (mlen - 4) >> 8;
		tmp[12] = (uint8_t)nch;
		tmp[13] = band == 2 ? 1 : 2;
		tmp[16] = b->alpha2[0];
		tmp[17] = b->alpha2[1];
		for (j = 0; j < nch; j++, idx++) {
			uint8_t *sku = tmp + MT7927_TXPWR_HDR + j * MT7927_SKU_LEN;
			uint8_t c = list[idx];
			bool known = band == 2 || (c % 4 == 0 && c <= 144) ||
			    (c >= 149 && c % 4 == 1);
			int8_t pw = known ? 40 : 127;

			tmp[14] = c == last;	/* last_msg */
			sku[0] = c;
			memset(sku + 1, 127, MT7927_SKU_LEN - 1);
			if (band == 2)
				memset(sku + 1, pw, 4);		/* cck */
			memset(sku + 1 + 4, pw, 8);		/* ofdm */
			memset(sku + 1 + 44, pw, MT7927_SKU_LEN - 1 - 44);
		}
		rv = mt7927_mcu_send(b, MT7927_UNI_SET_POWER_LIMIT, tmp, mlen,
		    true);
	}
	return rv;
}

int
mt7927_set_rate_txpower(struct mt7927_bringup *b)
{
	int rv;

	mt7927_op_lock(b);
	rv = mt7927_txpower_band(b, 2);
	if (rv == 0)
		rv = mt7927_txpower_band(b, 5);
	mt7927_op_unlock(b);
	MWX_DEV_LOG(b->sc, "MT7927 rate TX power limits (2.4 + 5 GHz) -> %d\n", rv);
	return rv;
}

/* Periodic snapshot for phase 4a debugging (command gate / poll context). */
void
mt7927_engine_log_diag(struct mt7927_bringup *b)
{
	struct mwx_softc *sc = b->sc;
	char types[3][64];
	int i, t;

	for (i = 0; i < MT7927_NRX; i++) {
		int o = 0;

		types[i][0] = '\0';
		for (t = 0; t < 16 && o < (int)sizeof(types[i]) - 8; t++)
			if (b->ring_types[i][t])
				o += snprintf(types[i] + o, sizeof(types[i]) - o,
				    "%s%d:%u", o ? "," : "", t, b->ring_types[i][t]);
	}
	MWX_DEV_LOG(sc, "MT7927 rings: rx4 %u [%s] cpu %u dma %u | rx6 %u [%s] "
	    "cpu %u dma %u | rx7 %u [%s] cpu %u dma %u | intr bits 0x%08x "
	    "sw 0x%08x | rx6 frames staged %u dropped %u\n",
	    b->ring_pkts[MT7927_RX_BAND0], types[MT7927_RX_BAND0],
	    mt7927_raw_rd(sc, b->rx[MT7927_RX_BAND0].regbase + MT_DMA_CPU_IDX),
	    mt7927_raw_rd(sc, b->rx[MT7927_RX_BAND0].regbase + MT_DMA_DMA_IDX),
	    b->ring_pkts[MT7927_RX_MCU], types[MT7927_RX_MCU],
	    mt7927_raw_rd(sc, b->rx[MT7927_RX_MCU].regbase + MT_DMA_CPU_IDX),
	    mt7927_raw_rd(sc, b->rx[MT7927_RX_MCU].regbase + MT_DMA_DMA_IDX),
	    b->ring_pkts[MT7927_RX_DATA2], types[MT7927_RX_DATA2],
	    mt7927_raw_rd(sc, b->rx[MT7927_RX_DATA2].regbase + MT_DMA_CPU_IDX),
	    mt7927_raw_rd(sc, b->rx[MT7927_RX_DATA2].regbase + MT_DMA_DMA_IDX),
	    b->intr_seen, b->mcu_sw_seen, b->stage_frames, b->stage_drops);
	for (i = 0; i < 2; i++) {
		b->mib_rx_time[i] = mt7927_rr(sc, MT7927_MIB(i, 0x058)) & 0xffffff;
		b->mib_tx_time[i] = mt7927_rr(sc, MT7927_MIB(i, 0x054)) & 0xffffff;
		MWX_DEV_LOG(sc, "MT7927 MIB band %d: rx mpdu %u fcs err %u rx time "
		    "%u tx time %u; tx ampdu %u mpdu tries %u ok %u, ack fail %u "
		    "ba miss %u\n", i, mt7927_rr(sc, MT7927_MIB(i, 0x780)),
		    mt7927_rr(sc, MT7927_MIB(i, 0x698)) >> 16,
		    b->mib_rx_time[i], b->mib_tx_time[i],
		    mt7927_rr(sc, MT7927_MIB(i, 0x558)),	/* SDR12 */
		    mt7927_rr(sc, MT7927_MIB(i, 0x564)),	/* SDR14 */
		    mt7927_rr(sc, MT7927_MIB(i, 0x568)),	/* SDR15 */
		    mt7927_rr(sc, MT7927_MIB(i, 0x520)) & 0xffff,	/* BSDR3 */
		    mt7927_rr(sc, MT7927_MIB(i, 0x518)) & 0xffff);	/* BSDR2 */
	}
	b->mib_windows++;
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
	mt7927_tx_free_mem(b);
	b->roc_active = false;
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
	b->owns_sc = true;
	os->lock = IOLockAlloc();
	os->svc = IOLockAlloc();
	os->op = IORecursiveLockAlloc();
	if (os->lock == NULL || os->svc == NULL || os->op == NULL)
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
		if (os->svc != NULL)
			IOLockFree(os->svc);
		if (os->op != NULL)
			IORecursiveLockFree(os->op);
		IOFree(os, sizeof(*os));
	}
	if (b != NULL) {
		if (b->sc != NULL)
			IOFree(b->sc, sizeof(struct mwx_softc));
		IOFree(b, sizeof(*b));
	}
	return NULL;
}

/*
 * Engine for the main driver: uses the driver's softc and BAR0 mapping;
 * interrupts are delivered on the driver's work loop.
 */
struct mt7927_bringup *
mt7927_engine_create(struct mwx_softc *sc, IOPCIDevice *dev, IOWorkLoop *wl)
{
	struct mt7927_bringup *b;
	struct mt7927_os *os;

	b = (struct mt7927_bringup *)mt7927_zalloc(sizeof(*b));
	os = (struct mt7927_os *)mt7927_zalloc(sizeof(*os));
	if (b == NULL || os == NULL)
		goto fail;
	os->lock = IOLockAlloc();
	os->svc = IOLockAlloc();
	os->op = IORecursiveLockAlloc();
	if (os->lock == NULL || os->svc == NULL || os->op == NULL)
		goto fail;
	os->wl = wl;
	b->os = os;
	b->pci = dev;
	b->sc = sc;
	return b;
fail:
	if (os != NULL) {
		if (os->lock != NULL)
			IOLockFree(os->lock);
		if (os->svc != NULL)
			IOLockFree(os->svc);
		if (os->op != NULL)
			IORecursiveLockFree(os->op);
		IOFree(os, sizeof(*os));
	}
	if (b != NULL)
		IOFree(b, sizeof(*b));
	return NULL;
}

void mt7927_bringup_destroy(struct mt7927_bringup *b);

/* Main driver: stop and free the engine (the softc and BAR stay). */
void
mt7927_engine_destroy(struct mt7927_bringup *b)
{
	mt7927_bringup_destroy(b);
}

void
mt7927_bringup_destroy(struct mt7927_bringup *b)
{
	struct mt7927_os *os;

	if (b == NULL)
		return;
	os = (struct mt7927_os *)b->os;
	b->running = false;
	mt7927_teardown(b);
	if (os != NULL) {
		OSSafeReleaseNULL(os->bar);
		if (os->lock != NULL)
			IOLockFree(os->lock);
		if (os->svc != NULL)
			IOLockFree(os->svc);
		if (os->op != NULL)
			IORecursiveLockFree(os->op);
		IOFree(os, sizeof(*os));
	}
	if (b->owns_sc)
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
	/* Linux world domain, as mt7925_regd_notifier() leaves it at boot */
	b->alpha2[0] = b->alpha2[1] = '0';
	if (cc != NULL && cc[0] >= 'A' && cc[0] <= 'Z' && cc[1] >= 'A' &&
	    cc[1] <= 'Z' && cc[2] == '\0') {
		b->alpha2[0] = cc[0];
		b->alpha2[1] = cc[1];
	}
}

static int
mt7927_run_stages(struct mt7927_bringup *b, int stage, const uint8_t *patch,
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
	mt7927_service(b);
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
	return passed;
}

/* Bring-up test: run up to stage, then always tear down. */
int
mt7927_bringup_run(struct mt7927_bringup *b, int stage, const uint8_t *patch,
    size_t patch_len, const uint8_t *ram, size_t ram_len, volatile bool *abort)
{
	int passed;

	passed = mt7927_run_stages(b, stage, patch, patch_len, ram, ram_len,
	    abort);
	mt7927_teardown(b);
	return passed;
}

/*
 * Main driver: run all stages and keep the hardware up. From here on the
 * interrupt handler services the rings and hands frames and events to the
 * callbacks. On failure the hardware is torn down again.
 */
int
mt7927_engine_start(struct mt7927_bringup *b, const uint8_t *patch,
    size_t patch_len, const uint8_t *ram, size_t ram_len, volatile bool *abort)
{
	int passed;

	passed = mt7927_run_stages(b, 5, patch, patch_len, ram, ram_len, abort);
	if (passed < 5 || mt7927_tx_alloc(b) != 0) {
		mt7927_teardown(b);
		return EIO;
	}
	mt7927_svc_lock(b);
	b->running = true;
	mt7927_svc_unlock(b);
	/* Restart interrupt delivery in running mode. */
	mt7927_raw_wr(b->sc, MT_WFDMA0_HOST_INT_ENA, b->irq_mask);
	MWX_DEV_LOG(b->sc, "MT7927 running: firmware up, hardware kept\n");
	return 0;
}

/* Stop: interrupt off and gone, DMA off, MCU halted, memory freed. */
void
mt7927_engine_stop(struct mt7927_bringup *b)
{
	if (b == NULL)
		return;
	b->running = false;
	mt7927_teardown(b);
}

void
mt7927_engine_set_txroom(struct mt7927_bringup *b, void (*fn)(void *))
{
	b->cb_txroom = fn;
}

/* RX header translation and hardware de-A-MSDU (set before bring-up). */
void
mt7927_engine_set_rx_decap(struct mt7927_bringup *b, bool on)
{
	b->rx_decap = on;
}

/* DMA descriptor info word of the frame being handed to cb_rx (else 0). */
uint32_t
mt7927_engine_rx_info(struct mt7927_bringup *b)
{
	return b->rx_cur_info;
}

/* Called after each pass over the RX rings, so frames can go up in batches. */
void
mt7927_engine_set_rxdone(struct mt7927_bringup *b, void (*fn)(void *))
{
	b->cb_rx_done = fn;
}

void
mt7927_engine_set_callbacks(struct mt7927_bringup *b, void *arg,
    void (*rx)(void *, const uint8_t *, uint32_t),
    void (*event)(void *, uint8_t, const uint8_t *, uint32_t))
{
	b->cb_arg = arg;
	b->cb_rx = rx;
	b->cb_event = event;
}

bool
mt7927_engine_running(struct mt7927_bringup *b)
{
	return b != NULL && b->running;
}

const uint8_t *
mt7927_engine_mac(struct mt7927_bringup *b)
{
	return b->mac_valid ? b->mac : NULL;
}

void
mt7927_engine_counters(struct mt7927_bringup *b, uint32_t *intr,
    uint32_t *isr, uint32_t *frames, uint32_t *other, uint32_t *events,
    uint32_t *timeouts)
{
	*intr = b->intr_count;
	*isr = b->isr_runs;
	*frames = b->rx_frames;
	*other = b->rx_other;
	*events = b->unsol_events;
	*timeouts = b->mcu_timeouts;
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

/*
 * ---------------------------------------------------------------------------
 * MT7927 as a third hardware type (MWX_HW_MT7927), phase 4a.
 *
 * The MT7927 engine above owns the chip: reset, rings, MSI, firmware and
 * the connac3 MCU dialect. This glue connects it to the mwx/net80211 side:
 * a kernel thread loads the firmware once the Data volume is mounted and
 * runs the engine, then the usual mwx_preinit()/mwx_init() follow. The
 * interface is added to the firmware, and net80211 scans through UNI
 * SCAN_REQ; frames from the data rings are parsed (connac3 RXD) and handed
 * to net80211. Joining a network is phase 4b; until then a join is turned
 * into another scan. On system sleep the chip is stopped and stays off
 * until reboot.
 * ---------------------------------------------------------------------------
 */
void mtk_dbg_publish();

#define	MT7927_FW_PATCH_PATH \
	"/Library/Firmware/mediatek/mt7927/WIFI_MT6639_PATCH_MCU_2_1_hdr.bin"
#define	MT7927_FW_RAM_PATH \
	"/Library/Firmware/mediatek/mt7927/WIFI_RAM_CODE_MT6639_2_1.bin"
#define	MT7927_FW_WAIT_SEC	180
#define	MT7927_SCAN_TIMEOUT_SEC	30

static void mt7927_hal_rx(void *, const uint8_t *, uint32_t);
static void mt7927_hal_rx_done(void *);
static void mt7927_reorder_timeo(void *);
static void mt7927_rx_amsdu_flush(struct mwx_softc *);
static void mt7927_rx_decap_reset(struct mwx_softc *);
static IOReturn mt7927_rx_ba_action(OSObject *, void *, void *, void *, void *);
static void mt7927_hal_event(void *, uint8_t, const uint8_t *, uint32_t);

static void
mt7927_vif_fill(struct mwx_softc *sc, struct mt7927_vif *v)
{
	struct ieee80211com *ic = &sc->sc_ic;

	memset(v, 0, sizeof(*v));
	v->idx = sc->sc_vif.idx;
	v->omac_idx = sc->sc_vif.omac_idx;
	v->band_idx = sc->sc_vif.band_idx;
	v->wmm_idx = sc->sc_vif.wmm_idx;
	v->wcid = sc->sc_vif.vif_mn.wcid;
	memcpy(v->addr, IEEE80211_ADDR_EQ(ic->ic_myaddr, etheranyaddr) ?
	    sc->sc_lladdr : ic->ic_myaddr, ETHER_ADDR_LEN);
}

static int
mt7927_hal_attach(struct mwx_softc *sc, struct pci_attach_args *pa)
{
	char cc[4] = { 0 };

	sc->sc_7927_lock = IOLockAlloc();
	sc->sc_7927_txlock = IOLockAlloc();
	if (sc->sc_7927_lock == NULL || sc->sc_7927_txlock == NULL)
		return ENOMEM;
	sc->sc_7927 = mt7927_engine_create(sc, pa->pa_tag, pa->workloop);
	if (sc->sc_7927 == NULL)
		return ENOMEM;
	mt7927_engine_set_callbacks(sc->sc_7927, sc, mt7927_hal_rx,
	    mt7927_hal_event);
	mt7927_engine_set_txroom(sc->sc_7927, mt7927_hal_txroom);
	mt7927_engine_set_rxdone(sc->sc_7927, mt7927_hal_rx_done);
	/* RX header translation + hardware de-A-MSDU like Linux (decap offload) */
	{
		int off = 0;

		sc->sc_7927_rx_decap = !PE_parse_boot_argn("-mtk7927nodecap",
		    &off, sizeof(off));
		sc->sc_7927_scan6g = !PE_parse_boot_argn("-mtk7927no6g",
		    &off, sizeof(off));
		sc->sc_ic.ic_6ghz_channels = sc->sc_7927_scan6g;
		{
			char nb[8];

			sc->sc_7927_nobgscan = PE_parse_boot_argn(
			    "-mtk7927nobgscan", nb, sizeof(nb));
		}
	}
	mt7927_engine_set_rx_decap(sc->sc_7927, sc->sc_7927_rx_decap);
	timeout_set(&sc->sc_7927_reorder_to, mt7927_reorder_timeo, sc);
	MWX_DEV_LOG(sc, "MT7927 RX header translation %s\n",
	    sc->sc_7927_rx_decap ? "on" : "off (-mtk7927nodecap)");
	mt7927_bringup_set_country(sc->sc_7927, NULL);	/* "00" */
	if (PE_parse_boot_argn("mtk7927cc", cc, sizeof(cc) - 1)) {
		MWX_DEV_LOG(sc, "MT7927 country %s (mtk7927cc)\n", cc);
		mt7927_bringup_set_country(sc->sc_7927, cc);
	}
	/* One interface: bss 0, own MAC 0, band 0 (2.4 GHz), last WTBL entry. */
	sc->sc_vif.idx = 0;
	sc->sc_vif.omac_idx = 0;
	sc->sc_vif.band_idx = 0;
	sc->sc_vif.wmm_idx = 0;
	sc->sc_vif.vif_mn.wcid = MT7927_WTBL_RESERVED;
	MWX_DEV_LOG(sc, "MT7927 attach: engine ready; firmware loads from disk "
	    "once the Data volume is mounted\n");
	return 0;
}

/* Runs on the main command gate: serialized with enable()/ioctl paths. */
static IOReturn
mt7927_hal_up_action(OSObject *, void *arg0, void *, void *, void *)
{
	struct mwx_softc *sc = (struct mwx_softc *)arg0;
	struct ifnet *ifp = &sc->sc_ic.ic_if;
	int rv;

	rv = mwx_preinit(sc);
	MWX_DEV_LOG(sc, "MT7927 preinit -> %d (fw_loaded=%d)\n", rv,
	    sc->sc_fw_loaded);
	if (rv == 0 && (ifp->if_flags & (IFF_UP | IFF_RUNNING)) == IFF_UP) {
		rv = mwx_init(ifp);
		MWX_DEV_LOG(sc, "MT7927 deferred interface init -> %d\n", rv);
	}
	return kIOReturnSuccess;
}

static void
mt7927_hal_thread(void *arg, wait_result_t)
{
	struct mwx_softc *sc = (struct mwx_softc *)arg;
	uint8_t *patch = NULL, *ram = NULL;
	size_t plen = 0, rlen = 0;
	int waited, i, e1 = 0, e2 = 0, rv = ENOENT;

	MWX_DEV_LOG(sc, "MT7927 init thread start\n");
	if (sc->sc_7927_fw_patch != NULL && sc->sc_7927_fw_ram != NULL) {
		/* wake: the images read at boot */
		patch = sc->sc_7927_fw_patch;
		plen = sc->sc_7927_fw_plen;
		ram = sc->sc_7927_fw_ram;
		rlen = sc->sc_7927_fw_rlen;
		waited = 0;
	}
	for (waited = 0; patch == NULL &&
	    waited <= MT7927_FW_WAIT_SEC && !sc->sc_7927_abort;
	    waited += 2) {
		e1 = mt7927_read_file(MT7927_FW_PATCH_PATH, &patch, &plen);
		if (e1 == 0) {
			e2 = mt7927_read_file(MT7927_FW_RAM_PATH, &ram, &rlen);
			if (e2 == 0)
				break;
			IOFree(patch, plen);
			patch = NULL;
		}
		if (waited % 20 == 0) {
			MWX_DEV_LOG(sc, "MT7927 waiting for firmware (%ds, patch "
			    "errno %d, ram errno %d)\n", waited, e1, e2);
			mtk_dbg_publish();
		}
		for (i = 0; i < 20 && !sc->sc_7927_abort; i++)
			IOSleep(100);
	}
	if (patch != NULL && ram != NULL && !sc->sc_7927_abort) {
		MWX_DEV_LOG(sc, "MT7927 firmware read: patch %zu bytes, ram %zu "
		    "bytes (after %ds)\n", plen, rlen, waited);
		rv = mt7927_engine_start(sc->sc_7927, patch, plen, ram, rlen,
		    &sc->sc_7927_abort);
		MWX_DEV_LOG(sc, "MT7927 engine start -> %d\n", rv);
	} else if (!sc->sc_7927_abort) {
		MWX_DEV_LOG(sc, "MT7927 firmware not found in "
		    "/Library/Firmware/mediatek/mt7927/; Wi-Fi stays off\n");
	}
	if (patch != NULL && ram != NULL && sc->sc_7927_fw_patch == NULL) {
		/* keep them for restarting the chip after sleep */
		sc->sc_7927_fw_patch = patch;
		sc->sc_7927_fw_plen = plen;
		sc->sc_7927_fw_ram = ram;
		sc->sc_7927_fw_rlen = rlen;
	} else if (sc->sc_7927_fw_patch == NULL) {
		if (patch != NULL)
			IOFree(patch, plen);
		if (ram != NULL)
			IOFree(ram, rlen);
	}

	if (rv == 0 && !sc->sc_7927_abort) {
		IOCommandGate *gate = gMwxHal != NULL ?
		    gMwxHal->mwxGate() : NULL;

		if (gate != NULL)
			gate->runAction(mt7927_hal_up_action, sc);
		else
			mt7927_hal_up_action(NULL, sc, NULL, NULL, NULL);
	}
	mtk_dbg_publish();

	IOLockLock(sc->sc_7927_lock);
	sc->sc_7927_thread_done = true;
	IOLockWakeup(sc->sc_7927_lock, (void *)&sc->sc_7927_thread_done, false);
	IOLockUnlock(sc->sc_7927_lock);
	mt7927_thread_exit();
}

static void
mt7927_hal_start(struct mwx_softc *sc)
{
	sc->sc_7927_abort = false;
	sc->sc_7927_thread_done = false;
	if (mt7927_start_thread(mt7927_hal_thread, sc))
		sc->sc_7927_thread = true;
	else
		MWX_DEV_LOG(sc, "MT7927 could not start the init thread\n");
}

/* Stop the init thread (if any) and make pending MCU waits give up. */
static void
mt7927_hal_detach(struct mwx_softc *sc)
{
	uint64_t deadline;

	sc->sc_7927_abort = true;
	if (!sc->sc_7927_thread || sc->sc_7927_lock == NULL)
		return;
	clock_interval_to_deadline(15, kSecondScale, &deadline);
	IOLockLock(sc->sc_7927_lock);
	while (!sc->sc_7927_thread_done) {
		if (IOLockSleepDeadline(sc->sc_7927_lock,
		    (void *)&sc->sc_7927_thread_done, deadline,
		    THREAD_UNINT) == THREAD_TIMED_OUT)
			break;
	}
	IOLockUnlock(sc->sc_7927_lock);
	if (!sc->sc_7927_thread_done)
		MWX_DEV_LOG(sc, "MT7927 init thread did not stop in time\n");
	else
		sc->sc_7927_thread = false;
}

static int
mt7927_hal_preinit(struct mwx_softc *sc)
{
	const uint8_t *mac;

	if (!mt7927_engine_running(sc->sc_7927))
		return ENXIO;
	mac = mt7927_engine_mac(sc->sc_7927);
	if (mac == NULL)
		return EIO;
	IEEE80211_ADDR_COPY(sc->sc_lladdr, mac);
	/* 2x2, 2.4 and 5 GHz (6 GHz is not supported by this driver yet). */
	sc->sc_capa.has_2ghz = 1;
	sc->sc_capa.has_5ghz = 1;
	sc->sc_capa.has_6ghz = 0;
	sc->sc_capa.num_streams = 2;
	sc->sc_capa.antenna_mask = 0x3;
	return 0;
}

/* mwx_init_hw() for MT7927: add the interface, RX filter, start scanning. */
static int
mt7927_hal_init_hw(struct mwx_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct ifnet *ifp = &ic->ic_if;
	const uint8_t *lladdr = ((struct arpcom *)ifp)->ac_enaddr;
	struct mt7927_vif v;
	int rv;

	if (!sc->sc_fw_loaded) {
		MWX_DEV_LOG(sc, "MT7927 init: firmware not up yet; the interface "
		    "starts when it is\n");
		return 0;
	}
	if (!IEEE80211_ADDR_EQ(lladdr, etheranyaddr) &&
	    !IEEE80211_ADDR_EQ(lladdr, ic->ic_myaddr)) {
		IEEE80211_ADDR_COPY(ic->ic_myaddr, lladdr);
		MWX_DEV_LOG(sc, "init mac address now %s\n",
		    ether_sprintf(ic->ic_myaddr));
	}
	mt7927_vif_fill(sc, &v);
	if ((rv = mt7927_dev_add(sc->sc_7927, &v, true)) != 0)
		return rv;
	/* mac80211 order after add_interface: hw_config (TX power), filter */
	mt7927_set_rate_txpower(sc->sc_7927);
	rv = mt7927_set_rxfilter(sc->sc_7927, v.band_idx, MT7927_FILTER_ENABLE);
	MWX_DEV_LOG(sc, "MT7927 RX filter -> %d\n", rv);

	ifp->if_flags |= IFF_RUNNING;
	ifq_clr_oactive(&ifp->if_snd);
	MWX_DEV_LOG(sc, "MT7927 interface running, starting scan\n");
	ieee80211_begin_scan(ifp);
	return 0;
}

/* mwx_stop() for MT7927 (interface was running). */
static void
mt7927_hal_stop(struct mwx_softc *sc)
{
	struct mt7927_vif v;

	if (!mt7927_engine_running(sc->sc_7927))
		return;
	mt7927_join_teardown(sc, "interface down");
	mt7927_vif_fill(sc, &v);
	if (sc->sc_flags & MWX_FLAG_SCANNING) {
		mt7927_scan_cancel(sc->sc_7927, &v);
		sc->sc_flags &= ~MWX_FLAG_SCANNING;
	}
	mt7927_dev_add(sc->sc_7927, &v, false);
	sc->sc_vif.band_idx = 0;
	sc->sc_7927_hwkeys = 0;
	sc->sc_7927_ptk_pending = false;
	ml_purge(&sc->sc_7927_rxml);
	sc->sc_7927_rxml_frames = 0;
}

/* Active (wildcard) scan of every channel in the net80211 table, as Linux. */
static int
mt7927_hal_scan(struct mwx_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct ieee80211_channel *c;
	struct mt7927_scan_chan ch[64];
	struct mt7927_vif v;
	int n = 0, rv;
	bool restricted;

	if (!mt7927_engine_running(sc->sc_7927))
		return ENXIO;
	/*
	 * Phase 4e.3: associated, macOS scans a few channels at a time (its
	 * channel subsets): only those, so the radio is off the home channel
	 * briefly (the firmware's split scan goes back in between).
	 */
#ifdef AIRPORT_WCL
	restricted = ic->ic_state == IEEE80211_S_RUN &&
	    ic->ic_wcl_scan_requested && ic->ic_wcl_scan_restricted;
#else
	restricted = false;
#endif
	for (c = &ic->ic_channels[1];
	    c <= &ic->ic_channels[IEEE80211_CHAN_MAX] && n < 64; c++) {
		unsigned num = (unsigned)(c - ic->ic_channels);

		if (c->ic_flags == 0)
			continue;
#ifdef AIRPORT_WCL
		if (restricted && !(ic->ic_wcl_scan_channels[num / 8] &
		    (1U << (num % 8))))
			continue;
#else
		(void)num;
#endif
		ch[n].band = IEEE80211_IS_CHAN_2GHZ(c) ? 1 : 2;
		ch[n].chan = (uint8_t)ieee80211_mhz2ieee(c->ic_freq, 0);
		n++;
	}
	/*
	 * Phase 4e.1: the 6 GHz preferred scanning channels (5, 21, ... 229),
	 * which cfg80211 scans when nothing points elsewhere; passive, as the
	 * channel domain marks 6 GHz NO_IR. -mtk7927no6g leaves them out.
	 */
	if (sc->sc_7927_scan6g && !restricted) {
		int psc;

		for (psc = 5; psc <= 229 && n < 64; psc += 16) {
			ch[n].band = 3;
			ch[n].chan = (uint8_t)psc;
			n++;
		}
	}
#ifdef AIRPORT_WCL
	else if (sc->sc_7927_scan6g) {
		int c6;

		for (c6 = 1; c6 <= 233 && n < 64; c6++)
			if (ic->ic_wcl_scan_channels6g[c6 / 8] & (1U << (c6 % 8))) {
				ch[n].band = 3;
				ch[n].chan = (uint8_t)c6;
				n++;
			}
	}
#endif
	if (n == 0)
		return EINVAL;
	mt7927_vif_fill(sc, &v);
	{
		/* probe-request IEs as net80211 builds them (rates, HT, VHT) */
		uint8_t ie2[MT7927_SCAN_IE_MAX], ie5[MT7927_SCAN_IE_MAX], *f;
		const uint8_t *ies[2] = { ie2, ie5 };
		uint16_t lens[2];

		f = ieee80211_add_rates(ie2, &ic->ic_sup_rates[IEEE80211_MODE_11G]);
		f = ieee80211_add_xrates(f, &ic->ic_sup_rates[IEEE80211_MODE_11G]);
		if (ic->ic_flags & IEEE80211_F_HTON)
			f = ieee80211_add_htcaps(f, ic);
		if (ic->ic_flags & IEEE80211_F_HEON) {		/* mac80211 adds HE caps */
			mt7927_he_caps(ic, false);
			f = ieee80211_add_hecaps(f, ic);
		}
		lens[0] = (uint16_t)(f - ie2);
		f = ieee80211_add_rates(ie5, &ic->ic_sup_rates[IEEE80211_MODE_11A]);
		if (ic->ic_flags & IEEE80211_F_HTON)
			f = ieee80211_add_htcaps(f, ic);
		if (ic->ic_flags & IEEE80211_F_VHTON)
			f = ieee80211_add_vhtcaps(f, ic);
		if (ic->ic_flags & IEEE80211_F_HEON) {
			mt7927_he_caps(ic, true);
			f = ieee80211_add_hecaps(f, ic);
			/* back to the band we are on, for a later (re)association */
			if (sc->sc_7927_joined && sc->sc_7927_bss.band == 1)
				mt7927_he_caps(ic, false);
		}
		lens[1] = (uint16_t)(f - ie5);
		rv = mt7927_scan_start_ex(sc->sc_7927, &v, ch, n, NULL, 0, true,
		    ies, lens);
	}
	if (rv == 0) {
		sc->sc_flags |= MWX_FLAG_SCANNING;
		sc->sc_7927_scan_ticks = 0;
	}
	return rv;
}

/* ---- Phase 4b glue: net80211 join on the MT7927 engine ---- */

#define	MT7927_PEER_WCID	1	/* first station WTBL entry (mt76_wcid_alloc) */
#define	MT7927_ROC_JOIN_MS	3000

static uint16_t	mt7927_vht_mcs_and(uint16_t, uint16_t);
static uint8_t	mt7927_vht_mcs_nss(uint16_t);

/* What BSS_INFO / STA_REC need about the AP net80211 chose. */
static void
mt7927_bss_fill(struct mwx_softc *sc, struct ieee80211_node *ni,
    struct mt7927_bss *bss)
{
	struct ieee80211com *ic = &sc->sc_ic;
	bool five = !IEEE80211_IS_CHAN_2GHZ(ni->ni_chan);
	bool ht = (ni->ni_flags & IEEE80211_NODE_HT) != 0;
	bool vht = (ni->ni_flags & IEEE80211_NODE_VHT) != 0;
	bool he = (ni->ni_flags & IEEE80211_NODE_HE) != 0;
	uint16_t supp = 0, basic = 0;
	int i, j, nofdm = 0;
	static const uint8_t ofdm[] = { 12, 18, 24, 36, 48, 72, 96, 108 };
	static const uint8_t cck[] = { 2, 4, 11, 22 };

	memset(bss, 0, sizeof(*bss));
	IEEE80211_ADDR_COPY(bss->bssid, ni->ni_bssid);
	bss->chan = (uint8_t)ieee80211_chan2ieee(ic, ni->ni_chan);
	bss->band = five ? 2 : 1;
	bss->bcn_int = ni->ni_intval ? ni->ni_intval : 100;
	bss->dtim = ni->ni_dtimperiod ? ni->ni_dtimperiod : 1;
	bss->aid = IEEE80211_AID(ni->ni_associd);
	bss->qos = (ni->ni_flags & IEEE80211_NODE_QOS) != 0;
	bss->peer_wcid = MT7927_PEER_WCID;
	/* mt76_connac_get_phy_mode() / _v2() from the peer's capabilities */
	if (five) {
		bss->phymode = 0x01 | (ht ? 0x10 : 0) | (vht ? 0x20 : 0);
		bss->phy_type = (1U << MT7927_PHY_TYPE_OFDM_INDEX) |
		    (ht ? 0x10 : 0) | (vht ? 0x20 : 0);
	} else {
		bss->phymode = 0x02 | 0x04 | (ht ? 0x08 : 0);	/* B | G | GN */
		bss->phy_type = 0x01 | (1U << MT7927_PHY_TYPE_ERP_INDEX) |
		    (ht ? 0x10 : 0);
	}
	/* supp_rates / basic_rates as mac80211 bitmaps over the sband's rates */
	for (i = 0; i < ni->ni_rates.rs_nrates; i++) {
		uint8_t r = ni->ni_rates.rs_rates[i] & IEEE80211_RATE_VAL;
		bool isbasic = (ni->ni_rates.rs_rates[i] & IEEE80211_RATE_BASIC) != 0;

		for (j = 0; j < (int)nitems(ofdm); j++)
			if (r == ofdm[j]) {
				supp |= 1U << (five ? j : j + 4);
				if (isbasic)
					basic |= 1U << (five ? j : j + 4);
				nofdm++;
			}
		if (!five)
			for (j = 0; j < (int)nitems(cck); j++)
				if (r == cck[j]) {
					supp |= 1U << j;
					if (isbasic)
						basic |= 1U << j;
				}
	}
	if (supp == 0)
		supp = five ? 0xff : 0xfff;
	bss->basic_rates = basic ? basic : (five ? 0x15 : 0x0f);
	/* RA_LEGACY_OFDM GENMASK(13, 6), RA_LEGACY_CCK GENMASK(3, 0) */
	if (five)
		bss->ra_legacy = (supp & 0xff) << 6;
	else
		bss->ra_legacy = (((supp >> 4) & 0xff) << 6) | (supp & 0xf);
	if (ht) {
		uint8_t af = ni->ni_ampdu_param & 0x3;

		memcpy(bss->ht_mcs, ni->ni_rxmcs, 10);
		/* the peer's HT capabilities (mt7925_mcu_sta_ht_tlv) */
		bss->ht_cap = ni->ni_htcaps;
		if (ni->ni_chw < IEEE80211_CHAN_WIDTH_40)
			bss->ht_cap &= ~IEEE80211_HTCAP_CBW20_40;
		bss->ampdu = ni->ni_ampdu_param & 0x1f;	/* factor | density */
		bss->max_ampdu_len = af;
		if (bss->ht_cap == 0)
			bss->ht_cap = 0x0100;		/* keep the TLV: RX STBC 1 */
	}
	if (vht) {
		uint8_t vaf = (ni->ni_vhtcaps >> 23) & 0x7;
		uint16_t rx = mt7927_vht_mcs_and(ni->ni_vht_mcsinfo.rx_mcs_map,
		    ic->ic_vht_tx_mcs_map);
		uint16_t tx = mt7927_vht_mcs_and(ni->ni_vht_mcsinfo.tx_mcs_map,
		    ic->ic_vht_rx_mcs_map);
		uint8_t nss = mt7927_vht_mcs_nss(rx), bwc;

		bss->vht_cap = ni->ni_vhtcaps ? ni->ni_vhtcaps : 1;
		bss->vht_rx_mcs = rx;
		bss->vht_tx_mcs = tx;
		if (vaf > bss->max_ampdu_len)
			bss->max_ampdu_len = vaf;
		/* IEEE80211_STA_RX_BW_20/40/80/160 | rx_nss << 4, as Linux sends it */
		bwc = ni->ni_chw == IEEE80211_CHAN_WIDTH_160 ? 3 :
		    ni->ni_chw >= IEEE80211_CHAN_WIDTH_80 ? 2 :
		    ni->ni_chw >= IEEE80211_CHAN_WIDTH_40 ? 1 : 0;
		bss->vht_opmode = bwc | (uint8_t)((nss ? nss : 1) << 4);
	}
	if (he) {
		/*
		 * mac80211's link_sta->he_cap is the AP's HE Capabilities
		 * element as received (ieee80211_he_cap_ie_to_sta_he_cap()):
		 * STA_REC_HE_V2 sends its caps and the MCS maps it receives,
		 * 160 MHz only on a 160 MHz link. The HE operation gives the
		 * BSS color, PE duration and RTS threshold (link_conf).
		 */
		const struct ieee80211_he_mcs_nss_supp *pm = &ni->ni_he_mcs_nss_supp;
		uint32_t op = ni->ni_he_oper_params;

		bss->he = 1;
		bss->phymode |= five ? 0x80 : 0x40;		/* PHY_MODE_AX_5G / _24G */
		bss->phy_type |= 1U << 6;			/* PHY_TYPE_BIT_HE */
		memcpy(bss->he_mac, ni->ni_he_cap_elem.mac_cap_info, 6);
		memcpy(bss->he_phy, ni->ni_he_cap_elem.phy_cap_info, 11);
		bss->he_mcs[0] = le16toh(pm->rx_mcs_80);
		if (ni->ni_chw == IEEE80211_CHAN_WIDTH_160) {
			bss->he_mcs[1] = le16toh(pm->rx_mcs_160);
			if (ni->ni_he_cap_elem.phy_cap_info[0] &
			    IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_80PLUS80_MHZ_IN_5G)
				bss->he_mcs[2] = le16toh(pm->rx_mcs_80p80);
		}
		bss->he_own_tx[0] = le16toh(ic->ic_he_mcs_nss_supp.tx_mcs_80);
		bss->he_own_tx[1] = le16toh(ic->ic_he_mcs_nss_supp.tx_mcs_160);
		bss->he_own_tx[2] = le16toh(ic->ic_he_mcs_nss_supp.tx_mcs_80p80);
		bss->he_color = (uint8_t)((op & IEEE80211_HE_OPERATION_BSS_COLOR_MASK) >>
		    IEEE80211_HE_OPERATION_BSS_COLOR_OFFSET);
		bss->he_color_en = (op & IEEE80211_HE_OPERATION_BSS_COLOR_DISABLED) == 0;
		bss->he_pe = (uint8_t)(op & IEEE80211_HE_OPERATION_DFLT_PE_DURATION_MASK);
		bss->he_rts = (uint16_t)((op & IEEE80211_HE_OPERATION_RTS_THRESHOLD_MASK) >>
		    IEEE80211_HE_OPERATION_RTS_THRESHOLD_OFFSET);
	}
	mwx_node_chan_width(ni, &bss->bw, &bss->center_chan);
	if (bss->bw == CMD_CBW_20MHZ)
		bss->center_chan = bss->chan;
	/* mt7925_mcu_sta_amsdu_tlv(): the largest MPDU the peer takes */
	if (sc->sc_7927_amsdu_ok && (ht || vht)) {
		if (vht)
			bss->amsdu = (uint8_t)(1 + (ni->ni_vhtcaps &
			    IEEE80211_VHTCAP_MAX_MPDU_MASK));
		else
			bss->amsdu = (ni->ni_htcaps & IEEE80211_HTCAP_AMSDU7935) ?
			    1 + IEEE80211_VHTCAP_MAX_MPDU_LENGTH_7991 :
			    1 + IEEE80211_VHTCAP_MAX_MPDU_LENGTH_3895;
		if (bss->amsdu > 1 + IEEE80211_VHTCAP_MAX_MPDU_LENGTH_11454)
			bss->amsdu = 1 + IEEE80211_VHTCAP_MAX_MPDU_LENGTH_3895;
	}
	bss->rx_hdr_trans = sc->sc_7927_rx_decap;
}

/* Per stream: 3 = not supported, else the lower of the two MCS limits. */
static uint16_t
mt7927_vht_mcs_and(uint16_t a, uint16_t b)
{
	uint16_t out = 0;
	int i;

	for (i = 0; i < 8; i++) {
		uint16_t x = (a >> (2 * i)) & 3, y = (b >> (2 * i)) & 3;

		out |= (uint16_t)(((x == 3 || y == 3) ? 3 : (x < y ? x : y)) << (2 * i));
	}
	return out;
}

static uint8_t
mt7927_vht_mcs_nss(uint16_t map)
{
	uint8_t n = 0;
	int i;

	for (i = 0; i < 8; i++)
		if (((map >> (2 * i)) & 3) != 3)
			n = (uint8_t)(i + 1);
	return n;
}

static void
mt7927_join_teardown(struct mwx_softc *sc, const char *why)
{
	struct mt7927_vif v;

	if (!sc->sc_7927_joined)
		return;
	mt7927_vif_fill(sc, &v);
	mt7927_roc_abort(sc->sc_7927, &v);
	mt7927_sta_rec(sc->sc_7927, &v, &sc->sc_7927_bss, true, false, 0, false);
	sc->sc_7927_bss.cipher = 0;
	mt7927_bss_info(sc->sc_7927, &v, &sc->sc_7927_bss, false);
	sc->sc_7927_joined = false;
	sc->sc_7927_assoc = false;
	sc->sc_7927_hwkeys = 0;
	sc->sc_7927_ptk_pending = false;
	mt7927_rx_decap_reset(sc);
	MWX_DEV_LOG(sc, "MT7927 left %s (%s)\n",
	    ether_sprintf(sc->sc_7927_bss.bssid), why);
}

/* AUTH: band, BSS_INFO, STA_REC for the AP, then get on its channel. */
static int
mt7927_join_prepare(struct mwx_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct ieee80211_node *ni = ic->ic_bss;
	struct mt7927_vif v;
	struct mt7927_bss bss;
	uint8_t band_idx;
	int rv;

	if (ni == NULL || ni->ni_chan == NULL ||
	    ni->ni_chan == IEEE80211_CHAN_ANYC)
		return EINVAL;
	mt7927_bss_fill(sc, ni, &bss);
	/* the association request's HE caps are for the AP's band */
	if (sc->sc_7927_he)
		mt7927_he_caps(ic, bss.band == 2);
	if (sc->sc_7927_joined &&
	    !IEEE80211_ADDR_EQ(sc->sc_7927_bss.bssid, bss.bssid))
		mt7927_join_teardown(sc, "new AP");
	if (sc->sc_7927_joined) {
		/* AUTH again on the same AP: keep the records, new ROC. */
		mt7927_vif_fill(sc, &v);
		/* the old keys go: the new association negotiates new ones */
		if (sc->sc_7927_hwkeys & MT7927_HWKEY_PAIRWISE)
			mt7927_sta_key(sc->sc_7927, &v, &sc->sc_7927_bss, true,
			    false, 0, 0, NULL, 0);
		if (sc->sc_7927_hwkeys & MT7927_HWKEY_GROUP)
			mt7927_sta_key(sc->sc_7927, &v, &sc->sc_7927_bss, false,
			    false, 0, 0, NULL, 0);
		sc->sc_7927_hwkeys = 0;
		sc->sc_7927_ptk_pending = false;
		sc->sc_7927_bss.cipher = 0;
		mt7927_roc_abort(sc->sc_7927, &v);
		return mt7927_roc(sc->sc_7927, &v, bss.chan, bss.band,
		    MT7927_ROC_JOIN_MS);
	}
	mt7927_vif_fill(sc, &v);
	if (sc->sc_flags & MWX_FLAG_SCANNING) {
		mt7927_scan_cancel(sc->sc_7927, &v);
		sc->sc_flags &= ~MWX_FLAG_SCANNING;
	}
	band_idx = bss.band == 1 ? 0 : 1;	/* mt7927_band_idx() */
	if ((rv = mt7927_band_reconfig(sc->sc_7927, &v, band_idx)) != 0)
		return rv;
	sc->sc_vif.band_idx = v.band_idx;
	MWX_DEV_LOG(sc, "MT7927 joining \"%.*s\" %s ch %u (%s GHz) rssi %d "
	    "%s%s rates basic 0x%x ra 0x%x\n", ni->ni_esslen,
	    (const char *)ni->ni_essid, ether_sprintf(bss.bssid), bss.chan,
	    bss.band == 1 ? "2.4" : "5", ni->ni_rssi,
	    (ni->ni_flags & IEEE80211_NODE_HT) ? "HT " : "",
	    (ni->ni_flags & IEEE80211_NODE_VHT) ? "VHT " : "",
	    bss.basic_rates, bss.ra_legacy);
	mt7927_wtbl_clear(sc->sc_7927, bss.peer_wcid);
	sc->sc_7927_bss = bss;
	sc->sc_7927_joined = true;
	if ((rv = mt7927_bss_info(sc->sc_7927, &v, &bss, true)) != 0 ||
	    (rv = mt7927_sta_rec(sc->sc_7927, &v, &bss, true, true, 0, true)) != 0)
		return rv;
	return mt7927_roc(sc->sc_7927, &v, bss.chan, bss.band,
	    MT7927_ROC_JOIN_MS);
}

/* RUN: STA_REC to ASSOC with the AID, then the BSS's broadcast entry. */
static int
mt7927_join_assoc(struct mwx_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct mt7927_vif v;
	int rv;

	if (!sc->sc_7927_joined)
		return EINVAL;
	mt7927_vif_fill(sc, &v);
	{
		/*
		 * The record was filled at AUTH from the scan node, before
		 * net80211 negotiated HT/VHT/QoS from the association response
		 * (ieee80211_ht/vht_negotiate): the firmware had a legacy
		 * 20 MHz peer. mt7925_mac_link_sta_assoc() builds these from
		 * the negotiated link_sta: do the same.
		 */
		struct mt7927_bss nb;

		mt7927_bss_fill(sc, ic->ic_bss, &nb);
		nb.cipher = sc->sc_7927_bss.cipher;
		sc->sc_7927_bss = nb;
		MWX_DEV_LOG(sc, "MT7927 peer at association: %s%s%s%sphymode 0x%02x "
		    "phy_type 0x%02x bw %u center %u ampdu 0x%02x max %u "
		    "vht_opmode 0x%02x ht mcs 0x%02x%02x\n",
		    (ic->ic_bss->ni_flags & IEEE80211_NODE_QOS) ? "QoS " : "",
		    (ic->ic_bss->ni_flags & IEEE80211_NODE_HT) ? "HT " : "",
		    (ic->ic_bss->ni_flags & IEEE80211_NODE_VHT) ? "VHT " : "",
		    (ic->ic_bss->ni_flags & IEEE80211_NODE_HE) ? "HE " : "",
		    nb.phymode, nb.phy_type, nb.bw, nb.center_chan, nb.ampdu,
		    nb.max_ampdu_len, nb.vht_opmode, nb.ht_mcs[1], nb.ht_mcs[0]);
		if (nb.he)
			MWX_DEV_LOG(sc, "MT7927 HE (802.11ax) with the AP: mac caps "
			    "%02x%02x%02x%02x%02x%02x, rx mcs 80 0x%04x 160 0x%04x, "
			    "our tx mcs 0x%04x/0x%04x, color %u%s, pe %u, rts %u\n",
			    nb.he_mac[0], nb.he_mac[1], nb.he_mac[2], nb.he_mac[3],
			    nb.he_mac[4], nb.he_mac[5], nb.he_mcs[0], nb.he_mcs[1],
			    nb.he_own_tx[0], nb.he_own_tx[1], nb.he_color,
			    nb.he_color_en ? "" : " (disabled)", nb.he_pe, nb.he_rts);
		MWX_DEV_LOG(sc, "MT7927 AP VHT operation: width %u center %u/%u, "
		    "negotiated VHT caps 0x%08x, chw %d\n",
		    ic->ic_bss->ni_vht_chanwidth, ic->ic_bss->ni_vht_chan1,
		    ic->ic_bss->ni_vht_chan2, ic->ic_bss->ni_vhtcaps,
		    (int)ic->ic_bss->ni_chw);
	}
	sc->sc_7927_bss.aid = IEEE80211_AID(ic->ic_bss->ni_associd);
	if ((rv = mt7927_bss_info(sc->sc_7927, &v, &sc->sc_7927_bss, true)) == 0 &&
	    (rv = mt7927_sta_rec(sc->sc_7927, &v, &sc->sc_7927_bss, true, true,
	    2, false)) == 0)
		rv = mt7927_sta_rec(sc->sc_7927, &v, &sc->sc_7927_bss, false, true,
		    2, false);
	sc->sc_7927_assoc = rv == 0;
	sc->sc_7927_assoc_polls = 0;
	MWX_DEV_LOG(sc, "MT7927 associated with %s aid %u -> %d\n",
	    ether_sprintf(sc->sc_7927_bss.bssid), sc->sc_7927_bss.aid, rv);
	if (rv == 0) {
		/* mac80211 calls conf_tx (mt7925_mcu_set_tx) at association */
		struct mt7927_edca e[4];

		mt7927_edca_fill(sc, e);
		sc->sc_7927_edca_dirty = false;
		mt7927_set_edca(sc->sc_7927, &v, e);
		/* BSS_CHANGED_PS with power save off (mt7925_mcu_uni_bss_ps) */
		mt7927_bss_ps(sc->sc_7927, &v, 0);
	}
	return rv;
}

/* mwx_newstate_task() for the MT7927. */
static void
mt7927_newstate(struct mwx_softc *sc, enum ieee80211_state ostate,
    enum ieee80211_state nstate, int arg)
{
	struct ieee80211com *ic = &sc->sc_ic;
	int rv = 0;

	MWX_DEV_LOG(sc, "newstate task %s -> %s arg=%d\n",
	    ieee80211_state_name[ostate], ieee80211_state_name[nstate], arg);
	if (nstate < IEEE80211_S_AUTH)
		mt7927_join_teardown(sc, ieee80211_state_name[nstate]);

	switch (nstate) {
	case IEEE80211_S_SCAN:
		if (ostate == IEEE80211_S_SCAN &&
		    (sc->sc_flags & MWX_FLAG_SCANNING))
			return;
		rv = mwx_scan(sc);
		break;
	case IEEE80211_S_AUTH:
		rv = mt7927_join_prepare(sc);
		break;
	case IEEE80211_S_ASSOC:
		break;
	case IEEE80211_S_RUN:
		if (ic->ic_opmode == IEEE80211_M_MONITOR)
			break;
		rv = mt7927_join_assoc(sc);
		break;
	default:
		break;
	}
	if (rv != 0 && nstate >= IEEE80211_S_AUTH) {
		MWX_DEV_LOG(sc, "MT7927 %s failed (%d), back to scanning\n",
		    ieee80211_state_name[nstate], rv);
		mt7927_join_teardown(sc, "setup failed");
		/* the scan is started by the next newstate task */
		ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
		return;
	}
	sc->sc_newstate(ic, nstate, arg);
}

/* Poll (about once a second): give the join ROC back once authorized. */
static void
mt7927_join_poll(struct mwx_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct mt7927_vif v;
	uint32_t grant_ms;

	if (!sc->sc_7927_assoc ||
	    !mt7927_roc_state(sc->sc_7927, &grant_ms))
		return;
	sc->sc_7927_assoc_polls++;
	if ((ic->ic_bss != NULL && ic->ic_bss->ni_port_valid) ||
	    sc->sc_7927_assoc_polls > 10) {
		mt7927_vif_fill(sc, &v);
		MWX_DEV_LOG(sc, "MT7927 releasing join ROC (%s)\n",
		    ic->ic_bss != NULL && ic->ic_bss->ni_port_valid ?
		    "authorized" : "timeout");
		mt7927_roc_abort(sc->sc_7927, &v);
	}
}

/*
 * Block Ack. net80211 asks from RX context (an ADDBA frame), where an MCU
 * command must not wait (the reply comes through the same interrupt work), so
 * the STA_REC goes out from the newstate task queue and net80211 is told the
 * result on the command gate (EBUSY: the driver answers later).
 */
#define	MT7927_BA_RX_START	0
#define	MT7927_BA_RX_STOP	1
#define	MT7927_BA_TX_START	2
#define	MT7927_BA_TX_STOP	3
#define	MT7927_KEY_SET		4

static int
mt7927_ba_queue(struct ieee80211com *ic, struct ieee80211_node *ni,
    uint8_t tid, uint8_t kind)
{
	struct mwx_softc *sc = (struct mwx_softc *)ic->ic_softc;
	struct mt7927_ba_op *op;

	if (!sc->sc_7927_assoc || ni != ic->ic_bss || tid >= 8)
		return ENOTSUP;
	IOLockLock(sc->sc_7927_lock);
	if (sc->sc_7927_baq_head - sc->sc_7927_baq_tail >=
	    nitems(sc->sc_7927_baq)) {
		IOLockUnlock(sc->sc_7927_lock);
		return ENOBUFS;
	}
	op = &sc->sc_7927_baq[sc->sc_7927_baq_head % nitems(sc->sc_7927_baq)];
	op->ni = ni;
	op->tid = tid;
	op->kind = kind;
	sc->sc_7927_baq_head++;
	IOLockUnlock(sc->sc_7927_lock);
	task_add(sc->sc_nswq, &sc->sc_7927_ba_task);
	return EBUSY;
}

static int
mt7927_ampdu_rx_start(struct ieee80211com *ic, struct ieee80211_node *ni,
    uint8_t tid)
{
	return mt7927_ba_queue(ic, ni, tid, MT7927_BA_RX_START);
}

static void
mt7927_ampdu_rx_stop(struct ieee80211com *ic, struct ieee80211_node *ni,
    uint8_t tid)
{
	(void)mt7927_ba_queue(ic, ni, tid, MT7927_BA_RX_STOP);
}

static int
mt7927_ampdu_tx_start(struct ieee80211com *ic, struct ieee80211_node *ni,
    uint8_t tid)
{
	return mt7927_ba_queue(ic, ni, tid, MT7927_BA_TX_START);
}

static void
mt7927_ampdu_tx_stop(struct ieee80211com *ic, struct ieee80211_node *ni,
    uint8_t tid)
{
	(void)mt7927_ba_queue(ic, ni, tid, MT7927_BA_TX_STOP);
}

/* net80211's answer to an ADDBA, on the command gate (serialised with RX). */
static IOReturn
mt7927_ba_answer_action(OSObject *, void *arg0, void *arg1, void *arg2,
    void *arg3)
{
	struct mwx_softc *sc = (struct mwx_softc *)arg0;
	struct ieee80211com *ic = &sc->sc_ic;
	struct ieee80211_node *ni = (struct ieee80211_node *)arg1;
	uint8_t tid = (uint8_t)(uintptr_t)arg2;
	uintptr_t code = (uintptr_t)arg3;	/* kind | ok << 8 */
	bool ok = (code >> 8) != 0;

	if (ni != ic->ic_bss || !sc->sc_7927_assoc)
		return kIOReturnSuccess;
	if ((code & 0xff) == MT7927_BA_RX_START) {
		if (ok) {
			ieee80211_addba_req_accept(ic, ni, tid);
			mt7927_rx_ba_action(NULL, sc, (void *)(uintptr_t)tid,
			    (void *)1, NULL);
		} else {
			ieee80211_addba_req_refuse(ic, ni, tid);
		}
	} else if ((code & 0xff) == MT7927_BA_TX_START) {
		if (ok)
			ieee80211_addba_resp_accept(ic, ni, tid);
		else
			ieee80211_addba_resp_refuse(ic, ni, tid,
			    IEEE80211_STATUS_UNSPECIFIED);
	}
	return kIOReturnSuccess;
}

static void
mt7927_ba_task(void *arg)
{
	struct mwx_softc *sc = (struct mwx_softc *)arg;
	struct ieee80211com *ic = &sc->sc_ic;
	IOCommandGate *gate = gMwxHal != NULL ? gMwxHal->mwxGate() : NULL;
	int s = splnet();

	for (;;) {
		struct mt7927_ba_op op;
		struct mt7927_vif v;
		uint16_t ssn = 0, win = 0;
		bool amsdu = false;
		int rv = ENXIO;

		IOLockLock(sc->sc_7927_lock);
		if (sc->sc_7927_baq_tail == sc->sc_7927_baq_head) {
			IOLockUnlock(sc->sc_7927_lock);
			break;
		}
		op = sc->sc_7927_baq[sc->sc_7927_baq_tail %
		    nitems(sc->sc_7927_baq)];
		explicit_bzero(sc->sc_7927_baq[sc->sc_7927_baq_tail %
		    nitems(sc->sc_7927_baq)].key, sizeof(op.key));
		sc->sc_7927_baq_tail++;
		IOLockUnlock(sc->sc_7927_lock);

		if (op.kind == MT7927_KEY_SET) {
			mt7927_key_install(sc, &op);
			continue;
		}
		/* the node may be gone already: only the current AP counts */
		if (op.ni != ic->ic_bss || !sc->sc_7927_assoc ||
		    !mt7927_engine_running(sc->sc_7927))
			continue;
		mt7927_vif_fill(sc, &v);
		switch (op.kind) {
		case MT7927_BA_RX_START: {
			struct ieee80211_rx_ba *ba = &op.ni->ni_rx_ba[op.tid];

			ssn = ba->ba_winstart;
			win = ba->ba_winsize;
			rv = mt7927_sta_ba(sc->sc_7927, &v, &sc->sc_7927_bss,
			    op.tid, false, true, ssn, win, false);
			break; }
		case MT7927_BA_TX_START: {
			struct ieee80211_tx_ba *ba = &op.ni->ni_tx_ba[op.tid];

			ssn = ba->ba_winstart;
			win = ba->ba_winsize;
			if (win == 0 || win > MT7927_REORDER_WIN)
				win = MT7927_REORDER_WIN;
			/* A-MSDU in A-MPDU when the AP allows it (its ADDBA
			 * response) and the chip encrypts */
			amsdu = sc->sc_7927_amsdu_ok &&
			    (sc->sc_7927_hwkeys & MT7927_HWKEY_PAIRWISE) &&
			    (ba->ba_params & IEEE80211_ADDBA_AMSDU) != 0;
			rv = mt7927_sta_ba(sc->sc_7927, &v, &sc->sc_7927_bss,
			    op.tid, true, true, ssn, win, amsdu);
			break; }
		case MT7927_BA_RX_STOP:
		case MT7927_BA_TX_STOP:
			mt7927_sta_ba(sc->sc_7927, &v, &sc->sc_7927_bss, op.tid,
			    op.kind == MT7927_BA_TX_STOP, false, 0, 0, false);
			if (op.kind == MT7927_BA_RX_STOP && gate != NULL)
				gate->runAction(mt7927_rx_ba_action, sc,
				    (void *)(uintptr_t)op.tid, NULL);
			continue;
		}
		if (gate != NULL)
			gate->runAction(mt7927_ba_answer_action, sc, op.ni,
			    (void *)(uintptr_t)op.tid,
			    (void *)(uintptr_t)(op.kind | ((rv == 0) << 8)));
	}
	splx(s);
}

/* Output room again after TX free events (work loop, from the engine). */
static void
mt7927_hal_txroom(void *arg)
{
	struct mwx_softc *sc = (struct mwx_softc *)arg;
	struct ifnet *ifp = &sc->sc_ic.ic_if;

	if (!ifq_is_oactive(&ifp->if_snd))
		return;
	ifq_clr_oactive(&ifp->if_snd);
	mwx_start(ifp);
#ifdef __PRIVATE_SPI__
	if (ifp->iface != NULL)
		ifp->iface->signalOutputThread();
#endif
}

/*
 * net80211's EDCA parameters (from the AP's WMM element, EDCA_AC_* order)
 * in the firmware's mac80211 order. An AP without WMM leaves them zero:
 * use the 802.11 defaults then.
 */
static void
mt7927_edca_fill(struct mwx_softc *sc, struct mt7927_edca *e)
{
	static const uint8_t map[4] = { EDCA_AC_VO, EDCA_AC_VI, EDCA_AC_BE,
	    EDCA_AC_BK };
	static const struct mt7927_edca def[4] = {
		{ 2, 2, 3, 47 }, { 2, 3, 4, 94 }, { 3, 4, 10, 0 }, { 7, 4, 10, 0 }
	};
	struct ieee80211com *ic = &sc->sc_ic;
	int i;

	for (i = 0; i < 4; i++) {
		const struct ieee80211_edca_ac_params *p = &ic->ic_edca_ac[map[i]];

		if (p->ac_aifsn == 0 || p->ac_ecwmax == 0) {
			e[i] = def[i];
			continue;
		}
		e[i].aifs = p->ac_aifsn;
		e[i].ecw_min = p->ac_ecwmin;
		e[i].ecw_max = p->ac_ecwmax;
		e[i].txop = p->ac_txoplimit;
	}
}

/* ic_updateedca (RX context): send them from the next watchdog tick. */
static void
mt7927_updateedca(struct ieee80211com *ic)
{
	struct mwx_softc *sc = (struct mwx_softc *)ic->ic_softc;

	sc->sc_7927_edca_dirty = true;
}

/* Data TX again after the pairwise key went to the chip (work loop). */
static IOReturn
mt7927_key_kick_action(OSObject *, void *arg0, void *, void *, void *)
{
	struct mwx_softc *sc = (struct mwx_softc *)arg0;
	struct ifnet *ifp = &sc->sc_ic.ic_if;

	ifq_clr_oactive(&ifp->if_snd);
	mwx_start(ifp);
#ifdef __PRIVATE_SPI__
	if (ifp->iface != NULL)
		ifp->iface->signalOutputThread();
#endif
	return kIOReturnSuccess;
}

/*
 * The task side of mt7927_set_key(): BSS_INFO with the cipher on the first
 * key (as mt7925_set_link_key() does), then STA_REC_KEY_V3.
 */
static void
mt7927_key_install(struct mwx_softc *sc, struct mt7927_ba_op *op)
{
	struct ieee80211com *ic = &sc->sc_ic;
	IOCommandGate *gate = gMwxHal != NULL ? gMwxHal->mwxGate() : NULL;
	struct mt7927_vif v;
	int rv = ENXIO;

	if (op->ni == ic->ic_bss && sc->sc_7927_assoc &&
	    mt7927_engine_running(sc->sc_7927)) {
		mt7927_vif_fill(sc, &v);
		rv = 0;
		if (sc->sc_7927_bss.cipher != MT7927_CIPHER_AES_CCMP) {
			sc->sc_7927_bss.cipher = MT7927_CIPHER_AES_CCMP;
			rv = mt7927_bss_info(sc->sc_7927, &v, &sc->sc_7927_bss,
			    true);
		}
		if (rv == 0)
			rv = mt7927_sta_key(sc->sc_7927, &v, &sc->sc_7927_bss,
			    op->key_pairwise, true, MT7927_CIPHER_AES_CCMP,
			    op->key_id, op->key, op->key_len);
	}
	explicit_bzero(op->key, sizeof(op->key));
	if (rv == 0) {
		sc->sc_7927_hwkeys |= op->key_pairwise ?
		    MT7927_HWKEY_PAIRWISE : MT7927_HWKEY_GROUP;
		/* new key, new PN space for the 802.3 path's replay check */
		if (op->key_pairwise)
			sc->sc_7927_pn_reset_uc = true;
		else
			sc->sc_7927_pn_reset_mc = true;
	} else {
		/* software keys stay set up: TX and RX fall back to them */
		sc->sc_7927_hwkey_fail++;
		if (op->key_pairwise)
			sc->sc_7927_hwkeys &= ~MT7927_HWKEY_PAIRWISE;
		MWX_DEV_LOG(sc, "MT7927 %s key id %u stays in software (%d)\n",
		    op->key_pairwise ? "pairwise" : "group", op->key_id, rv);
	}
	if (op->key_pairwise) {
		sc->sc_7927_ptk_pending = false;
		if (gate != NULL)
			gate->runAction(mt7927_key_kick_action, sc);
	}
}

/*
 * CCMP keys go to the chip (hardware encrypts TX, decrypts RX). net80211
 * keeps its software context too: frames the chip did not decrypt are
 * decrypted in software, and TX is encrypted in software until the chip
 * has the pairwise key or if installing it fails. Data TX is held while
 * the pairwise key is on its way, so no software PN gets ahead of the
 * chip's.
 */
static int
mt7927_set_key(struct ieee80211com *ic, struct ieee80211_node *ni,
    struct ieee80211_key *k)
{
	struct mwx_softc *sc = (struct mwx_softc *)ic->ic_softc;
	bool pairwise = !(k->k_flags & IEEE80211_KEY_GROUP);
	struct mt7927_ba_op *op;
	bool queued = false;
	int err = ieee80211_set_key(ic, ni, k);

	if (err == 0 && sc->sc_7927_hwcrypto &&
	    k->k_cipher == IEEE80211_CIPHER_CCMP && k->k_len <= 32 &&
	    ni == ic->ic_bss) {
		IOLockLock(sc->sc_7927_lock);
		if (sc->sc_7927_baq_head - sc->sc_7927_baq_tail <
		    nitems(sc->sc_7927_baq)) {
			op = &sc->sc_7927_baq[sc->sc_7927_baq_head %
			    nitems(sc->sc_7927_baq)];
			op->ni = ni;
			op->tid = 0;
			op->kind = MT7927_KEY_SET;
			op->key_pairwise = pairwise;
			op->key_id = (uint8_t)k->k_id;
			op->key_len = (uint8_t)k->k_len;
			memcpy(op->key, k->k_key, k->k_len);
			if (pairwise) {
				/* a new PTK: TX in software until the chip has it */
				sc->sc_7927_hwkeys &= ~MT7927_HWKEY_PAIRWISE;
				sc->sc_7927_ptk_pending = true;
			}
			sc->sc_7927_baq_head++;
			queued = true;
		}
		IOLockUnlock(sc->sc_7927_lock);
		if (queued)
			task_add(sc->sc_nswq, &sc->sc_7927_ba_task);
	}
	MWX_DEV_LOG(sc, "MT7927 %s key id %d cipher %d -> %d (%s)\n",
	    pairwise ? "pairwise" : "group", k->k_id, k->k_cipher, err,
	    queued ? "to the chip" : "software");
	return err;
}

static void
mt7927_delete_key(struct ieee80211com *ic, struct ieee80211_node *ni,
    struct ieee80211_key *k)
{
	if (k->k_flags & IEEE80211_KEY_SWCRYPTO)
		ieee80211_delete_key(ic, ni, k);
}

/* LLC/SNAP + EAPOL ethertype right after the 802.11 header. */
static bool
mt7927_is_eapol(const uint8_t *f, uint32_t len, uint32_t hdrlen)
{
	static const uint8_t snap[8] = { 0xaa, 0xaa, 0x03, 0, 0, 0, 0x88, 0x8e };

	return len >= hdrlen + 8 && memcmp(f + hdrlen, snap, 8) == 0;
}

/* mwx_start() for the MT7927: management frames, then data once in RUN. */
static void
mt7927_hal_output_locked(struct mwx_softc *sc, struct ifnet *ifp)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct ieee80211_node *ni;
	struct ieee80211_frame *wh;
	struct mt7927_txinfo ti;
	struct mbuf *m;
	uint32_t len;
	uint8_t type;
	bool hwenc;
	int rv;

	for (;;) {
		if (!mt7927_engine_tx_room(sc->sc_7927)) {
			/* the chip is full: leave the frames queued */
			sc->sc_7927_tx_held++;
			ifq_set_oactive(&ifp->if_snd);
			break;
		}
		m = mq_dequeue(&ic->ic_mgtq);
		if (m != NULL) {
			ni = (struct ieee80211_node *)mbuf_pkthdr_rcvif(m);
		} else {
			if (ic->ic_state != IEEE80211_S_RUN ||
			    (ic->ic_xflags & IEEE80211_F_TX_MGMT_ONLY) ||
			    sc->sc_7927_ptk_pending)
				break;
			m = ifq_dequeue(&ifp->if_snd);
			if (m == NULL)
				break;
			if (mbuf_len(m) < sizeof(struct ether_header) &&
			    (m = m_pullup(m, sizeof(struct ether_header))) == NULL) {
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
		}
		if (mbuf_len(m) < sizeof(*wh) &&
		    (m = m_pullup(m, sizeof(*wh))) == NULL) {
			if (ni != NULL)
				ieee80211_release_node(ic, ni);
			ifp->if_oerrors++;
			continue;
		}
		wh = mtod(m, struct ieee80211_frame *);
		hwenc = false;
		if (wh->i_fc[1] & IEEE80211_FC1_PROTECTED) {
			struct ieee80211_key *k = ieee80211_get_txkey(ic, wh, ni);

			if (k != NULL && ni != NULL && k == &ni->ni_pairwise_key &&
			    k->k_cipher == IEEE80211_CIPHER_CCMP &&
			    (sc->sc_7927_hwkeys & MT7927_HWKEY_PAIRWISE)) {
				/* the chip adds the CCMP header and MIC */
				hwenc = true;
				sc->sc_7927_tx_hwenc++;
			} else if ((m = ieee80211_encrypt(ic, m, k)) == NULL) {
				if (ni != NULL)
					ieee80211_release_node(ic, ni);
				ifp->if_oerrors++;
				sc->sc_7927_tx_encfail++;
				continue;
			}
			if (!hwenc)
				sc->sc_7927_tx_swenc++;
			wh = mtod(m, struct ieee80211_frame *);
		}
#if NBPFILTER > 0
		if (ic->ic_rawbpf != NULL)
			bpf_mtap(ic->ic_rawbpf, m, BPF_DIRECTION_OUT);
#endif
		len = (uint32_t)mbuf_pkthdr_len(m);
		if (len > sizeof(sc->sc_7927_txbuf)) {
			m_freem(m);
			if (ni != NULL)
				ieee80211_release_node(ic, ni);
			ifp->if_oerrors++;
			continue;
		}
		m_copydata(m, 0, (int)len, sc->sc_7927_txbuf);
		m_freem(m);
		wh = (struct ieee80211_frame *)sc->sc_7927_txbuf;
		type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;

		memset(&ti, 0, sizeof(ti));
		ti.protect = hwenc;
		ti.hdrlen = (uint8_t)ieee80211_get_hdrlen(wh);
		ti.multicast = IEEE80211_IS_MULTICAST(wh->i_addr1);
		ti.omac_idx = sc->sc_vif.omac_idx;
		ti.band_idx = sc->sc_vif.band_idx;
		ti.wcid = (!ti.multicast && sc->sc_7927_joined) ?
		    MT7927_PEER_WCID : sc->sc_vif.vif_mn.wcid;
		ti.rate_idx = MT7927_BASIC_RATES_IDX(
		    sc->sc_7927_joined ? sc->sc_7927_bss.band :
		    (sc->sc_vif.band_idx ? 2 : 1));
		if (type == IEEE80211_FC0_TYPE_DATA) {
			uint8_t tid = 0, ac;

			if (ieee80211_has_qos(wh))
				tid = ieee80211_get_qos(wh) & IEEE80211_QOS_TID;
			ac = ieee80211_up_to_ac(ic, tid);	/* EDCA_AC_* */
			/* LMAC order: BK 0, BE 1, VI 2, VO 3 */
			ti.q_idx = ac == EDCA_AC_BK ? 0 : ac == EDCA_AC_BE ? 1 :
			    ac == EDCA_AC_VI ? 2 : 3;
			ti.tid = tid;
			ti.fixed_rate = ti.multicast ||
			    mt7927_is_eapol(sc->sc_7927_txbuf, len, ti.hdrlen);
			if (!ti.fixed_rate && !ti.multicast) {
				/* the MAC packs MSDUs only of frames it encrypts */
				ti.amsdu = hwenc && sc->sc_7927_bss.amsdu != 0 &&
				    ieee80211_has_qos(wh);
				if (ti.amsdu)
					sc->sc_7927_tx_amsdu++;
				/* one rate sample every 256 unicast data frames */
				ti.txs = (++sc->sc_7927_txs_tick & 0xff) == 0;
			}
		} else {
			ti.q_idx = MT7927_LMAC_ALTX0;
			ti.tid = 0;				/* MT_TX_NORMAL */
			/* an ADDBA request is MT_TX_ADDBA (mt7925_mac_write_txwi_80211) */
			if ((wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) ==
			    IEEE80211_FC0_SUBTYPE_ACTION && len >= 26 &&
			    sc->sc_7927_txbuf[24] == IEEE80211_CATEG_BA &&
			    sc->sc_7927_txbuf[25] == IEEE80211_ACTION_ADDBA_REQ)
				ti.tid = 2;
			ti.fixed_rate = true;
		}
		rv = mt7927_tx_frame(sc->sc_7927, &ti, sc->sc_7927_txbuf, len);
		if (ni != NULL)
			ieee80211_release_node(ic, ni);
		if (rv != 0) {
			ifp->if_oerrors++;
			if (rv == ENOBUFS) {
				ifq_set_oactive(&ifp->if_snd);
				break;
			}
			continue;
		}
		if (ifp->netStat)
			ifp->netStat->outputPackets++;
	}
}

/*
 * mwx_start() runs on Skywalk's output thread and on the work loop (frames
 * net80211 sends while handling RX): one at a time, as they share the copy
 * buffer.
 */
static void
mt7927_hal_output(struct mwx_softc *sc, struct ifnet *ifp)
{
	if (sc->sc_7927_txlock == NULL)
		return;
	IOLockLock(sc->sc_7927_txlock);
	mt7927_hal_output_locked(sc, ifp);
	IOLockUnlock(sc->sc_7927_txlock);
}

/* Firmware event (interrupt or MCU-waiter thread): only cheap work here. */
static void
mt7927_hal_event(void *arg, uint8_t eid, const uint8_t *p, uint32_t len)
{
	struct mwx_softc *sc = (struct mwx_softc *)arg;

	if (eid != MT7927_UNI_EVENT_SCAN_DONE || !mt7927_scan_event_done(p, len))
		return;
	sc->sc_scan_done_count++;
	sc->sc_flags &= ~MWX_FLAG_SCANNING;
	task_add(systq, &sc->sc_scan_task);
}

/* Data-ring packet (interrupt work, main work loop): RXD + 802.11 frame. */

/* ---- Phase 4c.10: header-translated (802.3) receive path ---- */

#define	MT7927_RXD3_CSUM	((1U << 26) | (1U << 27))	/* IP, UDP/TCP sum */

extern void ieee80211_enqueue_data(struct ieee80211com *, mbuf_t,
    struct ieee80211_node *, int, struct mbuf_list *);

#define	MT7927_REORDER_TIMEO_MS	100	/* mt76_aggr_tid_to_timeo(): HZ / 10 */

static uint32_t
mt7927_now_ms(void)
{
	uint64_t ns;

	absolutetime_to_nanoseconds(mach_absolute_time(), &ns);
	return (uint32_t)(ns / 1000000ULL);
}

/* Frames of one unit up the stack (as net80211's decap ends) or freed. */
static void
mt7927_rx_chain(struct mwx_softc *sc, mbuf_t m, bool deliver)
{
	struct ieee80211com *ic = &sc->sc_ic;
	mbuf_t next;

	for (; m != NULL; m = next) {
		next = mbuf_nextpkt(m);
		mbuf_setnextpkt(m, NULL);
		if (!deliver || ic->ic_bss == NULL ||
		    ic->ic_state != IEEE80211_S_RUN) {
			mbuf_freem(m);
			continue;
		}
		/* port check, EAPOL to the key handshake, rest to the batch */
		ieee80211_enqueue_data(ic, m, ic->ic_bss,
		    (mbuf_flags(m) & MBUF_MCAST) != 0, &sc->sc_7927_rxml);
		sc->sc_7927_rxml_frames++;
	}
}

/*
 * CCMP replay check per TID (mt76_check_ccmp_pn), once per MPDU (the
 * subframes of an A-MSDU share its PN) and after reordering, as
 * mt76_rx_complete() runs it: retransmitted MPDUs arrive late with lower
 * PNs. Group-addressed frames use the group key's counters.
 */
static bool
mt7927_rx_pn_ok(struct mwx_softc *sc, const struct mt7927_rxunit *u)
{
	uint8_t *last;
	int i;

	if (!u->check_pn)
		return true;
	if (sc->sc_7927_pn_reset_uc) {
		sc->sc_7927_pn_reset_uc = false;
		memset(sc->sc_7927_pn_uc, 0, sizeof(sc->sc_7927_pn_uc));
	}
	if (sc->sc_7927_pn_reset_mc) {
		sc->sc_7927_pn_reset_mc = false;
		memset(sc->sc_7927_pn_mc, 0, sizeof(sc->sc_7927_pn_mc));
	}
	last = u->mcast ? sc->sc_7927_pn_mc[u->tid] : sc->sc_7927_pn_uc[u->tid];
	for (i = 5; i >= 0; i--) {		/* PN5 is the most significant */
		if (u->pn[i] != last[i])
			break;
	}
	if (i < 0 || u->pn[i] < last[i]) {
		sc->sc_7927_rx_replay++;
		return false;
	}
	memcpy(last, u->pn, 6);
	return true;
}

/* A unit leaves (in order, or given up): replay check, then up or freed. */
static void
mt7927_rx_unit_out(struct mwx_softc *sc, mbuf_t head,
    const struct mt7927_rxunit *u, bool deliver)
{
	if (!deliver)
		sc->sc_7927_rx_late++;
	else if (!mt7927_rx_pn_ok(sc, u))
		deliver = false;
	mt7927_rx_chain(sc, head, deliver);
}

static struct mt7927_rxu *
mt7927_rxu_get(struct mwx_softc *sc)
{
	struct mt7927_rxu *x;

	if (!sc->sc_7927_rxu_init) {
		sc->sc_7927_rxu_free = NULL;
		for (int i = (int)nitems(sc->sc_7927_rxu) - 1; i >= 0; i--) {
			sc->sc_7927_rxu[i].next = sc->sc_7927_rxu_free;
			sc->sc_7927_rxu_free = &sc->sc_7927_rxu[i];
		}
		sc->sc_7927_rxu_init = true;
	}
	if ((x = sc->sc_7927_rxu_free) != NULL)
		sc->sc_7927_rxu_free = x->next;
	return x;
}

static void
mt7927_rxu_put(struct mwx_softc *sc, struct mt7927_rxu *x)
{
	x->head = NULL;
	x->next = sc->sc_7927_rxu_free;
	sc->sc_7927_rxu_free = x;
}

/* mt7927_release_fn for the reorder buffers */
static void
mt7927_rxu_release(void *arg, void *unit, bool deliver)
{
	struct mwx_softc *sc = (struct mwx_softc *)arg;
	struct mt7927_rxu *x = (struct mt7927_rxu *)unit;

	mt7927_rx_unit_out(sc, (mbuf_t)x->head, &x->u, deliver);
	mt7927_rxu_put(sc, x);
}

static IOReturn
mt7927_reorder_timeo_action(OSObject *, void *arg0, void *, void *, void *)
{
	struct mwx_softc *sc = (struct mwx_softc *)arg0;
	uint32_t now = mt7927_now_ms();
	bool more = false;

	sc->sc_7927_reorder_armed = false;
	if (sc->sc_7927_amsdu_head != NULL) {
		if (now - sc->sc_7927_amsdu_when >= 20)
			mt7927_rx_amsdu_flush(sc);
		else
			more = true;
	}
	for (int tid = 0; tid < 8; tid++)
		more |= mt7927_reorder_check(&sc->sc_7927_reorder[tid], now,
		    MT7927_REORDER_TIMEO_MS, mt7927_rxu_release, sc);
	mt7927_hal_rx_done(sc);
	if (more) {
		sc->sc_7927_reorder_armed = true;
		timeout_add_msec(&sc->sc_7927_reorder_to,
		    MT7927_REORDER_TIMEO_MS / 2);
	}
	return kIOReturnSuccess;
}

/* Reorder timeout (mt76_rx_aggr_reorder_work): on the work loop's gate. */
static void
mt7927_reorder_timeo(void *arg)
{
	IOCommandGate *gate = gMwxHal != NULL ? gMwxHal->mwxGate() : NULL;
	int s = splnet();

	if (gate != NULL)
		gate->runAction(mt7927_reorder_timeo_action, arg);
	splx(s);
}

/* One complete MPDU: into its TID's reorder buffer, or straight on. */
static void
mt7927_rx_unit_finish(struct mwx_softc *sc, mbuf_t head,
    const struct mt7927_rxunit *u)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct mt7927_reorder *r;
	struct mt7927_rxu *x;

	if (!u->reorder || u->mcast || u->tid >= 8 ||
	    !sc->sc_7927_reorder[u->tid].active ||
	    (x = mt7927_rxu_get(sc)) == NULL) {
		mt7927_rx_unit_out(sc, head, u, true);
		return;
	}
	x->head = head;
	x->u = *u;
	r = &sc->sc_7927_reorder[u->tid];
	mt7927_reorder_add(r, u->seq, x, mt7927_now_ms(), mt7927_rxu_release,
	    sc);
	/* the frames bypass ieee80211_input_ba(): keep net80211's session */
	if (ic->ic_bss != NULL) {
		struct ieee80211_rx_ba *ba = &ic->ic_bss->ni_rx_ba[u->tid];

		if (ba->ba_timeout_val != 0)
			timeout_add_usec(&ba->ba_to, ba->ba_timeout_val);
	}
	if (r->n != 0 && !sc->sc_7927_reorder_armed) {
		sc->sc_7927_reorder_armed = true;
		timeout_add_msec(&sc->sc_7927_reorder_to,
		    MT7927_REORDER_TIMEO_MS / 2);
	}
}

static void
mt7927_rx_unit_free(mbuf_t m)
{
	mbuf_t next;

	for (; m != NULL; m = next) {
		next = mbuf_nextpkt(m);
		mbuf_setnextpkt(m, NULL);
		mbuf_freem(m);
	}
}

/* An A-MSDU still being gathered goes on as it is. */
static void
mt7927_rx_amsdu_flush(struct mwx_softc *sc)
{
	mbuf_t head = sc->sc_7927_amsdu_head;

	if (head == NULL)
		return;
	sc->sc_7927_amsdu_head = sc->sc_7927_amsdu_tail = NULL;
	mt7927_rx_unit_finish(sc, head, &sc->sc_7927_amsdu_meta);
}

/*
 * A frame the chip translated to 802.3 (mt7925_mac_fill_rx with
 * RX_FLAG_8023): no net80211 decap. The chip split A-MSDUs into subframes
 * (RXD4 first/middle/last), which are gathered into one unit like
 * mt76_rx_release_amsdu() before reordering.
 */
static void
mt7927_rx_8023(struct mwx_softc *sc, const uint8_t *p, uint32_t len)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct ieee80211_node *ni = ic->ic_bss;
	struct mt7927_rxunit u;
	struct mt7927_rxi ri;
	const uint8_t *d;
	uint32_t dlen, rxd3;
	unsigned int chunks = 1;
	uint16_t type;
	mbuf_t m = NULL;
	int rv;

	rv = mt7927_rx_parse(p, len, sc->sc_capa.antenna_mask ?
	    sc->sc_capa.antenna_mask : 0x3, &ri);
	if (rv != 0) {
		sc->sc_7927_rx_drop[rv & 7]++;
		return;
	}
	if (ic->ic_state != IEEE80211_S_RUN || ni == NULL || ri.frag ||
	    (ri.wlan_idx != sc->sc_7927_bss.peer_wcid &&
	    ri.wlan_idx != sc->sc_vif.vif_mn.wcid)) {
		sc->sc_7927_rx8023_drop++;
		return;
	}
	d = p + ri.hdr_off;
	dlen = ri.frame_len;
	type = (uint16_t)(d[12] << 8 | d[13]);
	/* RSN: only EAPOL may come in the clear, and only before the keys */
	if ((ic->ic_flags & IEEE80211_F_RSNON) && !ri.decrypted &&
	    (type != ETHERTYPE_PAE || ni->ni_port_valid)) {
		sc->sc_7927_rx8023_drop++;
		return;
	}
	if (mbuf_allocpacket(MBUF_DONTWAIT, dlen + ETHER_ALIGN, &chunks,
	    &m) != 0 || mbuf_maxlen(m) < dlen + ETHER_ALIGN) {
		if (m != NULL)
			mbuf_freem(m);
		sc->sc_ic.ic_if.if_ierrors++;
		return;
	}
	/* IP header aligned like net80211's decap leaves it */
	mbuf_setdata(m, (uint8_t *)mbuf_datastart(m) + ETHER_ALIGN, 0);
	if (ri.hdr_trans_err && type == ETHERTYPE_VLAN && dlen >= 18) {
		/* the chip put a 2-byte length after the VLAN tag */
		memcpy(mtod(m, uint8_t *), d, 16);
		memcpy(mtod(m, uint8_t *) + 16, d + 18, dlen - 18);
		dlen -= 2;
	} else {
		memcpy(mtod(m, uint8_t *), d, dlen);
	}
	mbuf_setlen(m, dlen);
	mbuf_pkthdr_setlen(m, dlen);
	rxd3 = mt7927_le32(p + 12);
	if (!(mt7927_engine_rx_info(sc->sc_7927) & 0xd) &&
	    (rxd3 & MT7927_RXD3_CSUM) == MT7927_RXD3_CSUM) {
		mbuf_set_csum_performed(m, MBUF_CSUM_DID_IP |
		    MBUF_CSUM_IP_GOOD | MBUF_CSUM_DID_DATA |
		    MBUF_CSUM_PSEUDO_HDR, 0xffff);
		sc->sc_7927_rx_csum++;
	}
	memset(&u, 0, sizeof(u));
	u.mcast = !ri.unicast || (d[0] & 0x01);
	if (u.mcast) {
		mbuf_setflags_mask(m, MBUF_MCAST, MBUF_MCAST);
		sc->sc_7927_rx_mcast++;
	} else {
		sc->sc_7927_rx_ucast++;
	}
	sc->sc_7927_rx8023++;
	/* what ieee80211_input() keeps up to date for the AP */
	ni->ni_inact = 0;
	if (ri.rssi < 0 && ri.rssi > -127)
		ni->ni_rssi = (uint8_t)mwx_dbm_to_rssi(ri.rssi);

	u.tid = 16;
	if (ri.has_g4) {
		u.seq = ri.seq_ctrl >> 4;
		if ((ri.fc & 0x00fc) == 0x0088) {		/* QoS data */
			u.tid = ri.qos_ctl & 0xf;
			/* normal ack (not no-ack or no explicit ack): in a BA */
			u.reorder = ((ri.qos_ctl >> 5) & 0x3) == 0;
		}
	} else {
		sc->sc_7927_rx_nog4++;
	}
	/* without group 4 the order is unknown: the chip's replay check only */
	u.check_pn = ri.decrypted && ri.has_pn && ri.has_g4 &&
	    ri.sec_mode == MT7927_CIPHER_AES_CCMP;
	memcpy(u.pn, ri.pn, 6);

	switch (ri.amsdu) {
	case 0:						/* a single MSDU */
		mt7927_rx_amsdu_flush(sc);
		mt7927_rx_unit_finish(sc, m, &u);
		break;
	case 3:						/* first subframe */
		mt7927_rx_amsdu_flush(sc);
		sc->sc_7927_amsdu_head = sc->sc_7927_amsdu_tail = m;
		sc->sc_7927_amsdu_meta = u;
		sc->sc_7927_amsdu_when = mt7927_now_ms();
		/* a last subframe that never comes: the timer sends it on */
		if (!sc->sc_7927_reorder_armed) {
			sc->sc_7927_reorder_armed = true;
			timeout_add_msec(&sc->sc_7927_reorder_to,
			    MT7927_REORDER_TIMEO_MS / 2);
		}
		break;
	default:					/* middle, last */
		if (sc->sc_7927_amsdu_head != NULL &&
		    sc->sc_7927_amsdu_meta.seq == u.seq &&
		    sc->sc_7927_amsdu_meta.tid == u.tid) {
			mbuf_setnextpkt(sc->sc_7927_amsdu_tail, m);
			sc->sc_7927_amsdu_tail = m;
		} else {
			mt7927_rx_amsdu_flush(sc);
			sc->sc_7927_amsdu_head = sc->sc_7927_amsdu_tail = m;
			sc->sc_7927_amsdu_meta = u;
		}
		if (ri.amsdu == 1)
			mt7927_rx_amsdu_flush(sc);
		break;
	}
}

/* A Block Ack Request from the AP moves our reorder window (mt76 check_ctl). */
static void
mt7927_rx_bar(struct mwx_softc *sc, const uint8_t *f, size_t len)
{
	uint16_t ctl, ssn;
	uint8_t tid;

	if (len < 20 || !sc->sc_7927_rx_decap)
		return;
	ctl = (uint16_t)(f[16] | f[17] << 8);
	ssn = (uint16_t)(f[18] | f[19] << 8) >> 4;
	tid = (uint8_t)(ctl >> 12);
	if (tid >= 8)
		return;
	mt7927_reorder_bar(&sc->sc_7927_reorder[tid], ssn,
	    mt7927_rxu_release, sc);
}

/* Leaving or stopping (work loop): drop held frames, start over on keys. */
static IOReturn
mt7927_rx_decap_reset_action(OSObject *, void *arg0, void *, void *, void *)
{
	struct mwx_softc *sc = (struct mwx_softc *)arg0;

	for (int tid = 0; tid < 8; tid++) {
		struct mt7927_reorder *r = &sc->sc_7927_reorder[tid];

		for (int i = 0; i < MT7927_REORDER_WIN; i++) {
			struct mt7927_rxu *x = (struct mt7927_rxu *)r->buf[i];

			if (x == NULL)
				continue;
			mt7927_rx_unit_free((mbuf_t)x->head);
			mt7927_rxu_put(sc, x);
		}
		memset(r, 0, sizeof(*r));
	}
	mt7927_rx_unit_free(sc->sc_7927_amsdu_head);
	sc->sc_7927_amsdu_head = sc->sc_7927_amsdu_tail = NULL;
	memset(sc->sc_7927_pn_uc, 0, sizeof(sc->sc_7927_pn_uc));
	memset(sc->sc_7927_pn_mc, 0, sizeof(sc->sc_7927_pn_mc));
	return kIOReturnSuccess;
}

static void
mt7927_rx_decap_reset(struct mwx_softc *sc)
{
	IOCommandGate *gate = gMwxHal != NULL ? gMwxHal->mwxGate() : NULL;

	if (sc->sc_7927_reorder_to != NULL)
		timeout_del(&sc->sc_7927_reorder_to);
	sc->sc_7927_reorder_armed = false;
	if (gate != NULL)
		gate->runAction(mt7927_rx_decap_reset_action, sc);
	else
		mt7927_rx_decap_reset_action(NULL, sc, NULL, NULL, NULL);
}

/* BA session start/stop for our reorder buffers (work loop). */
static IOReturn
mt7927_rx_ba_action(OSObject *, void *arg0, void *arg1, void *arg2, void *)
{
	struct mwx_softc *sc = (struct mwx_softc *)arg0;
	struct ieee80211com *ic = &sc->sc_ic;
	uint8_t tid = (uint8_t)(uintptr_t)arg1;
	bool start = arg2 != NULL;

	if (tid >= 8)
		return kIOReturnSuccess;
	if (start && ic->ic_bss != NULL) {
		const struct ieee80211_rx_ba *ba = &ic->ic_bss->ni_rx_ba[tid];

		mt7927_reorder_stop(&sc->sc_7927_reorder[tid],
		    mt7927_rxu_release, sc);
		mt7927_reorder_start(&sc->sc_7927_reorder[tid], ba->ba_winstart,
		    ba->ba_winsize);
	} else {
		mt7927_reorder_stop(&sc->sc_7927_reorder[tid],
		    mt7927_rxu_release, sc);
	}
	mt7927_hal_rx_done(sc);
	return kIOReturnSuccess;
}

static void
mt7927_hal_rx(void *arg, const uint8_t *p, uint32_t len)
{
	struct mwx_softc *sc = (struct mwx_softc *)arg;
	struct ifnet *ifp = &sc->sc_ic.ic_if;
	struct mbuf_list ml = MBUF_LIST_INITIALIZER();
	mbuf_t m = NULL;
	unsigned int chunks = 1;

	if (!(ifp->if_flags & IFF_RUNNING) || sc->sc_suspended)
		return;
	if (len >= 32 && (mt7927_le32(p + 8) & (1U << 7))) {	/* HDR_TRANS */
		mt7927_rx_8023(sc, p, len);
		if (sc->sc_7927_rxml_frames >= MT7927_RX_BATCH)
			mt7927_hal_rx_done(sc);
		return;
	}
	if (sc->sc_7927_amsdu_head != NULL)		/* order with the old path */
		mt7927_rx_amsdu_flush(sc);
	if (mbuf_allocpacket(MBUF_DONTWAIT, len, &chunks, &m) != 0) {
		ifp->if_ierrors++;
		return;
	}
	if (mbuf_maxlen(m) < len) {
		m_freem(m);
		ifp->if_ierrors++;
		return;
	}
	memcpy(mtod(m, uint8_t *), p, len);
	mbuf_setlen(m, len);
	mbuf_pkthdr_setlen(m, len);
	/*
	 * Up the stack in batches, like NAPI: if_input() hands each list to
	 * the interface and flushes its input queue once, so one call per
	 * frame meant one flush (a trip through the network stack) per frame.
	 */
	mwx_rx(sc, m, &sc->sc_7927_rxml);
	if (++sc->sc_7927_rxml_frames >= MT7927_RX_BATCH)
		mt7927_hal_rx_done(sc);
	(void)ml;
}

/* End of a pass over the RX rings (work loop thread): send the batch up. */
static void
mt7927_hal_rx_done(void *arg)
{
	struct mwx_softc *sc = (struct mwx_softc *)arg;
	struct ifnet *ifp = &sc->sc_ic.ic_if;

	sc->sc_7927_rxml_frames = 0;
	if (ml_empty(&sc->sc_7927_rxml))
		return;
	sc->sc_7927_rx_batches++;
	sc->sc_7927_rx_batched += ml_len(&sc->sc_7927_rxml);
	if (!(ifp->if_flags & IFF_RUNNING) || sc->sc_suspended) {
		ml_purge(&sc->sc_7927_rxml);
		return;
	}
	if_input(ifp, &sc->sc_7927_rxml);
}

/*
 * RX checksum offload (mt7925_mac_fill_rx with NETIF_F_RXCSUM): the chip
 * checked the IP and TCP/UDP checksums when RXD3 has both SUM bits and the
 * descriptor reports no checksum error. Not for an A-MSDU (one result for
 * several packets). The flags ride on the mbuf through net80211's decap.
 */
static void
mt7927_rx_csum(struct mwx_softc *sc, struct mbuf *m, bool ok)
{
	const struct ieee80211_frame *wh = mtod(m, struct ieee80211_frame *);

	if (!ok || mbuf_len(m) < sizeof(struct ieee80211_qosframe))
		return;
	if ((wh->i_fc[0] & (IEEE80211_FC0_TYPE_MASK |
	    IEEE80211_FC0_SUBTYPE_QOS)) == (IEEE80211_FC0_TYPE_DATA |
	    IEEE80211_FC0_SUBTYPE_QOS)) {
		uint32_t hl = (uint32_t)ieee80211_get_hdrlen(wh);

		if (hl < 2 || hl > mbuf_len(m) ||
		    (mtod(m, const uint8_t *)[hl - 2] & 0x80))	/* A-MSDU */
			return;
	} else if ((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) !=
	    IEEE80211_FC0_TYPE_DATA) {
		return;
	}
	mbuf_set_csum_performed(m, MBUF_CSUM_DID_IP | MBUF_CSUM_IP_GOOD |
	    MBUF_CSUM_DID_DATA | MBUF_CSUM_PSEUDO_HDR, 0xffff);
	sc->sc_7927_rx_csum++;
}

static int
mt7927_mac_fill_rx(struct mwx_softc *sc, struct mbuf *m,
    struct ieee80211_rxinfo *rxi)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct mt7927_rxi ri;
	bool csum_ok;
	int rv;

	rv = mt7927_rx_parse(mtod(m, const uint8_t *), (uint32_t)mbuf_len(m),
	    sc->sc_capa.antenna_mask ? sc->sc_capa.antenna_mask : 0x3, &ri);
	if (rv != 0) {
		sc->sc_7927_rx_drop[rv & 7]++;
		return -1;
	}
	csum_ok = !(mt7927_engine_rx_info(sc->sc_7927) & 0xd) &&
	    (mt7927_le32(mtod(m, const uint8_t *) + 12) & MT7927_RXD3_CSUM) ==
	    MT7927_RXD3_CSUM;
	if (ri.amsdu != 0 && !ri.hdr_trans &&
	    ri.frame_len >= sizeof(struct ieee80211_frame) + 2) {
		/*
		 * An A-MSDU subframe the chip split but did not translate:
		 * 2 pad bytes follow the 802.11 header (mt7925_mac_fill_rx
		 * pad_start). Move the header over them.
		 */
		uint8_t *wh0 = mtod(m, uint8_t *) + ri.hdr_off;
		uint32_t hl = (uint32_t)ieee80211_get_hdrlen(
		    (struct ieee80211_frame *)wh0);

		if (hl + 2 <= ri.frame_len) {
			memmove(wh0 + 2, wh0, hl);
			ri.hdr_off += 2;
			ri.frame_len -= 2;
		}
		sc->sc_7927_rx_untrans_amsdu++;
	}
	if (ri.band == 6) {
		/*
		 * 6 GHz: net80211's channel table has no 6 GHz entries yet
		 * (its numbers clash with 2.4/5 GHz), so the frame is dropped;
		 * log each network heard once, to see what the radio gets.
		 */
		const uint8_t *f = mtod(m, const uint8_t *) + ri.hdr_off;

		sc->sc_7927_rx_6g++;
		if (ri.frame_len >= 36 && (f[0] == 0x80 || f[0] == 0x50)) {
			uint32_t i, seen = 0;

			for (i = 0; i < sc->sc_7927_6g_n; i++)
				if (memcmp(sc->sc_7927_6g_bssid[i], f + 16, 6) == 0)
					seen = 1;
			if (!seen && sc->sc_7927_6g_n < nitems(sc->sc_7927_6g_bssid)) {
				const uint8_t *ie = f + 36, *end = f + ri.frame_len;
				char ssid[33] = "";

				memcpy(sc->sc_7927_6g_bssid[sc->sc_7927_6g_n++], f + 16, 6);
				while (ie + 2 <= end && ie + 2 + ie[1] <= end) {
					if (ie[0] == 0) {
						uint8_t l = ie[1] > 32 ? 32 : ie[1];

						memcpy(ssid, ie + 2, l);
						ssid[l] = 0;
						break;
					}
					ie += 2 + ie[1];
				}
				MWX_DEV_LOG(sc, "MT7927 6 GHz: %s \"%s\" %s ch %u rssi %d\n",
				    f[0] == 0x80 ? "beacon" : "probe response",
				    ssid[0] ? ssid : "(hidden)", ether_sprintf(f + 16),
				    ri.chan, ri.rssi);
			}
			/* phase 4e.2: to the front end, which shows it in macOS */
			if (ic->ic_event_handler != NULL && ic->ic_6ghz_channels) {
				struct ieee80211_beacon6g_event ev;
				const uint8_t *ie = f + 36, *end = f + ri.frame_len;

				memset(&ev, 0, sizeof(ev));
				ev.bssid = f + 16;
				ev.chan = ri.chan;
				ev.rssi = ri.rssi;
				ev.intval = (uint16_t)(f[32] | (f[33] << 8));
				ev.capinfo = (uint16_t)(f[34] | (f[35] << 8));
				ev.ies = ie;
				ev.length = (size_t)(end - ie);
				while (ie + 2 <= end && ie + 2 + ie[1] <= end) {
					if (ie[0] == 0 && ie[1] <= 32) {
						ev.ssid = ie + 2;
						ev.ssid_len = ie[1];
						break;
					}
					ie += 2 + ie[1];
				}
				ic->ic_event_handler(ic, IEEE80211_EVT_BEACON_6G, &ev);
			}
		}
		sc->sc_7927_rx_drop[0]++;
		return -1;
	}
	if (ri.chan == 0 || ri.chan > IEEE80211_CHAN_MAX ||
	    ic->ic_channels[ri.chan].ic_flags == 0) {
		sc->sc_7927_rx_drop[0]++;
		return -1;
	}
	rxi->rxi_chan = ri.chan;
	rxi->rxi_rssi = ri.rssi;
	if (ri.decrypted && ri.sec_mode == MT7927_CIPHER_AES_CCMP && ri.has_pn &&
	    ri.hdr_off >= IEEE80211_CCMP_HDRLEN) {
		/*
		 * The hardware strips the CCMP header and MIC. Put the header
		 * back (PN from RXD group 1, as mt76_insert_ccmp_hdr() does) so
		 * net80211 picks the right group key by its ID, checks the PN
		 * for replays and strips it again.
		 */
		uint8_t *wh0 = mtod(m, uint8_t *) + ri.hdr_off;
		uint32_t hl = (uint32_t)ieee80211_get_hdrlen(
		    (struct ieee80211_frame *)wh0);

		if (hl <= ri.frame_len) {
			uint8_t *nh = wh0 - IEEE80211_CCMP_HDRLEN, *iv;

			memmove(nh, wh0, hl);
			iv = nh + hl;
			iv[0] = ri.pn[0];
			iv[1] = ri.pn[1];
			iv[2] = 0;
			iv[3] = (uint8_t)(0x20 | (ri.key_id << 6));	/* ExtIV */
			iv[4] = ri.pn[2];
			iv[5] = ri.pn[3];
			iv[6] = ri.pn[4];
			iv[7] = ri.pn[5];
			m_adj(m, (int)(ri.hdr_off - IEEE80211_CCMP_HDRLEN));
			((struct ieee80211_frame *)nh)->i_fc[1] |=
			    IEEE80211_FC1_PROTECTED;
			rxi->rxi_flags |= IEEE80211_RXI_HWDEC;
			sc->sc_7927_rx_hwdec++;
			mt7927_rx_csum(sc, m, csum_ok);
			return 0;
		}
	}
	m_adj(m, (int)ri.hdr_off);
	if (ri.decrypted) {
		struct ieee80211_frame *wh = mtod(m, struct ieee80211_frame *);

		/* no PN to rebuild the header from: trust hardware replay checks */
		rxi->rxi_flags |= IEEE80211_RXI_HWDEC;
		wh->i_fc[1] &= ~IEEE80211_FC1_PROTECTED;
		sc->sc_7927_rx_hwdec_nopn++;
	}
	mt7927_rx_csum(sc, m, csum_ok);
	return 0;
}

/* End of a scan, on the command gate (no RX interrupt work meanwhile). */
static IOReturn
mt7927_end_scan_action(OSObject *, void *arg0, void *, void *, void *)
{
	struct mwx_softc *sc = (struct mwx_softc *)arg0;
	struct ieee80211com *ic = &sc->sc_ic;
	struct ieee80211_node *ni;
	/* Only the first scans: later listings evict the join/stall history. */
	bool list = sc->sc_scan_done_count <= 3;
	int n = 0;

	RB_FOREACH(ni, ieee80211_tree, &ic->ic_tree) {
		if (list && n < 32) {
			char ssid[IEEE80211_NWID_LEN + 1];
			int i, l = ni->ni_esslen;

			if (l > IEEE80211_NWID_LEN)
				l = IEEE80211_NWID_LEN;
			for (i = 0; i < l; i++)
				ssid[i] = (ni->ni_essid[i] >= 0x20 &&
				    ni->ni_essid[i] < 0x7f) ? ni->ni_essid[i] : '?';
			ssid[l] = '\0';
			MWX_DEV_LOG(sc, "MT7927   %-32s ch %3u rssi %3d %s%s\n",
			    l ? ssid : "(hidden)",
			    ieee80211_chan2ieee(ic, ni->ni_chan), ni->ni_rssi,
			    ether_sprintf(ni->ni_bssid),
			    (ni->ni_capinfo & IEEE80211_CAPINFO_PRIVACY) ?
			    " secured" : "");
		}
		n++;
	}
	sc->sc_scan_last_ieee80211_nodes = n;
	MWX_DEV_LOG(sc, "MT7927 scan #%u done: %d networks\n",
	    sc->sc_scan_done_count, n);
	mt7927_publish(sc->sc_tag, "MT7927ScanCount", sc->sc_scan_done_count);
	mt7927_publish(sc->sc_tag, "MT7927ScanNetworks", n);
	ieee80211_end_scan(&ic->ic_if);
	return kIOReturnSuccess;
}

static void
mt7927_hal_end_scan(struct mwx_softc *sc)
{
	IOCommandGate *gate = gMwxHal != NULL ? gMwxHal->mwxGate() :
	    NULL;

	if (gate != NULL)
		gate->runAction(mt7927_end_scan_action, sc);
	else
		mt7927_end_scan_action(NULL, sc, NULL, NULL, NULL);
}

/*
 * System sleep: leave the network and stop the chip (interrupt off, DMA off,
 * MCU halted). A desktop powers the card off in sleep anyway; on wake it is
 * started again from scratch with the firmware kept in memory.
 */
static void
mt7927_hal_suspend(struct mwx_softc *sc)
{
	struct ifnet *ifp = &sc->sc_ic.ic_if;

	if (ifp->if_flags & IFF_RUNNING)
		mwx_stop(ifp);
	mt7927_hal_detach(sc);		/* also ends MCU waits */
	mt7927_engine_stop(sc->sc_7927);
	sc->sc_fw_loaded = 0;
	MWX_DEV_LOG(sc, "MT7927 stopped for sleep\n");
	mtk_dbg_publish();
}

/*
 * System wake: start the chip again on the init thread (WFSYS reset,
 * firmware download, connac3 init), then preinit and, if the interface is
 * up, init on the command gate. macOS rejoins the network on its own.
 */
static void
mt7927_hal_resume(struct mwx_softc *sc)
{
	sc->sc_7927_wakes++;
	MWX_DEV_LOG(sc, "MT7927 wake #%u: restarting the chip\n",
	    sc->sc_7927_wakes);
	mt7927_hal_start(sc);
}

/*
 * The radio stopped hearing the AP: a firmware beacon-loss event (Linux:
 * mt7925_mcu_connection_loss_event()), or no receive airtime at all in a
 * 30 s MIB window while associated (on a working 5 GHz channel there is
 * always some). The AP deauthenticates us minutes later anyway; leave now,
 * as for a deauth from the AP, so macOS rejoins at once.
 */
static void
mt7927_link_watchdog(struct mwx_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	uint32_t loss, dumps, rxt, txt, windows;
	const char *why = NULL;

	if (!sc->sc_7927_assoc || ic->ic_state != IEEE80211_S_RUN ||
	    ic->ic_bss == NULL || !ic->ic_bss->ni_port_valid) {
		sc->sc_7927_run_polls = 0;
		return;
	}
	sc->sc_7927_run_polls++;
	mt7927_engine_link(sc->sc_7927, sc->sc_vif.band_idx, &loss, &dumps,
	    &rxt, &txt, &windows);
	if (sc->sc_7927_run_polls == 1) {
		/* baseline at association: count only what happens from now */
		sc->sc_7927_bcn_loss_seen = loss;
		sc->sc_7927_mib_seen = windows;
		return;
	}
	if (loss != sc->sc_7927_bcn_loss_seen) {
		/*
		 * Only noted: the firmware tracks beacons only with beacon
		 * filtering set up (BCNFT, power save), so mt7925 ignores this
		 * event without it. It came ~30 s after every join here while
		 * traffic flowed; leaving on it cost a needless rejoin.
		 */
		sc->sc_7927_bcn_loss_seen = loss;
		MWX_DEV_LOG(sc, "MT7927 link watchdog: firmware beacon loss "
		    "event (%u so far), not acted on; rx airtime %u us\n", loss,
		    rxt);
	}
	if (windows != sc->sc_7927_mib_seen) {
		sc->sc_7927_mib_seen = windows;
		/* a whole 30 s window inside this association, no RX airtime */
		if (sc->sc_7927_run_polls > 35 && rxt == 0)
			why = "no receive airtime for 30 s";
	}
	if (why == NULL)
		return;
	if (sc->sc_7927_last_recovery != 0 &&
	    sc->sc_7927_poll - sc->sc_7927_last_recovery < 60) {
		MWX_DEV_LOG(sc, "MT7927 link watchdog: %s (tx airtime %u us), "
		    "recovered %u s ago, waiting\n", why, txt,
		    sc->sc_7927_poll - sc->sc_7927_last_recovery);
		return;
	}
	sc->sc_7927_last_recovery = sc->sc_7927_poll;
	sc->sc_7927_recoveries++;
	MWX_DEV_LOG(sc, "MT7927 link watchdog: %s (tx airtime %u us, %u beacon "
	    "loss events, %u coredumps): leaving %s so it can be joined again "
	    "(recovery #%u)\n", why, txt, loss, dumps,
	    ether_sprintf(sc->sc_7927_bss.bssid), sc->sc_7927_recoveries);
	sc->sc_7927_run_polls = 0;
	/* ieee80211_recv_deauth() for a STA */
	ic->ic_deauth_reason = IEEE80211_REASON_ASSOC_EXPIRE;
	if (ic->ic_event_handler != NULL)
		(*ic->ic_event_handler)(ic, IEEE80211_EVT_STA_DEAUTH, NULL);
	ieee80211_new_state(ic, IEEE80211_S_AUTH, IEEE80211_FC0_SUBTYPE_DEAUTH);
}

/* Watchdog tick (1 s, command gate): scan timeout, periodic counters. */
static void
mt7927_hal_poll(struct mwx_softc *sc)
{
	uint32_t intr, isr, frames, other, events, timeouts;

	if (!sc->sc_fw_loaded || sc->sc_suspended ||
	    !mt7927_engine_running(sc->sc_7927))
		return;
	sc->sc_7927_poll++;
	if (sc->sc_flags & MWX_FLAG_SCANNING) {
		if (++sc->sc_7927_scan_ticks == MT7927_SCAN_TIMEOUT_SEC) {
			MWX_DEV_LOG(sc, "MT7927 scan: no completion after %d s, "
			    "ending it\n", MT7927_SCAN_TIMEOUT_SEC);
			sc->sc_flags &= ~MWX_FLAG_SCANNING;
			task_add(systq, &sc->sc_scan_task);
		}
	} else {
		sc->sc_7927_scan_ticks = 0;
	}
	mt7927_join_poll(sc);
	{
		struct ifnet *ifp = &sc->sc_ic.ic_if;

		if (ifq_is_oactive(&ifp->if_snd)) {
			ifq_clr_oactive(&ifp->if_snd);
			mwx_start(ifp);
		}
	}
	{
		uint32_t tok, ring;

		mt7927_engine_tick(sc->sc_7927);
		mt7927_engine_tx_depth(sc->sc_7927, &tok, &ring);
		if (tok > sc->sc_7927_depth_tok)
			sc->sc_7927_depth_tok = tok;
		if (ring > sc->sc_7927_depth_ring)
			sc->sc_7927_depth_ring = ring;
	}
	if (sc->sc_7927_poll % 30 == 1 ||
	    (sc->sc_7927_joined && sc->sc_7927_poll % 5 == 1)) {
		uint32_t q, d, fe, nt, rc, rf;

		mt7927_engine_tx_counters(sc->sc_7927, &q, &d, &fe, &nt, &rc, &rf);
		MWX_DEV_LOG(sc, "MT7927 tx: queued %u done %u free events %u "
		    "no token %u reclaimed %u ring full %u encfail %u, oerrors %u; "
		    "rx from bss: beacons %u mcast %u ucast %u, decrypt fail %u, "
		    "ierrors %u; chip keys 0x%x: rx decrypted %u (no PN %u), "
		    "tx hw %u sw %u, key failures %u\n",
		    q, d, fe, nt, rc, rf, sc->sc_7927_tx_encfail,
		    sc->sc_ic.ic_if.if_oerrors, sc->sc_7927_rx_bcn,
		    sc->sc_7927_rx_mcast, sc->sc_7927_rx_ucast,
		    (unsigned)sc->sc_ic.ic_stats.is_rx_wepfail,
		    sc->sc_ic.ic_if.if_ierrors, sc->sc_7927_hwkeys,
		    sc->sc_7927_rx_hwdec, sc->sc_7927_rx_hwdec_nopn,
		    sc->sc_7927_tx_hwenc, sc->sc_7927_tx_swenc,
		    sc->sc_7927_hwkey_fail);
	}
	if (sc->sc_7927_joined && sc->sc_7927_poll % 5 == 1) {
		uint32_t n, errs, t0, t1, rate;

		mt7927_engine_txs(sc->sc_7927, &n, &errs, &t0, &t1);
		rate = t0 & 0x3fff;			/* MT_TXS0_TX_RATE */
		MWX_DEV_LOG(sc, "MT7927 tx rate: %u samples (%u not acked), last "
		    "mode %u mcs %u nss %u bw %u%s, %d dBm; hw a-msdu %u (peer "
		    "max mpdu %u); last 5 s max: %u frames in the chip, %u "
		    "descriptors not fetched; held back %u, recoveries %u\n", n,
		    errs, (rate >> 6) & 0xf, rate & 0x3f,
		    ((rate >> 10) & 0xf) + 1, t0 >> 29,
		    (t0 & (7U << 16)) ? " not acked" : "", (int8_t)(t1 & 0xff),
		    sc->sc_7927_tx_amsdu, sc->sc_7927_bss.amsdu ?
		    sc->sc_7927_bss.amsdu - 1 : 0xff, sc->sc_7927_depth_tok,
		    sc->sc_7927_depth_ring, sc->sc_7927_tx_held,
		    sc->sc_7927_recoveries);
		sc->sc_7927_depth_tok = sc->sc_7927_depth_ring = 0;
		{
			uint32_t ev, ms, mx, re, fa, dev_, dms, dre;

			mt7927_engine_txfree_stats(sc->sc_7927, &ev, &ms, &mx,
			    &re, &fa);
			dev_ = ev - sc->sc_7927_tf_ev;
			dms = ms - sc->sc_7927_tf_ms;
			dre = re - sc->sc_7927_tf_re;
			MWX_DEV_LOG(sc, "MT7927 tx done: last 5 s %u frames in %u "
			    "free events (most in one %u), %u retries (%u.%02u "
			    "per frame); total failed %u\n", dms, dev_, mx, dre,
			    dms ? dre / dms : 0, dms ? (dre * 100 / dms) % 100 : 0,
			    fa);
			sc->sc_7927_tf_ev = ev;
			sc->sc_7927_tf_ms = ms;
			sc->sc_7927_tf_re = re;
		}
	}
	if (sc->sc_7927_poll % 30 == 1) {
		mt7927_engine_counters(sc->sc_7927, &intr, &isr, &frames, &other,
		    &events, &timeouts);
		MWX_DEV_LOG(sc, "MT7927 rx batches: %u, %u packets up the stack, "
		    "%u checksums checked by the chip\n", sc->sc_7927_rx_batches,
		    sc->sc_7927_rx_batched, sc->sc_7927_rx_csum);
		MWX_DEV_LOG(sc, "MT7927 rx 802.3 (chip-translated): %u frames, "
		    "%u dropped, %u replays, %u late/duplicate, %u without "
		    "group 4, %u untranslated A-MSDU subframes\n",
		    sc->sc_7927_rx8023, sc->sc_7927_rx8023_drop,
		    sc->sc_7927_rx_replay, sc->sc_7927_rx_late,
		    sc->sc_7927_rx_nog4, sc->sc_7927_rx_untrans_amsdu);
		MWX_DEV_LOG(sc, "MT7927 poll: intr %u isr %u rx frames %u "
		    "(net80211 %u, dropped ch %u short %u fcs %u icv %u trans %u) "
		    "other %u events %u timeouts %u scans %u state %d; 6 GHz "
		    "frames %u, networks %u; associated scans %u (refused %u)\n", intr,
		    isr, frames, sc->sc_rx_delivered, sc->sc_7927_rx_drop[0],
		    sc->sc_7927_rx_drop[MT7927_RX_SHORT],
		    sc->sc_7927_rx_drop[MT7927_RX_FCS_ERR],
		    sc->sc_7927_rx_drop[MT7927_RX_ICV_ERR],
		    sc->sc_7927_rx_drop[MT7927_RX_HDR_TRANS], other, events,
		    timeouts, sc->sc_scan_done_count, sc->sc_ic.ic_state,
		    sc->sc_7927_rx_6g, sc->sc_7927_6g_n, sc->sc_7927_bgscans,
		    sc->sc_7927_bgscan_busy);
		mt7927_publish(sc->sc_tag, "MT7927RxFrames", frames);
		mt7927_publish(sc->sc_tag, "MT7927MCUTimeouts", timeouts);
		mt7927_engine_log_diag(sc->sc_7927);
	}
	mt7927_link_watchdog(sc);
	if (sc->sc_7927_edca_dirty && sc->sc_7927_assoc) {
		struct mt7927_edca e[4];
		struct mt7927_vif v;

		sc->sc_7927_edca_dirty = false;
		mt7927_vif_fill(sc, &v);
		mt7927_edca_fill(sc, e);
		mt7927_set_edca(sc->sc_7927, &v, e);
	}
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
	case MWX_HW_MT7927:
		return ENODEV;	/* loaded by the MT7927 engine from disk */
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
	if (sc->sc_hwtype == MWX_HW_MT7927) {
		mt7927_hal_end_scan(sc);
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
 * Operating bandwidth and center channel negotiated with the AP: VHT160
 * (MT7927 only advertises it), VHT80, HT40 or 20 MHz. 80+80 is used as 80.
 */
static void
mwx_node_chan_width(struct ieee80211_node *ni, uint8_t *bw, uint8_t *center)
{
	*bw = CMD_CBW_20MHZ;
	*center = ieee80211_mhz2ieee(ni->ni_chan->ic_freq, ni->ni_chan->ic_flags);
	if (ni->ni_chan->ic_center_freq1 == 0)
		return;
	if ((ni->ni_flags & IEEE80211_NODE_VHT) &&
	    ni->ni_chw == IEEE80211_CHAN_WIDTH_160) {
		*bw = CMD_CBW_160MHZ;
		*center = ieee80211_mhz2ieee(ni->ni_chan->ic_center_freq1,
		    ni->ni_chan->ic_flags);
	} else if ((ni->ni_flags & IEEE80211_NODE_VHT) &&
	    (ni->ni_chw == IEEE80211_CHAN_WIDTH_80 ||
	    ni->ni_chw == IEEE80211_CHAN_WIDTH_80P80)) {
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
	if (vendor == PCI_VENDOR_MEDIATEK && product == 0x7927) {
		int on = 0;

		/* MT7927 work in progress: only on request. */
		matched = PE_parse_boot_argn("-mtk7927probe", &on, sizeof(on));
		MWX_LOG("MT7927 %s (-mtk7927probe %s)\n",
		    matched ? "matched" : "not matched",
		    matched ? "set" : "not set");
	}
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
    if (com->sc_hwtype == MWX_HW_MT7927)
        mt7927_hal_detach(com);		/* stops the init thread, keeps the engine */
    timeout_del(&com->sc_reset_to);
    if (com->sc_hwtype == MWX_HW_MT7927 && com->sc_7927_reorder_to != NULL)
        timeout_del(&com->sc_7927_reorder_to);
    /* Keep interrupts alive while in-flight MCU requests finish. */
    taskq_quiesce(com->sc_nswq);
    if (taskQueueOwned) taskq_quiesce(systq);
    if (ifp->if_flags & IFF_RUNNING) mwx_stop(ifp);
    timeout_free(&com->sc_reset_to);
    if (com->sc_hwtype == MWX_HW_MT7927 && com->sc_7927_reorder_to != NULL)
        timeout_free(&com->sc_7927_reorder_to);
    /* No interrupt callback may access buffers during their destruction. */
    if (com->sc_ih) {
        pci_intr_disestablish(pci->pa_pc, com->sc_ih);
        com->sc_ih = NULL;
    }
    if (com->sc_hwtype == MWX_HW_MT7927) {
        if (com->sc_7927 != NULL) {
            mt7927_engine_destroy(com->sc_7927);	/* IRQ, DMA, MCU, memory */
            com->sc_7927 = NULL;
        }
    } else if (com->sc_memh) {
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
    if (com->sc_hwtype != MWX_HW_MT7927) {
        mwx_txwi_free(com);
        mwx_dma_free(com);
    }
    if (com->sc_7927_lock != NULL) {
        IOLockFree(com->sc_7927_lock);
        com->sc_7927_lock = NULL;
    }
    if (com->sc_7927_fw_patch != NULL) {
        IOFree(com->sc_7927_fw_patch, com->sc_7927_fw_plen);
        com->sc_7927_fw_patch = NULL;
    }
    if (com->sc_7927_fw_ram != NULL) {
        IOFree(com->sc_7927_fw_ram, com->sc_7927_fw_rlen);
        com->sc_7927_fw_ram = NULL;
    }
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
	if (com->sc_hwtype == MWX_HW_MT7927)
		return "MT7927";
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
	if (com != NULL && com->sc_hwtype == MWX_HW_MT7927)
		return "WIFI_RAM_CODE_MT6639_2_1.bin";
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
	if (com != NULL && com->sc_hwtype == MWX_HW_MT7927 &&
	    com->sc_7927 != NULL) {
		/* the country the MT7927 firmware runs (mtk7927cc), not "00" */
		alpha2[0] = com->sc_7927->alpha2[0] ? com->sc_7927->alpha2[0] : '0';
		alpha2[1] = com->sc_7927->alpha2[1] ? com->sc_7927->alpha2[1] : '0';
		alpha2[2] = '\0';
	} else if (com != NULL) {
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

/*
 * MT7927: the rate of the last TX status sample (TXS0 TX_RATE and BW), as
 * mt7925_mac_add_txs_skb() decodes it: VHT at long GI, HE at 0.8 us (the GI
 * is not in the TXS). This is what the menu shows as Tx Rate and MCS.
 * Returns kbit/s, 0 when there is no sample or the mode is not HT/VHT/HE.
 */
static uint32_t
mt7927_txs_rate(struct mwx_softc *sc, int *mcs)
{
	/* 1 stream, 100 kbit/s, by bandwidth 20/40/80/160 */
	static const uint16_t vht[4][10] = {
		{ 65, 130, 195, 260, 390, 520, 585, 650, 780, 867 },
		{ 135, 270, 405, 540, 810, 1080, 1215, 1350, 1620, 1800 },
		{ 293, 585, 878, 1170, 1755, 2340, 2633, 2925, 3510, 3900 },
		{ 585, 1170, 1755, 2340, 3510, 4680, 5265, 5850, 7020, 7800 },
	};
	static const uint16_t he[4][12] = {
		{ 86, 172, 258, 344, 516, 688, 774, 860, 1032, 1147, 1290, 1434 },
		{ 172, 344, 516, 688, 1032, 1376, 1549, 1721, 2065, 2294, 2581, 2868 },
		{ 360, 721, 1081, 1441, 2162, 2882, 3243, 3603, 4324, 4804, 5404, 6005 },
		{ 721, 1441, 2162, 2882, 4324, 5765, 6485, 7206, 8647, 9608, 10809, 12010 },
	};
	uint32_t n, errs, t0, t1, rate, mode, idx, nss, bw;

	if (sc == NULL || sc->sc_7927 == NULL)
		return 0;
	mt7927_engine_txs(sc->sc_7927, &n, &errs, &t0, &t1);
	if (n == 0)
		return 0;
	rate = t0 & 0x3fff;				/* MT_TXS0_TX_RATE */
	mode = (rate >> 6) & 0xf;			/* MT_TX_RATE_MODE */
	idx = rate & 0x3f;				/* MT_TX_RATE_IDX */
	nss = ((rate >> 10) & 0xf) + 1;			/* MT_TX_RATE_NSS */
	bw = t0 >> 29;					/* MT_TXS0_BW */
	if (bw > 3 || nss > 4)
		return 0;
	switch (mode) {
	case 2: case 3:					/* HT, HT greenfield */
		if (idx > 31 || bw > 1)
			return 0;
		if (mcs != NULL)
			*mcs = (int)idx;
		return vht[bw][idx & 7] * 100U * ((idx >> 3) + 1);
	case 4:						/* VHT */
		idx &= 0xf;
		if (idx > 9)
			return 0;
		if (mcs != NULL)
			*mcs = (int)idx;
		return vht[bw][idx] * 100U * nss;
	case 8: case 9: case 10: case 11:		/* HE SU, EXT SU, TB, MU */
		idx &= 0xf;
		if (idx > 11)
			return 0;
		if (mcs != NULL)
			*mcs = (int)idx;
		return he[bw][idx] * 100U * nss;
	default:
		return 0;
	}
}

uint32_t
MtkMwx::getRxRateKbps()
{
	if (com != NULL && com->sc_hwtype == MWX_HW_MT7927)
		return mt7927_txs_rate(com, NULL);
	return mwx_rxr_last_kbps;
}

int
MtkMwx::getRxRateMcs()
{
	if (com != NULL && com->sc_hwtype == MWX_HW_MT7927) {
		int mcs = -1;

		return mt7927_txs_rate(com, &mcs) != 0 ? mcs : -1;
	}
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

	if (sc->sc_hwtype == MWX_HW_MT7927)
		return ENOTSUP;
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

	if (sc->sc_hwtype == MWX_HW_MT7927)
		return;
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

	if (sc->sc_hwtype == MWX_HW_MT7927)
		return ENOTSUP;
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
	if (sc->sc_hwtype == MWX_HW_MT7927) {
		mt7927_hal_suspend(sc);
		sc->sc_suspended = 1;
		return;
	}
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
	if (sc->sc_hwtype == MWX_HW_MT7927) {
		sc->sc_suspended = 0;
		mt7927_hal_resume(sc);
		return;
	}
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

	if (sc != NULL && sc->sc_hwtype == MWX_HW_MT7927) {
		mt7927_hal_poll(sc);
		return;
	}
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

#ifndef MT7927_HOST_TEST
/*
 * ---------------------------------------------------------------------------
 * MT7927 OS helpers for the engine and glue above, shared by both kexts
 * (SimpleMtkWlan and AirportMtkWlan). The chip runs as a third hardware type
 * of this driver behind -mtk7927probe. The firmware is read
 * from disk at runtime by a kernel thread once the Data volume is mounted,
 * never compiled into the kext:
 *   /Library/Firmware/mediatek/mt7927/WIFI_MT6639_PATCH_MCU_2_1_hdr.bin
 *   /Library/Firmware/mediatek/mt7927/WIFI_RAM_CODE_MT6639_2_1.bin
 * ---------------------------------------------------------------------------
 */
#include <sys/vnode.h>
#include <sys/uio.h>
#include <sys/fcntl.h>
#include <kern/thread.h>

#define MT7927_FW_MAX_SIZE	(4 * 1024 * 1024)

int
mt7927_read_file(const char *path, uint8_t **out, size_t *outLen)
{
    vfs_context_t ctx = vfs_context_create(NULL);
    vnode_t vp = NULLVP;
    struct vnode_attr va;
    uio_t uio = NULL;
    uint8_t *buf = NULL;
    size_t size = 0;
    int err;

    if (ctx == NULL)
        return ENOMEM;
    err = vnode_open(path, FREAD, 0, 0, &vp, ctx);
    if (err != 0) {
        vfs_context_rele(ctx);
        return err;
    }
    VATTR_INIT(&va);
    VATTR_WANTED(&va, va_data_size);
    err = vnode_getattr(vp, &va, ctx);
    if (err == 0 && !VATTR_IS_SUPPORTED(&va, va_data_size))
        err = ENOTSUP;
    if (err == 0) {
        if (va.va_data_size <= 0 || va.va_data_size > MT7927_FW_MAX_SIZE)
            err = EFBIG;
        else
            size = (size_t)va.va_data_size;
    }
    if (err == 0 && (buf = (uint8_t *)IOMalloc(size)) == NULL)
        err = ENOMEM;
    if (err == 0) {
        uio = uio_create(1, 0, UIO_SYSSPACE, UIO_READ);
        if (uio == NULL)
            err = ENOMEM;
        else
            err = uio_addiov(uio, CAST_USER_ADDR_T(buf), size);
    }
    if (err == 0)
        err = VNOP_READ(vp, uio, 0, ctx);
    if (err == 0 && uio_resid(uio) != 0)
        err = EIO;
    if (uio != NULL)
        uio_free(uio);
    vnode_close(vp, FREAD, ctx);
    vfs_context_rele(ctx);
    if (err != 0) {
        if (buf != NULL)
            IOFree(buf, size);
        return err;
    }
    *out = buf;
    *outLen = size;
    return 0;
}

bool
mt7927_start_thread(void (*fn)(void *, wait_result_t), void *arg)
{
    thread_t thread;

    if (kernel_thread_start(fn, arg, &thread) != KERN_SUCCESS)
        return false;
    thread_deallocate(thread);
    return true;
}

void
mt7927_thread_exit(void)
{
    thread_terminate(current_thread());
}
#endif /* MT7927_HOST_TEST */
