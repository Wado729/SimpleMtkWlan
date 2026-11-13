/*
 * MT7927 (connac3) types shared by the MT7927 engine and the mwx glue in
 * MtkMwx.cpp, and by tests/mt7927-probe.
 */
#ifndef MT7927_TYPES_H
#define MT7927_TYPES_H

#include <stdint.h>

/* MT7927 phase 4b: what BSS_INFO / STA_REC need about the AP joined. */
struct mt7927_bss {
	uint8_t		bssid[6];
	uint8_t		chan;		/* control channel */
	uint8_t		band;		/* 1: 2.4 GHz, 2: 5 GHz */
	uint16_t	bcn_int;
	uint8_t		dtim;
	uint8_t		qos;
	uint16_t	aid;
	uint16_t	peer_wcid;
	uint8_t		phymode;	/* PHY_MODE_* (BSS_INFO basic) */
	uint8_t		phy_type;	/* PHY_TYPE_BIT_* (STA_REC phy) */
	uint16_t	basic_rates;	/* mac80211 basic_rates bitmap */
	uint16_t	ra_legacy;	/* STA_REC ra: RA_LEGACY_OFDM | CCK */
	uint8_t		ht_mcs[10];
	/* phase 4c: 11n/ac (zero when the peer has none) */
	uint16_t	ht_cap;		/* HT capability info, ANDed with ours */
	uint32_t	vht_cap;	/* VHT capability info, ANDed with ours */
	uint16_t	vht_rx_mcs;	/* MCS map the peer receives (our TX) */
	uint16_t	vht_tx_mcs;	/* MCS map the peer sends (our RX) */
	uint8_t		ampdu;		/* A-MPDU factor | density << 2 */
	uint8_t		max_ampdu_len;	/* A-MPDU length exponent */
	uint8_t		vht_opmode;	/* bandwidth | rx_nss << 4 */
	uint8_t		bw;		/* CMD_CBW_*: 0 20, 1 40, 2 80 MHz */
	uint8_t		center_chan;	/* center of the operating channel */
	uint8_t		cipher;		/* CONNAC3_CIPHER_* in hardware, 0 none */
};

/* MT7927 phase 4b: per-frame TXD inputs. */
struct mt7927_txinfo {
	uint16_t	wcid;
	uint8_t		omac_idx;
	uint8_t		band_idx;
	uint8_t		q_idx;		/* LMAC queue: AC 0-3, ALTX0 0x10 */
	uint8_t		tid;
	uint8_t		hdrlen;
	uint8_t		rate_idx;	/* basic rate table entry if fixed */
	bool		fixed_rate;
	bool		multicast;
	bool		protect;	/* hardware encrypts (key in WTBL) */
};

#endif /* MT7927_TYPES_H */
