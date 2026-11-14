#!/usr/bin/env python3
"""
Host test for the MT7927 bring-up (phase 1 + 2). Slices the real MT7927
block out of MtkMwx.cpp (compiled with MT7927_HOST_TEST, which leaves out the
IOKit-only DMA/interrupt plumbing) and runs it against a simulated chip:
own handshake, L1 remap, CBINFRA reset, WFDMA rings that consume TX
descriptors and post MCU events, an MSI-style interrupt, and a firmware that
answers the connac2 download commands and the NIC capability query.
Usage: test-probe.py [sanitizers]   (default address,undefined)
"""
from pathlib import Path
import subprocess, sys
b = Path(__file__).resolve().parents[2]
out = Path(__file__).resolve().parent
src = (b / 'SimpleMtkWlan/hal_mwx/MtkMwx.cpp').read_text(encoding='utf-8')
start = src.index('#define\tMT7927_BAR_MIN_SIZE')
end = src.index('/*\n * To be honest this is ridiculous.')
block = src[start:end]
regs = (b / 'SimpleMtkWlan/hal_mwx/if_mwxreg.h').resolve()
types = (b / 'SimpleMtkWlan/hal_mwx/mt7927_types.h').resolve()

pre = r'''
#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>
#define MT7927_HOST_TEST 1
#define __packed __attribute__((packed))
#define __aligned(x) __attribute__((aligned(x)))
#define nitems(a) (sizeof(a) / sizeof((a)[0]))
#define htole32(x) (x)
#define le32toh(x) (x)
#define htole16(x) (x)
#define le16toh(x) (x)
#undef be32toh
#define be32toh(x) __builtin_bswap32(x)
#define IEEE80211_ADDR_LEN 6
#define IEEE80211_NWID_LEN 32
#define OSSynchronizeIO() do {} while (0)
typedef unsigned char UInt8; typedef int32_t SInt32;
#include "''' + str(regs) + r'''"
#include "''' + str(types) + r'''"
std::string logbuf;
#define MWX_DEV_LOG(sc, fmt, ...) do { char _b[600]; snprintf(_b, sizeof(_b), fmt, ##__VA_ARGS__); logbuf += _b; } while (0)
static void OSBitOrAtomic(uint32_t v, volatile uint32_t *p) { *p |= v; }
static void OSIncrementAtomic(volatile SInt32 *p) { (*p)++; }
#define OSDynamicCast(T, p) (dynamic_cast<T *>(p))
struct IORegistryPlane {}; IORegistryPlane *gIOServicePlane;
struct IORegistryEntry { IORegistryEntry *parent = nullptr; virtual ~IORegistryEntry() {}
  IORegistryEntry *getParentEntry(IORegistryPlane *) { return parent; } };
enum { kIOPCICapabilityIDPCIExpress = 0x10, kIOPCIConfigVendorID = 0, kIOPCIConfigDeviceID = 2 };
struct IOPCIDevice : IORegistryEntry {
  std::map<int,uint16_t> cfg; std::map<std::string,unsigned long long> props; std::map<std::string,std::string> sprops;
  uint16_t vid, did; bool busmaster = true;
  IOPCIDevice(uint16_t v, uint16_t d, uint16_t l) : vid(v), did(d) { cfg[0x90] = l; }
  bool findPCICapability(int, UInt8 *cap) { *cap = 0x80; return true; }
  uint16_t configRead16(int o) { return o == 0 ? vid : o == 2 ? did : cfg[o]; }
  void configWrite16(int o, uint16_t v) { cfg[o] = v; }
  void setProperty(const char *k, unsigned long long v, unsigned) { props[k] = v; }
  void setProperty(const char *k, const char *v) { sprops[k] = v; }
  void setBusMasterEnable(bool e) { busmaster = e; }
};
struct mwx_softc { struct { char dv_xname[16]; } sc_dev; int sc_st; char *sc_memh; size_t sc_mems; };
typedef char *bus_space_handle_t;
int flr_calls; int mwx_pci_flr(mwx_softc *, IOPCIDevice *) { flr_calls++; return 0; }

/* ---------------- simulated chip ---------------- */
uint64_t now_us;
struct Chip {
  std::map<uint32_t,uint32_t> bar, phys;
  bool fw_owned = true, own_ok = true, rgu_set = false, rgu_pulsed = false, mcu_own = false;
  uint64_t mcu_own_at = 0;
  /* firmware model */
  int sem_state = 0; bool patch_done = false, n9_ready = false, pwr_on = false;
  uint32_t dl_addr = 0, dl_len = 0, dl_got = 0; std::vector<std::pair<uint32_t, std::vector<uint8_t>>> regions;
  std::vector<std::string> cmds; bool mute = false; int mute_cmd = -1, mute_uni = -1;
  std::vector<std::string> chip_cfg; std::vector<uint8_t> domain; int fw_log = -1, dbdc = -1; uint32_t rts = 0;
  /* phase 4 */
  std::vector<std::string> uni_order; int dev_active = -1, bss_active = -1; uint8_t dev_addr[6] = {0}, dev_band = 0xff;
  uint32_t bss_conn = 0; uint16_t bss_wcid = 0; uint8_t bss_idx = 0xff; uint32_t rxfilter = 0xdeadbeef; int rxfilter_mode = -1;
  std::vector<std::pair<uint8_t,uint8_t>> scan_ch; int scan_type = -1, scan_cancel = 0; uint8_t scan_seq = 0, scan_hdr_bss = 0xff;
  int scan_beacons = 0; bool scan_done_event = true; int beacon_ring = 4;
  std::vector<std::pair<uint8_t,uint8_t>> txpwr; int txpwr_last = 0;
  uint32_t fw_start_option = 0xffff, fw_start_addr = 0xffff;
  /* phase 4b */
  std::vector<uint16_t> bss_tags; uint16_t bss_ntlv = 0; uint8_t bss_bssid[6] = {0}; int bss_conn_state = -1;
  uint8_t bss_phymode = 0, bss_rate_idx = 0, bss_rlm_ch = 0, bss_rlm_band = 0, bss_band = 0xff; uint16_t bss_basic_rate = 0;
  uint8_t bss_rlm_center = 0, bss_rlm_bw = 0xff, bss_rlm_sco = 0xff, bss_rlm_htop = 0xff;
  uint8_t bss_sec_mode = 0xff, bss_sec_status = 0xff, bss_sec_cipher = 0xff;
  uint8_t ps_bss = 0xff, ps_state = 0xff; int ps_n = 0;
  uint8_t scan_probes = 0; std::vector<std::pair<int, int>> scan_ies;
  uint8_t edca_bss = 0xff, edca[4][3] = {{0}}; uint16_t edca_txop[4] = {0}; int edca_n = 0;
  struct StaRec { uint16_t wcid; uint8_t muar; uint16_t ntlv; std::vector<uint16_t> tags; uint32_t conn_type; int conn_state;
                  uint16_t aid; uint8_t peer[6]; uint16_t extra; int state; uint16_t ra_legacy, basic_rate; uint8_t phy_type;
                  uint8_t ampdu, max_ampdu_len, vht_opmode; uint16_t ht_cap; uint32_t vht_cap; uint16_t vht_rx, vht_tx; uint8_t ht_mcs0;
                  int ba_tid = -1, ba_type = -1, ba_en = -1, ba_amsdu = -1; uint16_t ba_ssn = 0, ba_win = 0; int dis_hdr_trans = -1;
                  int key_add = -1, key_tx = -1, key_type = -1; uint8_t key_peer[6] = {0}, key_bss = 0, key_cipher = 0,
                  key_id = 0, key_len = 0, key_wlan = 0, key_mgmt = 0, key[32] = {0};
                  int amsdu_num = -1, amsdu_size = -1, amsdu_en = -1; };
  std::vector<StaRec> sta_recs;
  int roc_acquired = 0, roc_aborted = 0; uint8_t roc_ch = 0, roc_band = 0, roc_token = 0, roc_type = 0xff; uint32_t roc_maxint = 0;
  bool roc_grant = true;
  struct TxFrame { uint32_t txd[8]; uint16_t msdu, msdu1; uint32_t pa; uint16_t len; std::vector<uint8_t> frame; };
  std::vector<TxFrame> txf; bool tx_free_auto = true;
  size_t accesses = 0; int wfsys_resets = 0; bool dma_ever_enabled = false;
} chip;
static uint32_t l1() { return chip.bar[MT7925_HIF_REMAP_L1]; }
/* DMA memory registry: fake 32-bit bus addresses -> host buffers */
struct Mem { uint32_t pa; uint8_t *va; size_t size; };
std::vector<Mem> mems; uint32_t next_pa = 0x10000000; int live_allocs = 0;
static uint8_t *pa2va(uint32_t pa, size_t n) {
  for (auto &m : mems) if (pa >= m.pa && pa + n <= m.pa + m.size) return m.va + (pa - m.pa);
  fprintf(stderr, "bad DMA address 0x%08x len %zu\n", pa, n); abort();
}
struct mt7927_bringup; static void chip_tx_kick(int ring);
bool irq_registered = false, irq_ever_registered = false; struct mt7927_bringup *irq_arg;
static int mt7927_intr(void *arg);
static uint32_t rd(uint32_t off) {
  chip.accesses++;
  if (off == 0x0e0010) return chip.fw_owned ? PCIE_LPCR_HOST_OWN_SYNC : 0;           /* LPCTL */
  if (off == 0x0e00f0) return (chip.n9_ready ? 3 : 0) | (chip.pwr_on && !chip.n9_ready ? 1 : 0); /* CONN_ON_MISC */
  if (off == MT7927_ROMCODE_INDEX) {
    if (!chip.mcu_own) return 0xdead1234;
    return (now_us - chip.mcu_own_at) < 2000 ? 0x0001 : MT7927_MCU_IDLE_VALUE; }
  if (off >= MT7925_HIF_REMAP_BASE_L1 && off < MT7925_HIF_REMAP_BASE_L1 + 0x10000)
    return chip.phys[(l1() & 0xffff0000) | (off - MT7925_HIF_REMAP_BASE_L1)];
  if (off == MT_WFDMA0_GLO_CFG) return chip.bar[off] & ~(MT_WFDMA0_GLO_CFG_TX_DMA_BUSY | MT_WFDMA0_GLO_CFG_RX_DMA_BUSY);
  return chip.bar[off];
}
static void raise(uint32_t bits) { chip.bar[MT_WFDMA0_HOST_INT_STA] |= bits; }
static void wr(uint32_t off, uint32_t v) {
  chip.accesses++;
  if (off == 0x0e0010) { if (chip.own_ok) { if (v & PCIE_LPCR_HOST_SET_OWN) chip.fw_owned = true;
                                            if (v & PCIE_LPCR_HOST_CLR_OWN) chip.fw_owned = false; } return; }
  if (off >= MT7925_HIF_REMAP_BASE_L1 && off < MT7925_HIF_REMAP_BASE_L1 + 0x10000) {
    chip.phys[(l1() & 0xffff0000) | (off - MT7925_HIF_REMAP_BASE_L1)] = v; return; }
  if (off == MT7927_CBINFRA_RGU_WF_RST) { if (v & MT7927_CBINFRA_RGU_WF_RST_WF_SUBSYS) chip.rgu_set = true;
    else if (chip.rgu_set) { chip.rgu_pulsed = true; chip.rgu_set = false; } }
  if (off == MT7927_CBINFRA_MCU_OWN_SET && v == 1) { assert(chip.rgu_pulsed); chip.rgu_pulsed = false;
    chip.mcu_own = true; chip.mcu_own_at = now_us; chip.wfsys_resets++;
    chip.n9_ready = false; chip.pwr_on = false; chip.sem_state = 0; chip.patch_done = false; }
  if (off == MT_WFDMA0_HOST_INT_STA) { chip.bar[off] &= ~v; return; }                  /* W1C */
  if (off == MT_MCU_CMD) { chip.bar[off] &= ~v; return; }
  chip.bar[off] = v;
  if (off == MT_WFDMA0_GLO_CFG && (v & MT_WFDMA0_GLO_CFG_TX_DMA_EN)) chip.dma_ever_enabled = true;
  if (off == MT_WFDMA0_RST_DTX_PTR) for (int r : {0, 15, 16}) { chip.bar[MT7927_RING_REG(MT7927_TX_RING_BASE, r) + 8] = 0;
                                                               chip.bar[MT7927_RING_REG(MT7927_TX_RING_BASE, r) + 12] = 0; }
  for (int r : {0, 15, 16}) if (off == MT7927_RING_REG(MT7927_TX_RING_BASE, r) + MT_DMA_CPU_IDX) chip_tx_kick(r);
}
uint32_t bus_space_read_4(int, char *, uint32_t off) { return rd(off); }
void bus_space_write_4(int, char *, uint32_t off, uint32_t v) { wr(off, v); }
static void IODelay(unsigned us) { now_us += us; }
static void IOSleep(unsigned ms) { now_us += ms * 1000ull; }
'''

post = r'''
static int mt7927_dmamem_alloc(struct mt7927_dmamem *m, size_t size, bool) {
  memset(m, 0, sizeof(*m)); m->va = calloc(1, size); m->pa = next_pa; next_pa += (size + 0xfff) & ~0xfffu;
  m->size = size; m->handle = m->va; mems.push_back({m->pa, (uint8_t *)m->va, size}); live_allocs++; return 0; }
static void mt7927_dmamem_free(struct mt7927_dmamem *m) {
  if (m->handle) { for (size_t i = 0; i < mems.size(); i++) if (mems[i].va == m->va) { mems.erase(mems.begin() + i); break; }
    free(m->va); live_allocs--; } memset(m, 0, sizeof(*m)); }
static void mt7927_signal(struct mt7927_bringup *) {}
/* locks: single-threaded here; check pairing and that the service lock never nests */
int svc_depth = 0, svc_max = 0, op_depth = 0, op_taken = 0;
static void mt7927_svc_lock(struct mt7927_bringup *) { assert(svc_depth == 0 && "svc lock nested"); svc_depth++; svc_max = svc_max > svc_depth ? svc_max : svc_depth; }
/* An interrupt raised while the lock is held runs once it is released (the
 * work loop blocks on the IOLock on hardware). */
static bool irq_deferred = false; static void deliver_irq();
static void mt7927_svc_unlock(struct mt7927_bringup *) { assert(svc_depth == 1); svc_depth--;
  if (irq_deferred) { irq_deferred = false; deliver_irq(); } }
static void mt7927_op_lock(struct mt7927_bringup *) { op_depth++; op_taken++; }
static void mt7927_op_unlock(struct mt7927_bringup *) { assert(op_depth > 0); op_depth--; }
/* ---- simulated MSI: deliver when STA & ENA and a handler is registered ---- */
static void deliver_irq() {
  if (svc_depth > 0) { irq_deferred = true; return; }
  if (irq_registered && (chip.bar[MT_WFDMA0_HOST_INT_STA] & chip.bar[MT_WFDMA0_HOST_INT_ENA]))
    mt7927_intr(irq_arg);
}
static void mt7927_wait(struct mt7927_bringup *b, int ms) { now_us += ms * 1000ull; deliver_irq(); }
static int mt7927_irq_setup(struct mt7927_bringup *b) {
  wr(MT_WFDMA0_HOST_INT_ENA, 0); wr(MT_PCIE_MAC_INT_ENABLE, 0xff);
  irq_registered = irq_ever_registered = true; irq_arg = b; b->ih_cookie = (void *)1; return 0; }
static void mt7927_irq_teardown(struct mt7927_bringup *b) { if (b->ih_cookie) { irq_registered = false; b->ih_cookie = nullptr; } }

/* ---- the firmware model: post an MCU event into RX ring 6 ---- */
static void post_event(uint8_t seq, uint8_t eid, uint8_t ext_eid, const std::vector<uint8_t> &payload, uint8_t opt = 0) {
  uint32_t base = MT7927_RING_REG(MT7927_RX_RING_BASE, 6);
  uint32_t n = chip.bar[base + 4], cpu = chip.bar[base + 8], dma = chip.bar[base + 12];
  assert(n && dma != cpu && "RX ring 6 has no free buffer");
  struct mwx_desc *d = (struct mwx_desc *)pa2va(chip.bar[base] + dma * 16, 16);
  assert(!(d->ctrl & MT_DMA_CTL_DMA_DONE) && "posting into a slot the driver has not re-armed");
  uint32_t len = 44 + payload.size(), cap = (d->ctrl >> 16) & 0x3fff;
  assert(len <= cap);
  uint8_t *p = pa2va(d->buf0, len); memset(p, 0, 44);
  uint32_t rxd0 = (7u << 27) | len; memcpy(p, &rxd0, 4);
  uint16_t l = len - 32; memcpy(p + 32, &l, 2); p[32 + 4] = eid; p[32 + 5] = seq; p[32 + 6] = opt; p[32 + 8] = ext_eid;
  if (!payload.empty()) memcpy(p + 44, payload.data(), payload.size());
  d->ctrl = MT_DMA_CTL_DMA_DONE | MT_DMA_CTL_LAST_SEC0 | (len << 16);
  chip.bar[base + 12] = (dma + 1) % n;
  raise(MT7927_INT_RX_DONE_WM);
}
/* TXRX_NOTIFY (connac3 tx free, version 5): pair(wcid), header, msdu ids */
static void post_txfree(uint16_t wcid, uint16_t msdu) {
  uint32_t base = MT7927_RING_REG(MT7927_RX_RING_BASE, 6);
  uint32_t n = chip.bar[base + 4], cpu = chip.bar[base + 8], dma = chip.bar[base + 12];
  assert(n && dma != cpu && "RX ring 6 has no free buffer");
  struct mwx_desc *d = (struct mwx_desc *)pa2va(chip.bar[base] + dma * 16, 16);
  uint32_t w[5] = { (6u << 27) | (1u << 16) | 20u, 5u << 16, (1u << 31) | ((uint32_t)wcid << 12),
                    (1u << 30) | (1u << 24), (uint32_t)msdu | (0x7fffu << 15) };
  uint8_t *p = pa2va(d->buf0, 20); memcpy(p, w, 20);
  d->ctrl = MT_DMA_CTL_DMA_DONE | MT_DMA_CTL_LAST_SEC0 | (20u << 16);
  chip.bar[base + 12] = (dma + 1) % n;
  raise(MT7927_INT_RX_DONE_WM);
}
/* TXS (packet type 0) on RX ring 6: RXD dwords 0-1, then one 8-dword status entry */
static void post_txs(uint32_t txs0, uint32_t pid) {
  uint32_t base = MT7927_RING_REG(MT7927_RX_RING_BASE, 6);
  uint32_t n = chip.bar[base + 4], cpu = chip.bar[base + 8], dma = chip.bar[base + 12];
  assert(n && dma != cpu && "RX ring 6 has no free buffer");
  struct mwx_desc *d = (struct mwx_desc *)pa2va(chip.bar[base] + dma * 16, 16);
  /* PCI layout (mt7925_rx_check): 4 dword header, then 12 dword records */
  uint32_t w[16] = { (0u << 27) | 64u, 0, 0, 0, txs0, 0x000000f6u /* -10 dBm */, 1u << 16, pid << 24, 0, 0, 0, 0, 0, 0, 0, 0 };
  uint8_t *p = pa2va(d->buf0, 64); memcpy(p, w, 64);
  d->ctrl = MT_DMA_CTL_DMA_DONE | MT_DMA_CTL_LAST_SEC0 | (64u << 16);
  chip.bar[base + 12] = (dma + 1) % n;
  raise(MT7927_INT_RX_DONE_WM);
}
/* a beacon on RX ring 4: connac3 RXD (group 3 with RCPI) + 802.11 frame */
static void post_beacon(uint8_t chan, int k) {
  int ring = chip.beacon_ring;  /* hardware: frames come on the MCU ring 6 tagged type 7 / flag 1 */
  uint32_t base = MT7927_RING_REG(MT7927_RX_RING_BASE, ring);
  uint32_t n = chip.bar[base + 4], cpu = chip.bar[base + 8], dma = chip.bar[base + 12];
  assert(n && dma != cpu && "RX ring 4 has no free buffer");
  struct mwx_desc *d = (struct mwx_desc *)pa2va(chip.bar[base] + dma * 16, 16);
  std::vector<uint8_t> f(32 + 16, 0);
  uint32_t rxd1 = 1u << 18, rxd3 = (uint32_t)chan << 8;
  memcpy(&f[4], &rxd1, 4); memcpy(&f[12], &rxd3, 4);
  uint32_t v3 = 0x009a8c00u | (k ? 0x96 : 0x80); memcpy(&f[32 + 12], &v3, 4);   /* rcpi0, rcpi1 = 0x8c(-40), rcpi2 */
  const uint8_t hdr[24] = {0x80, 0, 0, 0, 0xff,0xff,0xff,0xff,0xff,0xff, 0x02,0x11,0x22,0x33,0x44,(uint8_t)(0x50 + k),
                           0x02,0x11,0x22,0x33,0x44,(uint8_t)(0x50 + k), 0, 0};
  f.insert(f.end(), hdr, hdr + 24);
  uint8_t fixed[12] = {0}; fixed[8] = 100; fixed[10] = 0x11; f.insert(f.end(), fixed, fixed + 12);
  const char *ssid = k ? "Neighbour" : "HomeNet"; f.push_back(0); f.push_back(strlen(ssid)); f.insert(f.end(), ssid, ssid + strlen(ssid));
  uint32_t len = f.size(), rxd0 = (ring == 6 ? (7u << 27) | (1u << 16) : (2u << 27)) | len; memcpy(&f[0], &rxd0, 4);
  uint32_t cap = (d->ctrl >> 16) & 0x3fff; assert(len <= cap && !(d->ctrl & MT_DMA_CTL_DMA_DONE));
  memcpy(pa2va(d->buf0, len), f.data(), len);
  d->ctrl = MT_DMA_CTL_DMA_DONE | MT_DMA_CTL_LAST_SEC0 | (len << 16);
  chip.bar[base + 12] = (dma + 1) % n;
  raise(ring == 6 ? MT7927_INT_RX_DONE_WM : MT7927_INT_RX_DONE_DATA);
}
static void handle_cmd(const uint8_t *buf, uint32_t len) {
  uint32_t txd0, txd1; memcpy(&txd0, buf, 4); memcpy(&txd1, buf + 4, 4);
  assert((txd0 & 0xffff) == len);                       /* TX_BYTES */
  assert(((txd0 >> 23) & 3) == 2);                      /* PKT_FMT = CMD */
  assert((txd0 >> 25) == MT_TX_MCU_PORT_RX_Q0);         /* Q_IDX */
  assert(txd1 == MT7925_HDR_FORMAT_CMD && "connac3 TXD1: HDR_FORMAT_CMD at bit 14, no LONG_FORMAT");
  const struct mwx_mcu_txd *m = (const struct mwx_mcu_txd *)buf;
  assert(m->pkt_type == MCU_PKT_ID && m->seq != 0 && m->seq < 16);
  char e[64]; bool uni = false; uint16_t ucid = 0; uint8_t opt = 0;
  if (len >= sizeof(struct mwx_uni_txd)) { const struct mwx_uni_txd *u = (const struct mwx_uni_txd *)buf;
    if (u->option & MCU_CMD_UNI) { uni = true; ucid = u->cid; opt = u->option; } }
  const uint8_t *pl = buf + (uni ? sizeof(struct mwx_uni_txd) : sizeof(struct mwx_mcu_txd));
  uint32_t plen = len - (uni ? sizeof(struct mwx_uni_txd) : sizeof(struct mwx_mcu_txd));
  if (uni && ucid != 0x0e) {
    snprintf(e, sizeof e, "uni%02x%s", ucid, opt == MCU_CMD_UNI_QUERY_ACK ? "q" : ""); chip.cmds.push_back(e);
    assert(((const struct mwx_uni_txd *)buf)->len == len - 32 && ((const struct mwx_uni_txd *)buf)->s2d_index == CMD_S2D_IDX_H2N);
    uint16_t tag, tl; memcpy(&tag, pl + 4, 2); memcpy(&tl, pl + 6, 2);
    bool query = opt == MCU_CMD_UNI_QUERY_ACK;
    assert((query || opt == MCU_CMD_UNI_EXT_ACK) && "UNI set: EXT_ACK, query: QUERY_ACK");
    if (chip.mute || ucid == chip.mute_uni) return;
    std::vector<uint8_t> r;
    switch (ucid) {
    case 0x2d:                                            /* EFUSE_CTRL */
      if (query) { assert(tag == 1 && tl == 28 && plen == 32); uint32_t a; memcpy(&a, pl + 8, 4); assert(a % 16 == 0);
        r.assign(80, 0); r[4] = 1; uint8_t *d = r.data() + 48;
        if (a == 0) { d[0] = 0x39; d[1] = 0x66; d[2] = 2; d[4] = 0x40; d[5] = 0xed; d[6] = 0; d[7] = 0x11; d[8] = 0x22; d[9] = 0x33; }
        if (a == 0xa70) d[1] = 0x01;
      } else { assert(tag == 2 && tl == 8 && plen == 12 && pl[8] == 0 && pl[9] == 1 && pl[10] == 0 && pl[11] == 0); }
      break;
    case 0x0b: assert(!query && tag == 0 && tl == 8 && plen == 12); chip.fw_log = pl[8]; break;   /* WSYS_CONFIG */
    case 0x28: assert(!query && tag == 0 && tl == 8 && plen == 12); chip.dbdc = pl[8]; break;     /* SET_DBDC_PARMS */
    case 0x15: assert(!query && plen >= 16); chip.domain.assign(pl, pl + plen); break;           /* SET_DOMAIN_INFO */
    case 0x08: assert(!query && pl[0] == 0);              /* BAND_CONFIG */
      if (tag == 0x0c) { assert(tl == 68 && plen == 72); chip.rxfilter_mode = pl[8]; memcpy(&chip.rxfilter, pl + 12, 4); break; }
      assert(tag == 8 && tl == 12); memcpy(&chip.rts, pl + 8, 4);
      { uint32_t pk; memcpy(&pk, pl + 12, 4); assert(pk == 2); } break;
    case 0x01:                                            /* DEV_INFO_UPDATE */
      assert(!query && plen == 16 && tag == 0 && tl == 12); chip.uni_order.push_back("dev");
      chip.dev_active = pl[8]; chip.dev_band = pl[1]; memcpy(chip.dev_addr, pl + 10, 6); break;
    case 0x02:                                            /* BSS_INFO_UPDATE */
      if (tag == 21) {                                    /* PS only (mt7925_mcu_uni_bss_ps) */
        assert(!query && tl == 8 && plen == 12 && pl[1] == 0 && pl[2] == 0 && pl[3] == 0);
        chip.ps_bss = pl[0]; chip.ps_state = pl[8]; chip.ps_n++; break; }
      assert(!query && tag == 0 && tl == 32); chip.uni_order.push_back("bss");
      chip.bss_idx = pl[0]; chip.bss_active = pl[8]; memcpy(&chip.bss_conn, pl + 12, 4);
      memcpy(&chip.bss_wcid, pl + 30, 2);                 /* sta_idx */
      if (plen == 36) { uint16_t bmc; memcpy(&bmc, pl + 24, 2); assert(bmc == chip.bss_wcid); break; }
      { /* join: basic first, then TLVs counted in the header's second word */
        memcpy(&chip.bss_ntlv, pl + 2, 2); chip.bss_tags.clear();
        chip.bss_conn_state = pl[16]; memcpy(chip.bss_bssid, pl + 18, 6); chip.bss_phymode = pl[29]; chip.bss_band = pl[11];
        uint32_t off = 4;
        while (off + 4 <= plen) { uint16_t tg, ln; memcpy(&tg, pl + off, 2); memcpy(&ln, pl + off + 2, 2);
          assert(ln >= 4 && off + ln <= plen); chip.bss_tags.push_back(tg);
          if (tg == 11) { assert(ln == 16); memcpy(&chip.bss_basic_rate, pl + off + 6, 2); chip.bss_rate_idx = pl[off + 13];
                          assert(pl[off + 14] == chip.bss_rate_idx); }
          if (tg == 2) { assert(ln == 16); chip.bss_rlm_ch = pl[off + 4]; chip.bss_rlm_band = pl[off + 12];
                         chip.bss_rlm_center = pl[off + 5]; chip.bss_rlm_bw = pl[off + 7]; chip.bss_rlm_htop = pl[off + 10];
                         chip.bss_rlm_sco = pl[off + 11]; assert(pl[off + 8] == 2 && pl[off + 9] == 2); }
          if (tg == 16) { assert(ln == 8); chip.bss_sec_mode = pl[off + 4]; chip.bss_sec_status = pl[off + 5];
                          chip.bss_sec_cipher = pl[off + 6]; }
          if (tg == 15) assert(ln == 8);
          if (tg == 26) assert(ln == 20 && pl[off + 13] == 0xff);
          if (tg == 23) assert(ln == 20 && pl[off + 4] == 1);
          off += ln; }
        assert(off == plen && chip.bss_ntlv == chip.bss_tags.size()); }
      break;
    case 0x03: {                                          /* STA_REC_UPDATE */
      assert(!query && plen >= 12);
      Chip::StaRec sr{}; sr.wcid = pl[1] | (pl[6] << 8); sr.muar = pl[5]; memcpy(&sr.ntlv, pl + 2, 2); assert(pl[4] == 1);
      sr.conn_state = -1; sr.state = -1;
      uint32_t off = 8;
      while (off + 4 <= plen) { uint16_t tg, ln; memcpy(&tg, pl + off, 2); memcpy(&ln, pl + off + 2, 2);
        assert(ln >= 4 && off + ln <= plen); sr.tags.push_back(tg);
        if (tg == 0) { assert(ln == 20); memcpy(&sr.conn_type, pl + off + 4, 4); sr.conn_state = pl[off + 8];
                       memcpy(&sr.aid, pl + off + 10, 2); memcpy(sr.peer, pl + off + 12, 6); memcpy(&sr.extra, pl + off + 18, 2); }
        if (tg == 0x15) { assert(ln == 12); memcpy(&sr.basic_rate, pl + off + 4, 2); sr.phy_type = pl[off + 6];
                          sr.ampdu = pl[off + 7]; sr.max_ampdu_len = pl[off + 10]; }
        if (tg == 1) { assert(ln == 16); memcpy(&sr.ra_legacy, pl + off + 4, 2); sr.ht_mcs0 = pl[off + 6]; }
        if (tg == 7) { assert(ln == 16); sr.state = pl[off + 4]; sr.vht_opmode = pl[off + 12]; }
        if (tg == 9) { assert(ln == 8); memcpy(&sr.ht_cap, pl + off + 4, 2); }
        if (tg == 10) { assert(ln == 16); memcpy(&sr.vht_cap, pl + off + 4, 4); memcpy(&sr.vht_rx, pl + off + 8, 2);
                        memcpy(&sr.vht_tx, pl + off + 10, 2); }
        if (tg == 6) { assert(ln == 16); sr.ba_tid = pl[off + 4]; sr.ba_type = pl[off + 5]; sr.ba_amsdu = pl[off + 6];
                       sr.ba_en = pl[off + 7]; memcpy(&sr.ba_ssn, pl + off + 8, 2); memcpy(&sr.ba_win, pl + off + 10, 2); }
        if (tg == 0x2b) { assert(ln == 8 && pl[off + 4] == 0 && pl[off + 5] == 1 && pl[off + 6] <= 1); sr.dis_hdr_trans = pl[off + 6]; }
        if (tg == 0x27) { assert(ln == 68); sr.key_add = pl[off + 4]; sr.key_tx = pl[off + 5]; sr.key_type = pl[off + 6];
                          assert(pl[off + 7] == 0); memcpy(sr.key_peer, pl + off + 8, 6); sr.key_bss = pl[off + 14];
                          sr.key_cipher = pl[off + 15]; sr.key_id = pl[off + 16]; sr.key_len = pl[off + 17];
                          sr.key_wlan = pl[off + 18]; sr.key_mgmt = pl[off + 19]; memcpy(sr.key, pl + off + 20, 32);
                          for (int k = 52; k < 68; k++) assert(pl[off + k] == 0); }
        if (tg == 0x0f) { assert(ln == 8); sr.amsdu_num = pl[off + 4]; sr.amsdu_size = pl[off + 5]; sr.amsdu_en = pl[off + 6]; }
        if (tg == 0x25) assert(ln == 8);
        if (tg == 0x23) assert(ln == 4);
        off += ln; }
      assert(off == plen && sr.ntlv == sr.tags.size());
      chip.sta_recs.push_back(sr);
      r = {0,0,0,0, 0,0,0,0};                             /* cid, pad, status 0 */
      break; }
    case 0x04: {                                          /* EDCA_UPDATE (mt7925_mcu_set_tx) */
      assert(!query && plen == 4 + 4 * 12 && pl[1] == 0 && pl[2] == 0 && pl[3] == 0);
      chip.edca_bss = pl[0]; chip.edca_n++;
      for (int k = 0; k < 4; k++) { const uint8_t *t = pl + 4 + 12 * k; uint16_t tg, ln; memcpy(&tg, t, 2); memcpy(&ln, t + 2, 2);
        assert(tg == 0 && ln == 12 && t[4] == k && t[5] == 0x0f && t[11] == 0);
        chip.edca[k][0] = t[10]; chip.edca[k][1] = t[6]; chip.edca[k][2] = t[7]; memcpy(&chip.edca_txop[k], t + 8, 2); }
      break; }
    case 0x27: {                                          /* ROC */
      assert(!query);
      if (tag == 0) { assert(tl == 24 && plen == 28); chip.roc_acquired++; chip.roc_token = pl[9]; chip.roc_ch = pl[10];
        chip.roc_band = pl[12]; chip.roc_type = pl[19]; memcpy(&chip.roc_maxint, pl + 20, 4); assert(pl[24] == 0xff); }
      else { assert(tag == 1 && tl == 12 && plen == 16 && pl[9] == chip.roc_token && pl[10] == 0xff); chip.roc_aborted++; }
      break; }
    case 0x16: {                                          /* SCAN_REQ */
      assert(!query); chip.scan_seq = pl[0]; chip.scan_hdr_bss = pl[1];
      uint16_t t0; memcpy(&t0, pl + 4, 2);
      if (t0 == 2) { assert(plen == 12); chip.scan_cancel++; break; }
      assert(t0 == 1);
      /* TLV chain: REQ(20) SSID(368) BSSID(16) CHANNEL(136) MISC(12) */
      const uint16_t want_tag[] = {1, 10, 11, 12, 14}, want_len[] = {20, 368, 16, 136, 12};
      uint32_t off = 4;
      for (int k = 0; k < 5; k++) { uint16_t tg, ln; memcpy(&tg, pl + off, 2); memcpy(&ln, pl + off + 2, 2);
        assert(tg == want_tag[k] && ln == want_len[k]);
        if (tg == 1) { chip.scan_type = pl[off + 4]; chip.scan_probes = pl[off + 5]; assert(pl[off + 6] == (1 << 5)); }
        if (tg == 10) { assert(pl[off + 4] == 1 && pl[off + 5] == 0); }            /* wildcard, no SSIDs */
        if (tg == 11) { for (int q = 0; q < 6; q++) assert(pl[off + 4 + q] == 0xff); }
        if (tg == 12) { assert(pl[off + 4] == 4); chip.scan_ch.clear();
          for (int q = 0; q < pl[off + 5]; q++) chip.scan_ch.push_back({pl[off + 8 + 2 * q], pl[off + 9 + 2 * q]}); }
        off += ln; }
      chip.scan_ies.clear();
      while (off < plen) {                                /* phase 4c.12: UNI_SCAN_IE per band */
        uint16_t tg, ln, il; memcpy(&tg, pl + off, 2); memcpy(&ln, pl + off + 2, 2); memcpy(&il, pl + off + 4, 2);
        assert(tg == 13 && ln == 8 + il && off + ln <= plen && (pl[off + 6] == 1 || pl[off + 6] == 2));
        chip.scan_ies.push_back({pl[off + 6], il}); off += ln; }
      assert(off == plen);
      break; }
    case 0x2c: {                                          /* SET_POWER_LIMIT */
      assert(!query && tag == 1 && tl == plen - 4 && plen == 52u + pl[12] * 450u && pl[12] >= 1 && pl[12] <= 3);
      for (int q = 0; q < pl[12]; q++) { const uint8_t *sku = pl + 52 + 450 * q; chip.txpwr.push_back({pl[13], sku[0]});
        assert((int8_t)sku[1 + 4] == 40 || (int8_t)sku[1 + 4] == 127); assert((int8_t)sku[1 + 12] == 127 && (int8_t)sku[449] == (int8_t)sku[1 + 4]); }
      if (pl[14]) chip.txpwr_last++;
      break; }
    case 0x35: assert(query && tag == 0 && tl == 8 && plen == 12);      /* THERMAL */
      r = {0,0,0,0, 0,0,12,0, 0,0,0,0, 45,0,0,0}; break;
    default: assert(!"unexpected UNI command");
    }
    post_event(m->seq, 0x01, 0, r);
    if (ucid == 0x0b && chip.fw_log == 1) {               /* a firmware text log line */
      const char *t = "(test) wifi firmware log line\n"; std::vector<uint8_t> lg(12, 0);
      lg.insert(lg.end(), t, t + strlen(t)); post_event(0, MT7927_UNI_EVENT_FW_LOG, 0, lg, MT7927_RXD_OPT_UNSOLICITED); }
    if (ucid == 0x28) post_event(0, 0x28, 0, {0,0,0,0, 0,0,8,0, 1,0,0,0}, MT7927_RXD_OPT_UNSOLICITED);
    if (ucid == 0x27 && tag == 0 && chip.roc_grant) {
      std::vector<uint8_t> g(4 + 20, 0); g[4] = 0; g[6] = 20; g[8] = pl[8]; g[9] = chip.roc_token; g[10] = 0; g[11] = chip.roc_ch;
      g[13] = chip.roc_band; g[17] = 0; uint32_t mi = chip.roc_maxint; memcpy(&g[20], &mi, 4);
      post_event(0, 0x27, 0, g, MT7927_RXD_OPT_UNSOLICITED); }
    if (ucid == 0x16 && !chip.scan_ch.empty() && chip.scan_cancel == 0) {
      for (auto &c : chip.scan_ch) if (chip.scan_beacons < 2) { post_beacon(c.second, chip.scan_beacons); chip.scan_beacons++; }
      if (chip.scan_done_event)
        post_event(0, MT7927_UNI_EVENT_SCAN_DONE, 0, {0,0,0,0, 0,0,8,0, 0,0,0,0}, MT7927_RXD_OPT_UNSOLICITED);
    }
    return;
  }
  if (uni) {
    snprintf(e, sizeof e, "uni%02x", ucid); chip.cmds.push_back(e);
    assert(opt == MCU_CMD_UNI_EXT_ACK - MCU_CMD_ACK && "CHIP_CONFIG: UNI|SET, ACK cleared (mt7925_mcu_fill_message)");
    assert(((const struct mwx_uni_txd *)buf)->len == len - 32);
    if (chip.mute) return;
    uint16_t tag; memcpy(&tag, pl + 4, 2);
    if (tag == 2) {                                       /* CHIP_CFG text, no response */
      uint16_t tl, ds; memcpy(&tl, pl + 6, 2); memcpy(&ds, pl + 12, 2);
      assert(plen == 336 && tl == 332 && ds == strlen((const char *)pl + 16) + 1);
      chip.chip_cfg.push_back((const char *)pl + 16); return; }
    assert(tag == 3);
    std::vector<uint8_t> r = { 3, 0, 0, 0 };            /* n_element=3 */
    auto tlv = [&](uint16_t t, std::vector<uint8_t> d) { uint16_t L = 4 + d.size();
      r.push_back(t & 0xff); r.push_back(t >> 8); r.push_back(L & 0xff); r.push_back(L >> 8); r.insert(r.end(), d.begin(), d.end()); };
    r[0] = 4; tlv(0x20, {0x10, 0, 0, 0, 0, 0, 0, 0x80}); tlv(5, {0x27, 0x79, 0, 0}); tlv(7, {0x40, 0xed, 0x00, 0x11, 0x22, 0x33, 0, 0}); tlv(0x18, {1, 0, 0, 0});
    post_event(m->seq, 0x01, 0, r); return;
  }
  assert(m->len == len - 32);
  assert(m->pq_id == MCU_PQ_ID(MT_TX_PORT_IDX_MCU, MT_TX_MCU_PORT_RX_Q0));
  snprintf(e, sizeof e, "cmd%02x", m->cid); chip.cmds.push_back(e);
  if (chip.mute || m->cid == chip.mute_cmd) return;
  uint32_t a = 0, b = 0, c = 0;
  if (len >= sizeof(*m) + 12) { memcpy(&a, pl, 4); memcpy(&b, pl + 4, 4); memcpy(&c, pl + 8, 4); }
  switch (m->cid) {
  case MCU_CMD_NIC_POWER_CTRL: assert(pl[0] == 1); chip.pwr_on = true; return;     /* no response */
  case MCU_CMD_PATCH_SEM_CONTROL: memcpy(&a, pl, 4);
    if (a == 1) { post_event(m->seq, 0x01, chip.patch_done ? 1 : 2, {}); chip.sem_state = 1; }
    else { post_event(m->seq, 0x01, 3, {}); chip.sem_state = 0; } return;
  case MCU_CMD_PATCH_START_REQ: case MCU_CMD_TARGET_ADDRESS_LEN_REQ:
    assert(chip.dl_got == chip.dl_len && "previous region incomplete");
    if (m->cid == MCU_CMD_PATCH_START_REQ) assert(a == 0x200000 || a == 0x900000 || a == 0xe0002800);
    else assert(!(a == 0x200000 || a == 0x900000 || a == 0xe0002800));
    assert(c & DL_MODE_NEED_RSP);
    chip.dl_addr = a; chip.dl_len = b; chip.dl_got = 0; chip.regions.push_back({a, {}});
    post_event(m->seq, 0x01, 0, {}); return;
  case MCU_CMD_PATCH_FINISH_REQ: assert(chip.dl_got == chip.dl_len); chip.patch_done = true;
    post_event(m->seq, 0x01, 0, {}); return;
  case MCU_CMD_FW_START_REQ: assert(chip.dl_got == chip.dl_len); memcpy(&chip.fw_start_option, pl, 4);
    memcpy(&chip.fw_start_addr, pl + 4, 4); chip.n9_ready = true; post_event(m->seq, 0x01, 0, {}); return;
  default: assert(!"unexpected MCU command");
  }
}
static void chip_tx_kick(int ring) {
  uint32_t base = MT7927_RING_REG(MT7927_TX_RING_BASE, ring);
  uint32_t n = chip.bar[base + 4], cpu = chip.bar[base + 8], dma = chip.bar[base + 12];
  assert(n && cpu < n);
  while (dma != cpu) {
    struct mwx_desc *d = (struct mwx_desc *)pa2va(chip.bar[base] + dma * 16, 16);
    assert(!(d->ctrl & MT_DMA_CTL_DMA_DONE) && (d->ctrl & MT_DMA_CTL_LAST_SEC0));
    uint32_t len = (d->ctrl >> 16) & 0x3fff; const uint8_t *p = pa2va(d->buf0, len);
    if (ring == 0) {                                     /* data: TXD + hw TXP, payload by pointer */
      assert(len == 64);
      Chip::TxFrame t{}; memcpy(t.txd, p, 32); memcpy(&t.msdu, p + 32, 2); memcpy(&t.msdu1, p + 34, 2);
      memcpy(&t.pa, p + 40, 4); memcpy(&t.len, p + 44, 2);
      assert((t.msdu & 0x8000) && (t.len & 0x8000) && t.msdu1 == 0xffff);
      uint32_t fl = t.len & 0x7fff; assert((t.txd[0] & 0xffff) == fl + 32);
      const uint8_t *fp = pa2va(t.pa, fl); t.frame.assign(fp, fp + fl); chip.txf.push_back(t);
      d->ctrl |= MT_DMA_CTL_DMA_DONE; dma = (dma + 1) % n; chip.bar[base + 12] = dma;
      if (chip.tx_free_auto) post_txfree(t.txd[1] & 0xfff, t.msdu & 0x7fff);
      continue; }
    if (ring == 16) { assert(chip.dl_got + len <= chip.dl_len && "scatter beyond the announced length");
      chip.regions.back().second.insert(chip.regions.back().second.end(), p, p + len); chip.dl_got += len;
      raise(MT7927_INT_TX_DONE_FWDL); }
    else { raise(1u << 25); handle_cmd(p, len); }
    d->ctrl |= MT_DMA_CTL_DMA_DONE; dma = (dma + 1) % n; chip.bar[base + 12] = dma;
  }
  deliver_irq();
}

/* ---- synthetic firmware files ---- */
static std::vector<uint8_t> make_patch(std::vector<std::pair<uint32_t,uint32_t>> secs) {
  std::vector<uint8_t> f(sizeof(mwx_patch_hdr) + secs.size() * sizeof(mwx_patch_sec));
  auto *h = (mwx_patch_hdr *)f.data(); memcpy(h->build_date, "20260519123456ab", 16);
  h->hw_sw_ver = be32toh(0x8a106639); h->desc.n_region = be32toh(secs.size());
  for (size_t i = 0; i < secs.size(); i++) {
    size_t off = f.size(); f.resize(off + secs[i].second);
    for (uint32_t k = 0; k < secs[i].second; k++) f[off + k] = (uint8_t)(i * 31 + k * 7);
    auto *s = (mwx_patch_sec *)(f.data() + sizeof(mwx_patch_hdr) + i * sizeof(mwx_patch_sec));
    s->type = be32toh(PATCH_SEC_TYPE_INFO); s->offs = be32toh(off); s->info.addr = be32toh(secs[i].first);
    s->info.len = be32toh(secs[i].second); s->info.sec_key_idx = be32toh(PATCH_SEC_ENC_TYPE_SCRAMBLE);
  }
  return f;
}
struct RamReg { uint32_t addr, len; uint8_t feat; };
static std::vector<uint8_t> make_ram(std::vector<RamReg> regs) {
  std::vector<uint8_t> f;
  for (size_t i = 0; i < regs.size(); i++) for (uint32_t k = 0; k < regs[i].len; k++) f.push_back((uint8_t)(i * 13 + k * 3));
  for (auto &r : regs) { mwx_fw_region g; memset(&g, 0, sizeof g); g.addr = r.addr; g.len = r.len; g.feature_set = r.feat;
    f.insert(f.end(), (uint8_t *)&g, (uint8_t *)&g + sizeof g); }
  mwx_fw_trailer t; memset(&t, 0, sizeof t); t.n_region = regs.size(); memcpy(t.fw_ver, "____010000", 10);
  memcpy(t.build_date, "20260519123456", 14); f.insert(f.end(), (uint8_t *)&t, (uint8_t *)&t + sizeof t);
  return f;
}

struct Rig { IOPCIDevice *port, *dev; IORegistryEntry *br; mwx_softc sc; mt7927_bringup b; };
static Rig *mk() {
  chip = Chip(); logbuf.clear(); now_us = 0; flr_calls = 0; irq_registered = irq_ever_registered = false;
  chip.bar[MT7925_HIF_REMAP_L1] = 0x18450000 | 0x1234;
  chip.phys[MT_HW_CHIPID] = 0x7fff0000; chip.phys[MT_HW_REV] = 0; chip.phys[MT_HW_EMI_CTL] = 0;
  chip.bar[MT7927_PCIE2AP_REMAP_WF_0_54] = 0xabcd0000;
  Rig *r = new Rig; r->port = new IOPCIDevice(0x8086, 0x7a38, 0x0042); r->br = new IORegistryEntry; r->br->parent = r->port;
  r->dev = new IOPCIDevice(0x14c3, 0x7927, 0x0043); r->dev->parent = r->br;
  memset(&r->sc, 0, sizeof r->sc); strcpy(r->sc.sc_dev.dv_xname, "mt7927"); r->sc.sc_mems = 0x200000; r->sc.sc_memh = (char *)1;
  memset(&r->b, 0, sizeof r->b); r->b.sc = &r->sc; r->b.pci = r->dev;
  return r;
}
static void rm(Rig *r) { delete r->dev; delete r->br; delete r->port; delete r; }
static int count(const char *c) { int n = 0; for (auto &s : chip.cmds) n += s == c; return n; }

int main() {
  uint32_t off;
  assert(mt7927_map(0x7c060010, &off) == MT7927_MAP_FIXED && off == 0x0e0010);
  assert(mt7927_map(0x7c0600f0, &off) == MT7927_MAP_FIXED && off == 0x0e00f0);   /* CONN_ON_MISC */
  assert(mt7927_map(0x54000120, &off) == MT7927_MAP_FIXED && off == 0x002120);   /* DUMMY_CR */
  assert(mt7927_map(0x7c026004, &off) == MT7927_MAP_FIXED && off == 0x0d6004);   /* DMASHDL_SW_CONTROL */
  assert(mt7927_map(0x70010200, &off) == MT7927_MAP_L1 && off == 0x130200);
  assert(mt7927_map(0x90000000, &off) == MT7927_MAP_NONE);

  auto patch = make_patch({{0x900000, 9000}, {0xe0002800, 5000}});
  auto ram = make_ram({{0x00100000, 10000, 0x01}, {0x02000000, 4096, FW_FEATURE_NON_DL},
                       {0xe0003000, 6000, FW_FEATURE_OVERRIDE_ADDR}});
  volatile bool abort_flag = false;

  /* 1: full run (stage 4) */
  Rig *r = mk();
  int passed = mt7927_bringup_run(&r->b, 4, patch.data(), patch.size(), ram.data(), ram.size(), &abort_flag);
  if (getenv("SHOWLOG")) fputs(logbuf.c_str(), stdout);
  assert(passed == 4);
  assert(r->dev->props["MT7927ProbeASICRev"] == 0x79270000 && r->dev->props["MT7927ProbeROMCODE"] == 0x1d1e);
  /* download: patch regions then WM regions (NON_DL skipped), bytes intact and in order */
  assert(chip.regions.size() == 4);
  assert(chip.regions[0].first == 0x900000 && chip.regions[0].second.size() == 9000);
  assert(memcmp(chip.regions[0].second.data(), patch.data() + be32toh(((mwx_patch_sec *)(patch.data() + sizeof(mwx_patch_hdr)))->offs), 9000) == 0);
  assert(chip.regions[1].first == 0xe0002800 && chip.regions[1].second.size() == 5000);
  assert(chip.regions[2].first == 0x00100000 && memcmp(chip.regions[2].second.data(), ram.data(), 10000) == 0);
  assert(chip.regions[3].first == 0xe0003000 && memcmp(chip.regions[3].second.data(), ram.data() + 14096, 6000) == 0);
  assert(chip.fw_start_option == FW_START_OVERRIDE && chip.fw_start_addr == 0xe0003000);
  assert(count("cmd04") == 1 && count("cmd10") == 2 && count("cmd07") == 1 && count("cmd02") == 1 && count("uni0e") == 1);
  assert(chip.cmds.front() == "cmd04");                    /* NIC_POWER_CTRL first */
  assert(r->dev->props["MT7927FWReady"] == 1 && r->dev->sprops["MT7927FWVersion"] == "____010000");
  assert(r->dev->sprops["MT7927MACAddress"] == "40:ed:00:11:22:33" && r->dev->props["MT7927NicHas6G"] == 1);
  assert(r->dev->props["MT7927NicCapElements"] == 4);
  /* interrupts went through the MT7927 map */
  assert(r->b.intr_count > 0 && (r->b.intr_seen & MT7927_INT_RX_DONE_WM) && (r->b.intr_seen & MT7927_INT_TX_DONE_FWDL));
  assert(r->dev->props["MT7927InterruptBits"] & MT7927_INT_RX_DONE_WM);
  /* prefetch / WFDMA values from mt7927_dma_prefetch_setup / wfdma_setup */
  assert(chip.bar[MT7927_WFDMA_PREFETCH_CFG0] == 0x660077 && chip.bar[MT7927_WFDMA_PREFETCH_CFG3] == 0x542200);
  assert(chip.bar[MT7927_WFDMA0_RX_RING6_EXT_CTRL] == 0x00800008 && chip.bar[MT_WFDMA0_TX_RING15_EXT_CTRL] == 0x01800010);
  assert(chip.bar[MT_WFDMA0_INT_RX_PRI] & 0x0f00);
  assert(chip.bar[MT_PCIE_MAC_PM] & MT_PCIE_MAC_PM_L0S_DIS);
  /* teardown: IRQ gone, DMA off, MCU halted by a second WFSYS reset, bus master off, memory freed */
  assert(!irq_registered && irq_ever_registered);
  assert(!(chip.bar[MT_WFDMA0_GLO_CFG] & (MT_WFDMA0_GLO_CFG_TX_DMA_EN | MT_WFDMA0_GLO_CFG_RX_DMA_EN)));
  assert(chip.bar[MT_WFDMA0_HOST_INT_ENA] == 0 && chip.bar[MT_PCIE_MAC_INT_ENABLE] == 0);
  assert(chip.wfsys_resets == 2 && !chip.n9_ready);
  assert(!r->dev->busmaster && live_allocs == 0);
  assert(chip.bar[MT7925_HIF_REMAP_L1] == (0x18450000 | 0x1234));
  assert(logbuf.find("outside BAR0") == std::string::npos && logbuf.find("refused") == std::string::npos);
  rm(r);

  /* 2: stage 1 stops after the reset: no rings, no IRQ, bus master untouched */
  r = mk();
  assert(mt7927_bringup_run(&r->b, 1, patch.data(), patch.size(), ram.data(), ram.size(), &abort_flag) == 1);
  assert(!irq_ever_registered && live_allocs == 0 && r->dev->busmaster && chip.cmds.empty() && chip.wfsys_resets == 1);
  rm(r);

  /* 3: stage 2: rings + DMA + IRQ, no MCU traffic, still torn down */
  r = mk();
  assert(mt7927_bringup_run(&r->b, 2, patch.data(), patch.size(), ram.data(), ram.size(), &abort_flag) == 2);
  assert(irq_ever_registered && !irq_registered && chip.dma_ever_enabled && chip.cmds.empty());
  assert(chip.wfsys_resets == 2 && !r->dev->busmaster && live_allocs == 0);
  rm(r);

  /* 4: firmware never answers PATCH_SEM -> timeout, then clean teardown */
  r = mk(); chip.mute_cmd = MCU_CMD_PATCH_SEM_CONTROL;
  uint64_t t0 = now_us;
  assert(mt7927_bringup_run(&r->b, 4, patch.data(), patch.size(), ram.data(), ram.size(), &abort_flag) == 2);
  assert(logbuf.find("timeout") != std::string::npos && now_us - t0 < 10000000ull);
  assert(!irq_registered && !r->dev->busmaster && live_allocs == 0 && chip.wfsys_resets == 2);
  rm(r);

  /* 5: patch already in the chip (warm reboot): download skipped, RAM still loaded */
  r = mk();
  {   /* pre-mark patch as downloaded after the first WFSYS reset clears state */
    passed = mt7927_bringup_run(&r->b, 2, nullptr, 0, nullptr, 0, &abort_flag); assert(passed == 2); rm(r);
  }
  r = mk();
  struct { static void go(Rig *r, std::vector<uint8_t> &p, std::vector<uint8_t> &m, volatile bool *ab) {
    assert(mt7927_phase1(&r->b) == 0); assert(mt7927_irq_setup(&r->b) == 0); assert(mt7927_dma_init(&r->b) == 0);
    chip.patch_done = true;
    assert(mt7927_mcu_init(&r->b, p.data(), p.size(), m.data(), m.size()) == 0);
    assert(chip.regions.size() == 2 && count("cmd07") == 0);        /* only WM regions sent */
    mt7927_teardown(&r->b); } } t; t.go(r, patch, ram, &abort_flag);
  assert(live_allocs == 0); rm(r);

  /* 6: corrupt patch header is rejected before any scatter */
  r = mk(); { auto bad = patch; ((mwx_patch_hdr *)bad.data())->desc.n_region = be32toh(1000);
    assert(mt7927_bringup_run(&r->b, 4, bad.data(), bad.size(), ram.data(), ram.size(), &abort_flag) == 2);
    assert(chip.regions.empty() && count("cmd10") == 2 && live_allocs == 0); }
  rm(r);

  /* 7: BAR too small -> no register access */
  r = mk(); r->sc.sc_mems = 0x100000; chip.accesses = 0;
  assert(mt7927_bringup_run(&r->b, 4, patch.data(), patch.size(), ram.data(), ram.size(), &abort_flag) == 0);
  assert(chip.accesses <= 4 && live_allocs == 0);   /* only the teardown's interrupt-off writes */
  rm(r);

  /* map: every MAC register phase 3 touches is reachable without L2 */
  for (uint32_t a : {MT7927_MDP_DCR0, MT7927_MDP_DCR1, MT7927_WTBL_UPDATE, MT7927_WTBL_ITCR, MT7927_WTBL_ITDR0,
                     MT7927_WTBL_ITDR1, MT7927_TMAC_CTCR0(0), MT7927_TMAC_CTCR0(1), MT7927_RMAC_MIB_TIME0(0),
                     MT7927_RMAC_MIB_TIME0(1), MT7927_RMAC_MIB_AIRTIME0(0), MT7927_RMAC_MIB_AIRTIME0(1),
                     MT7927_MIB_SCR1(0), MT7927_MIB_SCR1(1), MT7927_DMA_DCR0(0), MT7927_DMA_DCR0(1),
                     MT7927_WTBLOFF_RSCR(0), MT7927_WTBLOFF_RSCR(1)})
    assert(mt7927_map(a, &off) == MT7927_MAP_FIXED);
  assert(mt7927_map(MT7927_MDP_DCR1, &off) == MT7927_MAP_FIXED && off == 0x00e804);

  /* 8: stage 5, connac3 init, in Linux order */
  r = mk(); chip.bar[0x021e00] = 0x00800000 | 0x1234;   /* DMA_DCR0 band 0: RXD_G5_EN set, junk RX len */
  passed = mt7927_bringup_run(&r->b, 5, patch.data(), patch.size(), ram.data(), ram.size(), &abort_flag);
  if (getenv("SHOWLOG")) fputs(logbuf.c_str(), stdout);
  assert(passed == 5);
  {
    std::vector<std::string> want = {"uni0e", "uni2dq", "uni2dq", "uni0b", "uni2d", "uni28", "uni0e", "uni0e", "uni0e",
                                     "uni15", "uni08", "uni35q"};
    std::vector<std::string> got; bool on = false;
    for (auto &c : chip.cmds) { if (c == "uni0e") on = true; if (on) got.push_back(c); }
    if (got != want) { for (auto &c : got) fprintf(stderr, "%s ", c.c_str()); fputc('\n', stderr); }
    assert(got == want);
  }
  assert(chip.chip_cfg.size() == 3 && chip.chip_cfg[0] == "ThermalProtGband 0 100 90 80 30 1 1 115 105 5" &&
         chip.chip_cfg[1] == "ThermalProtAband 1 100 90 80 30 1 1 115 105 5" && chip.chip_cfg[2] == "KeepFullPwr 1");
  assert(chip.fw_log == 1 && chip.dbdc == 1 && chip.rts == 0x92b);
  {   /* SET_DOMAIN_INFO: hdr(alpha2[4] bw 0/3/3 pad) + tlv(tag 2) n 14/25/59 + 8-byte channels */
    auto &d = chip.domain; assert(d.size() == 16 + 8 * (14 + 25 + 59));
    assert(d[0] == 0 && d[1] == 0 && d[4] == 0 && d[5] == 3 && d[6] == 3);
    assert(d[8] == 2 && d[9] == 0 && (d[10] | d[11] << 8) == 8 + 8 * 98 && d[12] == 14 && d[13] == 25 && d[14] == 59);
    auto ch = [&](int i, uint32_t *fl) { uint32_t f; memcpy(&f, d.data() + 16 + 8 * i + 4, 4); *fl = f; return d[16 + 8 * i]; };
    uint32_t fl;
    assert(ch(0, &fl) == 1 && fl == 0); assert(ch(10, &fl) == 11 && fl == 0);
    assert(ch(11, &fl) == 12 && fl == MT7927_CHAN_NO_IR); assert(ch(13, &fl) == 14 && fl == (MT7927_CHAN_NO_IR | MT7927_CHAN_NO_OFDM));
    assert(ch(14, &fl) == 36 && fl == MT7927_CHAN_NO_IR); assert(ch(18, &fl) == 52 && fl == (MT7927_CHAN_NO_IR | MT7927_CHAN_RADAR));
    assert(ch(33, &fl) == 144 && (fl & MT7927_CHAN_RADAR)); assert(ch(34, &fl) == 149 && fl == MT7927_CHAN_NO_IR);
    assert(ch(38, &fl) == 165); assert(ch(39, &fl) == 1 && fl == MT7927_CHAN_NO_IR); assert(ch(97, &fl) == 233);
  }
  /* mac init through the fixed map */
  assert((chip.bar[0x00e804] & MT7927_MAX_RX_LEN_MASK) == MT7927_MAX_RX_LEN && !(chip.bar[0x00e800] & MT7927_MDP_DCR0_DAMSDU_EN));   /* 4c: whole A-MSDUs, sw keys */
  assert(chip.bar[0x021e00] == ((0x1234u & ~MT7927_MAX_RX_LEN_MASK) | MT7927_MAX_RX_LEN));   /* G5 cleared, len set */
  assert((chip.bar[0x0a1e00] & MT7927_MAX_RX_LEN_MASK) == MT7927_MAX_RX_LEN);
  assert(chip.bar[0x0210f4] == (0x3f | MT7927_CTCR0_DDLMT_EN | MT7927_CTCR0_VHT_SMPDU_EN) && chip.bar[0x0a10f4] == chip.bar[0x0210f4]);
  assert(chip.bar[0x0217c4] == MT7927_RMAC_MIB_RXTIME_EN && chip.bar[0x021780] == MT7927_RMAC_MIB_RXTIME_EN);
  assert(chip.bar[0x024804] == (MT7927_MIB_TXDUR_EN | MT7927_MIB_RXDUR_EN) && chip.bar[0x0a4804] == chip.bar[0x024804]);
  assert(chip.bar[0x023408] == MT7927_RSCR_RCPI_SET && chip.bar[0x0a3408] == MT7927_RSCR_RCPI_SET);
  assert((chip.bar[0x034380] & 0xfff) == 19 && (chip.bar[0x034380] & MT7927_WTBL_UPDATE_ADM_CLR));
  assert(chip.bar[0x0343b0] == (MT7927_WTBL_ITCR_WR | MT7927_WTBL_ITCR_EXEC | 25) && chip.bar[0x0343b8] == ((1 << 6) | 0x0c));
  assert(chip.bar[0x0343bc] == MT7927_WTBL_SPE_IDX_SEL && r->b.wtbl_busy == 0);
  /* results */
  assert(r->dev->props["MT7927EfuseHwType"] == 1 && r->dev->props["MT7927EfuseChipID"] == 0x6639);
  assert(r->dev->sprops["MT7927EfuseMAC"] == "40:ed:00:11:22:33" && logbuf.find("(matches firmware)") != std::string::npos);
  assert(r->dev->props["MT7927TemperatureC"] == 45 && r->dev->props["MT7927NicChipCap"] == 0x10);
  assert(r->b.chip_cap == 0x8000000000000010ull && r->dev->props["MT7927NicHwVer"] == 0x7927);
  assert(r->dev->props["MT7927P3Fatal"] == 0 && r->dev->props["MT7927MCUTimeouts"] == 0 && r->dev->props["MT7927CLCRecords"] == 0);
  assert(r->b.fw_log_events == 1 && r->b.fw_log_lines == 1 && r->b.unsol_events == 2);
  assert(logbuf.find("MT7927 fw: (test) wifi firmware log line\n") != std::string::npos);
  assert(logbuf.find("phase 3 PASS") != std::string::npos);
  assert(!irq_registered && !r->dev->busmaster && live_allocs == 0 && chip.wfsys_resets == 2);
  assert(chip.bar[MT7925_HIF_REMAP_L1] == (0x18450000 | 0x1234));
  assert(logbuf.find("refused") == std::string::npos);
  rm(r);

  /* 9: DBDC never answered: Linux only warns, but it is an MCU timeout -> stage 5 not passed */
  r = mk(); chip.mute_uni = 0x28;
  assert(mt7927_bringup_run(&r->b, 5, patch.data(), patch.size(), ram.data(), ram.size(), &abort_flag) == 4);
  assert(r->b.p3_warn == 1 && r->b.p3_fatal == 0 && r->b.mcu_timeouts == 1 && count("uni15") == 1);
  assert(!irq_registered && live_allocs == 0); rm(r);

  /* 10: channel domain never answered -> fatal, rest still attempted, clean teardown */
  r = mk(); chip.mute_uni = 0x15;
  assert(mt7927_bringup_run(&r->b, 5, patch.data(), patch.size(), ram.data(), ram.size(), &abort_flag) == 4);
  assert(r->b.p3_fatal == 1 && count("uni08") == 1 && live_allocs == 0); rm(r);

  /* 11: country code */
  r = mk(); mt7927_bringup_set_country(&r->b, "DE");
  assert(mt7927_bringup_run(&r->b, 5, patch.data(), patch.size(), ram.data(), ram.size(), &abort_flag) == 5);
  assert(chip.domain[0] == 'D' && chip.domain[1] == 'E' && chip.domain[2] == 0); rm(r);
  r = mk(); mt7927_bringup_set_country(&r->b, "de"); assert(r->b.alpha2[0] == '0' && r->b.alpha2[1] == '0');
  mt7927_bringup_set_country(&r->b, "DEU"); assert(r->b.alpha2[0] == '0'); rm(r);

  /* 12: a RAM image with a CLC region: records are found and counted */
  {
    std::vector<uint8_t> clc(48, 0); clc[0] = 32; clc[4] = 0; clc[5] = 2; clc[32] = 16; clc[36] = 3;
    std::vector<RamReg> regs = {{0x00100000, 10000, 0x01}, {0, (uint32_t)clc.size(), FW_FEATURE_NON_DL},
                                {0xe0003000, 6000, FW_FEATURE_OVERRIDE_ADDR}};
    auto ram2 = make_ram(regs);
    memcpy(ram2.data() + 10000, clc.data(), clc.size());
    auto *g = (mwx_fw_region *)(ram2.data() + ram2.size() - sizeof(mwx_fw_trailer) - 2 * sizeof(mwx_fw_region));
    g->reserved1[0] = MT7927_FW_TYPE_CLC;
    r = mk();
    assert(mt7927_bringup_run(&r->b, 5, patch.data(), patch.size(), ram2.data(), ram2.size(), &abort_flag) == 5);
    assert(r->dev->props["MT7927CLCRecords"] == 2 && chip.regions.size() == 4); rm(r);
  }

  /* 13: connac3 RX descriptor parser */
  {
    struct mt7927_rxi ri; std::vector<uint8_t> f(32 + 16 + 16 + 16 + 16 + 96 + 4 + 24, 0);
    auto w32 = [&](size_t o, uint32_t v) { memcpy(&f[o], &v, 4); };
    w32(4, (1u << 19) | (1u << 16) | (1u << 17) | (1u << 18) | (1u << 20));   /* groups 4,1,2,3,5 */
    w32(8, 2u << 13);                                                         /* HDR_OFFSET 2 -> 4 pad bytes */
    w32(12, 190u << 8);                                                       /* chfreq 190 -> 6 GHz ch 37 */
    w32(32 + 16 + 16 + 16 + 12, 0x7080a0b4u);                                 /* rcpi0 0xb4(-20) rcpi1 0xa0(-30) rcpi2 0x80 rcpi3 0x70 */
    assert(mt7927_rx_parse(f.data(), f.size(), 0x3, &ri) == 0);
    assert(ri.band == 6 && ri.chan == 37 && ri.rssi == -20 && ri.hdr_off == 32 + 64 + 96 + 4 && ri.frame_len == 24);
    assert(mt7927_rx_parse(f.data(), f.size(), 0x2, &ri) == 0 && ri.rssi == -30);           /* antenna mask */
    w32(12, (36u << 8) | (1u << 24)); assert(mt7927_rx_parse(f.data(), f.size(), 3, &ri) == MT7927_RX_FCS_ERR);
    w32(12, 36u << 8); w32(4, 1u << 25); assert(mt7927_rx_parse(f.data(), f.size(), 3, &ri) == MT7927_RX_ICV_ERR);
    /* phase 4c.10: header-translated frames parse; group 4 gives fc/seq/qos; RXD4 the A-MSDU position */
    w32(4, 1u << 19); w32(8, (1u << 7) | (1u << 25)); w32(16, 3); w32(32, 0x0188); w32(40, (0x0005u << 16) | (0x123u << 4));
    assert(mt7927_rx_parse(f.data(), f.size(), 3, &ri) == 0 && ri.hdr_trans && ri.hdr_trans_err && ri.amsdu == 3 &&
           ri.has_g4 && ri.fc == 0x0188 && (ri.seq_ctrl >> 4) == 0x123 && ri.qos_ctl == 5 && ri.hdr_off == 48);
    w32(4, (1u << 19) | (1u << 23)); assert(mt7927_rx_parse(f.data(), f.size(), 3, &ri) == MT7927_RX_HDR_TRANS);  /* CM */
    w32(4, 0); w32(8, 1u << 7); w32(16, 0); w32(32, 0); w32(40, 0);
    assert(mt7927_rx_parse(f.data(), 46, 3, &ri) == 0 && ri.hdr_trans && !ri.has_g4);      /* 14-byte 802.3 header fits */
    assert(mt7927_rx_parse(f.data(), 45, 3, &ri) == MT7927_RX_SHORT);
    w32(8, 0); assert(mt7927_rx_parse(f.data(), 40, 3, &ri) == MT7927_RX_SHORT);            /* no room for a header */
    assert(mt7927_rx_parse(f.data(), 31, 3, &ri) == MT7927_RX_SHORT);
    assert(mt7927_rx_parse(f.data(), f.size(), 3, &ri) == 0 && ri.band == 5 && ri.chan == 36 && ri.hdr_off == 32 && ri.rssi == -127);
    w32(12, 6u << 8); w32(8, 0x0004u << 16); w32(4, 0);                                    /* sec mode set, not CM/CLM */
    assert(mt7927_rx_parse(f.data(), f.size(), 3, &ri) == 0 && ri.band == 2 && ri.chan == 6 && ri.decrypted);
    w32(4, 1u << 23); assert(mt7927_rx_parse(f.data(), f.size(), 3, &ri) == 0 && !ri.decrypted);
    /* phase 4c.2: group 1 carries the PN (PN0 first), RXD1 bits 21-22 the key ID */
    w32(4, (1u << 16) | (2u << 21)); for (int k = 0; k < 6; k++) f[32 + k] = (uint8_t)(0x10 + k);
    assert(mt7927_rx_parse(f.data(), f.size(), 3, &ri) == 0 && ri.decrypted && ri.has_pn && ri.key_id == 2 &&
           ri.sec_mode == 4 && ri.pn[0] == 0x10 && ri.pn[5] == 0x15 && ri.hdr_off == 48);
    w32(4, 0); assert(mt7927_rx_parse(f.data(), f.size(), 3, &ri) == 0 && !ri.has_pn && ri.hdr_off == 32);
    std::vector<uint8_t> ev = {0,0,0,0, 2,0,8,0, 0,0,0,0, 0,0,8,0, 0,0,0,0};
    assert(mt7927_scan_event_done(ev.data(), ev.size()));
    ev[12] = 3; assert(!mt7927_scan_event_done(ev.data(), ev.size()));
    assert(!mt7927_scan_event_done(ev.data(), 3));
  }

  /* 13b: phase 4c.10 Block Ack reorder for header-translated frames (mt76 agg-rx.c) */
  {
    struct Rel { std::vector<std::pair<int, bool>> out; } rel;
    auto fn = [](void *arg, void *u, bool deliver) { ((Rel *)arg)->out.push_back({(int)(intptr_t)u, deliver}); };
    struct mt7927_reorder ro; memset(&ro, 0, sizeof ro);
    mt7927_reorder_add(&ro, 5, (void *)1, 0, fn, &rel);                 /* no session: straight through */
    assert(rel.out.size() == 1 && rel.out[0] == std::make_pair(1, true));
    rel.out.clear(); mt7927_reorder_start(&ro, 100, 64);
    mt7927_reorder_add(&ro, 100, (void *)100, 0, fn, &rel);             /* in order */
    mt7927_reorder_add(&ro, 102, (void *)102, 10, fn, &rel);            /* hole at 101: held */
    mt7927_reorder_add(&ro, 103, (void *)103, 10, fn, &rel);
    assert(rel.out.size() == 1 && ro.n == 2 && ro.head == 101);
    mt7927_reorder_add(&ro, 101, (void *)101, 20, fn, &rel);            /* fills the hole: 101 102 103 */
    assert(rel.out.size() == 4 && rel.out[1].first == 101 && rel.out[2].first == 102 && rel.out[3].first == 103 &&
           ro.n == 0 && ro.head == 104);
    mt7927_reorder_add(&ro, 102, (void *)9, 20, fn, &rel);              /* late duplicate: freed */
    assert(rel.out.back() == std::make_pair(9, false));
    rel.out.clear();
    mt7927_reorder_add(&ro, 106, (void *)106, 100, fn, &rel);           /* 104 105 missing */
    assert(!mt7927_reorder_check(&ro, 150, 100, fn, &rel) == false && rel.out.empty());   /* not yet timed out */
    assert(!mt7927_reorder_check(&ro, 200, 100, fn, &rel) && rel.out.size() == 1 && rel.out[0].first == 106 &&
           ro.head == 107);
    rel.out.clear();
    mt7927_reorder_add(&ro, 107 + 70, (void *)177, 300, fn, &rel);       /* beyond the window: head jumps */
    assert(ro.head == ((177 - 64 + 1) & 0xfff) && ro.n == 1 && rel.out.empty());
    mt7927_reorder_bar(&ro, 178, fn, &rel);                              /* BAR: everything before 178 goes */
    assert(rel.out.size() == 1 && rel.out[0].first == 177 && ro.head == 178);
    rel.out.clear();
    mt7927_reorder_start(&ro, 4090, 64);                                 /* sequence numbers wrap at 4096 */
    mt7927_reorder_add(&ro, 2, (void *)2, 0, fn, &rel);
    mt7927_reorder_add(&ro, 4090, (void *)4090, 0, fn, &rel);
    assert(rel.out.size() == 1 && rel.out[0].first == 4090 && ro.n == 1);
    mt7927_reorder_stop(&ro, fn, &rel);                                  /* DELBA: held frames go up in order */
    assert(rel.out.size() == 2 && rel.out[1].first == 2 && !ro.active && ro.n == 0);
  }

  /* 14: phase 4 engine: start keeps the hardware, ISR delivers frames and events, scan */
  {
    struct Got { std::vector<std::vector<uint8_t>> frames; std::vector<std::pair<uint8_t, std::vector<uint8_t>>> events; } got;
    r = mk(); svc_max = 0; op_taken = 0;
    mt7927_engine_set_callbacks(&r->b, &got,
      [](void *a, const uint8_t *p, uint32_t l) { ((Got *)a)->frames.emplace_back(p, p + l); },
      [](void *a, uint8_t eid, const uint8_t *p, uint32_t l) { ((Got *)a)->events.push_back({eid, std::vector<uint8_t>(p, p + l)}); });
    assert(mt7927_engine_start(&r->b, patch.data(), patch.size(), ram.data(), ram.size(), &abort_flag) == 0);
    assert(mt7927_engine_running(&r->b) && irq_registered && r->dev->busmaster && chip.wfsys_resets == 1);
    assert(chip.bar[MT_WFDMA0_GLO_CFG] & MT_WFDMA0_GLO_CFG_TX_DMA_EN);
    assert(chip.bar[MT_WFDMA0_HOST_INT_ENA] == r->b.irq_mask);
    assert(mt7927_engine_mac(&r->b) != nullptr && mt7927_engine_mac(&r->b)[0] == 0x40);
    assert(got.frames.empty() && op_depth == 0);

    struct mt7927_vif v = {}; v.idx = 0; v.omac_idx = 0; v.band_idx = 0; v.wmm_idx = 0; v.wcid = MT7927_WTBL_RESERVED;
    memcpy(v.addr, mt7927_engine_mac(&r->b), 6);
    assert(mt7927_dev_add(&r->b, &v, true) == 0);
    assert(chip.uni_order.size() == 2 && chip.uni_order[0] == "dev" && chip.uni_order[1] == "bss");
    assert(chip.dev_active == 1 && chip.dev_band == 0 && memcmp(chip.dev_addr, v.addr, 6) == 0);
    assert(chip.bss_active == 1 && chip.bss_conn == 0x00010001 && chip.bss_wcid == 19 && chip.bss_idx == 0);
    assert(mt7927_set_rate_txpower(&r->b) == 0 && chip.txpwr.size() == 14 + 46 && chip.txpwr_last == 2);
    assert(chip.txpwr[0].first == 1 && chip.txpwr[0].second == 1 && chip.txpwr[13].second == 14 && chip.txpwr[14].first == 2 &&
           chip.txpwr[14].second == 36 && chip.txpwr.back().second == 167);
    mt7927_engine_log_diag(&r->b);
    assert(logbuf.find("MT7927 MIB band 1") != std::string::npos && logbuf.find("rx4 0 []") != std::string::npos);
    assert(mt7927_set_rxfilter(&r->b, 0, MT7927_FILTER_ENABLE) == 0 && chip.rxfilter == 0x80000000u && chip.rxfilter_mode == 0);

    struct mt7927_scan_chan ch[3] = {{1, 1}, {1, 6}, {2, 36}};
    uint32_t isr0 = r->b.isr_runs;
    assert(mt7927_scan_start(&r->b, &v, ch, 3, nullptr, 0) == 0);
    assert(chip.scan_type == 0 && chip.scan_ch.size() == 3 && chip.scan_ch[2].first == 2 && chip.scan_ch[2].second == 36);
    assert(chip.scan_seq == 1 && chip.scan_hdr_bss == 0);
    /* the reply and the scan results arrive by interrupt while the command waits */
    assert(r->b.isr_runs > isr0 && got.frames.size() == 2 && r->b.rx_frames == 2);
    {
      struct mt7927_rxi ri;
      assert(mt7927_rx_parse(got.frames[0].data(), got.frames[0].size(), 0x3, &ri) == 0);
      assert(ri.band == 2 && ri.chan == 1 && ri.rssi == -40 && got.frames[0][ri.hdr_off] == 0x80);
      assert(memcmp(&got.frames[0][ri.hdr_off + 24 + 12 + 2], "HomeNet", 7) == 0);
      assert(mt7927_rx_parse(got.frames[1].data(), got.frames[1].size(), 0x3, &ri) == 0 && ri.chan == 6 && ri.rssi == -35);
    }
    bool done = false;
    for (auto &e : got.events) if (e.first == MT7927_UNI_EVENT_SCAN_DONE) done = mt7927_scan_event_done(e.second.data(), e.second.size());
    assert(done);
    assert(mt7927_scan_cancel(&r->b, &v) == 0 && chip.scan_cancel == 1 && chip.scan_seq == 1);
    /* 4a.3: as on hardware, beacons on the MCU ring (type 7, flag 1) are staged and delivered */
    chip.beacon_ring = 6; chip.scan_cancel = 0; chip.scan_beacons = 0; chip.scan_ch.clear();
    assert(mt7927_scan_start(&r->b, &v, ch, 3, nullptr, 0) == 0);
    post_event(0, 0x29, 0, {0,0,0,0}, MT7927_RXD_OPT_UNSOLICITED);   /* any later interrupt flushes the stage */
    assert(got.frames.size() == 4 && r->b.stage_frames == 2 && r->b.stage_drops == 0 && r->b.rx_frames == 4);
    assert(r->b.stage_head == r->b.stage_tail && r->b.ring_types[MT7927_RX_MCU][PKT_TYPE_NORMAL] == 2);
    {
      struct mt7927_rxi ri;
      assert(mt7927_rx_parse(got.frames[2].data(), got.frames[2].size(), 0x3, &ri) == 0 && ri.chan == 1 && ri.rssi == -40);
      assert(memcmp(&got.frames[2][ri.hdr_off + 24 + 12 + 2], "HomeNet", 7) == 0);
    }
    assert(mt7927_scan_cancel(&r->b, &v) == 0);
    chip.beacon_ring = 4;
    assert(mt7927_dev_add(&r->b, &v, false) == 0);
    assert(chip.uni_order.size() == 4 && chip.uni_order[2] == "bss" && chip.uni_order[3] == "dev" && chip.dev_active == 0);
    assert(r->b.mcu_timeouts == 0 && svc_max == 1 && svc_depth == 0 && op_depth == 0 && op_taken == 8);
    /* phase 4c.12: active wildcard scan with probe IEs per band (mt7925_mcu_hw_scan) */
    { const uint8_t ie2[] = {1, 2, 0x82, 0x84}, ie5[] = {1, 1, 0x8c, 45, 1, 0};
      const uint8_t *const ies[2] = {ie2, ie5}; const uint16_t lens[2] = {sizeof ie2, sizeof ie5};
      assert(mt7927_scan_start_ex(&r->b, &v, ch, 3, nullptr, 0, true, ies, lens) == 0);
      assert(chip.scan_type == 1 && chip.scan_probes == 2 && chip.scan_ies.size() == 2 &&
             chip.scan_ies[0] == std::make_pair(1, 4) && chip.scan_ies[1] == std::make_pair(2, 6));
      assert(mt7927_scan_start(&r->b, &v, ch, 3, nullptr, 0) == 0 && chip.scan_type == 0 && chip.scan_ies.empty()); }
    /* a data packet that is not an 802.11 frame is counted, not delivered */
    mt7927_engine_stop(&r->b);
    assert(!mt7927_engine_running(&r->b) && !irq_registered && !r->dev->busmaster && live_allocs == 0 && chip.wfsys_resets == 2);
    rm(r);
  }

  /* 16: phase 4b join on 5 GHz: band reconfig, BSS_INFO, STA_REC, ROC, data TX, TX free, leave */
  {
    r = mk(); svc_max = 0; op_taken = 0;
    assert(mt7927_engine_start(&r->b, patch.data(), patch.size(), ram.data(), ram.size(), &abort_flag) == 0);
    struct mt7927_vif v = {}; v.idx = 0; v.omac_idx = 0; v.band_idx = 0; v.wmm_idx = 0; v.wcid = MT7927_WTBL_RESERVED;
    memcpy(v.addr, mt7927_engine_mac(&r->b), 6);
    assert(mt7927_dev_add(&r->b, &v, true) == 0 && chip.dev_band == 0);
    chip.uni_order.clear();
    assert(mt7927_band_reconfig(&r->b, &v, 1) == 0 && v.band_idx == 1 && chip.dev_band == 1 && chip.dev_active == 1);
    assert(chip.uni_order.size() == 4 && chip.uni_order[0] == "bss" && chip.uni_order[1] == "dev" &&
           chip.uni_order[2] == "dev" && chip.uni_order[3] == "bss");
    assert(mt7927_band_reconfig(&r->b, &v, 1) == 0 && chip.uni_order.size() == 4);      /* same band: nothing */

    struct mt7927_bss bss = {};
    const uint8_t ap[6] = {0x40, 0x00, 0x00, 0x00, 0x03, 0x4b};
    memcpy(bss.bssid, ap, 6); bss.chan = 36; bss.band = 2; bss.bcn_int = 100; bss.dtim = 1; bss.qos = 1;
    bss.peer_wcid = 1; bss.phymode = 0x01; bss.phy_type = 1 << 3; bss.basic_rates = 0x15; bss.ra_legacy = 0xff << 6;
    mt7927_wtbl_clear(&r->b, 1);
    assert(mt7927_bss_info(&r->b, &v, &bss, true) == 0);
    const uint16_t want_bss[] = {0, 16, 11, 15, 26, 23, 2, 6};
    assert(chip.bss_tags.size() == 8 && memcmp(chip.bss_tags.data(), want_bss, sizeof want_bss) == 0);
    assert(chip.bss_conn_state == 0 && memcmp(chip.bss_bssid, ap, 6) == 0 && chip.bss_wcid == 1 && chip.bss_band == 1);
    assert(chip.bss_rate_idx == MT7927_BASIC_RATES_TBL + 4 && chip.bss_basic_rate == 0x540);
    assert(chip.bss_rlm_ch == 36 && chip.bss_rlm_band == 2 && chip.bss_phymode == 0x01);

    assert(mt7927_sta_rec(&r->b, &v, &bss, true, true, 0, true) == 0);
    const Chip::StaRec &s1 = chip.sta_recs.back();
    const uint16_t want_sta[] = {0, 0x15, 1, 7, 0x2b};
    assert(s1.wcid == 1 && s1.muar == 0 && s1.tags.size() == 5 && memcmp(s1.tags.data(), want_sta, sizeof want_sta) == 0);
    assert(s1.conn_type == 0x10002 && s1.conn_state == 2 && s1.extra == 3 && s1.state == 0 && memcmp(s1.peer, ap, 6) == 0);
    assert(s1.ra_legacy == 0x3fc0 && s1.basic_rate == 0x15 && s1.phy_type == 8);

    /* ROC: acquire, grant event (unsolicited), wait returns */
    assert(mt7927_roc(&r->b, &v, 36, 2, 3000) == 0 && chip.roc_acquired == 1 && chip.roc_ch == 36 && chip.roc_band == 2);
    assert(chip.roc_type == 0 && chip.roc_maxint == 3000 && r->b.roc_granted && r->b.roc_active && r->b.roc_grant_ms == 3000);
    assert(mt7927_roc(&r->b, &v, 36, 2, 3000) == EBUSY);

    /* auth frame: management, fixed rate on ALTX0, TGID band 1 */
    uint8_t auth[30] = {0xb0, 0x00, 0, 0}; memcpy(auth + 4, ap, 6); memcpy(auth + 10, v.addr, 6); memcpy(auth + 16, ap, 6);
    auth[24] = 0; auth[26] = 1;                                       /* open system, seq 1 */
    struct mt7927_txinfo ti = {}; ti.wcid = 1; ti.omac_idx = 0; ti.band_idx = 1; ti.q_idx = 0x10; ti.hdrlen = 24;
    ti.rate_idx = MT7927_BASIC_RATES_TBL + 4; ti.fixed_rate = true;
    assert(mt7927_tx_frame(&r->b, &ti, auth, sizeof auth) == 0);
    assert(chip.txf.size() == 1);
    {
      const Chip::TxFrame &t = chip.txf.back();
      assert((t.txd[0] >> 25) == 0x10 && ((t.txd[0] >> 23) & 3) == 0 && (t.txd[0] & 0xffff) == 30 + 32);
      assert((t.txd[1] & 0xfff) == 1 && ((t.txd[1] >> 12) & 3) == 1 && ((t.txd[1] >> 14) & 3) == 2);
      assert(((t.txd[1] >> 16) & 0x1f) == 12 && (t.txd[1] >> 31) == 1 && ((t.txd[1] >> 25) & 0x3f) == 0);
      assert(((t.txd[2] >> 4) & 3) == 0 && (t.txd[2] & 0xf) == 0xb);
      assert(((t.txd[3] >> 11) & 0x1f) == 15 && (t.txd[3] & (1u << 28)) && !(t.txd[3] & 1));
      assert(((t.txd[6] >> 16) & 0x3f) == MT7927_BASIC_RATES_TBL + 4 && (t.txd[6] & 0xc) == 0xc && ((t.txd[6] >> 4) & 0x3f) == 1);
      assert(t.frame.size() == 30 && memcmp(t.frame.data(), auth, 30) == 0);
    }
    assert(r->b.tx_done == 1 && r->b.tx_free_events == 1 && r->b.tok_busy[chip.txf.back().msdu & 0x7fff] == 0);
    /* a QoS data frame: rate control (no fixed rate), BE queue */
    uint8_t data[26 + 8 + 20] = {0x88, 0x01}; memcpy(data + 4, ap, 6); memcpy(data + 10, v.addr, 6); memcpy(data + 16, ap, 6);
    ti.q_idx = 1; ti.hdrlen = 26; ti.fixed_rate = false; ti.tid = 0;
    assert(mt7927_tx_frame(&r->b, &ti, data, sizeof data) == 0);
    assert(!(chip.txf.back().txd[1] >> 31) && (chip.txf.back().txd[0] >> 25) == 1 && ((chip.txf.back().txd[6] >> 16) & 0x3f) == 0);
    assert(((chip.txf.back().txd[2] >> 4) & 3) == 2 && (chip.txf.back().txd[2] & 0xf) == 8);
    /* no TX free events: the oldest token is reused once enough newer frames went out */
    chip.tx_free_auto = false;
    for (int k = 0; k < MT7927_TX_TOKENS; k++) assert(mt7927_tx_frame(&r->b, &ti, data, sizeof data) == 0);
    /* phase 4c.7: only once free events have stopped for MT7927_RECLAIM_TICKS watchdog seconds */
    assert(mt7927_tx_frame(&r->b, &ti, data, sizeof data) == ENOBUFS && r->b.tx_reclaimed == 0);
    assert(!mt7927_engine_tx_room(&r->b));
    for (int k = 0; k < MT7927_RECLAIM_TICKS; k++) mt7927_engine_tick(&r->b);
    assert(mt7927_engine_tx_room(&r->b));
    r->b.tx_blocked = false;
    for (int k = 0; k < 6; k++) assert(mt7927_tx_frame(&r->b, &ti, data, sizeof data) == 0);
    assert(r->b.tx_reclaimed == 6 && r->b.tx_queued == 2 + MT7927_TX_TOKENS + 6);
    /* phase 4c.3: once a free event comes back, a full set of tokens waits instead of being reclaimed */
    post_txfree(1, chip.txf.back().msdu & 0x7fff); deliver_irq();
    assert(r->b.tok_free_seq == r->b.tok_seq && r->b.tok_free_tick == r->b.wd_ticks);
    { uint32_t ev, ms, mx, re, fa; mt7927_engine_txfree_stats(&r->b, &ev, &ms, &mx, &re, &fa);
      assert(ev == r->b.tx_free_events && ms >= 2 && mx >= 1 && re == 0);
      mt7927_engine_txfree_stats(&r->b, &ev, &ms, &mx, &re, &fa); assert(mx == 0); }
    assert(mt7927_tx_frame(&r->b, &ti, data, sizeof data) == 0);                 /* the freed token */
    { uint32_t nt = r->b.tx_no_token;
      assert(mt7927_tx_frame(&r->b, &ti, data, sizeof data) == ENOBUFS && r->b.tx_no_token == nt + 1 &&
             r->b.tx_reclaimed == 6 && r->b.tx_blocked); }
    /* phase 4c.4: the room check says so before a frame is taken off the queue */
    r->b.tx_blocked = false;
    { uint32_t inflight, pend; mt7927_engine_tx_depth(&r->b, &inflight, &pend);
      assert(!mt7927_engine_tx_room(&r->b) && r->b.tx_blocked && inflight == MT7927_TX_TOKENS && pend < 256); }
    for (uint32_t k = 0; k < MT7927_TX_TOKENS; k++) r->b.tok_busy[k] = 0;      /* the chip catches up */
    assert(mt7927_engine_tx_room(&r->b));
    r->b.tx_blocked = false;
    chip.tx_free_auto = true;
    assert(mt7927_tx_frame(&r->b, &ti, auth, 4) == EINVAL);
    assert(svc_depth == 0 && op_depth == 0);

    /* associated: BSS_INFO again, STA_REC ASSOC for the AP and the broadcast entry */
    bss.aid = 5;
    assert(mt7927_sta_rec(&r->b, &v, &bss, true, true, 2, false) == 0 && chip.sta_recs.back().state == 2 &&
           chip.sta_recs.back().extra == 1 && chip.sta_recs.back().aid == 5);
    assert(chip.sta_recs.back().dis_hdr_trans == 1);                       /* decap offload off: not translated */
    /* phase 4c.10: with decap offload the AP's entry has RX header translation on, never the broadcast entry */
    bss.rx_hdr_trans = 1;
    assert(mt7927_sta_rec(&r->b, &v, &bss, true, true, 2, false) == 0 && chip.sta_recs.back().dis_hdr_trans == 0);
    assert(mt7927_sta_rec(&r->b, &v, &bss, false, true, 2, false) == 0 && chip.sta_recs.back().dis_hdr_trans == 1);
    bss.rx_hdr_trans = 0;
    assert(mt7927_sta_rec(&r->b, &v, &bss, false, true, 2, false) == 0);
    {
      const Chip::StaRec &bc = chip.sta_recs.back();
      assert(bc.wcid == MT7927_WTBL_RESERVED && bc.muar == 0xe && bc.conn_type == 0x10020 && bc.tags.size() == 2 &&
             bc.tags[0] == 0 && bc.tags[1] == 0x2b && bc.aid == 5);
    }
    /* phase 4c.4: EDCA_UPDATE, mac80211 AC order (VO VI BE BK), queue = index */
    { const struct mt7927_edca e[4] = { {2, 2, 3, 47}, {2, 3, 4, 94}, {3, 4, 6, 0}, {7, 4, 10, 0} };
      assert(mt7927_set_edca(&r->b, &v, e) == 0 && chip.edca_n == 1 && chip.edca_bss == v.idx);
      assert(chip.edca[0][0] == 2 && chip.edca[0][1] == 2 && chip.edca[0][2] == 3 && chip.edca_txop[0] == 47);
      assert(chip.edca[1][1] == 3 && chip.edca_txop[1] == 94 && chip.edca[2][0] == 3 && chip.edca[2][2] == 6 &&
             chip.edca[3][0] == 7 && chip.edca[3][2] == 10 && chip.edca_txop[3] == 0); }
    /* phase 4c.6: power save off, BSS_INFO with only the PS TLV */
    assert(mt7927_bss_ps(&r->b, &v, 0) == 0 && chip.ps_n == 1 && chip.ps_bss == v.idx && chip.ps_state == 0);
    /* phase 4c.2: CCMP keys in the chip */
    assert(chip.bss_sec_mode == 0 && chip.bss_sec_status == 1 && chip.bss_sec_cipher == 0);     /* open until a key */
    bss.cipher = 4;
    assert(mt7927_bss_info(&r->b, &v, &bss, true) == 0 && chip.bss_sec_mode == 7 && chip.bss_sec_status == 6 &&
           chip.bss_sec_cipher == 4);
    {
      uint8_t ptk[16], gtk[16];
      for (int k = 0; k < 16; k++) { ptk[k] = (uint8_t)(0xa0 + k); gtk[k] = (uint8_t)(0x30 + k); }
      assert(mt7927_sta_key(&r->b, &v, &bss, true, true, 4, 0, ptk, 16) == 0);
      const Chip::StaRec &pk = chip.sta_recs.back();
      assert(pk.wcid == 1 && pk.muar == v.omac_idx && pk.tags.size() == 1 && pk.tags[0] == 0x27 && pk.key_add == 1 &&
             pk.key_tx == 1 && pk.key_type == 1 && pk.key_cipher == 4 && pk.key_id == 0 && pk.key_len == 16 &&
             pk.key_wlan == 1 && pk.key_mgmt == 1 && pk.key_bss == v.idx && memcmp(pk.key_peer, ap, 6) == 0 &&
             memcmp(pk.key, ptk, 16) == 0 && pk.key[16] == 0);
      assert(mt7927_sta_key(&r->b, &v, &bss, false, true, 4, 1, gtk, 16) == 0);
      const Chip::StaRec &gk = chip.sta_recs.back();
      assert(gk.wcid == MT7927_WTBL_RESERVED && gk.muar == 0xe && gk.key_add == 1 && gk.key_tx == 0 && gk.key_type == 0 &&
             gk.key_id == 1 && gk.key_wlan == (MT7927_WTBL_RESERVED & 0xff) && memcmp(gk.key, gtk, 16) == 0 &&
             memcmp(gk.key_peer, ap, 6) == 0);
      assert(mt7927_sta_key(&r->b, &v, &bss, true, false, 0, 0, NULL, 0) == 0);
      const Chip::StaRec &rk = chip.sta_recs.back();
      assert(rk.key_add == 0 && rk.key_cipher == 0 && rk.key_len == 0 && rk.key[0] == 0 && rk.wcid == 1);
      assert(mt7927_sta_key(&r->b, &v, &bss, true, true, 4, 0, ptk, 33) == EINVAL);
    }
    /* hardware encryption: TXD3 PROTECT_FRAME, the frame goes out as given (protected bit set) */
    data[1] |= 0x40; ti.protect = true;
    assert(mt7927_tx_frame(&r->b, &ti, data, sizeof data) == 0);
    assert((chip.txf.back().txd[3] & 2) && chip.txf.back().frame.size() == sizeof data &&
           chip.txf.back().frame[1] == data[1]);
    ti.protect = false; data[1] &= ~0x40;
    assert(mt7927_tx_frame(&r->b, &ti, data, sizeof data) == 0 && !(chip.txf.back().txd[3] & 2));
    /* phase 4c.3: TXD3 HW_AMSDU; a TX status request (PID 0x80, host) drops HW_AMSDU and sets BA_DISABLE */
    ti.amsdu = true;
    assert(mt7927_tx_frame(&r->b, &ti, data, sizeof data) == 0 && (chip.txf.back().txd[3] & (1u << 5)) &&
           !(chip.txf.back().txd[3] & (1u << 28)) && chip.txf.back().txd[5] == 0);
    ti.txs = true;
    assert(mt7927_tx_frame(&r->b, &ti, data, sizeof data) == 0 && !(chip.txf.back().txd[3] & (1u << 5)) &&
           (chip.txf.back().txd[3] & (1u << 28)) && chip.txf.back().txd[5] == ((1u << 10) | 0x40));
    ti.amsdu = ti.txs = false;
    /* TX status: VHT (mode 4) MCS 9 NSS 2, 80 MHz; another PID is not ours */
    post_txs((2u << 29) | (4u << 6) | (1u << 10) | 9u, 0x40);
    post_txs((1u << 16) | 1u, 0x20); deliver_irq();
    { uint32_t n, e, t0, t1; mt7927_engine_txs(&r->b, &n, &e, &t0, &t1);
      assert(n == 1 && e == 0 && (t0 & 0x3fff) == ((4u << 6) | (1u << 10) | 9u) && (t0 >> 29) == 2 && (int8_t)(t1 & 0xff) == -10); }
    post_txs((1u << 16) | (1u << 6) | 4u, 0x40); deliver_irq();                   /* OFDM, ACK timeout */
    { uint32_t n, e, t0, t1; mt7927_engine_txs(&r->b, &n, &e, &t0, &t1); assert(n == 2 && e == 1); }
    bss.cipher = 0;
    /* leave: ROC abort, STA_REC remove, BSS_INFO without RLM */
    assert(mt7927_roc_abort(&r->b, &v) == 0 && chip.roc_aborted == 1 && !r->b.roc_active);
    assert(mt7927_roc_abort(&r->b, &v) == 0 && chip.roc_aborted == 1);
    assert(mt7927_sta_rec(&r->b, &v, &bss, true, false, 0, false) == 0);
    assert(chip.sta_recs.back().tags.size() == 2 && chip.sta_recs.back().tags[0] == 0x25 && chip.sta_recs.back().tags[1] == 0x23);
    assert(mt7927_bss_info(&r->b, &v, &bss, false) == 0 && chip.bss_conn_state == 1 && chip.bss_tags.size() == 6);
    /* no grant: the wait times out and the ROC is aborted */
    chip.roc_grant = false;
    assert(mt7927_roc(&r->b, &v, 36, 2, 3000) == ETIMEDOUT && chip.roc_aborted == 2 && !r->b.roc_active);
    chip.roc_grant = true;
    assert(r->b.mcu_timeouts == 0 && svc_depth == 0 && op_depth == 0);
    mt7927_engine_stop(&r->b);
    assert(!mt7927_engine_running(&r->b) && live_allocs == 0 && r->b.tok_chunk[0].va == nullptr);
    rm(r);
  }

  /* 17: phase 4c: 11n/ac STA_REC, 80 MHz RLM, block ack, RX batches beyond the stage, stop/start (sleep/wake) */
  {
    struct Got { std::vector<std::vector<uint8_t>> frames; } got;
    r = mk(); svc_max = 0; op_taken = 0;
    mt7927_engine_set_callbacks(&r->b, &got, [](void *a, const uint8_t *p, uint32_t l) { ((Got *)a)->frames.emplace_back(p, p + l); },
      [](void *, uint8_t, const uint8_t *, uint32_t) {});
    for (int round = 0; round < 3; round++) {               /* boot, then two wakes */
      assert(mt7927_engine_start(&r->b, patch.data(), patch.size(), ram.data(), ram.size(), &abort_flag) == 0);
      assert(mt7927_engine_running(&r->b) && r->b.rx[MT7927_RX_MCU].count == 512 && r->b.rx[MT7927_RX_MCU].bufsz == 4096 &&
             r->b.rx[MT7927_RX_BAND0].count == 1536 && r->b.rx[MT7927_RX_BAND0].per_chunk == 16 &&
             mt7927_ring_buf_pa(&r->b.rx[MT7927_RX_BAND0], 17) == r->b.rx[MT7927_RX_BAND0].buf_chunk[1].pa + 4096);
      assert(r->b.tx[MT7927_TX_BAND0].count == MT7927_TX_TOKENS && r->b.tok_chunk[0].va != nullptr &&
             r->b.tok_chunk[MT7927_TOK_CHUNKS - 1].va != nullptr);
      struct mt7927_vif v = {}; v.idx = 0; v.omac_idx = 0; v.band_idx = 1; v.wmm_idx = 0; v.wcid = MT7927_WTBL_RESERVED;
      memcpy(v.addr, mt7927_engine_mac(&r->b), 6);
      assert(mt7927_dev_add(&r->b, &v, true) == 0);
      struct mt7927_bss bss = {};
      const uint8_t ap[6] = {0x40, 0x00, 0x00, 0x00, 0x03, 0x4b};
      memcpy(bss.bssid, ap, 6); bss.chan = 36; bss.band = 2; bss.bcn_int = 100; bss.dtim = 1; bss.qos = 1; bss.aid = 3;
      bss.peer_wcid = 1; bss.phymode = 0x01 | 0x10 | 0x20; bss.phy_type = (1 << 3) | 0x10 | 0x20; bss.basic_rates = 0x15;
      bss.ra_legacy = 0xff << 6; bss.ht_mcs[0] = 0xff; bss.ht_mcs[1] = 0xff;
      bss.ht_cap = 0x09ef; bss.vht_cap = 0x0f8b79b2; bss.vht_rx_mcs = 0xfffa; bss.vht_tx_mcs = 0xfffa;
      bss.ampdu = 0x17; bss.max_ampdu_len = 7; bss.vht_opmode = 2 | (2 << 4); bss.bw = 2; bss.center_chan = 42;
      assert(mt7927_bss_info(&r->b, &v, &bss, true) == 0);
      assert(chip.bss_rlm_ch == 36 && chip.bss_rlm_center == 42 && chip.bss_rlm_bw == 2 && chip.bss_rlm_sco == 1 && chip.bss_rlm_htop == 4);
      assert(chip.bss_phymode == 0x31);
      assert(mt7927_sta_rec(&r->b, &v, &bss, true, true, 2, false) == 0);
      {
        const Chip::StaRec &sr = chip.sta_recs.back();
        const uint16_t want[] = {0, 0x15, 9, 10, 1, 7, 0x2b};
        assert(sr.tags.size() == 7 && memcmp(sr.tags.data(), want, sizeof want) == 0);
        assert(sr.ht_cap == 0x09ef && sr.vht_cap == 0x0f8b79b2 && sr.vht_rx == 0xfffa && sr.vht_tx == 0xfffa);
        assert(sr.ampdu == 0x17 && sr.max_ampdu_len == 7 && sr.vht_opmode == 0x22 && sr.phy_type == 0x38 && sr.ht_mcs0 == 0xff);
      }
      /* Block Ack: RX recipient tid 0, TX originator tid 6, off again */
      assert(mt7927_sta_ba(&r->b, &v, &bss, 0, false, true, 100, 64, false) == 0);
      { const Chip::StaRec &sr = chip.sta_recs.back();
        assert(sr.wcid == 1 && sr.muar == 0 && sr.tags.size() == 1 && sr.ba_tid == 0 && sr.ba_type == 2 && sr.ba_en == 1 &&
               sr.ba_ssn == 100 && sr.ba_win == 64 && sr.ba_amsdu == 0); }
      assert(mt7927_sta_ba(&r->b, &v, &bss, 6, true, true, 7, 64, false) == 0);
      assert(chip.sta_recs.back().ba_type == 1 && chip.sta_recs.back().ba_en == (1 << 6) && chip.sta_recs.back().ba_tid == 6);
      assert(mt7927_sta_ba(&r->b, &v, &bss, 6, true, false, 0, 0, false) == 0 && chip.sta_recs.back().ba_en == 0);
      /* phase 4c.3: firmware beacon loss / coredump events are counted; MIB windows recorded */
      if (round == 0) {
        post_event(0, 0x0c, 0, {0,0,0,0, 1,0,8,0, 0x40,0xed,0,0}, MT7927_RXD_OPT_UNSOLICITED); deliver_irq();
        post_event(0, 0x0a, 0, {0,0,0,0}, MT7927_RXD_OPT_UNSOLICITED); deliver_irq();
        uint32_t loss, dumps, rxt, txt, win;
        mt7927_engine_link(&r->b, 1, &loss, &dumps, &rxt, &txt, &win);
        assert(loss == 1 && dumps == 1 && r->b.eid_count[0x0c] == 1 && r->b.eid_count[0x0a] == 1);
        mt7927_engine_log_diag(&r->b);
        mt7927_engine_link(&r->b, 1, &loss, &dumps, &rxt, &txt, &win);
        assert(win == 1);
      }
      /* phase 4c.3: hardware A-MSDU TLV after VHT (max MPDU 11454 -> 2) */
      bss.amsdu = 3;
      assert(mt7927_sta_rec(&r->b, &v, &bss, true, true, 2, false) == 0);
      { const Chip::StaRec &sr = chip.sta_recs.back();
        const uint16_t want[] = {0, 0x15, 9, 10, 0x0f, 1, 7, 0x2b};
        assert(sr.tags.size() == 8 && memcmp(sr.tags.data(), want, sizeof want) == 0);
        assert(sr.amsdu_num == 8 && sr.amsdu_size == 2 && sr.amsdu_en == 1); }
      assert(mt7927_sta_rec(&r->b, &v, &bss, false, true, 2, false) == 0 && chip.sta_recs.back().amsdu_en == -1);
      bss.amsdu = 0;
      /* 150 frames land on the MCU ring before one interrupt: delivered in stage-sized batches, none dropped */
      got.frames.clear(); chip.beacon_ring = 6; irq_registered = false;
      for (int k = 0; k < 150; k++) post_beacon(36, k & 1);
      irq_registered = true; deliver_irq();
      assert(got.frames.size() == 150 && r->b.stage_drops == 0 && r->b.stage_head == r->b.stage_tail);
      chip.beacon_ring = 4;
      assert(r->b.mcu_timeouts == 0 && svc_depth == 0 && op_depth == 0);
      /* sleep: everything stops and is freed; wake runs the whole bring-up again */
      mt7927_engine_stop(&r->b);
      assert(!mt7927_engine_running(&r->b) && !irq_registered && !r->dev->busmaster && live_allocs == 0);
    }
    assert(chip.wfsys_resets >= 6);
    rm(r);
  }

  /* 15: engine start failure (firmware never answers) tears down */
  r = mk(); chip.mute_uni = 0x15;
  assert(mt7927_engine_start(&r->b, patch.data(), patch.size(), ram.data(), ram.size(), &abort_flag) == EIO);
  assert(!mt7927_engine_running(&r->b) && !irq_registered && live_allocs == 0 && chip.wfsys_resets == 2);
  rm(r);

  puts("PASS MT7927 bring-up: address map, phase 1 reset, MT7927 rings/prefetch/WFDMA flags, MSI-style "
       "interrupts on bits 14/26, connac3 MCU TXD, patch+RAM download byte-exact (NON_DL skipped, OVERRIDE "
       "start), FW_N9_RDY, NIC capability (MAC), stage limits, timeout, patch-already-loaded, bad header, "
       "teardown order (IRQ off, DMA off, WFSYS reset, bus master off, memory freed); phase 3 connac3 init in Linux "
       "order (eFuse, fw log, set_eeprom, mac init registers, DBDC, thermal, KeepFullPwr, channel domain, RTS, "
       "temperature), unsolicited firmware log events, DBDC/domain timeouts, country code, CLC scan; phase 4 "
       "connac3 RX parser, engine kept running, ISR delivery of frames/events/MCU replies, interface add/remove, "
       "RX filter, TX power limits, scan request/cancel layout, ring/MIB diagnostics; phase 4b band reconfig, BSS_INFO/STA_REC TLVs, ROC grant/timeout/abort, connac3 TXD+TXP data TX, TX free tokens and reclaim; phase 4c 4 KB RX buffers, 11n/ac STA_REC, 80 MHz RLM, block ack, RX batching, stop/start for sleep. Simulated chip, not hardware.");
  return 0;
}
'''
f = out / 'test-probe.cpp'
f.write_text(pre + block + post)
san = sys.argv[1] if len(sys.argv) > 1 else 'address,undefined'
subprocess.run(['clang++', '-std=c++14', '-fsanitize=' + san, '-g', '-Wno-format', '-Wno-unused-function',
                str(f), '-o', str(out / 'test-probe')], check=True)
r = subprocess.run([str(out / 'test-probe')], capture_output=True, text=True)
(out / 'test-probe-result.txt').write_text(r.stdout + r.stderr)
print(r.stdout + r.stderr); r.check_returncode()
