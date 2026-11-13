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
  for (int r : {15, 16}) if (off == MT7927_RING_REG(MT7927_TX_RING_BASE, r) + MT_DMA_CPU_IDX) chip_tx_kick(r);
}
uint32_t bus_space_read_4(int, char *, uint32_t off) { return rd(off); }
void bus_space_write_4(int, char *, uint32_t off, uint32_t v) { wr(off, v); }
static void IODelay(unsigned us) { now_us += us; }
static void IOSleep(unsigned ms) { now_us += ms * 1000ull; }
'''

post = r'''
static int mt7927_dmamem_alloc(struct mt7927_dmamem *m, size_t size) {
  memset(m, 0, sizeof(*m)); m->va = calloc(1, size); m->pa = next_pa; next_pa += (size + 0xfff) & ~0xfffu;
  m->size = size; m->handle = m->va; mems.push_back({m->pa, (uint8_t *)m->va, size}); live_allocs++; return 0; }
static void mt7927_dmamem_free(struct mt7927_dmamem *m) {
  if (m->handle) { for (size_t i = 0; i < mems.size(); i++) if (mems[i].va == m->va) { mems.erase(mems.begin() + i); break; }
    free(m->va); live_allocs--; } memset(m, 0, sizeof(*m)); }
static void mt7927_signal(struct mt7927_bringup *) {}
/* locks: single-threaded here; check pairing and that the service lock never nests */
int svc_depth = 0, svc_max = 0, op_depth = 0, op_taken = 0;
static void mt7927_svc_lock(struct mt7927_bringup *) { assert(svc_depth == 0 && "svc lock nested"); svc_depth++; svc_max = svc_max > svc_depth ? svc_max : svc_depth; }
static void mt7927_svc_unlock(struct mt7927_bringup *) { assert(svc_depth == 1); svc_depth--; }
static void mt7927_op_lock(struct mt7927_bringup *) { op_depth++; op_taken++; }
static void mt7927_op_unlock(struct mt7927_bringup *) { assert(op_depth > 0); op_depth--; }
/* ---- simulated MSI: deliver when STA & ENA and a handler is registered ---- */
static void deliver_irq() {
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
    case 0x02:                                            /* BSS_INFO_UPDATE basic */
      assert(!query && plen == 36 && tag == 0 && tl == 32); chip.uni_order.push_back("bss");
      chip.bss_idx = pl[0]; chip.bss_active = pl[8]; memcpy(&chip.bss_conn, pl + 12, 4);
      memcpy(&chip.bss_wcid, pl + 30, 2);                 /* sta_idx */
      { uint16_t bmc; memcpy(&bmc, pl + 24, 2); assert(bmc == chip.bss_wcid); }
      break;
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
        if (tg == 1) { chip.scan_type = pl[off + 4]; assert(pl[off + 6] == (1 << 5)); }
        if (tg == 10) { assert(pl[off + 4] == 1 && pl[off + 5] == 0); }            /* wildcard, no SSIDs */
        if (tg == 11) { for (int q = 0; q < 6; q++) assert(pl[off + 4 + q] == 0xff); }
        if (tg == 12) { assert(pl[off + 4] == 4); chip.scan_ch.clear();
          for (int q = 0; q < pl[off + 5]; q++) chip.scan_ch.push_back({pl[off + 8 + 2 * q], pl[off + 9 + 2 * q]}); }
        off += ln; }
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
  assert((chip.bar[0x00e804] & MT7927_MAX_RX_LEN_MASK) == MT7927_MAX_RX_LEN && (chip.bar[0x00e800] & MT7927_MDP_DCR0_DAMSDU_EN));
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
    w32(4, 0); w32(8, 1u << 7); assert(mt7927_rx_parse(f.data(), f.size(), 3, &ri) == MT7927_RX_HDR_TRANS);
    w32(8, 0); assert(mt7927_rx_parse(f.data(), 40, 3, &ri) == MT7927_RX_SHORT);            /* no room for a header */
    assert(mt7927_rx_parse(f.data(), 31, 3, &ri) == MT7927_RX_SHORT);
    assert(mt7927_rx_parse(f.data(), f.size(), 3, &ri) == 0 && ri.band == 5 && ri.chan == 36 && ri.hdr_off == 32 && ri.rssi == -127);
    w32(12, 6u << 8); w32(8, 0x0004u << 16); w32(4, 0);                                    /* sec mode set, not CM/CLM */
    assert(mt7927_rx_parse(f.data(), f.size(), 3, &ri) == 0 && ri.band == 2 && ri.chan == 6 && ri.decrypted);
    w32(4, 1u << 23); assert(mt7927_rx_parse(f.data(), f.size(), 3, &ri) == 0 && !ri.decrypted);
    std::vector<uint8_t> ev = {0,0,0,0, 2,0,8,0, 0,0,0,0, 0,0,8,0, 0,0,0,0};
    assert(mt7927_scan_event_done(ev.data(), ev.size()));
    ev[12] = 3; assert(!mt7927_scan_event_done(ev.data(), ev.size()));
    assert(!mt7927_scan_event_done(ev.data(), 3));
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
    /* a data packet that is not an 802.11 frame is counted, not delivered */
    mt7927_engine_stop(&r->b);
    assert(!mt7927_engine_running(&r->b) && !irq_registered && !r->dev->busmaster && live_allocs == 0 && chip.wfsys_resets == 2);
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
       "RX filter, TX power limits, scan request/cancel layout, ring/MIB diagnostics. Simulated chip, not hardware.");
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
