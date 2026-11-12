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
  std::vector<std::string> cmds; bool mute = false; int mute_cmd = -1;
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
static void post_event(uint8_t seq, uint8_t eid, uint8_t ext_eid, const std::vector<uint8_t> &payload) {
  uint32_t base = MT7927_RING_REG(MT7927_RX_RING_BASE, 6);
  uint32_t n = chip.bar[base + 4], cpu = chip.bar[base + 8], dma = chip.bar[base + 12];
  assert(n && dma != cpu && "RX ring 6 has no free buffer");
  struct mwx_desc *d = (struct mwx_desc *)pa2va(chip.bar[base] + dma * 16, 16);
  assert(!(d->ctrl & MT_DMA_CTL_DMA_DONE) && "posting into a slot the driver has not re-armed");
  uint32_t len = 44 + payload.size(), cap = (d->ctrl >> 16) & 0x3fff;
  assert(len <= cap);
  uint8_t *p = pa2va(d->buf0, len); memset(p, 0, 44);
  uint32_t rxd0 = (7u << 27) | len; memcpy(p, &rxd0, 4);
  uint16_t l = len - 32; memcpy(p + 32, &l, 2); p[32 + 4] = eid; p[32 + 5] = seq; p[32 + 8] = ext_eid;
  if (!payload.empty()) memcpy(p + 44, payload.data(), payload.size());
  d->ctrl = MT_DMA_CTL_DMA_DONE | MT_DMA_CTL_LAST_SEC0 | (len << 16);
  chip.bar[base + 12] = (dma + 1) % n;
  raise(MT7927_INT_RX_DONE_WM);
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
    if (u->cid == 0x0e && u->option != 0) { uni = true; ucid = u->cid; opt = u->option; } }
  const uint8_t *pl = buf + (uni ? sizeof(struct mwx_uni_txd) : sizeof(struct mwx_mcu_txd));
  if (uni) {
    snprintf(e, sizeof e, "uni%02x", ucid); chip.cmds.push_back(e);
    assert(opt == MCU_CMD_UNI_EXT_ACK - MCU_CMD_ACK && "CHIP_CONFIG: UNI|SET, ACK cleared (mt7925_mcu_fill_message)");
    assert(((const struct mwx_uni_txd *)buf)->len == len - 32);
    if (chip.mute) return;
    uint16_t tag; memcpy(&tag, pl + 4, 2); assert(tag == 3);
    std::vector<uint8_t> r = { 3, 0, 0, 0 };            /* n_element=3 */
    auto tlv = [&](uint16_t t, std::vector<uint8_t> d) { uint16_t L = 4 + d.size();
      r.push_back(t & 0xff); r.push_back(t >> 8); r.push_back(L & 0xff); r.push_back(L >> 8); r.insert(r.end(), d.begin(), d.end()); };
    tlv(5, {0x27, 0x79, 0, 0}); tlv(7, {0x40, 0xed, 0x00, 0x11, 0x22, 0x33, 0, 0}); tlv(0x18, {1, 0, 0, 0});
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
  assert(r->dev->props["MT7927NicCapElements"] == 3);
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

  puts("PASS MT7927 bring-up: address map, phase 1 reset, MT7927 rings/prefetch/WFDMA flags, MSI-style "
       "interrupts on bits 14/26, connac3 MCU TXD, patch+RAM download byte-exact (NON_DL skipped, OVERRIDE "
       "start), FW_N9_RDY, NIC capability (MAC), stage limits, timeout, patch-already-loaded, bad header, "
       "teardown order (IRQ off, DMA off, WFSYS reset, bus master off, memory freed). Simulated chip, not hardware.");
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
