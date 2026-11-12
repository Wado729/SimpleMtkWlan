#!/usr/bin/env python3
"""
Host test for the MT7927 phase 1 probe. Slices the real MT7927 block out of
MtkMwx.cpp and runs it against a simulated register file that follows the
Linux mt7925/mt7927 behaviour: L1 remap window, own handshake, CBINFRA reset
and ROMCODE_INDEX. Checks address translation, register order and results.
"""
from pathlib import Path
import subprocess, sys
b = Path(__file__).resolve().parents[2]
out = Path(__file__).resolve().parent
src = (b / 'SimpleMtkWlan/hal_mwx/MtkMwx.cpp').read_text(encoding='utf-8')
start = src.index('#define\tMT7927_BAR_MIN_SIZE')
end = src.index('/*\n * To be honest this is ridiculous.')
block = src[start:end]
regs = (b / 'SimpleMtkWlan/hal_mwx/if_mwxreg.h').read_text(encoding='utf-8')
defs = '\n'.join(l for l in regs.splitlines()
                 if l.startswith('#define') and any(k in l for k in (
                     'MT7927_', 'MT7925_HIF_REMAP', 'MWX_HIF_REG_', 'MT_CONN_ON_LPCTL',
                     'PCIE_LPCR_HOST', 'MT_HW_EMI_CTL', 'MT_HW_CHIPID', 'MT_HW_REV')))

pre = r'''
#include <cassert>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <map>
#include <string>
#include <vector>
typedef unsigned char UInt8; typedef int IOReturn;
#define nitems(a) (sizeof(a) / sizeof((a)[0]))
#include <cerrno>
std::string logbuf;
#define MWX_DEV_LOG(sc, fmt, ...) do { char _b[512]; snprintf(_b, sizeof(_b), fmt, ##__VA_ARGS__); logbuf += _b; } while (0)
''' + defs + r'''
/* ---- simulated chip ---- */
struct Chip {
  std::map<uint32_t,uint32_t> bar;      /* raw BAR offsets */
  std::map<uint32_t,uint32_t> phys;     /* addresses reached through L1 */
  std::vector<std::string> ev;
  uint64_t now_us = 0;
  bool lp_owned_by_fw = false;
  bool own_works = true;
  bool rgu_set_seen = false, rgu_cleared = false;
  uint64_t mcu_own_at = 0; bool mcu_own = false;
  bool rom_ok = true;
  size_t accesses = 0;
  uint32_t l1_reads_outside = 0;
} chip;
struct Soft { struct { char dv_xname[16]; } sc_dev; int sc_st; char *sc_memh; size_t sc_mems; } ;
#define mwx_softc Soft
static uint32_t l1() { return chip.bar[MT7925_HIF_REMAP_L1]; }
uint32_t bus_space_read_4(int, char *, uint32_t off) {
  chip.accesses++;
  if (off == 0x0e0010) return chip.lp_owned_by_fw ? PCIE_LPCR_HOST_OWN_SYNC : 0;
  if (off == MT7927_ROMCODE_INDEX) {
    if (!chip.mcu_own || !chip.rom_ok) return 0x0000;
    uint64_t dt = chip.now_us - chip.mcu_own_at;
    return dt < 2000 ? 0x0001 : dt < 6000 ? 0x1d1a : MT7927_MCU_IDLE_VALUE;
  }
  if (off >= MT7925_HIF_REMAP_BASE_L1 && off < MT7925_HIF_REMAP_BASE_L1 + 0x10000) {
    uint32_t a = (l1() & 0xffff0000) | (off - MT7925_HIF_REMAP_BASE_L1);
    return chip.phys[a];
  }
  return chip.bar[off];
}
void bus_space_write_4(int, char *, uint32_t off, uint32_t v) {
  chip.accesses++;
  char e[96];
  if (off == 0x0e0010) {
    if (v & PCIE_LPCR_HOST_SET_OWN) { if (chip.own_works) chip.lp_owned_by_fw = true; chip.ev.push_back("fw_own"); }
    if (v & PCIE_LPCR_HOST_CLR_OWN) { if (chip.own_works) chip.lp_owned_by_fw = false; chip.ev.push_back("drv_own"); }
    return;
  }
  if (off >= MT7925_HIF_REMAP_BASE_L1 && off < MT7925_HIF_REMAP_BASE_L1 + 0x10000) {
    uint32_t a = (l1() & 0xffff0000) | (off - MT7925_HIF_REMAP_BASE_L1);
    chip.phys[a] = v; snprintf(e, sizeof e, "phys %08x=%08x", a, v); chip.ev.push_back(e); return;
  }
  if (off == MT7927_CBINFRA_RGU_WF_RST) {
    if (v & MT7927_CBINFRA_RGU_WF_RST_WF_SUBSYS) { chip.rgu_set_seen = true; chip.ev.push_back("rgu_set"); }
    else if (chip.rgu_set_seen) { chip.rgu_cleared = true; chip.ev.push_back("rgu_clear"); }
  }
  if (off == MT7927_CBINFRA_MCU_OWN_SET && v == 1) {
    assert(chip.rgu_cleared && "MCU_OWN_SET before WF_SUBSYS pulse");
    chip.mcu_own = true; chip.mcu_own_at = chip.now_us; chip.ev.push_back("mcu_own_set");
  }
  if (off == MT7927_PCIE2AP_REMAP_WF_0_54) { snprintf(e, sizeof e, "remap54=%08x", v); chip.ev.push_back(e); }
  chip.bar[off] = v;
}
void IODelay(unsigned us) { chip.now_us += us; }
void IOSleep(unsigned ms) { chip.now_us += ms * 1000ull; }
/* ---- IOKit stubs ---- */
struct OSObject { virtual ~OSObject() {} void release() { delete this; } };
struct OSSymbol : OSObject { std::string s; static const OSSymbol *withCString(const char *c) { auto o = new OSSymbol; o->s = c; return o; } };
struct OSString : OSObject { std::string s; static OSString *withCString(const char *c) { auto o = new OSString; o->s = c; return o; } };
#define OSSafeReleaseNULL(x) do { if (x) { const_cast<OSObject *>(static_cast<const OSObject *>(x))->release(); (x) = nullptr; } } while (0)
#define OSDynamicCast(T, p) (dynamic_cast<T *>(p))
struct IORegistryPlane {}; IORegistryPlane *gIODTPlane, *gIOServicePlane;
struct IORegistryEntry : OSObject {
  IORegistryEntry *parent = nullptr; bool retained_by_test = true;
  virtual IORegistryEntry *getParentEntry(IORegistryPlane *) { return parent; }
  static IORegistryEntry *fromPath(const char *, IORegistryPlane *);
};
std::vector<std::string> nvram_writes; int nvram_syncs = 0;
struct IODTNVRAM : IORegistryEntry {
  bool setProperty(const OSSymbol *k, OSObject *v) { nvram_writes.push_back(k->s + "=" + static_cast<OSString *>(v)->s); return true; }
  void sync() { nvram_syncs++; }
};
IORegistryEntry *IORegistryEntry::fromPath(const char *, IORegistryPlane *) { return new IODTNVRAM; }
enum { kIOPCICapabilityIDPCIExpress = 0x10, kIOPCIConfigVendorID = 0, kIOPCIConfigDeviceID = 2 };
struct IOPCIDevice : IORegistryEntry {
  std::map<int,uint16_t> cfg; std::map<std::string,unsigned long long> props; uint16_t vid, did;
  IOPCIDevice(uint16_t v, uint16_t d, uint16_t lnk) : vid(v), did(d) { cfg[0x80 + 0x10] = lnk; }
  bool findPCICapability(int id, UInt8 *cap) { *cap = 0x80; return true; }
  uint16_t configRead16(int off) { if (off == 0) return vid; if (off == 2) return did; return cfg[off]; }
  void configWrite16(int off, uint16_t v) { cfg[off] = v; char e[64]; snprintf(e, sizeof e, "cfg %04x+%x=%04x", did, off, v); chip.ev.push_back(e); }
  void setProperty(const char *k, unsigned long long v, unsigned) { props[k] = v; }
};
struct Bridge : IORegistryEntry {};  /* IOPCI2PCIBridge between device and port */
bool bootarg_nvram = false;
bool PE_parse_boot_argn(const char *n, void *, int) { return bootarg_nvram && !strcmp(n, "-mtk7927nvram"); }
int flr_calls = 0;
int mwx_pci_flr(Soft *, IOPCIDevice *) { flr_calls++; chip.own_works = true; chip.ev.push_back("flr"); return 0; }
'''

post = r'''
static int idx(const char *s) { for (size_t i = 0; i < chip.ev.size(); i++) if (chip.ev[i] == s) return (int)i; return -1; }
struct Rig { IOPCIDevice *port, *dev; Bridge *br; Soft sc; };
static void rm(Rig &r) { delete r.dev; delete r.br; delete r.port; }
static Rig mk(size_t bar) {
  chip = Chip(); logbuf.clear(); nvram_writes.clear(); nvram_syncs = 0; flr_calls = 0;
  chip.bar[MT7925_HIF_REMAP_L1] = 0x18450000 | 0x1234;   /* arbitrary previous window + low bits */
  chip.phys[MT_HW_CHIPID] = 0x6639; chip.phys[MT_HW_REV] = 0x8a; chip.phys[MT_HW_EMI_CTL] = 0x1;
  chip.bar[MT7927_PCIE2AP_REMAP_WF_0_54] = 0xabcd0000;
  Rig r; r.port = new IOPCIDevice(0x8086, 0x7a38, 0x0042); r.br = new Bridge; r.br->parent = r.port;
  r.dev = new IOPCIDevice(0x14c3, 0x7927, 0x0043); r.dev->parent = r.br;
  memset(&r.sc, 0, sizeof r.sc); strcpy(r.sc.sc_dev.dv_xname, "mwx0"); r.sc.sc_mems = bar;
  return r;
}
int main() {
  /* translation */
  uint32_t off;
  assert(mt7927_map(0x7c060010, &off) == MT7927_MAP_FIXED && off == 0x0e0010);
  assert(mt7927_map(0x70010200, &off) == MT7927_MAP_L1 && off == 0x130200);
  assert(mt7927_map(0x18011100, &off) == MT7927_MAP_L1 && off == 0x131100);
  assert(mt7927_map(0x1f8600, &off) == MT7927_MAP_RAW && off == 0x1f8600);
  assert(mt7927_map(0x820e0004, &off) == MT7927_MAP_FIXED && off == 0x020004);
  assert(mt7927_map(0x7c500010, &off) == MT7927_MAP_FIXED && off == 0x060010);
  assert(mt7927_map(0x90000000, &off) == MT7927_MAP_NONE);

  /* 1: healthy chip, raw CHIPID 0x6639 forced to 0x7927 */
  Rig r = mk(0x200000);
  bool ret = mt7927_probe_only(&r.sc, r.dev);
  assert(!ret);
  assert(r.dev->cfg[0x90] == 0x0040 && r.port->cfg[0x90] == 0x0040);      /* ASPM bits cleared on both */
  assert(idx("cfg 7927+90=0040") < idx("cfg 7a38+90=0040"));               /* downstream first */
  assert(idx("cfg 7a38+90=0040") < idx("fw_own") && idx("fw_own") < idx("drv_own"));
  assert(idx("drv_own") < idx("rgu_set") && idx("rgu_set") < idx("rgu_clear") && idx("rgu_clear") < idx("mcu_own_set"));
  assert(idx("phys 18011100=00000003") >= 0 && idx("phys 18011100=00000003") < idx("rgu_set"));  /* EMI SLPPROT before reset */
  assert(idx("remap54=abcd1807") >= 0 && idx("remap54=abcd1807") < idx("rgu_set"));
  assert(chip.bar[MT7927_PCIE2AP_REMAP_WF_0_54] == 0xabcd0000);              /* sema remap restored */
  assert(chip.bar[MT7925_HIF_REMAP_L1] == (0x18450000 | 0x1234));            /* L1 window restored */
  assert(r.dev->props["MT7927ProbeASICRev"] == 0x7927008a);
  assert(r.dev->props["MT7927ProbeRawChipID"] == 0x6639);
  assert(r.dev->props["MT7927ProbeROMCODE"] == MT7927_MCU_IDLE_VALUE);
  assert(r.dev->props["MT7927ProbeResetOK"] == 1);
  assert(logbuf.find("ASIC revision: 6639008a") != std::string::npos);
  assert(logbuf.find("forcing chip=0x7927") != std::string::npos);
  assert(logbuf.find("probe-only PASS") != std::string::npos);
  assert(logbuf.find("value=0x00001d1a") != std::string::npos);                        /* ROM progress traced */
  assert(logbuf.find("outside BAR0") == std::string::npos);
  assert(nvram_writes.empty() && nvram_syncs == 0);                          /* crumbs off by default */

  if (getenv("SHOWLOG")) fputs(logbuf.c_str(), stdout);
  rm(r);
  /* 2: ROM never idles -> timeout reported, within ~200 ms of polling */
  r = mk(0x200000); chip.rom_ok = false; bootarg_nvram = true;
  uint64_t t0 = chip.now_us;
  assert(!mt7927_probe_only(&r.sc, r.dev));
  assert(r.dev->props["MT7927ProbeResetOK"] == 0 && r.dev->props["MT7927ProbeROMCODE"] == 0);
  assert(logbuf.find("WFSYS reset timeout (ROMCODE_INDEX=0x0000)") != std::string::npos);
  assert(chip.now_us - t0 < 400000);
  assert(!nvram_writes.empty() && nvram_writes.back().find("6 FAIL wfsys reset") != std::string::npos);
  assert(nvram_syncs == (int)nvram_writes.size());
  bootarg_nvram = false;

  rm(r);
  /* 3: own handshake wedged -> one FLR, then succeeds */
  r = mk(0x200000); chip.own_works = false;
  assert(!mt7927_probe_only(&r.sc, r.dev));
  assert(flr_calls == 1 && idx("flr") < idx("rgu_set"));
  assert(r.dev->props["MT7927ProbeResetOK"] == 1);

  rm(r);
  /* 4: BAR too small -> no register access at all */
  r = mk(0x100000);
  assert(!mt7927_probe_only(&r.sc, r.dev));
  assert(chip.accesses == 0 && chip.ev.empty());
  assert(logbuf.find("BAR0 smaller") != std::string::npos);

  rm(r);
  puts("PASS MT7927 probe: address map, ASPM order, own handshake, EMI before CBINFRA reset, "
       "WF_SUBSYS pulse before MCU_OWN_SET, ROM idle poll and timeout, L1/sema remaps restored, "
       "FLR fallback, BAR size guard, NVRAM crumbs opt-in. Simulated chip, not hardware.");
  return 0;
}
'''
f = out / 'test-probe.cpp'
f.write_text(pre + block + post)
san = sys.argv[1] if len(sys.argv) > 1 else 'address,undefined'
subprocess.run(['clang++', '-std=c++14', '-fsanitize=' + san, '-g', '-Wno-format', str(f), '-o', str(out / 'test-probe')], check=True)
r = subprocess.run([str(out / 'test-probe')], capture_output=True, text=True)
(out / 'test-probe-result.txt').write_text(r.stdout + r.stderr)
print(r.stdout + r.stderr); r.check_returncode()
