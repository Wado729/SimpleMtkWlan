#!/usr/bin/env python3
"""Phase 4v: beacons of our multiple-BSSID set's transmitted BSSID count as
frames from our AP for the link watchdog.

Extracts mt7927_mbssid_lists/mt7927_rx_count_bss/mt7927_rx_from_bss from
MtkMwx.cpp, compiled against stubs:
  - the Multiple BSSID element (71) of the Deco's transmitted BSSID ..:4c
    (MaxBSSID Indicator 2, profiles with Multiple BSSID-Index 1 and 2) lists
    ..:4d and ..:4e (cfg80211_gen_new_bssid()), not ..:4f, nor the
    transmitter itself, nor another prefix; the index wraps modulo 2^n;
    index 0, an indicator of 0 or 9 and cut elements are ignored;
  - associated to ..:4d, the first beacon from ..:4c learns it (one log
    line) and counts; later ones count without parsing; the watchdog's
    total moves with them;
  - not counted: probe responses from ..:4c, beacons of an AP that does not
    list us, beacons before ASSOC; frames from ..:4d count as before;
  - a new BSSID of ours (roam) is learned again, not matched to the old set.
"""
import pathlib, subprocess, sys, tempfile
root = pathlib.Path(__file__).resolve().parents[2]
s = (root / "SimpleMtkWlan/hal_mwx/MtkMwx.cpp").read_text()
def fn(src, sig, rtype):
    i = src.index(rtype + "\n" + sig + "(")
    return src[i:src.index("\n}\n", i) + 3]
code = r'''
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cassert>
#include <vector>
#include <cstddef>
enum { IEEE80211_S_INIT, IEEE80211_S_SCAN, IEEE80211_S_AUTH, IEEE80211_S_ASSOC, IEEE80211_S_RUN };
#define IEEE80211_FC0_TYPE_MASK 0x0c
#define IEEE80211_FC0_TYPE_MGT 0x00
#define IEEE80211_FC0_TYPE_CTL 0x04
#define IEEE80211_FC0_TYPE_DATA 0x08
#define IEEE80211_FC0_SUBTYPE_MASK 0xf0
#define IEEE80211_FC0_SUBTYPE_BEACON 0x80
#define IEEE80211_FC0_SUBTYPE_PROBE_RESP 0x50
#define IEEE80211_ELEMID_MULTI_BSSID 71
#define IEEE80211_ELEMID_MULTI_BSSID_IDX 85
#define IEEE80211_ADDR_EQ(a, b) (memcmp((a), (b), 6) == 0)
#define IEEE80211_ADDR_COPY(d, s) memcpy((d), (s), 6)
#define IEEE80211_IS_MULTICAST(_a) (*(_a) & 0x01)
struct ieee80211_frame { uint8_t i_fc[2], i_dur[2], i_addr1[6], i_addr2[6], i_addr3[6], i_seq[2]; };
static_assert(sizeof(ieee80211_frame) == 24, "802.11 header");
struct ieee80211_node { uint8_t ni_bssid[6]; };
struct ieee80211com { int ic_state; ieee80211_node *ic_bss; };
struct mwx_softc { ieee80211com sc_ic; uint32_t sc_7927_rx_bcn, sc_7927_rx_mcast, sc_7927_rx_ucast, sc_7927_rx_bss_mgt;
  bool sc_7927_mbss_known, sc_7927_mbss_heard; uint8_t sc_7927_mbss_for[6], sc_7927_mbss_tx[6], sc_7927_mbss_max, sc_7927_mbss_idx;
  uint32_t sc_7927_rx_tx_bcn, sc_7927_probe_acks; };
static int logs;
static const char *ether_sprintf(const uint8_t *) { return "tx"; }
#define MWX_DEV_LOG(sc, ...) (logs++, printf(__VA_ARGS__))
''' + fn(s, "mt7927_mbssid_parse", "static bool") + fn(s, "mt7927_mbssid_index", "static bool") + \
    fn(s, "mt7927_mbssid_lists", "static bool") + fn(s, "mt7927_rx_count_bss", "static void") + \
    fn(s, "mt7927_rx_from_bss", "static uint32_t") + r'''
typedef std::vector<uint8_t> V;
static const uint8_t TX[6] = { 0x72, 0x00, 0x00, 0x00, 0x03, 0x4c }, B4D[6] = { 0x72, 0x00, 0x00, 0x00, 0x03, 0x4d },
  B4E[6] = { 0x72, 0x00, 0x00, 0x00, 0x03, 0x4e }, B4F[6] = { 0x72, 0x00, 0x00, 0x00, 0x03, 0x4f },
  FAR[6] = { 0x42, 0x00, 0x00, 0x00, 0x03, 0x71 }, OTHER[6] = { 0x72, 0x00, 0x00, 0x00, 0x04, 0x4d };
/* Nontransmitted BSSID Profile: capability (83), SSID, Multiple BSSID-Index (85) */
static V profile(const char *ssid, uint8_t idx) {
  V p = { 83, 2, 0x11, 0x00, 0, (uint8_t)strlen(ssid) }; p.insert(p.end(), ssid, ssid + strlen(ssid));
  V x = { 85, 3, idx, 1, 0 }; p.insert(p.end(), x.begin(), x.end());
  V s = { 0, (uint8_t)p.size() }; s.insert(s.end(), p.begin(), p.end()); return s; }
static V mbssid(uint8_t n, std::vector<V> subs) {
  V b = { n }; for (auto &x : subs) b.insert(b.end(), x.begin(), x.end());
  V e = { 71, (uint8_t)b.size() }; e.insert(e.end(), b.begin(), b.end()); return e; }
/* the Deco's beacon: hidden SSID, RSN-ish filler, the MBSSID element, more after */
static V deco_ies() {
  V ie = { 0, 0, 1, 1, 0x8c, 48, 2, 1, 0 };
  V m = mbssid(2, { profile("Home_6GHz", 1), profile("Home_MLO", 2), V{ 221, 3, 0, 0x10, 0x18 } });
  ie.insert(ie.end(), m.begin(), m.end());
  V tail = { 255, 2, 108, 0 }; ie.insert(ie.end(), tail.begin(), tail.end()); return ie; }
static V frame(uint8_t fc0, const uint8_t *a1, const uint8_t *a2, const uint8_t *a3, const V &ies) {
  V f(24 + 12, 0); f[0] = fc0; memcpy(&f[4], a1, 6); memcpy(&f[10], a2, 6); memcpy(&f[16], a3, 6);
  f.insert(f.end(), ies.begin(), ies.end()); return f; }
static const uint8_t BC[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, ME[6] = { 2, 0, 0, 0, 0, 1 };
static bool lists(const V &ie, const uint8_t *tx, const uint8_t *b, uint8_t *idx = nullptr, uint8_t *n = nullptr) {
  uint8_t i = 0, m = 0; bool r = mt7927_mbssid_lists(ie.data(), ie.size(), tx, b, &i, &m);
  if (idx) *idx = i; if (n) *n = m; return r; }
static void rx(mwx_softc *sc, const V &f) { V c = f; mt7927_rx_count_bss(sc, c.data(), c.size()); }
int main() {
  /* the element */
  V ie = deco_ies(); uint8_t idx, n;
  assert(lists(ie, TX, B4D, &idx, &n) && idx == 1 && n == 2);
  assert(lists(ie, TX, B4E, &idx, &n) && idx == 2);
  assert(!lists(ie, TX, B4F) && !lists(ie, TX, TX) && !lists(ie, TX, OTHER) && !lists(ie, FAR, B4D));
  /* wrap: ..:4f with n = 2, index 1 -> ..:4c */
  { V w = mbssid(2, { profile("x", 1) }); assert(lists(w, B4F, TX)); assert(!lists(w, B4F, V{0,0,0,0,0,0x50}.data())); }
  /* n = 8: the whole last octet; index 0, n = 0 / 9: none */
  { V w = mbssid(8, { profile("x", 200) }); uint8_t b[6]; memcpy(b, TX, 6); b[5] = (uint8_t)(0x4c + 200); assert(lists(w, TX, b)); }
  { V w = mbssid(2, { profile("x", 0) }); assert(!lists(w, TX, TX)); }
  { V w = mbssid(0, { profile("x", 1) }); assert(!lists(w, TX, B4D)); }
  { V w = mbssid(9, { profile("x", 1) }); assert(!lists(w, TX, B4D)); }
  { V w = mbssid(2, { profile("x", 5) }); assert(!lists(w, TX, B4D)); }      /* index >= 2^n */
  /* cut short anywhere: never read past the end (ASan), never a false match */
  { size_t mend = 9 + 2 + ie[10];                     /* end of the MBSSID element */
    for (size_t k = 0; k <= ie.size(); k++) { uint8_t *h = new uint8_t[k ? k : 1];
      if (k) memcpy(h, ie.data(), k);
      uint8_t i, m; bool r = mt7927_mbssid_lists(h, k, TX, B4D, &i, &m); assert(r == (k >= mend)); delete[] h; } }
  /* a profile whose length runs past its element: skipped */
  { V w = mbssid(2, { profile("x", 1) }); w[4] = 0xf0; assert(!lists(w, TX, B4D)); }

  /* counting, associated to ..:4d */
  ieee80211_node ap{}; memcpy(ap.ni_bssid, B4D, 6);
  mwx_softc sc{}; sc.sc_ic.ic_bss = &ap; sc.sc_ic.ic_state = IEEE80211_S_AUTH;
  V bcn = frame(0x80, BC, TX, TX, ie);
  rx(&sc, bcn); assert(!sc.sc_7927_mbss_known && sc.sc_7927_rx_tx_bcn == 0);    /* not before ASSOC */
  sc.sc_ic.ic_state = IEEE80211_S_RUN;
  uint32_t h0 = mt7927_rx_from_bss(&sc);
  rx(&sc, bcn);
  assert(sc.sc_7927_mbss_known && !memcmp(sc.sc_7927_mbss_tx, TX, 6) && !memcmp(sc.sc_7927_mbss_for, B4D, 6));
  assert(sc.sc_7927_rx_tx_bcn == 1 && logs == 1 && mt7927_rx_from_bss(&sc) == h0 + 1);
  assert(sc.sc_7927_mbss_max == 2 && sc.sc_7927_mbss_idx == 1);
  assert(sc.sc_7927_rx_bcn == 0 && sc.sc_7927_rx_bss_mgt == 0);
  /* later beacons count without the element (one log per association) */
  rx(&sc, frame(0x80, BC, TX, TX, V{ 0, 0 })); assert(sc.sc_7927_rx_tx_bcn == 2 && logs == 1);
  /* not: probe responses from ..:4c, the far Deco, a beacon whose BSSID field differs */
  rx(&sc, frame(0x50, ME, TX, TX, ie)); rx(&sc, frame(0x80, BC, FAR, FAR, ie)); rx(&sc, frame(0x80, BC, TX, FAR, ie));
  assert(sc.sc_7927_rx_tx_bcn == 2 && sc.sc_7927_rx_bss_mgt == 0);
  /* frames from ..:4d as before */
  rx(&sc, frame(0x80, BC, B4D, B4D, V{})); rx(&sc, frame(0x08, ME, B4D, B4D, V{})); rx(&sc, frame(0x08, BC, B4D, B4D, V{}));
  rx(&sc, frame(0x50, ME, B4D, B4D, V{})); rx(&sc, frame(0xd4, ME, B4D, B4D, V{}));   /* control: not counted */
  assert(sc.sc_7927_rx_bcn == 1 && sc.sc_7927_rx_ucast == 1 && sc.sc_7927_rx_mcast == 1 && sc.sc_7927_rx_bss_mgt == 1);
  /* short frames: nothing */
  { V t(10, 0x80); rx(&sc, t); V b2 = frame(0x80, BC, FAR, FAR, V{}); b2.resize(30); rx(&sc, b2); }
  /* an AP that does not list us: never learned */
  { mwx_softc s2{}; s2.sc_ic.ic_bss = &ap; s2.sc_ic.ic_state = IEEE80211_S_RUN;
    rx(&s2, frame(0x80, BC, FAR, FAR, ie)); rx(&s2, frame(0x80, BC, TX, TX, V{ 0, 0 }));
    assert(!s2.sc_7927_mbss_known && s2.sc_7927_rx_tx_bcn == 0); }
  /* roamed to ..:4e without a leave: learned again for it */
  memcpy(ap.ni_bssid, B4E, 6);
  rx(&sc, frame(0x80, BC, TX, TX, V{ 0, 0 })); assert(sc.sc_7927_rx_tx_bcn == 2);
  rx(&sc, bcn); assert(sc.sc_7927_rx_tx_bcn == 3 && !memcmp(sc.sc_7927_mbss_for, B4E, 6) && logs == 2);
  /* known from the scan (4v.1): the first beacon from it logs, without the element */
  { mwx_softc s3{}; s3.sc_ic.ic_bss = &ap; s3.sc_ic.ic_state = IEEE80211_S_ASSOC; s3.sc_7927_mbss_known = true;
    memcpy(s3.sc_7927_mbss_for, B4E, 6); memcpy(s3.sc_7927_mbss_tx, TX, 6); s3.sc_7927_mbss_max = 2; s3.sc_7927_mbss_idx = 2; int l = logs;
    rx(&s3, frame(0x80, BC, TX, TX, V{ 0, 0 })); rx(&s3, frame(0x80, BC, TX, TX, V{ 0, 0 }));
    assert(s3.sc_7927_rx_tx_bcn == 2 && logs == l + 1 && s3.sc_7927_mbss_heard); }
  /* cleared (join/leave): learned again */
  sc.sc_7927_mbss_known = false; rx(&sc, frame(0x80, BC, TX, TX, V{ 0, 0 })); assert(sc.sc_7927_rx_tx_bcn == 3);
  printf("PASS\n"); return 0;
}
'''
with tempfile.TemporaryDirectory() as d:
    c = pathlib.Path(d) / "t.cpp"; c.write_text(code)
    exe = pathlib.Path(d) / "t"
    r = subprocess.run(["clang++", "-std=c++17", "-g", "-fsanitize=address,undefined", "-Wall", "-Wno-unused-function",
                        "-Wno-misleading-indentation", str(c), "-o", str(exe)], capture_output=True, text=True)
    if r.returncode: print(r.stderr[:4000]); sys.exit(1)
    if r.stderr.strip(): print(r.stderr[:2000])
    r = subprocess.run([str(exe)], capture_output=True, text=True); print(r.stdout[-1500:], r.stderr[-1500:])
    sys.exit(r.returncode)
