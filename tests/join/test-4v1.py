#!/usr/bin/env python3
"""Phase 4v.1: multiple-BSSID sets remembered from scans, looked up at the join.

Extracts mt7927_mbssid_parse/mt7927_mbssid_index/mt7927_rx_mbss_note/
mt7927_mbss_lookup from MtkMwx.cpp, compiled against stubs:
  - a beacon or probe response (addr2 == addr3) with a Multiple BSSID
    element is remembered by its transmitted BSSID (MaxBSSID Indicator and
    the indexes with a profile); other frames, and frames without the
    element, are not;
  - the join of ..:4d finds index 1 of the set of ..:4c (max indicator 2),
    ..:4e index 2; ..:4f (no profile) and other networks nothing;
  - the same transmitter heard again updates its entry; with the table
    full the oldest entry goes; the newest set that lists us wins;
  - a set unheard for more than MT7927_MBSS_EXPIRE_MS (5 min) is not used.
The TLV bytes (BSS_INFO 11V_MBSSID) are in tests/mt7927-probe.
"""
import pathlib, subprocess, sys, tempfile
root = pathlib.Path(__file__).resolve().parents[2]
s = (root / "SimpleMtkWlan/hal_mwx/MtkMwx.cpp").read_text()
def fn(src, sig, rtype):
    i = src.index(rtype + "\n" + sig + "(")
    return src[i:src.index("\n}\n", i) + 3]
sets = s[s.index("#define\tMT7927_MBSS_SETS"):s.index("struct mwx_softc {")]
code = r'''
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cassert>
#include <vector>
#define IEEE80211_FC0_TYPE_MASK 0x0c
#define IEEE80211_FC0_TYPE_MGT 0x00
#define IEEE80211_FC0_SUBTYPE_MASK 0xf0
#define IEEE80211_FC0_SUBTYPE_BEACON 0x80
#define IEEE80211_FC0_SUBTYPE_PROBE_RESP 0x50
#define IEEE80211_ELEMID_MULTI_BSSID 71
#define IEEE80211_ELEMID_MULTI_BSSID_IDX 85
#define IEEE80211_ADDR_EQ(a, b) (memcmp((a), (b), 6) == 0)
#define IEEE80211_ADDR_COPY(d, s) memcpy((d), (s), 6)
struct ieee80211_frame { uint8_t i_fc[2], i_dur[2], i_addr1[6], i_addr2[6], i_addr3[6], i_seq[2]; };
''' + sets + r'''
static uint32_t now_ms = 1000;
static uint32_t mt7927_now_ms(void) { return now_ms; }
struct mwx_softc { struct mt7927_mbss_set sc_7927_mbss_sets[MT7927_MBSS_SETS]; uint32_t sc_7927_mbss_seq;
  bool sc_7927_mbss_known, sc_7927_mbss_heard; uint8_t sc_7927_mbss_for[6], sc_7927_mbss_tx[6], sc_7927_mbss_max, sc_7927_mbss_idx; };
''' + fn(s, "mt7927_mbssid_parse", "static bool") + fn(s, "mt7927_mbssid_index", "static bool") + \
    fn(s, "mt7927_rx_mbss_note", "static void") + fn(s, "mt7927_mbss_lookup", "static bool") + r'''
typedef std::vector<uint8_t> V;
static V profile(uint8_t idx) { V p = { 83, 2, 0x11, 0, 0, 1, 'x', 85, 1, idx }; V s = { 0, (uint8_t)p.size() };
  s.insert(s.end(), p.begin(), p.end()); return s; }
static V mbss(uint8_t n, std::vector<uint8_t> idx) { V b = { n }; for (auto i : idx) { V p = profile(i); b.insert(b.end(), p.begin(), p.end()); }
  V e = { 71, (uint8_t)b.size() }; e.insert(e.end(), b.begin(), b.end()); return e; }
static V frame(uint8_t fc0, const uint8_t *a2, const uint8_t *a3, const V &ies) {
  V f(36, 0); f[0] = fc0; memset(&f[4], 0xff, 6); memcpy(&f[10], a2, 6); memcpy(&f[16], a3, 6);
  f.insert(f.end(), ies.begin(), ies.end()); return f; }
static void note(mwx_softc *sc, V f) { mt7927_rx_mbss_note(sc, f.data(), f.size()); }
static uint8_t M[64][6];
static const uint8_t *mac(uint8_t b4, uint8_t last) { static int k; uint8_t *p = M[k++ % 64];
  uint8_t v[6] = { 0x72, 0x00, 0x00, 0x00, b4, last }; memcpy(p, v, 6); return p; }
int main() {
  mwx_softc sc{};
  const uint8_t *tx = mac(0xc3, 0x4c), *b4d = mac(0xc3, 0x4d), *b4e = mac(0xc3, 0x4e), *b4f = mac(0xc3, 0x4f);
  /* nothing heard: no set */
  assert(!mt7927_mbss_lookup(&sc, b4d) && !sc.sc_7927_mbss_known);
  /* not remembered: data, a beacon without the element, addr2 != addr3 */
  note(&sc, frame(0x08, tx, tx, mbss(2, { 1, 2 }))); note(&sc, frame(0x80, tx, tx, V{ 0, 0 }));
  note(&sc, frame(0x80, tx, b4d, mbss(2, { 1, 2 }))); { V t(30, 0); note(&sc, t); }
  assert(!mt7927_mbss_lookup(&sc, b4d));
  /* the Deco's probe response */
  note(&sc, frame(0x50, tx, tx, mbss(2, { 1, 2 })));
  assert(mt7927_mbss_lookup(&sc, b4d) && sc.sc_7927_mbss_known && !sc.sc_7927_mbss_heard &&
         sc.sc_7927_mbss_idx == 1 && sc.sc_7927_mbss_max == 2 && !memcmp(sc.sc_7927_mbss_tx, tx, 6) &&
         !memcmp(sc.sc_7927_mbss_for, b4d, 6));
  assert(mt7927_mbss_lookup(&sc, b4e) && sc.sc_7927_mbss_idx == 2);
  sc.sc_7927_mbss_known = false;
  assert(!mt7927_mbss_lookup(&sc, b4f) && !mt7927_mbss_lookup(&sc, tx) && !mt7927_mbss_lookup(&sc, mac(0xc4, 0x4d)));
  assert(!sc.sc_7927_mbss_known);
  /* heard again (beacon): the same entry, updated (index 3 now, not 1) */
  note(&sc, frame(0x80, tx, tx, mbss(2, { 2, 3 })));
  { int used = 0; for (auto &e : sc.sc_7927_mbss_sets) used += e.n != 0; assert(used == 1); }
  assert(!mt7927_mbss_lookup(&sc, b4d) && mt7927_mbss_lookup(&sc, b4f) && sc.sc_7927_mbss_idx == 3);
  /* full table: the oldest goes */
  for (int i = 0; i < MT7927_MBSS_SETS; i++) note(&sc, frame(0x80, mac((uint8_t)(0x10 + i), 0x40), mac((uint8_t)(0x10 + i), 0x40), mbss(3, { 1 })));
  { int used = 0; for (auto &e : sc.sc_7927_mbss_sets) used += e.n != 0; assert(used == MT7927_MBSS_SETS); }
  assert(!mt7927_mbss_lookup(&sc, b4f));                                   /* ..:4c was the oldest */
  assert(mt7927_mbss_lookup(&sc, mac(0x17, 0x41)) && sc.sc_7927_mbss_max == 3 && sc.sc_7927_mbss_idx == 1);
  /* review: a set unheard for more than 5 minutes is not used; heard again, it is */
  { mwx_softc s4{}; const uint8_t *t = mac(0x30, 0x40); now_ms = 50000;
    note(&s4, frame(0x80, t, t, mbss(2, { 1 })));
    now_ms += MT7927_MBSS_EXPIRE_MS; assert(mt7927_mbss_lookup(&s4, mac(0x30, 0x41)));
    now_ms += 1; s4.sc_7927_mbss_known = false;
    assert(!mt7927_mbss_lookup(&s4, mac(0x30, 0x41)) && !s4.sc_7927_mbss_known);
    note(&s4, frame(0x50, t, t, mbss(2, { 1 }))); assert(mt7927_mbss_lookup(&s4, mac(0x30, 0x41))); }
  /* two sets listing the same BSSID: the newest */
  { mwx_softc s2{}; const uint8_t *t1 = mac(0x20, 0x40), *t2 = mac(0x20, 0x44);
    note(&s2, frame(0x80, t1, t1, mbss(3, { 5 }))); note(&s2, frame(0x80, t2, t2, mbss(3, { 1 })));
    assert(mt7927_mbss_lookup(&s2, mac(0x20, 0x45)) && !memcmp(s2.sc_7927_mbss_tx, t2, 6) && s2.sc_7927_mbss_idx == 1);
    note(&s2, frame(0x80, t1, t1, mbss(3, { 5 })));
    assert(mt7927_mbss_lookup(&s2, mac(0x20, 0x45)) && !memcmp(s2.sc_7927_mbss_tx, t1, 6) && s2.sc_7927_mbss_idx == 5); }
  printf("PASS\n"); return 0;
}
'''
with tempfile.TemporaryDirectory() as d:
    c = pathlib.Path(d) / "t.cpp"; c.write_text(code)
    exe = pathlib.Path(d) / "t"
    r = subprocess.run(["clang++", "-std=c++17", "-g", "-fsanitize=address,undefined", "-Wall", "-Wno-unused-function",
                        str(c), "-o", str(exe)], capture_output=True, text=True)
    if r.returncode: print(r.stderr[:4000]); sys.exit(1)
    if r.stderr.strip(): print(r.stderr[:2000])
    r = subprocess.run([str(exe)], capture_output=True, text=True); print(r.stdout[-1500:], r.stderr[-1500:])
    sys.exit(r.returncode)
