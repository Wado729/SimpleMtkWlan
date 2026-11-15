#!/usr/bin/env python3
"""Phase 4l: channel switch center channels and scheduling.

Extracts mt7927_csa_center() and mt7927_csa_start() from MtkMwx.cpp:
  - centers for 40/80/160 MHz on 5 GHz (36-64, 100-144, 149-177) and 6 GHz
    (1-233), 0 where the channelization has no such block, 20 MHz = primary;
  - a switch is timed count * beacon interval (TU) after the announcement,
    the same target again only re-times it, the current channel is ignored.
"""
import pathlib, subprocess, sys, tempfile
root = pathlib.Path(__file__).resolve().parents[2]
s = (root / "SimpleMtkWlan/hal_mwx/MtkMwx.cpp").read_text()
n = (root / "mtk80211/openbsd/net80211/ieee80211_input.c").read_text()
def fn(sig, rtype, src=None):
    src = s if src is None else src
    i = src.index(rtype + "\n" + sig + "(")
    return src[i:src.index("\n}\n", i) + 3]
# review M1: the beacon path matches our AP by BSSID (ni is the scan node)
assert "IEEE80211_ADDR_EQ(wh->i_addr3, ic->ic_bss->ni_bssid)" in n
code = r'''
#include <cstdint>
#include <cstdio>
#include <cassert>
struct CTimeout {};
struct ieee80211com { void *ic_softc; };
struct mt7927_bss { uint8_t chan, band; uint16_t bcn_int; };
struct mwx_softc { ieee80211com sc_ic; bool sc_7927_assoc; CTimeout *sc_7927_csa_to; mt7927_bss sc_7927_bss;
  bool sc_7927_csa_pending; uint8_t sc_7927_csa_chan, sc_7927_csa_band, sc_7927_csa_mode; int8_t sc_7927_csa_cbw; uint8_t sc_7927_csa_center; };
static int armed = -1, logs;
static int timeout_add_msec(CTimeout **, int ms) { armed = ms; return 1; }
#define MWX_DEV_LOG(sc, ...) (logs++, printf(__VA_ARGS__))
/* net80211 side */
enum { IEEE80211_M_STA = 1, IEEE80211_S_RUN = 4 };
#define IEEE80211_ELEMID_WIDE_BW_CHANNEL_SWITCH 194
#define IEEE80211_ELEMID_CHANNEL_SWITCH_WRAPPER 196
struct n80211 { int ic_opmode, ic_state; void (*ic_csa_start)(n80211 *, uint8_t, uint8_t, uint8_t, uint8_t, int8_t, uint8_t); };
#define ieee80211com n80211
static int c_chan, c_band, c_count, c_mode, c_cbw, c_ccfs0, c_calls;
static void hook(n80211 *, uint8_t ch, uint8_t b, uint8_t cnt, uint8_t m, int8_t w, uint8_t c0) { c_chan = ch; c_band = b; c_count = cnt; c_mode = m; c_cbw = w; c_ccfs0 = c0; c_calls++; }
''' + fn('ieee80211_find_wbcs', 'static const uint8_t *', n) + fn('ieee80211_sta_csa', 'static void', n) + '''
#undef ieee80211com
''' + fn("mt7927_csa_center", "static uint8_t") + fn("mt7927_csa_start", "static void") + r'''
int main() {
  /* 6 GHz */
  assert(mt7927_csa_center(3, 69, 3) == 79 && mt7927_csa_center(3, 165, 3) == 175);
  assert(mt7927_csa_center(3, 37, 2) == 39 && mt7927_csa_center(3, 1, 1) == 3 && mt7927_csa_center(3, 5, 1) == 3);
  assert(mt7927_csa_center(3, 69, 0) == 69 && mt7927_csa_center(3, 70, 2) == 0);
  assert(mt7927_csa_center(3, 229, 3) == 0);            /* 225-253 is no 160 MHz block */
  assert(mt7927_csa_center(3, 213, 2) == 215);
  /* 5 GHz */
  assert(mt7927_csa_center(2, 36, 1) == 38 && mt7927_csa_center(2, 40, 1) == 38 && mt7927_csa_center(2, 44, 1) == 46);
  assert(mt7927_csa_center(2, 36, 2) == 42 && mt7927_csa_center(2, 48, 2) == 42 && mt7927_csa_center(2, 52, 2) == 58);
  assert(mt7927_csa_center(2, 100, 2) == 106 && mt7927_csa_center(2, 132, 2) == 138 && mt7927_csa_center(2, 149, 2) == 155);
  assert(mt7927_csa_center(2, 44, 3) == 50 && mt7927_csa_center(2, 116, 3) == 114 && mt7927_csa_center(2, 165, 3) == 163);
  assert(mt7927_csa_center(2, 132, 3) == 0);            /* 132-160 is no 160 MHz block */
  assert(mt7927_csa_center(2, 38, 1) == 0 && mt7927_csa_center(1, 6, 1) == 0);
  /* scheduling */
  CTimeout to; mwx_softc sc{}; sc.sc_ic.ic_softc = &sc; sc.sc_7927_csa_to = &to;
  sc.sc_7927_bss = {69, 3, 100};
  mt7927_csa_start(&sc.sc_ic, 165, 0, 10, 1, -1, 0); assert(armed == -1);   /* not associated */
  sc.sc_7927_assoc = true;
  mt7927_csa_start(&sc.sc_ic, 69, 0, 10, 1, -1, 0); assert(armed == -1);    /* same channel */
  mt7927_csa_start(&sc.sc_ic, 165, 0, 10, 1, -1, 0);
  assert(armed == 1024 && sc.sc_7927_csa_pending && sc.sc_7927_csa_chan == 165 && sc.sc_7927_csa_band == 3 && logs == 1);
  mt7927_csa_start(&sc.sc_ic, 165, 0, 9, 1, -1, 0); assert(armed == 921 && logs == 1);   /* re-timed, no new log */
  armed = -1; mt7927_csa_start(&sc.sc_ic, 165, 0, 0, 1, -1, 0); assert(armed == -1);     /* already timed */
  mt7927_csa_start(&sc.sc_ic, 37, 2, 0, 0, 2, 42); assert(armed == 1 && sc.sc_7927_csa_band == 2 && sc.sc_7927_csa_center == 42 && logs == 2);
  /* net80211 parse: band and width from the operating class and WBCS */
  n80211 ic{IEEE80211_M_STA, IEEE80211_S_RUN, hook};
  ieee80211_sta_csa(&ic, 1, 134, 165, 10, nullptr); assert(c_calls == 1 && c_band == 3 && c_cbw == 3 && c_chan == 165);
  ieee80211_sta_csa(&ic, 0, 133, 37, 5, nullptr); assert(c_band == 3 && c_cbw == 2);
  ieee80211_sta_csa(&ic, 0, 0, 44, 5, nullptr); assert(c_band == 0 && c_cbw == -1);          /* CSA: width unknown */
  ieee80211_sta_csa(&ic, 0, 128, 36, 5, nullptr); assert(c_band == 2 && c_cbw == 2);
  ieee80211_sta_csa(&ic, 0, 116, 36, 5, nullptr); assert(c_band == 2 && c_cbw == 1);
  ieee80211_sta_csa(&ic, 0, 115, 36, 5, nullptr); assert(c_band == 2 && c_cbw == 0);
  { const uint8_t w[] = {194, 3, 1, 42, 50}; ieee80211_sta_csa(&ic, 0, 0, 36, 5, w); assert(c_cbw == 3 && c_ccfs0 == 50); }
  { const uint8_t w[] = {194, 3, 1, 42, 0}; ieee80211_sta_csa(&ic, 0, 0, 36, 5, w); assert(c_cbw == 2 && c_ccfs0 == 42); }
  { const uint8_t w[] = {194, 3, 0, 0, 0}; ieee80211_sta_csa(&ic, 0, 134, 165, 5, w); assert(c_cbw == 1 && c_ccfs0 == 0); } /* 20/40 never wider */
  { const uint8_t w[] = {194, 3, 0, 0, 0}; ieee80211_sta_csa(&ic, 0, 0, 36, 5, w); assert(c_cbw == 0); }
  { const uint8_t e[] = {37, 3, 1, 9, 5, 196, 5, 194, 3, 2, 50, 0}; const uint8_t *w = ieee80211_find_wbcs(e, e + sizeof e); assert(w == e + 7); }
  ic.ic_state = 3; int k = c_calls; ieee80211_sta_csa(&ic, 0, 0, 36, 5, nullptr); assert(c_calls == k);   /* not in RUN */
  printf("PASS\n"); return 0;
}
'''
with tempfile.TemporaryDirectory() as d:
    c = pathlib.Path(d) / "t.cpp"; c.write_text(code); exe = pathlib.Path(d) / "t"
    r = subprocess.run(["clang++", "-std=c++17", "-g", "-fsanitize=address,undefined", "-Wno-everything", str(c), "-o", str(exe)], capture_output=True, text=True)
    if r.returncode: print(r.stderr[:3000]); sys.exit(1)
    r = subprocess.run([str(exe)], capture_output=True, text=True); print(r.stdout[-1500:], r.stderr[-1500:]); sys.exit(r.returncode)
