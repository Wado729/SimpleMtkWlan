#!/usr/bin/env python3
"""Phase 4i: association retransmission/comeback and the link watchdog's probes.

Extracts from net80211 ieee80211_assoc_arm/timeout/begin/comeback and from
MtkMwx.cpp mt7927_rx_from_bss/mt7927_probe_ap/mt7927_link_watchdog/
mt7927_link_leave, compiled against stubs:
  - the first request arms a 500 ms retry, at most 3 requests in all,
    nothing once out of ASSOC, nothing without ic_assoc_retry;
  - status 30: retry after the comeback time (TU * 1024 / 1000, 1 s without
    the element, at most 2 s), not when the tries are used up;
  - watchdog: 30 s without RX airtime but frames from the AP: stay; without
    frames: probe (management timer cleared in RUN), an answer keeps the
    link, three unanswered probes leave with a deauth and a deauth event.
"""
import pathlib, re, subprocess, sys, tempfile
root = pathlib.Path(__file__).resolve().parents[2]
p = (root / "mtk80211/openbsd/net80211/ieee80211_proto.c").read_text()
s = (root / "SimpleMtkWlan/hal_mwx/MtkMwx.cpp").read_text()
def fn(src, sig, rtype):
    i = src.index(rtype + "\n" + sig + "(")
    return src[i:src.index("\n}\n", i) + 3]
defs = re.search(r"#define IEEE80211_ASSOC_MAX_TRIES.*?#define IEEE80211_ASSOC_COMEBACK_MAX_MS\t2000\n", p, re.S).group(0)
code = r'''
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cassert>
#include <vector>
#include <string>
enum ieee80211_state { IEEE80211_S_INIT, IEEE80211_S_SCAN, IEEE80211_S_AUTH, IEEE80211_S_ASSOC, IEEE80211_S_RUN };
enum { IEEE80211_M_STA = 1, IEEE80211_M_HOSTAP = 2 };
#define IEEE80211_FC0_SUBTYPE_ASSOC_REQ 0x00
#define IEEE80211_FC0_SUBTYPE_PROBE_REQ 0x40
#define IEEE80211_FC0_SUBTYPE_DEAUTH 0xc0
#define IEEE80211_REASON_ASSOC_EXPIRE 4
#define IEEE80211_EVT_STA_DEAUTH 7
struct CTimeout {};
struct ieee80211_node { uint8_t ni_macaddr[6]; int ni_port_valid; };
struct ifn { const char *if_xname; };
struct ieee80211com { int ic_opmode; int ic_state; ieee80211_node *ic_bss; CTimeout *ic_assoc_to;
  uint8_t ic_assoc_retry, ic_assoc_tries, ic_assoc_reassoc, ic_leave_pending; ifn ic_if; int ic_mgt_timer; int ic_deauth_reason;
  void (*ic_event_handler)(ieee80211com*, int, void*); };
static int armed = -1, sends_assoc, sends_probe, sends_deauth, events, newstates, last_arg;
static int timeout_add_msec(CTimeout **, int ms) { armed = ms; return 1; }
static const char *ether_sprintf(const uint8_t *) { return "ap"; }
#define XYLog(...) printf(__VA_ARGS__)
static int send_mgmt(ieee80211com *ic, ieee80211_node *, int type, int arg) {
  if (type == IEEE80211_FC0_SUBTYPE_ASSOC_REQ) { sends_assoc++; last_arg = arg; }
  if (type == IEEE80211_FC0_SUBTYPE_PROBE_REQ) { sends_probe++; ic->ic_mgt_timer = 5; }
  if (type == IEEE80211_FC0_SUBTYPE_DEAUTH) sends_deauth++;
  return 0; }
#define IEEE80211_SEND_MGMT(ic, ni, t, a) send_mgmt(ic, ni, t, a)
static void ieee80211_new_state(ieee80211com *ic, int st, int) { ic->ic_state = st; newstates++; }
static void evh(ieee80211com *, int e, void *) { if (e == IEEE80211_EVT_STA_DEAUTH) events++; }
''' + defs + fn(p, "ieee80211_assoc_arm", "void") + fn(p, "ieee80211_assoc_timeout", "void") + \
   fn(p, "ieee80211_assoc_begin", "static void") + fn(p, "ieee80211_assoc_comeback", "void") + r'''
struct mt7927_bringup {};
struct mt7927_bss { uint8_t bssid[6]; };
struct mwx_softc { ieee80211com sc_ic; bool sc_7927_assoc; uint32_t sc_7927_run_polls, sc_7927_bcn_loss_seen, sc_7927_mib_seen,
  sc_7927_recoveries, sc_7927_last_recovery, sc_7927_poll, sc_7927_rx_bcn, sc_7927_rx_mcast, sc_7927_rx_ucast, sc_7927_rx_bss_mgt,
  sc_7927_wd_probes, sc_7927_wd_rx_mark, sc_7927_wd_window_mark, sc_7927_probe_acks; int sc_flags; bool sc_7927_csa_leave, sc_7927_csa_verify, sc_7927_bcnft_on; mt7927_bringup *sc_7927; struct { int band_idx; } sc_vif; mt7927_bss sc_7927_bss; };
static uint32_t E_loss, E_rxt, E_windows;
static void mt7927_engine_link(mt7927_bringup *, int, uint32_t *loss, uint32_t *dumps, uint32_t *rxt, uint32_t *txt, uint32_t *w) {
  *loss = E_loss; *dumps = 0; *rxt = E_rxt; *txt = 0; *w = E_windows; }
#define MWX_DEV_LOG(sc, ...) printf(__VA_ARGS__)
#define MWX_FLAG_SCANNING 0x1
static int nulls, ack_nulls;
struct mwx_softc;
static int mt7927_send_null_probe(struct mwx_softc *);
''' + fn(s, "mt7927_rx_from_bss", "static uint32_t") + fn(s, "mt7927_probe_ap", "static void") + \
   "static void mt7927_link_leave(struct mwx_softc *, const char *, uint32_t, uint32_t, uint32_t);\n" + \
   fn(s, "mt7927_link_watchdog", "static void") + fn(s, "mt7927_link_leave", "static void") + r'''
static int mt7927_send_null_probe(struct mwx_softc *sc) { nulls++; if (ack_nulls) sc->sc_7927_probe_acks++; return 0; }
int main() {
  ieee80211_node ap{}; ieee80211com ic{}; ic.ic_opmode = IEEE80211_M_STA; ic.ic_bss = &ap; ic.ic_if.if_xname = "mwx0";
  /* off unless the driver asks */
  ieee80211_assoc_begin(&ic, 0); assert(armed == -1);
  ic.ic_assoc_retry = 1; ic.ic_state = IEEE80211_S_ASSOC;
  ieee80211_assoc_begin(&ic, 1); assert(armed == 500 && ic.ic_assoc_tries == 1);
  armed = -1; ieee80211_assoc_timeout(&ic); assert(sends_assoc == 1 && last_arg == 1 && armed == 500 && ic.ic_assoc_tries == 2);
  armed = -1; ieee80211_assoc_timeout(&ic); assert(sends_assoc == 2 && ic.ic_assoc_tries == 3 && armed == 500);
  armed = -1; ieee80211_assoc_timeout(&ic); assert(sends_assoc == 2 && armed == -1);     /* 3 in all */
  /* comeback */
  ieee80211_assoc_begin(&ic, 0); armed = -1;
  ieee80211_assoc_comeback(&ic, 1000); assert(armed == 1024);
  ieee80211_assoc_comeback(&ic, 0); assert(armed == 1000);
  ieee80211_assoc_comeback(&ic, 100000); assert(armed == 2000);
  ieee80211_assoc_comeback(&ic, 1); assert(armed == 10);
  ic.ic_assoc_tries = 3; armed = -1; ieee80211_assoc_comeback(&ic, 1000); assert(armed == -1);
  /* not while a leave is on its way (state changes at the end of the task) */
  ic.ic_assoc_tries = 1; ic.ic_leave_pending = 1; { int k = sends_assoc; ieee80211_assoc_timeout(&ic); assert(sends_assoc == k); }
  ic.ic_leave_pending = 0;
  /* comeback does nothing when the driver did not ask for retries */
  ic.ic_assoc_retry = 0; armed = -1; ieee80211_assoc_comeback(&ic, 1000); assert(armed == -1); ic.ic_assoc_retry = 1;
  /* not out of ASSOC */
  ic.ic_assoc_tries = 1; ic.ic_state = IEEE80211_S_RUN; int n = sends_assoc; ieee80211_assoc_timeout(&ic); assert(sends_assoc == n);
  ic.ic_opmode = IEEE80211_M_HOSTAP; armed = -1; ieee80211_assoc_arm(&ic, 500); assert(armed == -1);

  /* link watchdog */
  mwx_softc sc{}; sc.sc_ic.ic_opmode = IEEE80211_M_STA; sc.sc_ic.ic_state = IEEE80211_S_RUN; sc.sc_ic.ic_bss = &ap; ap.ni_port_valid = 1;
  sc.sc_ic.ic_event_handler = evh; sc.sc_7927_assoc = true; sc.sc_7927_poll = 1000;
  E_rxt = 0; E_windows = 0;
  mt7927_link_watchdog(&sc);                       /* baseline */
  for (int i = 0; i < 40; i++) { sc.sc_7927_poll++; mt7927_link_watchdog(&sc); }
  /* window with no airtime but multicast from the AP: stay */
  sc.sc_7927_rx_mcast += 3; E_windows = 1; sc.sc_7927_poll++; mt7927_link_watchdog(&sc);
  assert(sends_probe == 0 && sc.sc_7927_wd_probes == 0 && newstates == 0);
  /* silent window: probe 1, management timer cleared */
  E_windows = 2; sc.sc_7927_poll++; mt7927_link_watchdog(&sc);
  assert(sends_probe == 1 && sc.sc_7927_wd_probes == 1 && sc.sc_ic.ic_mgt_timer == 0);
  /* scanning: probes held */
  sc.sc_flags = MWX_FLAG_SCANNING; sc.sc_7927_poll++; mt7927_link_watchdog(&sc); assert(sends_probe == 1 && sc.sc_7927_wd_probes == 1);
  sc.sc_flags = 0;
  /* answered: stay */
  sc.sc_7927_rx_bss_mgt++; sc.sc_7927_poll++; mt7927_link_watchdog(&sc);
  assert(sc.sc_7927_wd_probes == 0 && newstates == 0 && sends_deauth == 0);
  /* silent again: probes 1..3 then leave */
  E_windows = 3; sc.sc_7927_poll++; mt7927_link_watchdog(&sc); assert(sends_probe == 1);   /* the answer fell in this window */
  E_windows = 4; sc.sc_7927_poll++; mt7927_link_watchdog(&sc); assert(sends_probe == 2);
  sc.sc_7927_poll++; mt7927_link_watchdog(&sc); assert(sends_probe == 3 && sc.sc_7927_wd_probes == 2);
  sc.sc_7927_poll++; mt7927_link_watchdog(&sc); assert(sends_probe == 4 && sc.sc_7927_wd_probes == 3);
  sc.sc_7927_poll++; mt7927_link_watchdog(&sc);
  assert(sends_deauth == 1 && events == 1 && newstates == 1 && sc.sc_ic.ic_state == IEEE80211_S_AUTH && sc.sc_7927_recoveries == 1);
  assert(nulls == 4);                              /* a null frame with every probe */
  /* phase 4k: an acked null probe keeps the link (no frames otherwise) */
  sc.sc_ic.ic_state = IEEE80211_S_RUN; sc.sc_7927_run_polls = 0; sc.sc_7927_last_recovery = 0; mt7927_link_watchdog(&sc);
  for (int i = 0; i < 40; i++) { sc.sc_7927_poll++; mt7927_link_watchdog(&sc); }
  ack_nulls = 1; E_windows = 10; sc.sc_7927_poll++; mt7927_link_watchdog(&sc); assert(sends_probe == 5 && nulls == 5);
  sc.sc_7927_poll++; mt7927_link_watchdog(&sc); assert(sc.sc_7927_wd_probes == 0 && newstates == 1);
  ack_nulls = 0;
  /* airtime present: nothing */
  sc.sc_ic.ic_state = IEEE80211_S_RUN; sc.sc_7927_run_polls = 0; mt7927_link_watchdog(&sc);
  for (int i = 0; i < 40; i++) { sc.sc_7927_poll++; mt7927_link_watchdog(&sc); }
  E_rxt = 500; E_windows = 11; sc.sc_7927_poll++; mt7927_link_watchdog(&sc); assert(sends_probe == 5);
  printf("PASS\n"); return 0;
}
'''
with tempfile.TemporaryDirectory() as d:
    c = pathlib.Path(d) / "t.cpp"; c.write_text(code)
    exe = pathlib.Path(d) / "t"
    r = subprocess.run(["clang++", "-std=c++17", "-g", "-fsanitize=address,undefined", "-Wno-everything", str(c), "-o", str(exe)], capture_output=True, text=True)
    if r.returncode: print(r.stderr[:4000]); sys.exit(1)
    r = subprocess.run([str(exe)], capture_output=True, text=True); print(r.stdout[-1500:], r.stderr[-1500:])
    sys.exit(r.returncode)
