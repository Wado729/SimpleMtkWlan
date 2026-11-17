#!/usr/bin/env python3
"""Phase 4x: the MT7927 newstate task (mt7927_newstate, real code, stubbed HAL).

  - R2: an ASSOC that runs after a SCAN task (ic_state SCAN) is not passed
    to net80211 (SCAN -> ASSOC sends nothing and waits 5 s): the scan
    running goes on, or a new one is queued; mwx_newstate's queued state is
    put back so a later ASSOC is not skipped as a repeat; AUTH -> ASSOC as
    before;
  - R3: the 4r sweep cancel runs on the command gate;
  - C5: the drop log files a RUN exit as voluntary only when macOS left
    and nothing from outside came first (ic_drop_involuntary), and clears
    the latch; entering RUN clears it too;
  - R10: an Authentication frame that cannot be sent arms ic_mgt_timer
    (ieee80211_send_auth_req, net80211).
"""
import pathlib, subprocess, sys, tempfile
root = pathlib.Path(__file__).resolve().parents[2]
s = (root / "SimpleMtkWlan/hal_mwx/MtkMwx.cpp").read_text()
pr = (root / "mtk80211/openbsd/net80211/ieee80211_proto.c").read_text()
def fn(sig, rtype, src=None):
    src = s if src is None else src
    i = src.index(rtype + "\n" + sig + "(")
    return src[i:src.index("\n}\n", i) + 3]
code = r'''
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cassert>
#include <string>
#define AIRPORT_WCL 1
typedef int IOReturn;
enum { kIOReturnSuccess = 0, kIOReturnNotReady = 0x2d8 };
enum ieee80211_state { IEEE80211_S_INIT, IEEE80211_S_SCAN, IEEE80211_S_AUTH, IEEE80211_S_ASSOC, IEEE80211_S_RUN };
static const char *ieee80211_state_name[] = { "INIT", "SCAN", "AUTH", "ASSOC", "RUN" };
enum { IEEE80211_M_STA = 1, IEEE80211_M_MONITOR = 8 };
#define IEEE80211_F_TX_MGMT_ONLY 0x1
#define MWX_FLAG_SCANNING 0x1
struct OSObject {};
struct ifn { const char *if_xname; short if_timer; };
struct ieee80211com { int ic_opmode, ic_state; uint8_t ic_leave_pending, ic_drop_involuntary; uint32_t ic_xflags;
  ifn ic_if; int ic_mgt_timer;
  bool ic_wcl_join_requested, ic_wcl_scan_requested; uint8_t ic_wcl_join_chan6g, ic_wcl_join_scans; };
struct mt7927_bss { uint8_t bssid[6]; };
struct mwx_softc { ieee80211com sc_ic; int sc_flags; bool sc_7927_scan_nstate, sc_7927_scan6g; mt7927_bss sc_7927_bss;
  enum ieee80211_state sc_ns_state; int (*sc_newstate)(ieee80211com *, enum ieee80211_state, int); };
#define MWX_DEV_LOG(sc, ...) printf(__VA_ARGS__)
static const char *ether_sprintf(const uint8_t *) { return "ap"; }
static std::string snap_why; static int snaps, snap_vol = -1, teardowns, scans, prepares, assocs, aborts, gated, in_gate;
static int net_calls, net_last = -1, queued = -1;
static void mtk_dbg_snapshot(const char *why, bool v) { snaps++; snap_why = why; snap_vol = v; }
static void mtk_dbg_publish() {}
static void mt7927_join_teardown(mwx_softc *, const char *) { teardowns++; }
static int mwx_scan(mwx_softc *sc) { scans++; sc->sc_flags |= MWX_FLAG_SCANNING; return 0; }
static int mt7927_join_prepare(mwx_softc *) { prepares++; return 0; }
static int mt7927_join_assoc(mwx_softc *) { assocs++; return 0; }
static IOReturn mt7927_abort_scan_for_join(mwx_softc *) { assert(in_gate); aborts++; return kIOReturnSuccess; }
static mwx_softc *the_sc;
static void ieee80211_new_state(ieee80211com *, int st, int) { queued = st; the_sc->sc_ns_state = (enum ieee80211_state)st; }
static int net_newstate(ieee80211com *ic, enum ieee80211_state st, int) { net_calls++; net_last = st; ic->ic_state = st; return 0; }
typedef IOReturn (*Action)(OSObject *, void *, void *, void *, void *);
struct IOCommandGate { IOReturn runAction(Action a, void *a0) { gated++; in_gate = 1; IOReturn r = a(nullptr, a0, nullptr, nullptr, nullptr); in_gate = 0; return r; } };
static IOCommandGate the_gate;
struct MtkMwx { IOCommandGate *mwxGate() { return &the_gate; } };
static MtkMwx hal, *gMwxHal = &hal;
/* R10: net80211's Authentication request */
struct ieee80211_node { uint8_t ni_macaddr[6]; };
#define IEEE80211_FC0_SUBTYPE_AUTH 0xb0
#define IEEE80211_TRANS_WAIT 5
#define XYLog(...) printf(__VA_ARGS__)
static int send_rv, auth_sends;
#define IEEE80211_SEND_MGMT(ic, ni, t, a) (auth_sends++, send_rv)
''' + fn("ieee80211_send_auth_req", "static void", pr) + fn("mt7927_join_scan_abort_action", "static IOReturn") + fn("mt7927_newstate", "static void") + r'''
static void task(mwx_softc *sc) {          /* mwx_newstate_task */
  mt7927_newstate(sc, (enum ieee80211_state)sc->sc_ic.ic_state, sc->sc_ns_state, 0);
}
int main() {
  mwx_softc sc{}; the_sc = &sc; sc.sc_newstate = net_newstate; sc.sc_ic.ic_opmode = IEEE80211_M_STA;
  ieee80211com *ic = &sc.sc_ic;
  /* R2: AUTH (SAE accepted) -> ASSOC as before */
  ic->ic_state = IEEE80211_S_AUTH; sc.sc_ns_state = IEEE80211_S_ASSOC; task(&sc);
  assert(net_calls == 1 && net_last == IEEE80211_S_ASSOC);
  /* R2: a SCAN task ran first (scan running), then the queued ASSOC */
  ic->ic_state = IEEE80211_S_SCAN; sc.sc_flags = MWX_FLAG_SCANNING; sc.sc_ns_state = IEEE80211_S_ASSOC; queued = -1;
  task(&sc);
  assert(net_calls == 1 && ic->ic_state == IEEE80211_S_SCAN && queued == -1);
  assert(sc.sc_ns_state == IEEE80211_S_SCAN);      /* a later ASSOC is no "repeat" */
  /* no scan running: a new one is queued */
  sc.sc_flags = 0; sc.sc_ns_state = IEEE80211_S_ASSOC; task(&sc);
  assert(net_calls == 1 && queued == IEEE80211_S_SCAN && ic->ic_state == IEEE80211_S_SCAN);
  /* down (INIT): dropped, nothing started */
  ic->ic_state = IEEE80211_S_INIT; sc.sc_ns_state = IEEE80211_S_ASSOC; queued = -1; task(&sc);
  assert(net_calls == 1 && queued == -1 && sc.sc_ns_state == IEEE80211_S_INIT);
  /* something else queued meanwhile: kept */
  ic->ic_state = IEEE80211_S_SCAN; sc.sc_flags = MWX_FLAG_SCANNING;
  sc.sc_ns_state = IEEE80211_S_AUTH; mt7927_newstate(&sc, IEEE80211_S_SCAN, IEEE80211_S_ASSOC, 0);
  assert(sc.sc_ns_state == IEEE80211_S_AUTH && net_calls == 1);

  /* R3: the 4r cancel of a sweep for a 6 GHz join, on the gate */
  ic->ic_wcl_join_requested = true; ic->ic_wcl_join_chan6g = 37; sc.sc_7927_scan6g = true;
  ic->ic_leave_pending = 1; ic->ic_xflags = IEEE80211_F_TX_MGMT_ONLY;
  sc.sc_ns_state = IEEE80211_S_SCAN; task(&sc);
  assert(gated == 1 && aborts == 1 && !ic->ic_leave_pending && ic->ic_xflags == 0 && net_calls == 1);
  ic->ic_wcl_join_chan6g = 38; task(&sc); assert(gated == 2 && aborts == 1);   /* not a 6 GHz 20 MHz primary */
  ic->ic_wcl_join_chan6g = 0; ic->ic_wcl_join_requested = false;

  /* C5: drop log labels */
  ic->ic_state = IEEE80211_S_RUN; ic->ic_leave_pending = 1; ic->ic_drop_involuntary = 0;
  sc.sc_flags = 0; sc.sc_ns_state = IEEE80211_S_SCAN; task(&sc);
  assert(snaps == 1 && snap_vol == 1 && snap_why.find("macOS left") != std::string::npos);
  /* the AP's deauth, then macOS's fast leave: lost, not voluntary */
  ic->ic_state = IEEE80211_S_RUN; ic->ic_leave_pending = 1; ic->ic_drop_involuntary = 1;
  sc.sc_flags = 0; task(&sc);
  assert(snaps == 2 && snap_vol == 0 && snap_why.find("macOS left") == std::string::npos &&
         snap_why.find(", lost") != std::string::npos && ic->ic_drop_involuntary == 0);
  /* the watchdog's leave alone */
  ic->ic_state = IEEE80211_S_RUN; ic->ic_leave_pending = 0; ic->ic_drop_involuntary = 1;
  sc.sc_ns_state = IEEE80211_S_AUTH; task(&sc);
  assert(snaps == 3 && snap_vol == 0 && ic->ic_drop_involuntary == 0 && prepares == 1);
  /* review: entering RUN starts with no drop latched (one left from before can't label this link) */
  ic->ic_state = IEEE80211_S_ASSOC; ic->ic_drop_involuntary = 1; sc.sc_ns_state = IEEE80211_S_RUN;
  { int n = net_calls; task(&sc); assert(net_calls == n + 1 && net_last == IEEE80211_S_RUN && assocs == 1); }
  assert(ic->ic_drop_involuntary == 0);
  ic->ic_leave_pending = 1; sc.sc_ns_state = IEEE80211_S_SCAN; task(&sc);
  assert(snaps == 4 && snap_vol == 1);               /* macOS's leave later: voluntary */
  /* R10: an Authentication frame that cannot be sent still arms the 5 s timer */
  ieee80211_node ap{}; ic->ic_if.if_xname = "mwx0"; ic->ic_opmode = IEEE80211_M_STA;
  ic->ic_mgt_timer = 0; send_rv = 0; ieee80211_send_auth_req(ic, &ap, 1);
  assert(auth_sends == 1 && ic->ic_mgt_timer == 0);      /* sent: ieee80211_send_mgmt arms it */
  send_rv = 55; ieee80211_send_auth_req(ic, &ap, 1);
  assert(auth_sends == 2 && ic->ic_mgt_timer == IEEE80211_TRANS_WAIT && ic->ic_if.if_timer == 1);
  printf("PASS\n"); return 0;
}
'''
with tempfile.TemporaryDirectory() as d:
    c = pathlib.Path(d) / "t.cpp"; c.write_text(code); exe = pathlib.Path(d) / "t"
    r = subprocess.run(["clang++", "-std=c++17", "-g", "-fsanitize=address,undefined", "-Wno-everything", str(c), "-o", str(exe)], capture_output=True, text=True)
    if r.returncode: print(r.stderr[:4000]); sys.exit(1)
    r = subprocess.run([str(exe)], capture_output=True, text=True); print(r.stdout[-2500:], r.stderr[-1500:])
    sys.exit(r.returncode)
