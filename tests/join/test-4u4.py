"""Phase 4u.4: a "not authenticated" deauth right after authentication
(state ASSOC, from our AP, reason 9 or 6) authenticates again at the next
1 s tick, once per join; the front end sees ic_deauth_retrying. Other
reasons, other states, or a second time: as before (the 5 s timer)."""
import pathlib, subprocess, sys, tempfile
root = pathlib.Path(__file__).resolve().parents[2]
src = (root / "mtk80211/openbsd/net80211/ieee80211_input.c").read_text()
a = src.index("ieee80211_recv_deauth(struct ieee80211com *ic, mbuf_t m,")
fn = "void\n" + src[a:src.index("\n}\n", a) + 3]
code = r'''
#include <cstdint>
#include <cstdio>
#include <cassert>
#include <cstring>
typedef uint8_t u_int8_t; typedef uint16_t u_int16_t;
#define XYLog(...) ((void)0)
#define DPRINTF(x) ((void)0)
#define IEEE80211_M_STA 1
#define IEEE80211_M_HOSTAP 6
#define IEEE80211_STA_ONLY 1
enum { IEEE80211_S_INIT, IEEE80211_S_SCAN, IEEE80211_S_AUTH, IEEE80211_S_ASSOC, IEEE80211_S_RUN };
#define IEEE80211_FC0_SUBTYPE_DEAUTH 0xc0
#define IEEE80211_F_BGSCAN 1
#define IEEE80211_F_DISABLE_BG_AUTO_CONNECT 2
#define IEEE80211_F_STAYAUTH 4
#define IEEE80211_EVT_STA_DEAUTH 7
#define IEEE80211_REASON_NOT_AUTHED 6
#define IEEE80211_REASON_ASSOC_NOT_AUTHED 9
#define LE_READ_2(p) ((uint16_t)((p)[0] | ((p)[1] << 8)))
struct ieee80211_frame { uint8_t hdr[24]; };
struct ieee80211_node { int x; };
struct _mbuf { uint8_t data[64]; size_t len; };
typedef _mbuf *mbuf_t;
static size_t mbuf_len(mbuf_t m) { return m->len; }
#define mtod(m, t) ((t)(m)->data)
struct ieee80211com;
struct stats { unsigned is_rx_deauth; };
struct ieee80211com {
  int ic_opmode, ic_state, ic_flags, ic_userflags; bool ic_leave_pending;
  uint16_t ic_deauth_reason; uint8_t ic_notauth_retries; bool ic_deauth_retrying, ic_notauth_pending;
  int ic_mgt_timer; ieee80211_node *ic_bss; stats ic_stats;
  void (*ic_event_handler)(ieee80211com *, int, void *);
};
static int newstates, seen_retrying = -1;
static void ieee80211_new_state(ieee80211com *ic, int s, int) { newstates++; ic->ic_state = s; }
static void evh(ieee80211com *ic, int e, void *) { if (e == IEEE80211_EVT_STA_DEAUTH) seen_retrying = ic->ic_deauth_retrying; }
''' + fn + r'''
static void deauth(ieee80211com *ic, ieee80211_node *ni, int reason) {
  _mbuf m{}; m.len = 26; m.data[24] = reason & 0xff; m.data[25] = reason >> 8;
  ieee80211_recv_deauth(ic, &m, ni);
}
int main() {
  ieee80211_node bss{}, other{};
  ieee80211com ic{}; ic.ic_opmode = IEEE80211_M_STA; ic.ic_bss = &bss; ic.ic_event_handler = evh;
  /* reason 9 in ASSOC from our AP: retry at the next tick, front end told */
  ic.ic_state = IEEE80211_S_ASSOC; ic.ic_mgt_timer = 5;
  deauth(&ic, &bss, 9);
  assert(seen_retrying == 1 && ic.ic_state == IEEE80211_S_AUTH && ic.ic_mgt_timer == 1 && ic.ic_notauth_retries == 1);
  assert(ic.ic_notauth_pending && !ic.ic_deauth_retrying);   /* only during the event */
  /* review: another one before the new authentication started: same retry */
  ic.ic_mgt_timer = 3;
  deauth(&ic, &bss, 9);
  assert(seen_retrying == 1 && ic.ic_mgt_timer == 1 && ic.ic_notauth_retries == 1);
  /* the new authentication started (join_bss clears pending); a second failure: as before */
  ic.ic_notauth_pending = false;
  ic.ic_state = IEEE80211_S_ASSOC; ic.ic_mgt_timer = 5;
  deauth(&ic, &bss, 9);
  assert(seen_retrying == 0 && ic.ic_mgt_timer == 5);
  /* a new join (counter reset), reason 6 also */
  ic.ic_notauth_retries = 0; ic.ic_notauth_pending = false; ic.ic_state = IEEE80211_S_ASSOC; ic.ic_mgt_timer = 4;
  deauth(&ic, &bss, 6);
  assert(seen_retrying == 1 && ic.ic_mgt_timer == 1);
  /* other reasons, other states, other senders: as before */
  ic.ic_notauth_retries = 0; ic.ic_notauth_pending = false; ic.ic_state = IEEE80211_S_ASSOC; ic.ic_mgt_timer = 5;
  deauth(&ic, &bss, 3); assert(seen_retrying == 0 && ic.ic_mgt_timer == 5 && ic.ic_notauth_retries == 0);
  ic.ic_state = IEEE80211_S_RUN; ic.ic_mgt_timer = 0;
  deauth(&ic, &bss, 9); assert(seen_retrying == 0 && ic.ic_notauth_retries == 0);
  ic.ic_state = IEEE80211_S_ASSOC; ic.ic_mgt_timer = 5;
  deauth(&ic, &other, 9); assert(seen_retrying == 0 && ic.ic_notauth_retries == 0);
  /* leaving: ignored entirely */
  ic.ic_leave_pending = true; ic.ic_state = IEEE80211_S_ASSOC; seen_retrying = -1;
  deauth(&ic, &bss, 9); assert(seen_retrying == -1);
  puts("PASS: reason 9/6 right after authentication retries at once, once per join");
  return 0;
}
'''
with tempfile.TemporaryDirectory() as d:
    c = pathlib.Path(d) / "t.cpp"; c.write_text(code)
    exe = pathlib.Path(d) / "t"
    r = subprocess.run(["clang++", "-std=c++17", "-g", "-fsanitize=address,undefined", "-Wno-everything", str(c), "-o", str(exe)], capture_output=True, text=True)
    if r.returncode: print(r.stderr[:4000]); sys.exit(1)
    r = subprocess.run([str(exe)], capture_output=True, text=True); print(r.stdout, r.stderr[-1500:])
    sys.exit(r.returncode)
