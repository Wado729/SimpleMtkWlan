#!/usr/bin/env python3
"""Phase 4x: how a roam ends, and two front-end fixes, on the real WCL.cpp code.

Extracts AirportItlwmSkywalkInterface::abortWCLRoam, finishWCLRoam,
notifyWCLFirstBeacon, retryWCLFirstBeacon and clearRoamScan, compiled against
a stub of the interface:
  - abortWCLRoam (macOS's leave or join, the driver stopping): WCL gets the
    roam completion with the given status, the timer stops, the link names
    the old AP again, nothing is left by the driver; only once;
  - finishWCLRoam(false) (the 10 s timer): completion "timeout", the target
    blocked for 5 minutes, the old AP named, then a real leave and the held
    link down; success without the new AP's BSS counts as a failure;
    success: reassoc, link up with the new BSSID, completion 0, no leave;
  - R8: a first beacon before RUN is held, a 20 ms timer looks for RUN
    (bounded) and sends link up + first beacon there;
  - C1: a roam scan given up clears its request flags unless macOS's own
    scan request holds them.
"""
import pathlib, subprocess, sys, tempfile
root = pathlib.Path(__file__).resolve().parents[2]
w = (root / "AirportMtkWlan/WCL/WCL.cpp").read_text()
def member(name):
    i = w.index("void AirportItlwmSkywalkInterface::" + name + "(")
    return w[i:w.index("\n}\n", i) + 3]
def const(name):
    i = w.index(name + " = ")
    j = w.rindex("static constexpr", 0, i)
    return w[j:w.index(";", i) + 1] + "\n"
code = r'''
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cassert>
#include <cstddef>
#include <vector>
typedef int IOReturn;
enum { kIOReturnSuccess = 0, kIOReturnTimeout = 0x2d6, kIOReturnAborted = 0x2eb, kIOReturnOffline = 0x2c9 };
enum { IEEE80211_S_INIT, IEEE80211_S_SCAN, IEEE80211_S_AUTH, IEEE80211_S_ASSOC, IEEE80211_S_RUN };
#define XYLog(...) printf(__VA_ARGS__)
static const char *ether_sprintf(const uint8_t *) { return "ap"; }
static uint64_t now_ms = 100000;
static uint64_t airport_up_time() { return now_ms; }
namespace AirportWCL {
enum { FirstBeacon = 212, LinkStatus = 216, Reassoc = 73, RoamDone = 80 };
struct ReassocEvent { uint32_t status, reason; };
struct RoamStatus { uint32_t status, reason; uint64_t startTime, endTime; uint8_t reserved[0xa8 - 0x18]; };
static constexpr uint32_t kRoamReasonLowRSSI = 0xe0820c01;
struct ConnectionPeer { uint8_t bssid[6]; uint8_t pad[2]; uint32_t driverStatus; };
struct FirstBeaconEvent { uint16_t status, reason; ConnectionPeer peer; };
struct LinkStatusEvent { uint8_t bssid[6]; uint8_t up, inSleep; uint32_t reason, reserved; };
}
struct IOTimerEventSource { int armed = -1; void setTimeoutMS(uint32_t ms) { armed = int(ms); } void cancelTimeout() { armed = -1; } };
struct ieee80211com { int ic_state; bool ic_wcl_scan_requested, ic_wcl_scan_restricted; };
struct Hal { ieee80211com ic{}; ieee80211com *get80211Controller() { return &ic; } };
struct Msg { int id; uint32_t status; uint8_t up; uint8_t bssid[6]; };
struct Instance {
  std::vector<Msg> msgs;
  void postMessage(void *, int id, const void *data, size_t len, bool) {
    Msg m{}; m.id = id;
    if (id == AirportWCL::RoamDone) m.status = static_cast<const AirportWCL::RoamStatus *>(data)->status;
    if (id == AirportWCL::LinkStatus) { auto l = static_cast<const AirportWCL::LinkStatusEvent *>(data); m.up = l->up; memcpy(m.bssid, l->bssid, 6); }
    msgs.push_back(m);
  }
};
''' + const("kRoamBlockMs") + const("kFirstBeaconRetryMs") + const("kFirstBeaconRetries") + r'''
struct AirportItlwmSkywalkInterface {
  Instance *instance; Hal *fHalService;
  IOTimerEventSource *joinTimer, *firstBeaconTimer;
  bool roamPending = false, roamScanPending = false, scanPending = false, joinPending = false;
  bool assocNotified = false, firstBeaconNotified = false, firstBeaconDeferredLogged = false;
  bool wclBssValid = false, wclLinkIndicated = false, portAuthorized = false;
  uint8_t firstBeaconRetries = 0; uint32_t wclJoinBeacons = 0;
  uint8_t joinBSSID[6] = {}, roamFromBSSID[6] = {}, roamBlockBSSID[6] = {};
  uint64_t roamStartMs = 0, roamBlockUntilMs = 0, linkUpMs = 0;
  bool publishOK = true; int leaves = 0, syncs = 0, finishes = 0, finishStatus = -1;
  bool publishRoamBss() { return publishOK; }
  IOReturn leaveWCLNetwork(const char *) { leaves++; return 0; }
  void syncLinkAfterRoam() { syncs++; }
  void updateWCLLinkQuality(bool = false) {}
  void finishWCLJoin(uint16_t st, uint16_t, IOReturn) { finishes++; finishStatus = st; }
  void abortWCLRoam(IOReturn, const char *);
  void finishWCLRoam(bool, const char *);
  void notifyWCLFirstBeacon(const char *);
  void retryWCLFirstBeacon();
  void clearRoamScan();
};
''' + member("abortWCLRoam") + member("finishWCLRoam") + member("notifyWCLFirstBeacon") + \
      member("retryWCLFirstBeacon") + member("clearRoamScan") + r'''
static const uint8_t OLD[6] = {0x42,0x00,0x00,0x00,0x03,0x71}, NEW[6] = {0x72,0x00,0x00,0x00,0x03,0x4d};
static void roaming(AirportItlwmSkywalkInterface &s) {
  s.roamPending = true; memcpy(s.roamFromBSSID, OLD, 6); memcpy(s.joinBSSID, NEW, 6);
  s.joinTimer->setTimeoutMS(10000); s.instance->msgs.clear(); s.leaves = s.syncs = 0;
}
int main() {
  Instance inst; Hal hal; IOTimerEventSource jt, ft;
  AirportItlwmSkywalkInterface s; s.instance = &inst; s.fHalService = &hal; s.joinTimer = &jt; s.firstBeaconTimer = &ft;
  /* abandoned (macOS left): completion with that status, old AP named, no leave of its own */
  roaming(s); s.abortWCLRoam(kIOReturnAborted, "macOS");
  assert(!s.roamPending && jt.armed == -1 && inst.msgs.size() == 1 && inst.msgs[0].id == AirportWCL::RoamDone);
  assert(inst.msgs[0].status == uint32_t(kIOReturnAborted) && memcmp(s.joinBSSID, OLD, 6) == 0 && s.leaves == 0);
  s.abortWCLRoam(kIOReturnAborted, "again"); assert(inst.msgs.size() == 1);      /* only once */
  s.finishWCLRoam(false, "late"); assert(inst.msgs.size() == 1 && s.leaves == 0);
  /* timed out: completion "timeout", target blocked 5 min, old AP named, real leave + link down */
  roaming(s); s.finishWCLRoam(false, "timeout");
  assert(!s.roamPending && jt.armed == -1 && inst.msgs.size() == 1 && inst.msgs[0].id == AirportWCL::RoamDone);
  assert(inst.msgs[0].status == uint32_t(kIOReturnTimeout));
  assert(memcmp(s.roamBlockBSSID, NEW, 6) == 0 && s.roamBlockUntilMs == now_ms + kRoamBlockMs);
  assert(memcmp(s.joinBSSID, OLD, 6) == 0 && s.leaves == 1 && s.syncs == 1);
  /* port authorized but no BSS of the new AP for WCL: a failure too */
  roaming(s); memset(s.roamBlockBSSID, 0, 6); s.publishOK = false; s.finishWCLRoam(true, "port authorized");
  assert(inst.msgs.back().status == uint32_t(kIOReturnTimeout) && s.leaves == 1 && memcmp(s.roamBlockBSSID, NEW, 6) == 0);
  /* done: reassoc, link up with the new BSSID, completion 0, no leave */
  roaming(s); s.publishOK = true; now_ms += 5000; s.finishWCLRoam(true, "port authorized");
  assert(inst.msgs.size() == 3 && inst.msgs[0].id == AirportWCL::Reassoc && inst.msgs[1].id == AirportWCL::LinkStatus);
  assert(inst.msgs[1].up == 1 && memcmp(inst.msgs[1].bssid, NEW, 6) == 0);
  assert(inst.msgs[2].id == AirportWCL::RoamDone && inst.msgs[2].status == 0 && s.leaves == 0 && s.linkUpMs == now_ms);
  assert(s.assocNotified && s.firstBeaconNotified && memcmp(s.joinBSSID, NEW, 6) == 0);

  /* R8: a first beacon before RUN is held; the timer sends it in RUN */
  inst.msgs.clear(); s.joinPending = true; s.assocNotified = true; s.firstBeaconNotified = false;
  s.wclBssValid = true; s.portAuthorized = false; s.firstBeaconDeferredLogged = false; s.firstBeaconRetries = 0;
  hal.ic.ic_state = IEEE80211_S_ASSOC;
  s.notifyWCLFirstBeacon("beacon");
  assert(inst.msgs.empty() && s.firstBeaconDeferredLogged && ft.armed == int(kFirstBeaconRetryMs) && !s.firstBeaconNotified);
  ft.armed = -1; s.retryWCLFirstBeacon();                    /* the timer: still not RUN */
  assert(inst.msgs.empty() && s.firstBeaconRetries == 1 && ft.armed == int(kFirstBeaconRetryMs));
  hal.ic.ic_state = IEEE80211_S_RUN; s.retryWCLFirstBeacon();   /* RUN: link up, first beacon */
  assert(inst.msgs.size() == 2 && inst.msgs[0].id == AirportWCL::LinkStatus && inst.msgs[0].up == 1);
  assert(inst.msgs[1].id == AirportWCL::FirstBeacon && s.firstBeaconNotified && s.wclLinkIndicated && ft.armed == -1);
  assert(s.finishes == 0);                                     /* port not authorized yet */
  s.retryWCLFirstBeacon(); assert(inst.msgs.size() == 2);       /* once */
  /* bounded while RUN never comes; nothing without a held beacon */
  inst.msgs.clear(); s.firstBeaconNotified = false; s.firstBeaconRetries = 0; hal.ic.ic_state = IEEE80211_S_ASSOC;
  s.notifyWCLFirstBeacon("beacon");
  for (int i = 0; i < 200 && ft.armed != -1; i++) { ft.armed = -1; s.retryWCLFirstBeacon(); }
  assert(ft.armed == -1 && s.firstBeaconRetries == kFirstBeaconRetries && inst.msgs.empty());
  s.firstBeaconDeferredLogged = false; s.firstBeaconRetries = 0; hal.ic.ic_state = IEEE80211_S_RUN;
  s.retryWCLFirstBeacon(); assert(inst.msgs.empty() && s.firstBeaconRetries == 0);
  /* 4n kept: in RUN at once, with the port authorized the join completes */
  s.portAuthorized = true; s.notifyWCLFirstBeacon("beacon");
  assert(inst.msgs.size() == 2 && s.finishes == 1 && s.finishStatus == 0);

  /* C1: a roam scan given up takes its request flags along ... */
  s.roamScanPending = true; s.scanPending = false; hal.ic.ic_wcl_scan_requested = hal.ic.ic_wcl_scan_restricted = true;
  s.clearRoamScan(); assert(!s.roamScanPending && !hal.ic.ic_wcl_scan_requested && !hal.ic.ic_wcl_scan_restricted);
  /* ... not macOS's, nor flags it did not set */
  s.roamScanPending = true; s.scanPending = true; hal.ic.ic_wcl_scan_requested = hal.ic.ic_wcl_scan_restricted = true;
  s.clearRoamScan(); assert(!s.roamScanPending && hal.ic.ic_wcl_scan_requested && hal.ic.ic_wcl_scan_restricted);
  s.scanPending = false; s.clearRoamScan(); assert(hal.ic.ic_wcl_scan_requested && hal.ic.ic_wcl_scan_restricted);
  puts("PASS: roam abandon/timeout/done; first beacon held until RUN; roam scan flags");
  return 0;
}
'''
with tempfile.TemporaryDirectory() as d:
    c = pathlib.Path(d) / "t.cpp"; c.write_text(code); exe = pathlib.Path(d) / "t"
    r = subprocess.run(["clang++", "-std=c++17", "-g", "-fsanitize=address,undefined", "-Wno-everything", str(c), "-o", str(exe)], capture_output=True, text=True)
    if r.returncode: print(r.stderr[:4000]); sys.exit(1)
    r = subprocess.run([str(exe)], capture_output=True, text=True); print(r.stdout[-1500:], r.stderr[-1500:])
    sys.exit(r.returncode)
