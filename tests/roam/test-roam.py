#!/usr/bin/env python3
"""Phase 4u/4w: the roam decision (AirportWCL::roamProfile, roamWanted,
nextRoamScanMs, roamConfirmed).

Extracts the real functions from WCL.hpp. 4w: a Mac's roam profile per band
of the current BSS, IO80211's default profile 0 (printRoamingBracket,
Sequoia 15.8.1): roam only at or below -70 dBm on 6 GHz (-75 dBm on 2.4 and
5 GHz) and to an AP at least 12 dB stronger; roam scans 30 s apart, doubling
up to 180 s, a wide one first and then every 90 s (fullscan_period); the
cadence starts over only 3 dB above the trigger. (airportd on AC power asks
for 20 s to 90 s, full scan 120 s, but our driver returns Unsupported to
WCL_ROAM_PROFILE_CONFIG; we keep the conservative default.)
4u: go only on a second, newer reading of the same AP (one reading from one
scan is not enough); a different AP or the same reading again re-arms; 4w
review: at most two early (15 s) confirming scans per AP armed.
"""
from pathlib import Path
import subprocess, tempfile, re
root = Path(__file__).resolve().parents[2]
s = (root / 'AirportMtkWlan/WCL/WCL.hpp').read_text()
def grab(start, end_marker):
    i = s.index(start)
    return s[i:s.index(end_marker, i) + len(end_marker)]
profile = grab('enum RoamBand {', '\n}\n')
wanted = grab('inline bool roamWanted(', '\n}\n')
nextscan = grab('inline uint64_t nextRoamScanMs(', '\n}\n')
reset = grab('static constexpr int kRoamResetHysteresisDb', '\n}\n')
widef = grab('inline bool roamScanWide(', '\n}\n')
set6g = grab('inline bool set6gChannel(', '\n}\n')
confirm = grab('struct RoamConfirm {', '\n}\n')
pre = '#include <cassert>\n#include <cstdint>\n#include <cstdio>\n#include <cstring>\n#include <cstddef>\nnamespace AirportWCL {\n'
main = r'''
}
using namespace AirportWCL;
int main() {
    const RoamProfile p2 = roamProfile(kRoamBand2g), p5 = roamProfile(kRoamBand5g),
        p6 = roamProfile(kRoamBand6g);
    /* 6 GHz, Band:2 Index 0 RSSI[-70,-128] C6g(12,..) */
    assert(p6.triggerDbm == -70 && p6.deltaDb == 12);
    assert(!roamWanted(p6, -69, -40));      /* link not weak */
    assert(roamWanted(p6, -70, -58));       /* exactly -70 and +12 */
    assert(!roamWanted(p6, -70, -59));      /* +11 only */
    assert(roamWanted(p6, -84, -71));       /* 4u.1 hardware: far -84 to near -71 */
    assert(!roamWanted(p6, -76, -85));      /* the Nov 17 log: near -76, far -85 */
    assert(!roamWanted(p6, -72, -64));      /* the old -72/+8 rule's edge: not now */
    /* 2.4 and 5 GHz, Band:0/1 Index 1 RSSI[-75,-128] C2g/C5g(12,..) */
    assert(p2.triggerDbm == -75 && p2.deltaDb == 12);
    assert(p5.triggerDbm == -75 && p5.deltaDb == 12);
    assert(!roamWanted(p5, -74, -40) && !roamWanted(p2, -74, -40));
    assert(roamWanted(p5, -75, -63) && roamWanted(p2, -75, -63));
    assert(!roamWanted(p5, -75, -64) && !roamWanted(p2, -75, -64));
    /* Scan(2,90,30,2,180,..) on every band: 30, 60, 120, 180, 180 s */
    const RoamProfile all[3] = {p2, p5, p6};
    for (const RoamProfile &p : all) {
        assert(p.initScanMs == 30000 && p.backoff == 2 && p.maxScanMs == 180000);
        uint64_t iv = 0;
        const uint64_t want[6] = {30000, 60000, 120000, 180000, 180000, 180000};
        for (int i = 0; i < 6; i++) {
            iv = nextRoamScanMs(p, iv);
            assert(iv == want[i]);
        }
        assert(nextRoamScanMs(p, 0) == 30000);         /* reset: the first again */
        assert(p.fullScanMs == 90000);
    }
    /* review: hysteresis, the cadence starts over only 3 dB above the trigger */
    assert(!roamScanReset(p6, -69) && !roamScanReset(p6, -68) && roamScanReset(p6, -67));
    assert(!roamScanReset(p5, -73) && roamScanReset(p5, -72) && roamScanReset(p2, -72));
    {   /* an average flapping -71/-69 at the 6 GHz trigger still backs off */
        uint64_t iv = 0;
        for (int tick = 0; tick < 10; tick++) {
            int cur = (tick & 1) ? -69 : -71;
            if (cur > p6.triggerDbm) {
                if (roamScanReset(p6, cur)) iv = 0;
            } else {
                iv = nextRoamScanMs(p6, iv);
            }
        }
        assert(iv == 180000);
    }
    /* review: wide first after a reset, then once per fullscan_period */
    assert(roamScanWide(p6, 0, 5000));
    assert(!roamScanWide(p6, 5000, 35000) && !roamScanWide(p6, 5000, 94999));
    assert(roamScanWide(p6, 5000, 95000));
    {   /* once 90 s or more apart, every scan is wide */
        uint64_t t = 0, last = 0, iv = 0; int wides = 0;
        for (int i = 0; i < 8; i++) {
            if (roamScanWide(p6, last, t + 1000)) { last = t + 1000; wides++; }
            iv = nextRoamScanMs(p6, iv); t += iv;
        }
        /* scans at 1, 31, 91, 211, 391, ... s: all wide but the one at 31 */
        assert(wides == 7);
    }
    const uint8_t a[6] = {0x72,0x00,0x00,0x00,0x03,0x4d}, b[6] = {0x42,0x00,0x00,0x00,0x03,0x71};
    RoamConfirm c = {};
    assert(!roamConfirmed(c, a, 1000));     /* first reading arms */
    assert(!roamConfirmed(c, a, 1000));     /* same reading again: still waiting */
    assert(roamConfirmed(c, a, 25000));     /* a newer reading: go */
    assert(!c.armed);
    assert(!roamConfirmed(c, a, 30000));    /* after a go: arms again */
    assert(!roamConfirmed(c, b, 31000));    /* another AP: re-arms for it */
    assert(roamConfirmed(c, b, 52000));
    /* review: quickScans, the early confirming scans, per AP armed */
    RoamConfirm q = {};
    assert(!roamConfirmed(q, a, 1000) && q.quickScans == 0);
    q.quickScans = kRoamConfirmQuickScans;
    assert(!roamConfirmed(q, a, 1000) && q.quickScans == 2);  /* same AP: kept */
    assert(!roamConfirmed(q, b, 2000) && q.quickScans == 2);  /* another AP, same episode: kept */
    /* A, B, A, B alternating as the best: the count stays capped */
    for (int i = 0; i < 6; i++) assert(!roamConfirmed(q, (i & 1) ? b : a, 2100 + i) && q.quickScans == 2);
    q.quickScans = 2; q.armed = false;
    assert(!roamConfirmed(q, b, 3000) && q.quickScans == 0);  /* re-armed: anew */
    /* 4u.1: the 6 GHz request bitmap, read as mt7927_hal_scan reads it */
    uint8_t bm[30] = {};
    assert(set6gChannel(bm, sizeof(bm), 165));
    assert(!set6gChannel(bm, sizeof(bm), 165));      /* already there */
    assert(!set6gChannel(bm, sizeof(bm), 0) && !set6gChannel(bm, sizeof(bm), 234));
    for (unsigned psc = 5; psc <= 229; psc += 16) set6gChannel(bm, sizeof(bm), psc);
    int picked = 0;
    for (unsigned c6 = 1; c6 <= 233; c6++)
        if (bm[c6 / 8] & (1U << (c6 % 8))) { picked++; assert(c6 == 165 || (c6 - 5) % 16 == 0); }
    assert(picked == 15);                               /* the 15 PSCs (165 is one) */
    puts("PASS: per-band -70/-75 dBm, +12 dB rule; 30-180 s scans, wide per 90 s, 3 dB "
         "hysteresis; two separate readings, two quick scans; "
         "6 GHz request bitmap");
}
'''
with tempfile.TemporaryDirectory() as d:
    p = Path(d)
    (p / 't.cpp').write_text(pre + set6g + profile + '\n' + reset + '\n' + wanted + nextscan + '\n' + widef + confirm + main)
    subprocess.run(['clang++', '-std=c++14', '-fsanitize=address,undefined', '-g',
                    str(p / 't.cpp'), '-o', str(p / 't')], check=True)
    r = subprocess.run([str(p / 't')], capture_output=True, text=True)
    print(r.stdout + r.stderr)
    r.check_returncode()

# 4u.2 review: the roam aims its 6 GHz join scan at the on-air channel number
# (ieee80211_chan2number), not the table index (ieee80211_chan2ieee)
w = (root / "AirportMtkWlan/WCL/WCL.cpp").read_text()
i = w.index("bool AirportItlwmSkywalkInterface::startWCLRoam(")
body = w[i:w.index("\n}\n", i)]
assert "ieee80211_chan2number(ic, target->ni_chan)" in body and "chan2ieee" not in body, "startWCLRoam channel"
print("PASS: startWCLRoam uses the on-air channel number")

# 4w: the profile follows the band of our AP, in the roam check and in the
# scan backoff; a waiting candidate's second reading does not wait 30 s
# (its first one is only good for kRoamHeardMs); link loss keeps no signal rule
def fn(name):
    i = w.index("AirportItlwmSkywalkInterface::" + name + "(")
    return w[i:w.index("\n}\n", i)]
check, scan, lost = fn("checkWCLRoam"), fn("startWCLRoamScan"), fn("roamAfterLinkLoss")
assert "roamProfileFor(bss->ni_chan)" in check and "roamWanted(prof, cur, bestRssi)" in check
assert "cur > prof.triggerDbm" in check and "prof.initScanMs" in check
assert "wanted && roamConfirm.armed && due > kRoamConfirmScanMs" in check
assert "roamConfirm.quickScans < AirportWCL::kRoamConfirmQuickScans" in check
assert "roamConfirm.quickScans++" in check
assert "AirportWCL::roamScanReset(prof, cur)" in check and "roamLastWideMs = 0;" in check
assert "prof = roamProfileFor(bss->ni_chan)" in scan and "nextRoamScanMs(prof, roamScanIntervalMs)" in scan
assert "roamScanWide(prof, roamLastWideMs, scanMs)" in scan and "cur <= prof.triggerDbm" in scan
assert "if (started && wide)\n        roamLastWideMs = scanMs;" in scan
assert "roamScanCount" not in w
assert "roamWanted" not in lost and "Profile" not in lost
assert "now - roamLastScanMs > 20000" in check, "stuck roam-scan expiry"
m = re.search(r"kRoamConfirmScanMs = (\d+);", w)
h = re.search(r"kRoamHeardMs = (\d+);", w)
assert m and h and int(m.group(1)) + 5000 <= int(h.group(1)), "confirm scan inside the heard window"
print("PASS: per-band profile in the roam check and scan backoff; wide first and every "
      "90 s; 3 dB hysteresis; at most two 15 s confirm scans")
