#!/usr/bin/env python3
"""Phase 4u: the roam decision (AirportWCL::roamWanted, roamConfirmed).

Extracts the real functions from WCL.hpp: roam only at or below -72 dBm and
to an AP at least 8 dB stronger; go only on a second, newer reading of the
same AP (one reading from one scan is not enough); a different AP or the
same reading again re-arms instead.
"""
from pathlib import Path
import subprocess, tempfile, re
root = Path(__file__).resolve().parents[2]
s = (root / 'AirportMtkWlan/WCL/WCL.hpp').read_text()
def grab(start, end_marker):
    i = s.index(start)
    return s[i:s.index(end_marker, i) + len(end_marker)]
consts = grab('static constexpr int kRoamTriggerDbm', 'kRoamDeltaDb = 8;')
wanted = grab('inline bool roamWanted(', '\n}\n')
set6g = grab('inline bool set6gChannel(', '\n}\n')
confirm = grab('struct RoamConfirm {', '\n}\n')
pre = '#include <cassert>\n#include <cstdint>\n#include <cstdio>\n#include <cstring>\n#include <cstddef>\nnamespace AirportWCL {\n'
main = r'''
}
using namespace AirportWCL;
int main() {
    assert(!roamWanted(-71, -50));          /* link not weak */
    assert(roamWanted(-72, -64));           /* exactly -72 and +8 */
    assert(!roamWanted(-72, -65));          /* +7 only */
    assert(roamWanted(-89, -70));
    const uint8_t a[6] = {0x72,0x00,0x00,0x00,0x03,0x4d}, b[6] = {0x42,0x00,0x00,0x00,0x03,0x71};
    RoamConfirm c = {};
    assert(!roamConfirmed(c, a, 1000));     /* first reading arms */
    assert(!roamConfirmed(c, a, 1000));     /* same reading again: still waiting */
    assert(roamConfirmed(c, a, 25000));     /* a newer reading: go */
    assert(!c.armed);
    assert(!roamConfirmed(c, a, 30000));    /* after a go: arms again */
    assert(!roamConfirmed(c, b, 31000));    /* another AP: re-arms for it */
    assert(roamConfirmed(c, b, 52000));
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
    puts("PASS: -72 dBm / +8 dB rule; two separate readings; 6 GHz request bitmap");
}
'''
with tempfile.TemporaryDirectory() as d:
    p = Path(d)
    (p / 't.cpp').write_text(pre + set6g + consts + '\n' + wanted + confirm + main)
    subprocess.run(['clang++', '-std=c++14', '-fsanitize=address,undefined', '-g',
                    str(p / 't.cpp'), '-o', str(p / 't')], check=True)
    r = subprocess.run([str(p / 't')], capture_output=True, text=True)
    print(r.stdout + r.stderr)
    r.check_returncode()
