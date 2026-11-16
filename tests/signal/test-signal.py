#!/usr/bin/env python3
"""Phase 4t: the AP's signal is an average of the AP's own frames only.

Extracts the real mt7927_sig_note() and mt7927_rx_from_ap() from MtkMwx.cpp
and checks: a stream of frames from the AP converges to their level (EWMA,
1/8 per frame, as mac80211's DECLARE_EWMA(signal, 10, 8)); a single spike
moves it by ~1/8 only; another transmitter's frame and control frames are
not the AP's; min/max/last/count are kept.
"""
from pathlib import Path
import subprocess, tempfile
root = Path(__file__).resolve().parents[2]
s = (root / 'SimpleMtkWlan/hal_mwx/MtkMwx.cpp').read_text()
def grab(start, end_marker='\n}\n'):
    i = s.index(start)
    return s[i:s.index(end_marker, i) + len(end_marker)]
note = grab('static int\nmt7927_sig_note(')
from_ap = grab('static bool\nmt7927_rx_from_ap(')
pre = r'''
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#define IEEE80211_FC0_TYPE_MASK 0x0c
#define IEEE80211_FC0_TYPE_MGT 0x00
#define IEEE80211_FC0_TYPE_CTL 0x04
#define IEEE80211_FC0_TYPE_DATA 0x08
struct mwx_softc {
    int32_t sc_7927_sig_avg16;
    int8_t sc_7927_sig_last, sc_7927_sig_min, sc_7927_sig_max;
    uint32_t sc_7927_sig_n;
};
'''
main = r'''
int main() {
    const uint8_t ap[6] = {0x72,0x00,0x00,0x00,0x03,0x4d};
    const uint8_t other[6] = {0x42,0x00,0x00,0x00,0x03,0x71};
    const uint8_t txbss[6] = {0x72,0x00,0x00,0x00,0x03,0x4c};
    assert(mt7927_rx_from_ap(0x80, ap, ap));          /* beacon from the AP */
    assert(mt7927_rx_from_ap(0x88, ap, ap));          /* QoS data */
    assert(!mt7927_rx_from_ap(0x80, other, ap));      /* other mesh node */
    assert(!mt7927_rx_from_ap(0x50, txbss, ap));      /* other BSSID */
    assert(!mt7927_rx_from_ap(0xd4, ap, ap));         /* ACK: control */
    mwx_softc sc = {};
    int a = mt7927_sig_note(&sc, -71);
    assert(a == -71 && sc.sc_7927_sig_n == 1);
    for (int i = 0; i < 200; i++) a = mt7927_sig_note(&sc, -71);
    assert(a == -71);
    a = mt7927_sig_note(&sc, -51);                     /* one spike */
    assert(a >= -69 && a <= -68);                      /* 1/8 of 20 dB */
    for (int i = 0; i < 200; i++) a = mt7927_sig_note(&sc, -81);
    assert(a >= -81 && a <= -80);                      /* settles within 0.5 dB */
    assert(sc.sc_7927_sig_min == -81 && sc.sc_7927_sig_max == -51);
    assert(sc.sc_7927_sig_last == -81 && sc.sc_7927_sig_n == 402);
    puts("PASS: AP frames only; EWMA 1/8 converges, a spike moves it ~1/8; min/max/last/count");
}
'''
with tempfile.TemporaryDirectory() as d:
    p = Path(d)
    (p / 't.cpp').write_text(pre + note + from_ap + main)
    subprocess.run(['clang++', '-std=c++14', '-fsanitize=address,undefined', '-g',
                    str(p / 't.cpp'), '-o', str(p / 't')], check=True)
    r = subprocess.run([str(p / 't')], capture_output=True, text=True)
    print(r.stdout + r.stderr)
    r.check_returncode()
