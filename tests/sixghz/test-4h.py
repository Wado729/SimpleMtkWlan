#!/usr/bin/env python3
"""Phase 4h: receive-rate parsing (P-RXV) and 6 GHz power by width.

Extracts mt7927_rx_parse() and mt7927_txpower_band() from MtkMwx.cpp:
  - group 3 (P-RXV) gives mode/MCS/NSS/bandwidth as mt7925_mac_fill_rx_rate
    reads them (connac3 field layout), RSSI unchanged;
  - band 6 SET_POWER_LIMIT messages: band byte 3, Linux's channel list and
    batching, 12 dBm OFDM/20 MHz, 15/18/21 dBm for 40/80/160 MHz in the
    HT/VHT/HE sections at mt7925_mcu_build_sku()'s offsets, small RUs lower,
    127 for channels off the 20 MHz grid; 5 GHz unchanged (20 dBm).
"""
import pathlib, re, subprocess, sys, tempfile
root = pathlib.Path(__file__).resolve().parents[2]
s = (root / "SimpleMtkWlan/hal_mwx/MtkMwx.cpp").read_text()
def fn(sig, rtype):
    i = s.index(rtype + "\n" + sig + "(")
    return s[i:s.index("\n}\n", i) + 3]
rxi = re.search(r"enum \{\n\tMT7927_RX_SHORT = 1,.*?\n\};\n\nstruct mt7927_rxi \{.*?\n\};", s, re.S).group(0)
code = r'''
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cassert>
#include <vector>
#define nitems(a) (sizeof(a)/sizeof((a)[0]))
#define MT7927_TXPWR_HDR 52
#define MT7927_SKU_LEN 450
#define MT7927_UNI_SET_POWER_LIMIT 0x1f
static uint32_t mt7927_le32(const uint8_t*p){uint32_t v;memcpy(&v,p,4);return v;}
''' + rxi + r'''
struct mt7927_bringup { char alpha2[2]; };
static std::vector<std::vector<uint8_t>> msgs;
static int mt7927_mcu_send(mt7927_bringup*, int, const void*p, uint32_t n, bool){ msgs.emplace_back((const uint8_t*)p,(const uint8_t*)p+n); return 0; }
''' + fn("mt7927_rx_parse", "int") + fn("mt7927_txpower_band", "static int") + r'''
static void put(uint8_t*p,uint32_t v){memcpy(p,&v,4);}
int main(){
  /* RXD with group 3: HE SU, 2 streams, MCS 11, 160 MHz */
  uint8_t f[32+16+64]={0}; put(f+4,1u<<18); put(f+12,(69u<<8)); 
  uint32_t v0=11|(1u<<7), v2=3|(8u<<11), v3=0xb4b4b4b4; put(f+32,v0); put(f+40,v2); put(f+44,v3);
  mt7927_rxi ri; assert(mt7927_rx_parse(f,sizeof f,3,&ri)==0);
  assert(ri.has_rxv && ri.rx_mode==8 && ri.rx_nss==2 && ri.rx_mcs==11 && ri.rx_bw==3 && ri.rssi==-20 && ri.hdr_off==48);
  put(f+32,7|(0u<<7)); put(f+40,2|(4u<<11)); assert(mt7927_rx_parse(f,sizeof f,3,&ri)==0 && ri.rx_mode==4 && ri.rx_mcs==7 && ri.rx_nss==1 && ri.rx_bw==2);
  put(f+32,0x13); put(f+40,0|(2u<<11)); assert(mt7927_rx_parse(f,sizeof f,3,&ri)==0 && ri.rx_mode==2 && ri.rx_mcs==0x13);   /* HT keeps nss in the index */
  put(f+4,0); assert(mt7927_rx_parse(f,sizeof f,3,&ri)==0 && !ri.has_rxv);
  /* 6 GHz power */
  mt7927_bringup b{{'U','S'}}; assert(mt7927_txpower_band(&b,6)==0);
  assert(msgs.size()==37);                                /* 109 channels, 3 per message, last has 109 % 3 = 1 */
  int seen=0, last=0;
  for(auto&m:msgs){ assert(m[13]==3 && m[16]=='U'); int n=m[12]; assert(m.size()==52u+n*450u);
    for(int j=0;j<n;j++){ const uint8_t*k=&m[52+j*450]; uint8_t c=k[0]; const int8_t*sk=(const int8_t*)k+1; seen++;
      if(m[14]) last=c;
      if(c%4!=1){ for(int x=4;x<449;x++) assert(sk[x]==127); continue; }
      for(int x=0;x<4;x++) assert(sk[x]==127);            /* no CCK on 6 GHz */
      for(int x=4;x<12;x++) assert(sk[x]==24);            /* OFDM 12 dBm */
      for(int x=12;x<44;x++) assert(sk[x]==127);          /* OFDM wider slots unset, as Linux */
      for(int x=44;x<52;x++) assert(sk[x]==24); for(int x=52;x<60;x++) assert(sk[x]==30); assert(sk[60]==24);
      const int vht[4]={24,30,36,42}; for(int r=0;r<4;r++) for(int x=0;x<12;x++) assert(sk[61+12*r+x]==vht[r]);
      const int he[7]={4,10,16,24,30,36,42}; for(int r=0;r<7;r++) for(int x=0;x<12;x++) assert(sk[109+12*r+x]==he[r]);
      for(int x=193;x<449;x++) assert(sk[x]==24); } }
  assert(seen==109 && last==233);
  msgs.clear(); assert(mt7927_txpower_band(&b,5)==0);
  { const int8_t*sk=(const int8_t*)&msgs[0][52+1]; assert(msgs[0][13]==2 && sk[4]==40 && sk[44]==40 && sk[109+12*6]==40 && sk[193]==40); }
  puts("PASS: P-RXV rate parsing (HE/VHT/HT, absent group 3); 6 GHz SET_POWER_LIMIT by width (OFDM/HT/VHT/HE at mt7925 offsets, 127 off-grid, 37 messages, last ch 233); 5 GHz unchanged.");
}
'''
d = pathlib.Path(tempfile.mkdtemp(prefix="mtk-4h-"))
(d/"t.cpp").write_text(code)
r = subprocess.run(["clang++","-std=c++14","-fsanitize=address,undefined","-g","-Wno-everything",str(d/"t.cpp"),"-o",str(d/"t")],capture_output=True,text=True)
if r.returncode: print(r.stderr[-3000:]); sys.exit(1)
r = subprocess.run([str(d/"t")],capture_output=True,text=True); print(r.stdout+r.stderr[-2000:]); sys.exit(r.returncode)
