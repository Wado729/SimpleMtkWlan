#!/usr/bin/env python3
"""Phase 4g: joining 6 GHz networks, the pieces that can run on the host.

Compiles the driver's own code (extracted from the sources) against the real
net80211/ieee80211.h with small stubs, under ASan/UBSan:
  - net80211 channel helpers: 6 GHz table indexes 182..240 (Ersiter's
    181 + (ch+3)/4), on-air numbers, frequencies, band-aware lookups;
  - ieee80211_setmode()'s active set: 6 GHz stays active in every mode but 11b;
  - ieee80211_he_negotiate(): width/center from the 6 GHz Operation Info;
  - ieee80211_add_he_6ghz_capa(): the element bytes (mt7925 values);
  - mwx_node_chan_width() + mt7927_bss_fill(): band 3, the on-air channel,
    phymode A|AN|AC|AX_5G, phymode_ext AX_6G, STA_REC_VHT forced,
    STA_REC_HE_6G capa, A-MPDU factor/density from the AP's 6 GHz caps
    (mt7925_mcu_sta_phy_tlv), BSS width from HE.
"""
import pathlib, re, subprocess, sys, tempfile
root = pathlib.Path(__file__).resolve().parents[2]
nb = root / "mtk80211/openbsd/net80211"
hal = root / "SimpleMtkWlan/hal_mwx"
c80211 = (nb / "ieee80211.c").read_text()
outc = (nb / "ieee80211_output.c").read_text()
proto = (nb / "ieee80211_proto.c").read_text()
mwx = (hal / "MtkMwx.cpp").read_text()
var = (nb / "ieee80211_var.h").read_text()

def fn(src, sig, rtype):
    i = src.index(rtype + "\n" + sig + "(")
    return src[i:src.index("\n}\n", i) + 3]

funcs = "".join([
    fn(c80211, "ieee80211_mhz2ieee", "u_int"),
    fn(c80211, "ieee80211_chan2ieee", "u_int"),
    fn(c80211, "ieee80211_chan2number", "u_int"),
    fn(c80211, "ieee80211_ieee2chanidx", "u_int"),
    fn(c80211, "ieee80211_ieee2mhz", "u_int"),
    fn(outc, "ieee80211_add_he_6ghz_capa", "uint8_t *"),
    fn(proto, "ieee80211_he_negotiate", "void"),
])
# setmode's active-set loop, as a function over the same table
sm = c80211[c80211.index("    memset(ic->ic_chan_active, 0, sizeof(ic->ic_chan_active));"):]
sm = sm[:sm.index("    /*\n     * If no current/default channel")]
chanflags = re.search(r"static const u_int chanflags\[\] = \{.*?\};", c80211, re.S).group(0)
hal_funcs = "".join([
    fn(mwx, "mwx_node_chan_width", "static void"),
    fn(mwx, "mt7927_vht_mcs_and", "static uint16_t"),
    fn(mwx, "mt7927_vht_mcs_nss", "static uint8_t"),
    fn(mwx, "mt7927_bss_fill", "static void"),
])
a = var.index("#define IEEE80211_CHAN_CCK")
defs = var[a:var.index("\n\n", var.index("#define\tIEEE80211_IS_CHAN_XR"))]
types = (hal / "mt7927_types.h").read_text()
bss = re.search(r"struct mt7927_bss \{.*?\n\};", types, re.S).group(0)

d = pathlib.Path(tempfile.mkdtemp(prefix="mtk-6g-"))
(d / "inc/sys").mkdir(parents=True)
for h in ("endian", "_clock", "_types", "types", "param", "systm"):
    (d / f"inc/sys/{h}.h").write_text("#pragma once\n#include <endian.h>\n")
for h in ("_if_ether.h", "_if_media.h", "_arc4random.h"):
    (d / "inc/sys" / h).write_text("#pragma once\n")

prog = r'''
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string>
typedef uint8_t u_int8_t; typedef uint16_t u_int16_t; typedef uint32_t u_int32_t; typedef uint64_t u_int64_t;
typedef unsigned u_int; typedef unsigned char u_char;
#define __packed __attribute__((packed))
static inline int hweight8(unsigned v){return __builtin_popcount(v&0xff);}
#define DIV_ROUND_UP(n,d) (((n)+(d)-1)/(d))
#include "''' + str(nb / "ieee80211.h") + r'''"
#define min(a,b) ((a)<(b)?(a):(b))
#define MIN(a,b) ((a)<(b)?(a):(b))
#define nitems(a) (sizeof(a)/sizeof((a)[0]))
#define NBBY 8
#define setbit(a,i) ((a)[(i)/NBBY] |= 1<<((i)%NBBY))
#define isset(a,i) ((a)[(i)/NBBY] & (1<<((i)%NBBY)))
#define IEEE80211_CHAN_MAX 255
#define IEEE80211_CHAN_ANY 0xffff
#define IEEE80211_CHAN_ANYC ((struct ieee80211_channel *)IEEE80211_CHAN_ANY)
static std::string logbuf;
#define XYLog(...) do{char b_[256];snprintf(b_,sizeof b_,__VA_ARGS__);logbuf+=b_;}while(0)
static inline uint32_t u32_get_bits(uint32_t v, uint32_t m){return (v&m)/(m&-m);}
#define IEEE80211_F_HEON 0x80000000
#define IEEE80211_C_SUPPORTS_VHT_EXT_NSS_BW 0x00080000
enum ieee80211_phymode { IEEE80211_MODE_AUTO, IEEE80211_MODE_11A, IEEE80211_MODE_11B, IEEE80211_MODE_11G,
  IEEE80211_MODE_11N, IEEE80211_MODE_11AC, IEEE80211_MODE_11AX };
#define IEEE80211_NODE_HT 0x0400
#define IEEE80211_NODE_QOS 0x0002
#define IEEE80211_NODE_VHT 0x10000
#define IEEE80211_NODE_HE 0x200000
''' + defs + r'''
struct ieee80211_channel { u_int16_t ic_freq; u_int32_t ic_flags; u_int16_t ic_center_freq1, ic_center_freq2; };
struct _ifnet { const char *if_xname; };
struct ieee80211_rateset { u_int8_t rs_nrates; u_int8_t rs_rates[15]; };
struct ieee80211com {
  struct _ifnet ic_if; struct ieee80211_channel ic_channels[IEEE80211_CHAN_MAX+1];
  u_char ic_chan_active[32]; u_int32_t ic_modecaps, ic_flags, ic_caps; u_int8_t ic_ampdu_params;
  struct ieee80211_he_cap_elem ic_he_cap_elem; struct ieee80211_he_mcs_nss_supp ic_he_mcs_nss_supp;
  uint16_t ic_vht_tx_mcs_map, ic_vht_rx_mcs_map;
};
struct ieee80211_node {
  u_int8_t ni_bssid[6]; u_int32_t ni_flags; struct ieee80211_rateset ni_rates; u_int16_t ni_intval;
  u_int8_t ni_dtimperiod; u_int16_t ni_associd; struct ieee80211_channel *ni_chan; u_int8_t ni_ampdu_param;
  u_int8_t ni_rxmcs[10]; u_int16_t ni_htcaps; u_int8_t ni_chw; u_int32_t ni_vhtcaps; u_int16_t ni_htop1;
  struct ieee80211_vht_mcs_info ni_vht_mcsinfo; struct ieee80211_he_cap_elem ni_he_cap_elem;
  struct ieee80211_he_mcs_nss_supp ni_he_mcs_nss_supp; uint32_t ni_he_oper_params; uint16_t ni_he_oper_nss_set;
  uint8_t ni_he_optional[8]; uint16_t ni_he_6ghz_capa;
};
#define IEEE80211_ADDR_COPY(d,s) memcpy(d,s,6)
#define LE_WRITE_2(p,v) do{(p)[0]=(uint8_t)(v);(p)[1]=(uint8_t)((v)>>8);}while(0)
''' + funcs + r'''
static void active_set(struct ieee80211com *ic, enum ieee80211_phymode mode){
  ''' + chanflags + r'''
  u_int modeflags = chanflags[mode]; const struct ieee80211_channel *c; int i;
''' + sm + r'''
}
enum { CMD_CBW_20MHZ, CMD_CBW_40MHZ, CMD_CBW_80MHZ, CMD_CBW_160MHZ, CMD_CBW_10MHZ, CMD_CBW_5MHZ, CMD_CBW_8080MHZ };
#define MT7927_PHY_TYPE_ERP_INDEX 1
#define MT7927_PHY_TYPE_OFDM_INDEX 3
#define MT7927_PEER_WCID 1
''' + bss + r'''
struct mwx_softc { struct ieee80211com sc_ic; bool sc_7927_amsdu_ok, sc_7927_rx_decap; };
''' + hal_funcs + r'''
static struct ieee80211com ic;
static void table(){
  memset(&ic,0,sizeof ic);
  static const uint8_t c5[]={36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165,169,173};
  for(int c=1;c<=14;c++){ic.ic_channels[c].ic_freq=ieee80211_ieee2mhz(c,IEEE80211_CHAN_2GHZ);ic.ic_channels[c].ic_flags=IEEE80211_CHAN_CCK|IEEE80211_CHAN_OFDM|IEEE80211_CHAN_DYN|IEEE80211_CHAN_2GHZ|IEEE80211_CHAN_HT20;}
  for(uint8_t c:c5){ic.ic_channels[c].ic_freq=ieee80211_ieee2mhz(c,IEEE80211_CHAN_5GHZ);ic.ic_channels[c].ic_flags=IEEE80211_CHAN_A|IEEE80211_CHAN_HT20|IEEE80211_CHAN_HT40|IEEE80211_CHAN_VHT20|IEEE80211_CHAN_VHT40|IEEE80211_CHAN_VHT80;}
  /* the HAL's phase 4g block, as written in mwx_preinit */
  for(unsigned c6=1;c6<=233;c6+=4){struct ieee80211_channel*c=&ic.ic_channels[IEEE80211_6GHZ_CHANIDX(c6)];
    c->ic_freq=(u_int16_t)ieee80211_ieee2mhz(c6,IEEE80211_CHAN_6GHZ);c->ic_flags=IEEE80211_CHAN_A|IEEE80211_CHAN_6GHZ|IEEE80211_CHAN_PASSIVE;}
}
int main(){
  table();
  /* indexes: clear of 2.4/5 GHz, one per 20 MHz channel, numbers/frequencies round-trip */
  int n6=0;
  for(int i=0;i<=IEEE80211_CHAN_MAX;i++){ struct ieee80211_channel*c=&ic.ic_channels[i]; if(!c->ic_flags)continue;
    assert(ieee80211_chan2ieee(&ic,c)==(u_int)i);
    if(IEEE80211_IS_CHAN_6GHZ(c)){ n6++; u_int ch=ieee80211_chan2number(&ic,c); assert(i>=182&&i<=240&&ch>=1&&ch<=233&&(ch-1)%4==0);
      assert(c->ic_freq==5950+5*ch && ieee80211_mhz2ieee(c->ic_freq,c->ic_flags)==ch);
      assert(ieee80211_ieee2chanidx(&ic,ch,IEEE80211_CHAN_6GHZ)==(u_int)i && IEEE80211_IS_CHAN_A(c) && IEEE80211_IS_CHAN_5GHZ(c));
    } else { assert(i<=177 && ieee80211_chan2number(&ic,c)==(u_int)i && ieee80211_ieee2chanidx(&ic,i,c->ic_flags)==(u_int)i);
      assert(ieee80211_mhz2ieee(c->ic_freq,c->ic_flags)==(u_int)i); }
  }
  assert(n6==59 && IEEE80211_6GHZ_CHANIDX(1)==182 && IEEE80211_6GHZ_CHANIDX(69)==199 && IEEE80211_6GHZ_CHANIDX(233)==240);
  assert(ieee80211_ieee2chanidx(&ic,70,IEEE80211_CHAN_6GHZ)==0 && ieee80211_ieee2chanidx(&ic,237,IEEE80211_CHAN_6GHZ)==0);
  assert(ieee80211_ieee2chanidx(&ic,0,IEEE80211_CHAN_6GHZ)==0 && ieee80211_ieee2chanidx(&ic,36,IEEE80211_CHAN_6GHZ)==0);
  assert(ieee80211_ieee2chanidx(&ic,199,IEEE80211_CHAN_5GHZ)==0);       /* a 6 GHz index is no 5 GHz channel */
  assert(ieee80211_chan2number(&ic,IEEE80211_CHAN_ANYC)==IEEE80211_CHAN_ANY);
  /* setmode: 6 GHz active in every mode but 11b; 2.4/5 GHz unchanged */
  enum ieee80211_phymode on[]={IEEE80211_MODE_AUTO,IEEE80211_MODE_11A,IEEE80211_MODE_11AX};
  for(auto m:on){active_set(&ic,m); assert(isset(ic.ic_chan_active,199)&&isset(ic.ic_chan_active,182)&&isset(ic.ic_chan_active,240));}
  active_set(&ic,IEEE80211_MODE_11AX); assert(isset(ic.ic_chan_active,36)&&isset(ic.ic_chan_active,1));
  active_set(&ic,IEEE80211_MODE_11B); assert(!isset(ic.ic_chan_active,199)&&isset(ic.ic_chan_active,6)&&!isset(ic.ic_chan_active,36));
  active_set(&ic,IEEE80211_MODE_11AC); assert(isset(ic.ic_chan_active,199)&&isset(ic.ic_chan_active,36));
  active_set(&ic,IEEE80211_MODE_11N); assert(isset(ic.ic_chan_active,199)&&isset(ic.ic_chan_active,36));
  /* HE 6 GHz Band Capabilities element: ext 59, mt7925's values, SM PS disabled */
  { uint8_t b[8]={0}; ic.ic_ampdu_params=0x14|0x3; uint8_t*e=ieee80211_add_he_6ghz_capa(b,&ic);
    assert(e==b+5 && b[0]==255 && b[1]==3 && b[2]==59);
    uint16_t capa=b[3]|(b[4]<<8); assert((capa&7)==5 && ((capa>>3)&7)==7 && ((capa>>6)&3)==2 && ((capa>>9)&3)==3 && (capa&0x3000)==0x3000 && !(capa&0x0800)); }
  /* he_negotiate on 6 GHz */
  ic.ic_modecaps=1<<IEEE80211_MODE_11AX; ic.ic_flags=IEEE80211_F_HEON;
  ic.ic_he_cap_elem.phy_cap_info[0]=IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_40MHZ_80MHZ_IN_5G|IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_160MHZ_IN_5G;
  struct ieee80211_node ni; memset(&ni,0,sizeof ni);
  struct ieee80211_channel *c69=&ic.ic_channels[199]; ni.ni_chan=c69;
  struct { uint8_t w,c0,c1,peer; int chw; u_int center; } cases[]={
    {3,71,79,0x0c,IEEE80211_CHAN_WIDTH_160,79},   /* 160 MHz: CCFS1 */
    {3,71,79,0x04,IEEE80211_CHAN_WIDTH_80,71},    /* the AP's 160 but not the peer cap: primary 80 */
    {3,71,0,0x0c,IEEE80211_CHAN_WIDTH_80,71},     /* no CCFS1 */
    {2,71,0,0x04,IEEE80211_CHAN_WIDTH_80,71},
    {1,67,0,0x04,IEEE80211_CHAN_WIDTH_40,67},
    {2,71,0,0x00,IEEE80211_CHAN_WIDTH_20,0},      /* peer says 20 MHz only */
    {0,69,0,0x0c,IEEE80211_CHAN_WIDTH_20,0},
  };
  for(auto &t:cases){ ni.ni_flags=0; ni.ni_he_cap_elem.phy_cap_info[0]=t.peer;
    ni.ni_he_oper_params=IEEE80211_HE_OPERATION_6GHZ_OP_INFO|IEEE80211_HE_OPERATION_CO_HOSTED_BSS;
    memset(ni.ni_he_optional,0,8); ni.ni_he_optional[1]=69; ni.ni_he_optional[2]=t.w; ni.ni_he_optional[3]=t.c0; ni.ni_he_optional[4]=t.c1; ni.ni_he_optional[5]=6;
    c69->ic_center_freq1=c69->ic_center_freq2=0; ieee80211_he_negotiate(&ic,&ni);
    assert((ni.ni_flags&IEEE80211_NODE_HE) && ni.ni_chw==t.chw);
    if(t.center) assert(c69->ic_center_freq1==5950+5*t.center); else assert(c69->ic_center_freq1==c69->ic_freq);
    uint8_t bw,cc; mwx_node_chan_width(&ni,&bw,&cc);
    assert(bw==(t.chw==IEEE80211_CHAN_WIDTH_160?CMD_CBW_160MHZ:t.chw==IEEE80211_CHAN_WIDTH_80?CMD_CBW_80MHZ:t.chw==IEEE80211_CHAN_WIDTH_40?CMD_CBW_40MHZ:CMD_CBW_20MHZ));
    assert(cc==(t.center?t.center:69)); }
  /* no 6 GHz Operation Info: 20 MHz */
  ni.ni_he_oper_params=0; ieee80211_he_negotiate(&ic,&ni); assert(ni.ni_chw==IEEE80211_CHAN_WIDTH_20);
  /* bss_fill on Home_6GHz-like AP: ch 69, 160 MHz, HE, AP 6 GHz caps */
  static struct mwx_softc sc; sc.sc_ic=ic; sc.sc_7927_amsdu_ok=true; sc.sc_7927_rx_decap=true;
  struct ieee80211_channel *s69=&sc.sc_ic.ic_channels[199]; ni.ni_chan=s69;
  ni.ni_he_oper_params=IEEE80211_HE_OPERATION_6GHZ_OP_INFO; memset(ni.ni_he_optional,0,8);
  ni.ni_he_optional[0]=69; ni.ni_he_optional[1]=3; ni.ni_he_optional[2]=71; ni.ni_he_optional[3]=79;
  ni.ni_he_cap_elem.phy_cap_info[0]=0x0c; ieee80211_he_negotiate(&sc.sc_ic,&ni);
  static const uint8_t r[]={0x8c,0x12,0x98,0x24,0xb0,0x48,0x60,0x6c}; ni.ni_rates.rs_nrates=8; memcpy(ni.ni_rates.rs_rates,r,8);
  ni.ni_he_6ghz_capa=0x36bd;   /* density 5, exp 7, MPDU 11454, SM PS off, antpat */
  ni.ni_he_mcs_nss_supp.rx_mcs_80=htole16(0xfffa); ni.ni_he_mcs_nss_supp.rx_mcs_160=htole16(0xfffa);
  struct mt7927_bss b; mt7927_bss_fill(&sc,&ni,&b);
  assert(b.band==3 && b.chan==69 && b.phymode==(0x01|0x10|0x20|0x80) && b.phymode_ext==0x01 && b.vht_tlv==1);
  assert(b.he_6g_capa==0x36bd && b.ampdu==((7&3)|(5<<2)) && b.max_ampdu_len==7 && b.he==1);
  assert(b.phy_type==((1U<<MT7927_PHY_TYPE_OFDM_INDEX)|(1U<<6)) && b.vht_cap==0 && b.ht_cap==0);
  assert(b.bw==CMD_CBW_160MHZ && b.center_chan==79 && b.basic_rates==0x15 && b.ra_legacy==(0xff<<6));
  assert(b.he_mcs[0]==0xfffa && b.he_mcs[1]==0xfffa);
  /* without the AP's 6 GHz caps: no AX_6G, no forced VHT TLV, no HE_6G */
  ni.ni_he_6ghz_capa=0; mt7927_bss_fill(&sc,&ni,&b); assert(b.phymode_ext==0 && b.vht_tlv==0 && b.he_6g_capa==0 && b.band==3);
  /* a 5 GHz AP is untouched: band 2, channel = index, no 6 GHz fields */
  struct ieee80211_node n5; memset(&n5,0,sizeof n5); n5.ni_chan=&sc.sc_ic.ic_channels[36]; n5.ni_rates=ni.ni_rates;
  mt7927_bss_fill(&sc,&n5,&b); assert(b.band==2 && b.chan==36 && b.phymode==0x01 && b.phymode_ext==0 && !b.vht_tlv && !b.he_6g_capa);
  puts("PASS: 6 GHz channel table (59 entries at 182..240), numbers/frequencies/lookups, active set (all modes but 11b), HE 6 GHz width/center, HE 6 GHz capa element, band-3 BSS/STA fields; 5 GHz unchanged; ASan/UBSan.");
}
'''
(d / "t.cpp").write_text(prog)
r = subprocess.run(["clang++", "-std=c++14", "-I", str(d / "inc"), "-fsanitize=address,undefined", "-g", "-Wno-everything",
                    str(d / "t.cpp"), "-o", str(d / "t")], capture_output=True, text=True)
if r.returncode:
    print(r.stderr[-4000:]); sys.exit(1)
r = subprocess.run([str(d / "t")], capture_output=True, text=True)
print(r.stdout + r.stderr[-3000:]); sys.exit(r.returncode)
