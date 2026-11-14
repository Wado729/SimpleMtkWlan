from pathlib import Path
import subprocess,sys,tempfile
b=Path(__file__).resolve().parent
src=Path(sys.argv[1]) if len(sys.argv)>1 else b.parents[1]/'SimpleMtkWlan/hal_mwx/MtkMwx.cpp'
s=src.read_text()
i=s.index('static void\nmt7927_rx_csum(');j=s.index('static int\nmt7927_mac_fill_rx(');f=s[i:s.index('\n}\n',j)+3]
pre=r'''
#include <cassert>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>
#include <string>
#define IEEE80211_CHAN_MAX 255
#define IEEE80211_FC1_PROTECTED 0x40
#define IEEE80211_RXI_HWDEC 0x1
#define IEEE80211_CCMP_HDRLEN 8
#define MT7927_CIPHER_AES_CCMP 4
struct ieee80211_frame{uint8_t i_fc[2];uint8_t rest[22];};
struct chan{int ic_flags;};
struct ieee80211com;
#define IEEE80211_EVT_BEACON_6G 9
struct ieee80211_beacon6g_event{const uint8_t*bssid;const uint8_t*ssid;uint8_t ssid_len;uint8_t chan;int8_t rssi;uint16_t intval,capinfo;const uint8_t*ies;size_t length;};
struct ieee80211com{chan ic_channels[256];void(*ic_event_handler)(ieee80211com*,int,void*)=nullptr;uint8_t ic_6ghz_channels=0;};
struct capa{uint8_t antenna_mask=3;};
#define MT7927_RXD3_CSUM ((1U << 26) | (1U << 27))
struct mt7927_bringup{uint32_t info;};
struct mwx_softc{ieee80211com sc_ic;capa sc_capa;unsigned sc_7927_rx_drop[8]={0};unsigned sc_7927_rx_hwdec=0,sc_7927_rx_hwdec_nopn=0,sc_7927_rx_csum=0,sc_7927_rx_untrans_amsdu=0;mt7927_bringup*sc_7927;
 unsigned sc_7927_rx_6g=0;uint8_t sc_7927_6g_bssid[32][6];unsigned sc_7927_6g_n=0;uint8_t sc_7927_6g_heard[30];};
#define nitems(a) (sizeof(a)/sizeof((a)[0]))
static std::vector<std::string> logs; static char ebuf[18];
static const char*ether_sprintf(const uint8_t*a){snprintf(ebuf,sizeof ebuf,"%02x:%02x:%02x:%02x:%02x:%02x",a[0],a[1],a[2],a[3],a[4],a[5]);return ebuf;}
#define MWX_DEV_LOG(sc,...) do{char l[256];snprintf(l,sizeof l,__VA_ARGS__);logs.push_back(l);}while(0)
struct ieee80211_qosframe{uint8_t b[26];};
#define IEEE80211_FC0_TYPE_MASK 0x0c
#define IEEE80211_FC0_TYPE_DATA 0x08
#define IEEE80211_FC0_SUBTYPE_QOS 0x80
#define MBUF_CSUM_DID_IP 1
#define MBUF_CSUM_IP_GOOD 2
#define MBUF_CSUM_DID_DATA 4
#define MBUF_CSUM_PSEUDO_HDR 8
uint32_t mt7927_engine_rx_info(mt7927_bringup*b){return b->info;}
static uint32_t mt7927_le32(const uint8_t*p){uint32_t v;memcpy(&v,p,4);return v;}
struct ieee80211_rxinfo{int rxi_flags;int rxi_chan;int rxi_rssi;};
struct mt7927_rxi{uint32_t hdr_off,frame_len;uint8_t chan,band,band_idx;int8_t rssi;bool decrypted,unicast;uint16_t wlan_idx;
 uint8_t sec_mode,key_id;bool has_pn;uint8_t pn[6];bool hdr_trans,hdr_trans_err,frag;uint8_t amsdu;bool has_g4;uint16_t fc,seq_ctrl,qos_ctl;};
struct mbuf{uint8_t*data;size_t len;int csum=0;};
void mbuf_set_csum_performed(mbuf*m,int f,int){m->csum=f;}
#define mtod(m,t) ((t)((m)->data))
size_t mbuf_len(mbuf*m){return m->len;}
void m_adj(mbuf*m,int n){assert(n>=0&&(size_t)n<=m->len);m->data+=n;m->len-=n;}
int ieee80211_get_hdrlen(const ieee80211_frame*wh){return (wh->i_fc[0]&0x80)?26:24;}  /* QoS data or not */
mt7927_rxi next;int parse_rv;
int mt7927_rx_parse(const uint8_t*,uint32_t,uint8_t,mt7927_rxi*ri){*ri=next;return parse_rv;}
'''
main=r'''
static void frame(std::vector<uint8_t>&buf,uint32_t off,bool qos){
 buf.assign(off+26+40,0); buf[off]=qos?0x88:0x08; buf[off+1]=0x01; for(int k=2;k<(qos?26:24);k++)buf[off+k]=(uint8_t)(k+0x40);
 for(int k=0;k<40;k++)buf[off+(qos?26:24)+k]=(uint8_t)(0xc0+k);}
int main(){
 mt7927_bringup eng{0}; mwx_softc sc; sc.sc_7927=&eng; for(auto&c:sc.sc_ic.ic_channels)c.ic_flags=1;
 for(int qos=0;qos<2;qos++){
  uint32_t hl=qos?26:24, off=48; std::vector<uint8_t> buf; frame(buf,off,qos);
  std::vector<uint8_t> orig(buf);
  mbuf m{buf.data(),buf.size()}; ieee80211_rxinfo rxi{};
  next={}; next.hdr_off=off; next.frame_len=(uint32_t)buf.size()-off; next.chan=36; next.band=5; next.decrypted=true;
  next.sec_mode=4; next.key_id=1; next.has_pn=true; for(int k=0;k<6;k++)next.pn[k]=(uint8_t)(0x10+k);
  assert(mt7927_mac_fill_rx(&sc,&m,&rxi)==0);
  assert(m.data==buf.data()+off-8 && m.len==buf.size()-off+8 && (rxi.rxi_flags&IEEE80211_RXI_HWDEC) && rxi.rxi_chan==36);
  assert(m.data[1]==(0x01|0x40));                                      /* protected again */
  assert(memcmp(m.data+2,orig.data()+off+2,hl-2)==0);                   /* header moved intact */
  const uint8_t iv[8]={0x10,0x11,0,0x20|(1<<6),0x12,0x13,0x14,0x15};
  assert(memcmp(m.data+hl,iv,8)==0);
  assert(memcmp(m.data+hl+8,orig.data()+off+hl,40)==0);                  /* payload untouched */
  assert(sc.sc_7927_rx_hwdec==(unsigned)(qos+1));
 }
 { /* phase 4e.1: 6 GHz beacons are logged once per BSSID, then dropped */
  std::vector<uint8_t> buf(32+36+2+9+2+4,0); uint8_t*f=buf.data()+32; f[0]=0x80;
  const uint8_t bss[6]={0x40,0x00,0x00,0x00,0x03,0x4c}; memcpy(f+16,bss,6); f[36]=0; f[37]=9; memcpy(f+38,"Home_6GHz",9);
  f[47]=1; f[48]=4; for(int r=0;r<2;r++){
   mbuf m{buf.data(),buf.size()}; ieee80211_rxinfo rxi{}; unsigned d0=sc.sc_7927_rx_drop[0];
   next={}; next.hdr_off=32; next.frame_len=(uint32_t)buf.size()-32; next.chan=69; next.band=6; next.rssi=-79;
   assert(mt7927_mac_fill_rx(&sc,&m,&rxi)==-1 && sc.sc_7927_rx_drop[0]==d0+1);}
  assert(sc.sc_7927_rx_6g==2 && sc.sc_7927_6g_n==1 && logs.size()==1);
  /* phase 4e.2: with 6 GHz on, every one goes to the front end as an event */
  static std::vector<std::string> evs; sc.sc_ic.ic_6ghz_channels=1;
  sc.sc_ic.ic_event_handler=[](ieee80211com*,int code,void*d){auto e=(ieee80211_beacon6g_event*)d;assert(code==9);
    char l[96]; snprintf(l,sizeof l,"%.*s ch %u rssi %d int %u ies %zu",e->ssid_len,(const char*)e->ssid,e->chan,e->rssi,e->intval,e->length); evs.push_back(l);};
  f[32]=100; f[34]=0x11; { mbuf m{buf.data(),buf.size()}; ieee80211_rxinfo rxi{};
   next={}; next.hdr_off=32; next.frame_len=(uint32_t)buf.size()-32; next.chan=69; next.band=6; next.rssi=-76;
   assert(mt7927_mac_fill_rx(&sc,&m,&rxi)==-1); }
  assert(evs.size()==1 && evs[0]=="Home_6GHz ch 69 rssi -76 int 100 ies 17" && logs.size()==1);
  sc.sc_ic.ic_event_handler=nullptr; sc.sc_ic.ic_6ghz_channels=0;
  assert(logs[0].find("6 GHz: beacon \"Home_6GHz\" 40:00:00:00:03:4c ch 69 rssi -79")!=std::string::npos);
 }
 { /* no PN: header stays, protected bit cleared */
  std::vector<uint8_t> buf; frame(buf,32,true); buf[33]|=0x40; mbuf m{buf.data(),buf.size()}; ieee80211_rxinfo rxi{};
  next={}; next.hdr_off=32; next.frame_len=(uint32_t)buf.size()-32; next.chan=36; next.decrypted=true; next.sec_mode=4;
  assert(mt7927_mac_fill_rx(&sc,&m,&rxi)==0 && m.data==buf.data()+32 && !(m.data[1]&0x40) && (rxi.rxi_flags&1) &&
         sc.sc_7927_rx_hwdec_nopn==1);
 }
 { /* not decrypted: untouched apart from the RXD */
  std::vector<uint8_t> buf; frame(buf,32,true); buf[33]|=0x40; mbuf m{buf.data(),buf.size()}; ieee80211_rxinfo rxi{};
  next={}; next.hdr_off=32; next.frame_len=(uint32_t)buf.size()-32; next.chan=36; next.sec_mode=4; next.has_pn=true;
  assert(mt7927_mac_fill_rx(&sc,&m,&rxi)==0 && m.data==buf.data()+32 && (m.data[1]&0x40) && rxi.rxi_flags==0);
 }
 { /* other cipher (TKIP): no rebuilt header */
  std::vector<uint8_t> buf; frame(buf,48,true); mbuf m{buf.data(),buf.size()}; ieee80211_rxinfo rxi{};
  next={}; next.hdr_off=48; next.frame_len=(uint32_t)buf.size()-48; next.chan=36; next.decrypted=true; next.sec_mode=2; next.has_pn=true;
  assert(mt7927_mac_fill_rx(&sc,&m,&rxi)==0 && m.data==buf.data()+48 && sc.sc_7927_rx_hwdec_nopn==2);
 }
 { /* RX checksum offload: both RXD3 SUM bits, no error in the descriptor; never for an A-MSDU */
  for(int amsdu=0;amsdu<2;amsdu++) for(int err=0;err<2;err++){
   std::vector<uint8_t> buf; frame(buf,32,true); buf[12+3]|=0x0c; if(amsdu)buf[32+24]|=0x80;
   eng.info=err?4:0; mbuf m{buf.data(),buf.size()}; ieee80211_rxinfo rxi{}; unsigned c0=sc.sc_7927_rx_csum;
   next={}; next.hdr_off=32; next.frame_len=(uint32_t)buf.size()-32; next.chan=36;
   assert(mt7927_mac_fill_rx(&sc,&m,&rxi)==0);
   bool want=!amsdu&&!err; assert((m.csum==15)==want && sc.sc_7927_rx_csum==c0+(want?1:0)); }
  std::vector<uint8_t> buf; frame(buf,32,true); mbuf m{buf.data(),buf.size()}; ieee80211_rxinfo rxi{}; eng.info=0;
  next={}; next.hdr_off=32; next.frame_len=(uint32_t)buf.size()-32; next.chan=36;
  assert(mt7927_mac_fill_rx(&sc,&m,&rxi)==0 && m.csum==0);                  /* SUM bits not set */
 }
 { /* phase 4c.10: an untranslated A-MSDU subframe loses the 2 pad bytes after its header */
  std::vector<uint8_t> buf; frame(buf,32,true); buf.insert(buf.begin()+32+26,{0xee,0xee}); std::vector<uint8_t> orig(buf);
  mbuf m{buf.data(),buf.size()}; ieee80211_rxinfo rxi{}; eng.info=0;
  next={}; next.hdr_off=32; next.frame_len=(uint32_t)buf.size()-32; next.chan=36; next.amsdu=3;
  assert(mt7927_mac_fill_rx(&sc,&m,&rxi)==0 && m.data==buf.data()+34 && sc.sc_7927_rx_untrans_amsdu==1);
  assert(memcmp(m.data,orig.data()+32,26)==0 && memcmp(m.data+26,orig.data()+32+28,10)==0);
 }
 { /* parse error and 6 GHz: dropped */
  std::vector<uint8_t> buf(64); mbuf m{buf.data(),buf.size()}; ieee80211_rxinfo rxi{};
  parse_rv=3; assert(mt7927_mac_fill_rx(&sc,&m,&rxi)==-1 && sc.sc_7927_rx_drop[3]==1); parse_rv=0;
  next={}; next.band=6; next.chan=37; assert(mt7927_mac_fill_rx(&sc,&m,&rxi)==-1);
 }
 puts("PASS: hardware-decrypted CCMP frames get their header rebuilt from the group-1 PN and key ID (QoS and non-QoS), header/payload intact; no-PN and non-CCMP fall back; undecrypted frames untouched; ASan/UBSan.");
}
'''
tmp=tempfile.TemporaryDirectory(prefix='mtk-hwdec-');art=Path(tmp.name)
cpp=art/'t.cpp';exe=art/'t';cpp.write_text(pre+f+main)
subprocess.run(['clang++','-std=c++14','-fsanitize=address,undefined','-g','-Wno-everything',str(cpp),'-o',str(exe)],check=True)
raise SystemExit(subprocess.run([str(exe)]).returncode)
