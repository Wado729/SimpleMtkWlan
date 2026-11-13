from pathlib import Path
import subprocess,sys,tempfile
b=Path(__file__).resolve().parent
src=Path(sys.argv[1]) if len(sys.argv)>1 else b.parents[1]/'SimpleMtkWlan/hal_mwx/MtkMwx.cpp'
s=src.read_text()
i=s.index('static int\nmt7927_mac_fill_rx(');f=s[i:s.index('\n}\n',i)+3]
pre=r'''
#include <cassert>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>
#define IEEE80211_CHAN_MAX 255
#define IEEE80211_FC1_PROTECTED 0x40
#define IEEE80211_RXI_HWDEC 0x1
#define IEEE80211_CCMP_HDRLEN 8
#define MT7927_CIPHER_AES_CCMP 4
struct ieee80211_frame{uint8_t i_fc[2];uint8_t rest[22];};
struct chan{int ic_flags;};
struct ieee80211com{chan ic_channels[256];};
struct capa{uint8_t antenna_mask=3;};
struct mwx_softc{ieee80211com sc_ic;capa sc_capa;unsigned sc_7927_rx_drop[8]={0};unsigned sc_7927_rx_hwdec=0,sc_7927_rx_hwdec_nopn=0;};
struct ieee80211_rxinfo{int rxi_flags;int rxi_chan;int rxi_rssi;};
struct mt7927_rxi{uint32_t hdr_off,frame_len;uint8_t chan,band,band_idx;int8_t rssi;bool decrypted,unicast;uint16_t wlan_idx;
 uint8_t sec_mode,key_id;bool has_pn;uint8_t pn[6];};
struct mbuf{uint8_t*data;size_t len;};
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
 mwx_softc sc; for(auto&c:sc.sc_ic.ic_channels)c.ic_flags=1;
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
