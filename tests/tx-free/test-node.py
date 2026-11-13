from pathlib import Path
import subprocess,sys,tempfile
b=Path(__file__).resolve().parent
src=Path(sys.argv[1]) if len(sys.argv)>1 else b.parents[1]/'SimpleMtkWlan/hal_mwx/MtkMwx.cpp'
s=src.read_text();f=s[s.index('void\nmwx_start('):s.index('\nint\nmwx_ioctl(')]
pre=r'''
#include <cassert>
#include <cstdio>
#include <cstddef>
#define NBPFILTER 0
const int IFF_RUNNING=1,IFF_UP=2,IEEE80211_S_RUN=4,IEEE80211_F_TX_MGMT_ONLY=8;
struct ieee80211_node{int refs=0;};
struct mbuf{ieee80211_node*node;};struct queue{mbuf*m=nullptr;};
struct netstat{unsigned long long outputPackets=0,outputErrors=0;};
struct ifnet {void*if_softc;int if_flags=3;queue if_snd;int if_oerrors=0,if_timer=0;netstat*netStat=nullptr;};
struct ieee80211com {int ic_state=4,ic_xflags=0;queue ic_mgtq;};
enum mwx_hw_type{MWX_HW_MT7921,MWX_HW_MT7922,MWX_HW_MT7927};
struct mwx_softc{ieee80211com sc_ic;unsigned sc_tx_full_cnt=0;mwx_hw_type sc_hwtype=MWX_HW_MT7921;};
int freed;void m_freem(mbuf*){freed++;}
int room=1;
int mwx_tx_has_room(mwx_softc*,unsigned){return room;}
int paused;
void ifq_set_oactive(queue*){paused++;}struct ether_header{char bytes[14];};
bool ifq_is_oactive(queue*){return false;}
mbuf*mq_dequeue(queue*q){auto m=q->m;q->m=nullptr;return m;}
mbuf*ifq_dequeue(queue*q){return mq_dequeue(q);}
int purged;void mq_purge(queue*q){if(q->m){purged++;q->m=nullptr;}}
void*mbuf_pkthdr_rcvif(mbuf*m){return m->node;}
size_t mbuf_len(mbuf*){return 64;}
mbuf*m_pullup(mbuf*m,size_t){return m;}
mbuf*ieee80211_encap(ifnet*,mbuf*m,ieee80211_node**ni){*ni=m->node;(*ni)->refs++;return m;}
void ieee80211_release_node(ieee80211com*,ieee80211_node*ni){assert(ni->refs>0);ni->refs--;}
int result;
int mwx_tx(mwx_softc*,mbuf*,ieee80211_node*ni){assert(ni->refs==1);return result;}
int mt7927_out;void mt7927_hal_output(mwx_softc*,ifnet*){mt7927_out++;}
'''
main=r'''
int main(){
 for(int mgmt=0;mgmt<2;mgmt++)for(int error=0;error<2;error++){
  mwx_softc sc; ifnet ifp; ifp.if_softc=&sc;ieee80211_node ni;mbuf m{&ni};result=error;
  if(mgmt){ni.refs++;sc.sc_ic.ic_mgtq.m=&m;}else ifp.if_snd.m=&m;
  mwx_start(&ifp);assert(ni.refs==0);assert(ifp.if_oerrors==error);
 }
 {mwx_softc sc; ifnet ifp; ifp.if_softc=&sc;ieee80211_node ni;mbuf m{&ni};room=0;paused=0;ifp.if_snd.m=&m;
  mwx_start(&ifp);assert(ifp.if_snd.m==&m&&paused==1&&sc.sc_tx_full_cnt==1&&ni.refs==0);room=1;}
 {mwx_softc sc;sc.sc_hwtype=MWX_HW_MT7927;ifnet ifp;ifp.if_softc=&sc;ieee80211_node ni;mbuf m{&ni},m2{&ni};
  sc.sc_ic.ic_mgtq.m=&m;ifp.if_snd.m=&m2;freed=purged=0;mt7927_out=0;mwx_start(&ifp);
  assert(mt7927_out==1&&sc.sc_ic.ic_mgtq.m==&m&&ifp.if_snd.m==&m2&&purged==0&&freed==0&&ni.refs==0);}
 puts("PASS: extracted mwx_start balances enqueue node references for data/management, success/failure; pauses without dropping when TX is full; MT7927 hands both queues to its own output path.");
}
'''
tmp=tempfile.TemporaryDirectory(prefix='mtk-tx-test-');art=Path(tmp.name)
cpp=art/'node-test.cpp';exe=art/'node-test';cpp.write_text(pre+f+main)
subprocess.run(['clang++','-std=c++14','-fsanitize=address,undefined','-g',str(cpp),'-o',str(exe)],check=True)
raise SystemExit(subprocess.run([str(exe)]).returncode)
