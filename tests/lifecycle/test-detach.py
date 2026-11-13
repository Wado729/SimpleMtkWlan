from pathlib import Path
import subprocess
b=Path(__file__).resolve().parents[2]
out=Path(__file__).resolve().parent
src=(b/'SimpleMtkWlan/hal_mwx/MtkMwx.cpp').read_text()
body=src.split('MtkMwx::detach(IOPCIDevice *device)\n{',1)[1].split('\n}\n',1)[0]
pre=r'''
#include <cassert>
#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <vector>
#include <algorithm>
#include <cstdio>
#define MWX_LOG(...) ((void)0)
#define IFF_RUNNING 1
#define MT_WFDMA0_HOST_INT_ENA 0
struct IOPCIDevice {};
struct ifnet { int if_flags=0; };
struct IC { ifnet ic_if; };
enum mwx_hw_type{MWX_HW_MT7921,MWX_HW_MT7922,MWX_HW_MT7927};
struct IOLock;
struct Soft { IC sc_ic; bool sc_detaching=false,sc_net_attached=false; void *sc_reset_to=nullptr,*sc_nswq=nullptr,*sc_ih=nullptr; int sc_memh=0,sc_st=0,sc_mems=0;
  mwx_hw_type sc_hwtype=MWX_HW_MT7921; void *sc_7927=nullptr; IOLock *sc_7927_lock=nullptr;
  uint8_t *sc_7927_fw_patch=nullptr,*sc_7927_fw_ram=nullptr; size_t sc_7927_fw_plen=0,sc_7927_fw_rlen=0; };
struct PCI { int pa_pc=0; };
std::vector<int> events; void *systq=(void*)1;
void events_lock(){events.push_back(13);}
void mt7927_hal_detach(Soft*s){assert(s->sc_detaching);events.push_back(14);}
void mt7927_engine_destroy(void*){events.push_back(15);}
struct IOLock {}; void IOLockFree(IOLock*l){delete l;events_lock();}
int fw_freed=0; void IOFree(void*p,size_t){free(p);fw_freed++;}
void taskq_destroy(void *q) { if(q) events.push_back(8); }
void taskq_quiesce(void *q) { if(q) events.push_back(2); }
void timeout_del(void**) {events.push_back(1);}
void timeout_free(void**) {events.push_back(4);}
void mwx_stop(ifnet*) {events.push_back(3);}
void pci_intr_disestablish(int,void*) {events.push_back(5);}
void mwx_write(Soft*,int,int) {events.push_back(6);}
void mwx_dma_disable(Soft*,int) {events.push_back(6);}
void ieee80211_ifdetach(ifnet*) {events.push_back(7);}
void mwx_txwi_free(Soft*) {events.push_back(9);}
void mwx_dma_free(Soft*) {events.push_back(10);}
void bus_space_unmap(int,int,int) {events.push_back(11);}
class MtkMwx {public: Soft *com=nullptr; PCI *pci=nullptr; bool taskQueueOwned=false;
void releaseAll(){events.push_back(12);delete com;com=nullptr;delete pci;pci=nullptr;}
void detach(IOPCIDevice*);
};
'''
post=r'''
int index(int n){auto it=std::find(events.begin(),events.end(),n);return it==events.end()?-1:it-events.begin();}
int main(){
 for(int mask=0;mask<16;mask++) {
  events.clear();MtkMwx h;h.com=new Soft;h.pci=new PCI;h.taskQueueOwned=true;
  h.com->sc_memh=(mask&1)?1:0;h.com->sc_ih=(mask&2)?(void*)2:nullptr;
  h.com->sc_net_attached=mask&4;h.com->sc_nswq=(void*)3;
  h.com->sc_ic.ic_if.if_flags=(mask&8)?IFF_RUNNING:0;
  h.detach(nullptr); assert(!h.com&&!h.pci&&!h.taskQueueOwned);
  assert(index(2)<index(9));assert(index(4)<index(9));assert(index(8)<index(9));assert(index(10)<index(12));
  if(mask&1){assert(index(6)<index(9));assert(index(10)<index(11));}else assert(index(11)==-1);
  if(mask&2)assert(index(5)<index(9));else assert(index(5)==-1);
  assert((index(7)>=0)==bool(mask&4));assert((index(3)>=0)==bool(mask&8));
  events.clear();h.detach(nullptr);assert(events.size()==1&&events[0]==12);
 }
 MtkMwx h;h.taskQueueOwned=true;events.clear();h.detach(nullptr);assert(!h.taskQueueOwned&&events[0]==8);
 for(int running=0;running<2;running++){ /* MT7927: thread stopped first, stop before the engine goes, no MT7921 DMA calls */
  events.clear();MtkMwx m;m.com=new Soft;m.pci=new PCI;m.taskQueueOwned=true;m.com->sc_hwtype=MWX_HW_MT7927;
  m.com->sc_memh=1;m.com->sc_7927=(void*)5;m.com->sc_7927_lock=new IOLock;m.com->sc_nswq=(void*)3;m.com->sc_net_attached=true;
  m.com->sc_ic.ic_if.if_flags=running?IFF_RUNNING:0;
  m.com->sc_7927_fw_patch=(uint8_t*)malloc(8);m.com->sc_7927_fw_plen=8;m.com->sc_7927_fw_ram=(uint8_t*)malloc(16);m.com->sc_7927_fw_rlen=16;
  fw_freed=0;m.detach(nullptr);
  assert(index(14)==0&&index(15)>0&&index(6)==-1&&index(9)==-1&&index(10)==-1&&index(13)>0&&index(11)>index(15));
  assert(fw_freed==2);   /* firmware kept for wake is released */
  if(running)assert(index(3)<index(15));
 }
 puts("PASS actual HAL detach body: 16 partial/full resource combinations, repeated detach, IRQ/queue/timer-before-buffer ordering; MT7927 thread-stop/engine-destroy ordering, cached firmware freed. Mocks do not prove kernel scheduling.");
}
'''
f=out/'test-detach.cpp';f.write_text(pre+'void MtkMwx::detach(IOPCIDevice *device)\n{'+body+'\n}\n'+post)
subprocess.run(['clang++','-std=c++14','-fsanitize=address,undefined','-g',str(f),'-o',str(out/'test-detach')],check=True)
r=subprocess.run([str(out/'test-detach')],capture_output=True,text=True);(out/'test-detach-result.txt').write_text(r.stdout+r.stderr);print(r.stdout+r.stderr);r.check_returncode()
