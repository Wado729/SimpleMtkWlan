//
//  MtkMwx.hpp
//  SimpleMtkWlan
//
//  Created by laobamac (王孝慈) on 2026/5/17.
//  Copyright © 2026 laobamac (王孝慈). All rights reserved.
//

/*
 * MediaTek MT7922 HAL for SimpleMtkWlan.
 *
 * The driver body is ported from OpenBSD if_mwx.  This header only exposes
 * the SimpleMtkWlan HAL boundary; OpenBSD driver internals stay in MtkMwx.cpp.
 */

#ifndef MtkMwx_hpp
#define MtkMwx_hpp

#include <compat.h>
#include <HAL/MtkHalService.hpp>
#include <HAL/MtkDriverInfo.hpp>
#include <HAL/MtkDriverController.hpp>

struct mwx_softc;
struct pci_attach_args;

class MtkMwx : public MtkHalService, MtkDriverInfo, MtkDriverController {
    OSDeclareDefaultStructors(MtkMwx)

public:
    bool attach(IOPCIDevice *device) override;
    void detach(IOPCIDevice *device) override;
    IOReturn enable(IONetworkInterface *interface) override;
    IOReturn disable(IONetworkInterface *interface) override;
    struct ieee80211com *get80211Controller() override;
    MtkDriverInfo *getDriverInfo() override;
    MtkDriverController *getDriverController() override;
    void free() override;

    const char *getFirmwareVersion() override;
    int16_t getBSSNoise() override;
    bool is5GBandSupport() override;
    int getTxNSS() override;
    const char *getFirmwareName() override;
    UInt32 supportedFeatures() override;
    const char *getFirmwareCountryCode() override;
    uint32_t getTxQueueSize() override;
    uint32_t getRxRateKbps() override;
    int getRxRateMcs() override;

    void clearScanningFlags() override;
    void debugPoll() override;
    void suspend() override;
    void resume() override;
    IOReturn setMulticastList(IOEthernetAddress *addr, int count) override;

    static bool mwx_match(IOPCIDevice *device);

    IOEthernetController *mwxController();
    int mwxSleepNsec(void *ident, int priority, const char *wmesg, uint64_t timo);
    void mwxWakeup(void *ident);

private:
    void releaseAll();

    bool taskQueueOwned;
    struct mwx_softc *com;
    struct pci_attach_args *pci;
};

/*
 * MT7927 bring-up (phase 1 + 2), implemented in MtkMwx.cpp and driven by
 * MtkMt7927Bringup in SimpleMtkWlan.cpp. Independent of the MT7921 HAL.
 */
struct mt7927_bringup;
struct mt7927_bringup *mt7927_bringup_create(IOPCIDevice *dev, IOWorkLoop *wl);
int mt7927_bringup_run(struct mt7927_bringup *b, int stage,
    const uint8_t *patch, size_t patch_len, const uint8_t *ram, size_t ram_len,
    volatile bool *abort);
void mt7927_bringup_set_country(struct mt7927_bringup *b, const char *cc);
void mt7927_bringup_destroy(struct mt7927_bringup *b);

#endif /* MtkMwx_hpp */
