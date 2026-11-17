//
//  WCL.cpp
//  AirportItlwm
//
//  Created by laobamac on 2026/10/1.
//  Copyright © 2026 laobamac. All rights reserved.
//

#ifdef AIRPORT_WCL
#include "../AirportItlwmV2.hpp"
#include "../AirportItlwmSkywalkInterface.hpp"
#include <kern/thread_call.h>
#include <kern/clock.h>
#include <net80211/ieee80211_node.h>
#include <net80211/ieee80211_ioctl.h>
#include <net80211/ieee80211_priv.h>
#include <crypto/sha1.h>

/* phase 4m: when the current join request came in (ms of uptime), for the log */
static uint64_t wclJoinStartMs;

extern IOCommandGate *_fCommandGate;

struct AirportItlwmSkywalkInterface::CountryUpdate {
    AirportItlwmSkywalkInterface *interface;
    AirportItlwm *controller;
    IOCommandGate *gate;
    IO80211WorkQueue *queue;
    thread_call_t call;
};

void AirportItlwmSkywalkInterface::deferWCLCountryUpdate()
{
    auto queue = instance->getWorkQueue();
    if (wclStopping || !_fCommandGate || !queue)
        return;
    auto update = static_cast<CountryUpdate *>(IOMalloc(sizeof(CountryUpdate)));
    if (!update)
        return;
    update->call = thread_call_allocate(wclCountryUpdateThread, update);
    if (!update->call) {
        IOFree(update, sizeof(*update));
        return;
    }
    update->interface = this;
    update->controller = instance;
    update->gate = _fCommandGate;
    update->queue = queue;
    retain();
    instance->retain();
    update->gate->retain();
    queue->retain();
    thread_call_enter(update->call);
}

void AirportItlwmSkywalkInterface::wclCountryUpdateThread(void *arg, void *)
{
    auto update = static_cast<CountryUpdate *>(arg);
    // Native country notifications synchronously query WCL. Holding the gate
    // is necessary, but executing on the driver's workloop thread is forbidden.
    update->gate->runAction(wclCountryUpdateGated, update);
    thread_call_free(update->call);
    update->interface->release();
    update->controller->release();
    update->gate->release();
    update->queue->release();
    IOFree(update, sizeof(*update));
}

IOReturn AirportItlwmSkywalkInterface::wclCountryUpdateGated(
    OSObject *, void *arg, void *, void *, void *)
{
    auto update = static_cast<CountryUpdate *>(arg);
    if (update->interface->wclStopping)
        return kIOReturnNotReady;
    if (!update->queue->inGate() || update->queue->onThread())
        return kIOReturnNotPermitted;
    update->interface->postMessage(APPLE80211_M_COUNTRY_CODE_CHANGED, nullptr, 0, false);
    return kIOReturnSuccess;
}

bool AirportItlwmSkywalkInterface::initWCL()
{
    joinTimer = IOTimerEventSource::timerEventSource(this, wclJoinTimeout);
    if (!joinTimer)
        return false;
    return instance->getWorkQueue()->addEventSource(joinTimer) == kIOReturnSuccess;
}

void AirportItlwmSkywalkInterface::stopWCL()
{
    // Pending country tasks must observe shutdown under the same gate.
    if (_fCommandGate)
        _fCommandGate->runAction(stopWCLGated, this);
    wclStopping = true;
    if (joinTimer) {
        joinTimer->cancelTimeout();
        if (joinTimer->getWorkLoop())
            joinTimer->getWorkLoop()->removeEventSource(joinTimer);
        OSSafeReleaseNULL(joinTimer);
    }
    if (scanSource)
        scanSource->cancelTimeout();
    scanPending = joinPending = false;
    scanDeferred = false;
    joinDeferred = false;
    explicit_bzero(&deferredJoin, sizeof(deferredJoin));
    if (fHalService) {
        ieee80211com *ic = fHalService->get80211Controller();
        ic->ic_wcl_join_requested = false;
        ic->ic_wcl_scan_requested = false;
        explicit_bzero(ic->ic_psk, sizeof(ic->ic_psk));
        AirportWCL::clearSAE(ic);
    }
}

IOReturn AirportItlwmSkywalkInterface::stopWCLGated(
    OSObject *, void *arg, void *, void *, void *)
{
    auto self = static_cast<AirportItlwmSkywalkInterface *>(arg);
    self->portAuthorized = false;
    self->updateWCLLinkQuality(true);
    self->wclStopping = true;
    return kIOReturnSuccess;
}

void AirportItlwmSkywalkInterface::updateWCLLinkQuality(bool force)
{
    if (_fCommandGate)
        _fCommandGate->runAction(updateWCLLinkQualityGated, this,
                                reinterpret_cast<void *>(uintptr_t(force)));
}

IOReturn AirportItlwmSkywalkInterface::updateWCLLinkQualityGated(
    OSObject *, void *arg0, void *arg1, void *, void *)
{
    auto self = static_cast<AirportItlwmSkywalkInterface *>(arg0);
    if (self->wclStopping || !self->fHalService)
        return kIOReturnNotReady;
    auto queue = self->instance->getWorkQueue();
    if (!queue || !queue->inGate())
        return kIOReturnNotPermitted;
    auto interface = self->mExpansionData ? self->getBSDInterface() : nullptr;
    if (!interface) {
        self->wclLinkQualityInterface = nullptr;
        self->wclReportedLinkQuality = -2;
        return kIOReturnNotReady;
    }
    auto ic = self->fHalService->get80211Controller();
    int quality = -2;
    if (self->portAuthorized && self->linkState() == kIO80211NetworkLinkUp &&
        (ifnet_flags(interface) & (IFF_UP | IFF_RUNNING)) == (IFF_UP | IFF_RUNNING) &&
        ic && ic->ic_state == IEEE80211_S_RUN && ic->ic_bss &&
        IEEE80211_ADDR_EQ(ic->ic_bss->ni_bssid, self->joinBSSID)) {
        int rssi = IWM_MIN_DBM + ic->ic_bss->ni_rssi;
        quality = rssi >= -70 ? 100 : (rssi >= -85 ? 50 : 20);
    }
    if (arg1 || quality != self->wclReportedLinkQuality ||
        interface != self->wclLinkQualityInterface) {
        self->setLQM(static_cast<unsigned long long>(static_cast<long long>(quality)));
        self->wclReportedLinkQuality = quality;
        self->wclLinkQualityInterface = interface;
    }
    return kIOReturnSuccess;
}

void AirportItlwmSkywalkInterface::free()
{
    if (joinTimer)
        stopWCL();
    IO80211InfraProtocol::free();
}

IOReturn AirportItlwmSkywalkInterface::wclCommand(OSObject *, void *a0, void *a1, void *a2, void *)
{
    auto self = static_cast<AirportItlwmSkywalkInterface *>(a0);
    if (self->wclStopping)
        return kIOReturnNotReady;
    switch (uintptr_t(a1)) {
        case 13: return self->copyWCLChannels(a2);
        case 14: return self->copyWCLTrafficCounters(a2);
        case 15:
            return self->fHalService->setScanHomeAwayTime(
                AirportWCL::read32(static_cast<const uint8_t *>(a2)));
        case 12:
            self->handleWCLEvent(int(uintptr_t(a2)), nullptr);
            return kIOReturnSuccess;
        case 11: self->clearWCLPMKSA(); return kIOReturnSuccess;
        case 8: return self->installWCLKey(static_cast<apple80211_key *>(a2));
        case 9: return self->accessWCLRSN(static_cast<apple80211_rsn_ie_data *>(a2), true);
        case 10: return self->accessWCLRSN(static_cast<apple80211_rsn_ie_data *>(a2), false);
        case 0: return self->beginWCLScan(static_cast<apple80211ScanRequest *>(a2));
        case 1: return self->beginWCLJoin(static_cast<apple80211AssocCandidates *>(a2));
        case 2: return self->abortWCLJoin();
        case 3: return self->leaveWCLNetwork("macOS disassociate");
        case 6: return self->copyWCLExtendedBss(a2);
        case 7:
            if (!a2 || !self->wclBssValid || !self->wclAssociatedBeacons)
                return kIOReturnNotReady;
            memcpy(a2, self->wclBeaconInfo, sizeof(self->wclBeaconInfo));
            return kIOReturnSuccess;
        case 5:
            if (!a2 || !self->wclBssValid)
                return kIOReturnNotReady;
            memcpy(a2, self->wclBssInfo, sizeof(self->wclBssInfo));
            return kIOReturnSuccess;
        case 4:
            self->finishWCLScan(kIOReturnAborted);
            return kIOReturnSuccess;
    }
    return kIOReturnUnsupported;
}

IOReturn AirportItlwmSkywalkInterface::setWCL_SCAN_REQ(apple80211ScanRequest *request)
{
    return _fCommandGate->runAction(wclCommand, this, nullptr, request);
}

IOReturn AirportItlwmSkywalkInterface::setWCL_SCAN_ABORT(void *)
{
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(4));
}

IOReturn AirportItlwmSkywalkInterface::setWCL_ASSOCIATE(apple80211AssocCandidates *request)
{
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(1), request);
}

#if __IO80211_TARGET == __MAC_15_2
IOReturn AirportItlwmSkywalkInterface::setWCL_JOIN_ABORT(void *)
#else
IOReturn AirportItlwmSkywalkInterface::setWCL_JOIN_ABORT(apple80211_wcl_abort_join *)
#endif
{
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(2));
}

IOReturn AirportItlwmSkywalkInterface::setWCL_LEAVE_NETWORK(apple80211_leave_network *)
{
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(3));
}

IOReturn AirportItlwmSkywalkInterface::beginWCLScan(apple80211ScanRequest *request)
{
    AirportWCL::ScanRequest scan;
    if (!AirportWCL::decodeScan(request, 0x1550, scan))
        return kIOReturnBadArgument;
    return startWCLScan(scan);
}

void AirportItlwmSkywalkInterface::startDeferredWCLScan()
{
    if (!scanDeferred)
        return;
    scanDeferred = scanPending = false;
    scanSource->cancelTimeout();
    if (startWCLScan(deferredScan) != kIOReturnSuccess) {
        IOReturn status = kIOReturnAborted;
        instance->postMessage(this, AirportWCL::ScanDone, &status, sizeof(status), true);
    }
}

/*
 * Phase 4e.7, following Ersiter's Eric-AirportItlwm startWCLScan: a scan is
 * not refused because another one runs (the newer supersedes it) or because
 * the driver is still coming up (it is held and issued when ready). Each
 * refusal silently lost those channels: from outside, a Wi-Fi menu that
 * never shows them.
 */
IOReturn AirportItlwmSkywalkInterface::startWCLScan(const AirportWCL::ScanRequest &scan)
{
    ieee80211com *ic = fHalService->get80211Controller();
    if (!(ic->ic_if.if_flags & IFF_RUNNING)) {
        if (ic->ic_if.if_flags & IFF_UP) {
            if (scanPending)
                finishWCLScan(kIOReturnAborted);
            deferredScan = scan;
            scanDeferred = scanPending = true;
            scanCompleted = false;
            scanSource->setTimeoutMS(20000);
            return kIOReturnSuccess;
        }
        return kIOReturnNotReady;
    }
    if (joinPending || roamPending)     // phase 4u
        return kIOReturnBusy;
    if (ic->ic_state == IEEE80211_S_AUTH || ic->ic_state == IEEE80211_S_ASSOC)
        return kIOReturnBusy;
    // A HAL that cannot restart a running scan (MT7922) keeps the old rule.
    if (!ic->ic_wcl_scan_restart_supported &&
        (scanPending || (ic->ic_flags & IEEE80211_F_BGSCAN)))
        return kIOReturnBusy;
    if (scanPending)
        finishWCLScan(kIOReturnAborted);    // the newer request supersedes it
    if (scan.channelCount) {
        bool usable = false;
        for (unsigned channel = 1; channel <= IEEE80211_CHAN_MAX; ++channel)
            if (ic->ic_channels[channel].ic_flags &&
                !IEEE80211_IS_CHAN_6GHZ(&ic->ic_channels[channel]) &&
                AirportWCL::scanChannelSelected(scan.channels, true, channel))
                usable = true;
        // 6 GHz channels: the driver scans them apart from net80211's table
        if (ic->ic_6ghz_channels)
            for (unsigned i = 0; i < sizeof(scan.channels6g); ++i)
                if (scan.channels6g[i])
                    usable = true;
        if (!usable)
            return kIOReturnUnsupported;
    }
    scanPending = true;
    scanCompleted = false;
    scanSkipCompletion = ic->ic_state == IEEE80211_S_SCAN &&
        ((scan.type != 2 && scan.ssidLength != 0) ||
         ic->ic_wcl_scan_ssid_length != 0 || ic->ic_des_esslen != 0);
    ic->ic_wcl_scan_requested = true;
    ic->ic_wcl_scan_active = scan.type != 2;
    ic->ic_wcl_scan_ssid_length = scan.type == 2 ? 0 : scan.ssidLength;
    memcpy(ic->ic_wcl_scan_ssid, scan.ssid, sizeof(scan.ssid));
    ic->ic_wcl_scan_restricted = scan.channelCount != 0;
    memcpy(ic->ic_wcl_scan_channels, scan.channels, sizeof(scan.channels));
    memcpy(ic->ic_wcl_scan_channels6g, scan.channels6g, sizeof(scan.channels6g));
    scanSource->setTimeoutMS(20000);
    if (ic->ic_state == IEEE80211_S_RUN && (ic->ic_flags & IEEE80211_F_BGSCAN)) {
        // a scan is running: the HAL starts this one when it ends
        ic->ic_wcl_scan_restart = true;
    } else if (ic->ic_state == IEEE80211_S_RUN) {
        ieee80211_begin_cache_bgscan(&ic->ic_if);
        if (!(ic->ic_flags & IEEE80211_F_BGSCAN)) {
            scanPending = false;
            ic->ic_wcl_scan_requested = false;
            scanSource->cancelTimeout();
            return kIOReturnBusy;
        }
    } else if (ic->ic_state != IEEE80211_S_SCAN) {
        int error = ic->ic_newstate(ic, IEEE80211_S_SCAN, -1);
        if (error) {
            scanPending = false;
            ic->ic_wcl_scan_requested = false;
            scanSource->cancelTimeout();
            return kIOReturnError;
        }
    } else if (ic->ic_wcl_scan_idle) {
        // The stack waits for us between scans (ieee80211_end_scan).
        ic->ic_wcl_scan_idle = false;
        scanSkipCompletion = false;
        ieee80211_next_scan(&ic->ic_if);
    } else if (ic->ic_wcl_scan_restart_supported) {
        // A scan is running in SCAN state: the HAL starts this one when it
        // ends, instead of completing this request with that scan's tail.
        ic->ic_wcl_scan_restart = true;
        scanSkipCompletion = false;
    }
    return kIOReturnSuccess;
}

void AirportItlwmSkywalkInterface::finishWCLScan(IOReturn status)
{
    if (!scanPending)
        return;
    scanPending = false;
    scanDeferred = false;
    scanCompleted = false;
    scanSource->cancelTimeout();
    fHalService->get80211Controller()->ic_wcl_scan_requested = false;
    fHalService->get80211Controller()->ic_wcl_scan_restart = false;
    instance->postMessage(this, AirportWCL::ScanDone, &status, sizeof(status), true);
}

void AirportItlwmSkywalkInterface::completeWCLScan()
{
    if (!wclStopping)
        finishWCLScan(scanCompleted ? kIOReturnSuccess : kIOReturnTimeout);
}

void AirportItlwmSkywalkInterface::publishWCLBeacon(const ieee80211_node *node, const uint8_t *ies, size_t length)
{
    if (!node || node->ni_esslen > 32 || !AirportWCL::validIEs(ies, length))
        return;
    ieee80211com *ic = fHalService->get80211Controller();
    if (!node->ni_chan || node->ni_chan == IEEE80211_CHAN_ANYC)
        return;
    // Phase 4g: a 6 GHz node (index 182..240) by its number, band 6G
    const bool is6g = IEEE80211_IS_CHAN_6GHZ(node->ni_chan);
    unsigned channel = ieee80211_chan2number(ic, node->ni_chan);
    if (!channel || channel > (is6g ? 233u : 196u))
        return;
    // macOS's 6 GHz scan list comes from IEEE80211_EVT_BEACON_6G; the node
    // speaks only for the network joined (the BSS info WCL asks for).
    if (is6g && !IEEE80211_ADDR_EQ(node->ni_bssid, joinBSSID))
        return;
    size_t size = sizeof(AirportWCL::BeaconMetadata) + length;
    auto metadata = static_cast<AirportWCL::BeaconMetadata *>(IOMalloc(size));
    if (!metadata)
        return;
    *metadata = {};
    metadata->ieLength = uint32_t(length);
    metadata->channelSpec = uint16_t(channel | (is6g ? 0x5000 :
        IEEE80211_IS_CHAN_5GHZ(node->ni_chan) ? 0xd000 : 0x1000));
    metadata->channel = channel;
    metadata->ssidLength = node->ni_esslen;
    memcpy(metadata->ssid, node->ni_essid, node->ni_esslen);
    memcpy(metadata->bssid, node->ni_bssid, 6);
    metadata->rssi = IWM_MIN_DBM + node->ni_rssi;
    metadata->interval = node->ni_intval;
    metadata->capability = node->ni_capinfo;
    metadata->flags = AirportWCL::SSIDPresent | AirportWCL::RSSIValid;
    memcpy(metadata + 1, ies, length);
    {
        /*
         * WPA3 networks (SAE 8, FT-SAE 9, SAE-EXT-KEY 24/25): log what
         * they ask for once per SSID and band, to plan SAE/PMF/MLO.
         */
        AirportWCL::RSNSummary rsn = AirportWCL::summarizeRSN(ies, length);
        const uint32_t saeAkms = (1u << 8) | (1u << 9) | (1u << 24) | (1u << 25);
        static uint32_t seen[32];
        static unsigned nseen;
        if (rsn.rsn && (rsn.akms & saeAkms)) {
            uint32_t h = 2166136261u;
            for (unsigned i = 0; i < node->ni_esslen; ++i)
                h = (h ^ node->ni_essid[i]) * 16777619u;
            h = (h ^ (is6g ? 6u : channel > 14 ? 5u : 2u)) * 16777619u;
            bool logged = false;
            for (unsigned i = 0; i < nseen; ++i)
                logged |= seen[i] == h;
            if (!logged && nseen < 32) {
                seen[nseen++] = h;
                XYLog("WCL SAE network \"%.*s\" ch %u: akms 0x%x pairwise 0x%x group %u rsn caps 0x%04x (mfp %s)%s\n",
                      node->ni_esslen, node->ni_essid, channel, rsn.akms, rsn.pairwise,
                      rsn.group, rsn.caps, (rsn.caps & 0x40) ? "required" :
                      (rsn.caps & 0x80) ? "capable" : "off", rsn.mlo ? ", multi-link (MLO)" : "");
            }
        }
    }
    /*
     * Show PSK/SAE transition networks as they are, so macOS joins them
     * with WPA3 (phase 4j.2: default; -mtknowcltransition hides SAE).
     */
    static int showTransition = -1;
    if (showTransition < 0) {
        int v = 0;
        // phase 4j.2: on by default; -mtknowcltransition turns it off
        showTransition = PE_parse_boot_argn("-mtknowcltransition", &v, sizeof(v)) ? 0 : 1;
    }
    metadata->ieLength = showTransition ? uint32_t(length) :
        uint32_t(AirportWCL::selectWPA2TransitionMode(
        reinterpret_cast<uint8_t *>(metadata + 1), length));
    size_t messageSize = sizeof(*metadata) + metadata->ieLength;
    if (assocNotified && IEEE80211_ADDR_EQ(node->ni_bssid, joinBSSID)) {
        wclBssValid = messageSize <= sizeof(wclBssInfo);
        if (wclBssValid) {
            bzero(wclBssInfo, sizeof(wclBssInfo));
            memcpy(wclBssInfo, metadata, messageSize);
        }
    }
    instance->postMessage(this, AirportWCL::ScanResult, metadata, messageSize, true);
    IOFree(metadata, size);
}

/*
 * A 6 GHz network the driver heard (IEEE80211_EVT_BEACON_6G): no net80211
 * node, so the metadata comes from the frame. Chanspec band 6G (0x5000: WL_CHANSPEC_BAND_6G 0x4000 | 20 MHz 0x1000).
 */
void AirportItlwmSkywalkInterface::publishWCLBeacon6G(const ieee80211_beacon6g_event *ev)
{
    if (!ev || !ev->bssid || ev->ssid_len > 32 || !ev->chan || ev->chan > 233)
        return;
    // Phase 4e.8: keep the valid elements, as Ersiter does; a nameless
    // result (hidden network, or no SSID element survived) is not listed.
    size_t ieLength = AirportWCL::validIEPrefix(ev->ies, ev->length);
    if (!ieLength || !ev->ssid_len)
        return;
    size_t size = sizeof(AirportWCL::BeaconMetadata) + ieLength;
    auto metadata = static_cast<AirportWCL::BeaconMetadata *>(IOMalloc(size));
    if (!metadata)
        return;
    *metadata = {};
    metadata->channelSpec = uint16_t(ev->chan | 0x5000);
    metadata->channel = ev->chan;
    metadata->ssidLength = ev->ssid_len;
    if (ev->ssid && ev->ssid_len)
        memcpy(metadata->ssid, ev->ssid, ev->ssid_len);
    memcpy(metadata->bssid, ev->bssid, 6);
    metadata->rssi = ev->rssi;
    metadata->interval = ev->intval;
    metadata->capability = ev->capinfo;
    metadata->flags = (ev->ssid_len ? AirportWCL::SSIDPresent : 0) | AirportWCL::RSSIValid;
    memcpy(metadata + 1, ev->ies, ieLength);
    metadata->ieLength = uint32_t(ieLength);
    size_t messageSize = sizeof(*metadata) + metadata->ieLength;
    instance->postMessage(this, AirportWCL::ScanResult, metadata, messageSize, true);
    IOFree(metadata, size);
}

void AirportItlwmSkywalkInterface::clearWCLPMKSA()
{
    auto ic = fHalService->get80211Controller();
    ieee80211_pmk *pmk;
    while ((pmk = TAILQ_FIRST(&ic->ic_pmksa))) {
        TAILQ_REMOVE(&ic->ic_pmksa, pmk, pmk_next);
        explicit_bzero(pmk, sizeof(*pmk));
        ::free(pmk);
    }
}

IOReturn AirportItlwmSkywalkInterface::setCLEAR_PMKSA_CACHE(void *)
{
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(11));
}

IOReturn AirportItlwmSkywalkInterface::installWCLKey(apple80211_key *key)
{
    static_assert(sizeof(apple80211_key) == 0x94, "WCL cipher key layout");
    if (!key || !AirportWCL::validCipherKey(key->key_cipher_type, key->key_len,
            key->key_flags, key->key_index, key->key_rsc_len))
        return kIOReturnBadArgument;
    auto ic = fHalService->get80211Controller();
    auto ni = ic->ic_bss;
    if (!ic->ic_wcl_enterprise || !ni || ic->ic_state != IEEE80211_S_RUN)
        return kIOReturnNotReady;
    if (key->key_cipher_type == APPLE80211_CIPHER_PMK ||
        key->key_cipher_type == APPLE80211_CIPHER_PMKSA ||
        key->key_cipher_type == APPLE80211_CIPHER_MSK) {
        // WCL's native user-client rejects PTK/GTK, and delivers a PMK/MSK
        // instead. Use the existing net80211 four-way/group-key handshake.
        if (!ieee80211_is_8021x_akm((enum ieee80211_akm)ni->ni_rsnakms))
            return kIOReturnBadArgument;
        uint8_t any = 0;
        for (auto byte : key->key_ea.octet) any |= byte;
        if (any && !IEEE80211_ADDR_EQ(key->key_ea.octet, ni->ni_bssid))
            return kIOReturnBadArgument;
        auto pmk = ieee80211_pmksa_add(ic, (enum ieee80211_akm)ni->ni_rsnakms,
                                     ni->ni_macaddr, key->key, 0);
        IOReturn result = pmk ? kIOReturnSuccess : kIOReturnNoMemory;
        return result;
    }
    return kIOReturnUnsupported;
}

IOReturn AirportItlwmSkywalkInterface::accessWCLRSN(apple80211_rsn_ie_data *data, bool write)
{
    if (!data) return kIOReturnBadArgument;
    auto ic = fHalService->get80211Controller();
    if (write) {
        if (!AirportWCL::validRSNOverride(data->ie, data->len))
            return kIOReturnBadArgument;
        // net80211 constructs negotiated IEs for its own key handshake.
        return kIOReturnUnsupported;

    }
    const uint8_t *ie = ic->ic_bss ? ic->ic_bss->ni_rsnie : nullptr;
    if (!ie) return kIOReturnNotReady;
    size_t length = size_t(ie[1]) + 2;
    if (length > sizeof(data->ie)) return kIOReturnBadArgument;
    bzero(data, sizeof(*data));
    data->version = APPLE80211_VERSION;
    data->len = length;
    memcpy(data->ie, ie, length);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::beginWCLJoin(apple80211AssocCandidates *request)
{
    AirportWCL::JoinRequest join;
    if (!AirportWCL::decodeJoin(request, 0x2cc, join)) {
        // What a request we cannot take carries (lengths and types only,
        // never key bytes): how macOS hands over e.g. a WPA3 password.
        const uint8_t *p = reinterpret_cast<const uint8_t *>(request);
        if (p)
            XYLog("WCL join rejected: auth lower=%u upper=0x%x ssid_len=%u key len=%u type=%u index=%u flags=0x%x rsn_ie len=%u candidates=%u\n",
                  AirportWCL::read32(p + 0x10), AirportWCL::read32(p + 0x14),
                  AirportWCL::read32(p + 0x1c), AirportWCL::read32(p + 0x44),
                  AirportWCL::read32(p + 0x48), AirportWCL::read16(p + 0x4e),
                  AirportWCL::read16(p + 0x4c), AirportWCL::read16(p + 0xd4),
                  AirportWCL::read32(p + 0x214));
        return kIOReturnBadArgument;
    }
    return startWCLJoin(join);
}

IOReturn AirportItlwmSkywalkInterface::startWCLJoin(AirportWCL::JoinRequest &join)
{
    wclJoinStartMs = airport_up_time();     // phase 4m: join time in the log
    /*
     * WPA3 (SAE) asked for, with the password itself. Phase 4f.2: offer
     * net80211 both SAE (password + H2E PT) and WPA2-PSK (from the same
     * password); ieee80211_choose_rsnparams takes SAE on an SAE-only
     * network, and on a transition network (PSK too) only with
     * -mtk7927saetransition -- WPA2-PSK stays the tested path there. It
     * decides at join time, so a network not scanned yet works too.
     */
    const uint32_t saeAuth = APPLE80211_AUTHTYPE_WPA3_SAE | APPLE80211_AUTHTYPE_WPA3_FT_SAE;
    bool sae = false;
    // WPA3-Personal with the password itself (as before 4f.2, anything else
    // with SAE bits stays invalid below)
    const bool wpa3Personal = (join.upperAuth & saeAuth) &&
        !(join.upperAuth & ~(saeAuth | APPLE80211_AUTHTYPE_WPA2_PSK)) &&
        AirportWCL::isPassphrase(join);
    if (wpa3Personal) {
        ieee80211com *jic = fHalService->get80211Controller();
        ieee80211_node *jn = ieee80211_find_node(jic, join.bssid);
        AirportWCL::RSNSummary r = {};
        if (jn && jn->ni_rsnie && jn->ni_rsnie[1] >= 2)
            r = AirportWCL::summarizeRSN(jn->ni_rsnie, size_t(jn->ni_rsnie[1]) + 2);
        static int preferSAE = -1;
        if (preferSAE < 0) {
            char v[8];
            preferSAE = PE_parse_boot_argn("-mtk7927saetransition", v, sizeof(v)) ? 1 : 0;
        }
        jic->ic_sae_prefer = preferSAE;
        sae = (jic->ic_caps & IEEE80211_C_MFP) && join.keyLength <= sizeof(jic->ic_sae_password);
        XYLog("WCL join asks for WPA3 (upper 0x%x) on %s: network %s akms 0x%x rsn caps 0x%04x%s -> %s\n",
              join.upperAuth, ether_sprintf(join.bssid), r.rsn ? "known," : "not scanned yet,", r.akms, r.caps,
              (jn && (jn->ni_rsnxecaps & IEEE80211_RSNXECAP_H2E)) ? " H2E" : "",
              !sae ? "WPA2-PSK from the password (no MFP in this driver)" :
              preferSAE ? "SAE, or WPA2-PSK if the network has no SAE" :
              "SAE on an SAE-only network, WPA2-PSK where offered");
    }
    // Validated as WPA2-PSK (classifyLegacyAuth knows no SAE). On a copy:
    // join itself keeps macOS's request, so a deferred join (private MAC,
    // resumeWCLJoin) comes back here as WPA3 again (review of 4f.2).
    AirportWCL::LegacyAuth auth;
    if (wpa3Personal) {
        AirportWCL::JoinRequest probe = join;
        probe.upperAuth = APPLE80211_AUTHTYPE_WPA2_PSK;
        auth = AirportWCL::classifyLegacyAuth(probe);
        explicit_bzero(&probe, sizeof(probe));
    } else
        auth = AirportWCL::classifyLegacyAuth(join);
    XYLog("WCL join ssid_len=%u bssid=%s chanspec=0x%x auth lower=%u upper=0x%x -> %s, key len=%u type=%u%s, rsn_ie len=%u\n",
          join.ssidLength, ether_sprintf(join.bssid), join.channelSpec, join.lowerAuth, join.upperAuth,
          AirportWCL::legacyAuthName(auth), join.keyLength, join.keyCipher,
          AirportWCL::isPassphrase(join) ? " (passphrase)" : "", join.rsnLength);
    bool personal = auth == AirportWCL::LegacyAuth::Personal;
    bool enterprise = auth == AirportWCL::LegacyAuth::Enterprise;
    bool supported = auth != AirportWCL::LegacyAuth::Invalid;
    ieee80211com *ic = fHalService->get80211Controller();
    // Applying a private MAC restarts firmware asynchronously. WCL can issue
    // the association before that restart has completed; keep one request
    // until the HAL reports READY rather than making the user retry it.
    if (supported && !joinPending && ic->ic_wcl_mac_reconfig &&
        (ic->ic_if.if_flags & IFF_UP)) {
        deferredJoin = join;
        memcpy(joinBSSID, join.bssid, sizeof(joinBSSID));
        explicit_bzero(&join, sizeof(join));
        joinDeferred = joinPending = true;
        joinTimer->setTimeoutMS(30000);
        return kIOReturnSuccess;
    }
    // Phase 4e.8: a join retires a pending scan (Ersiter does the same);
    // scans now run back to back, so refusing made joins wait or fail.
    if (supported && (ic->ic_if.if_flags & IFF_RUNNING) && !joinPending &&
        scanPending && ic->ic_wcl_scan_restart_supported)
        finishWCLScan(kIOReturnAborted);
    if (!supported || !(ic->ic_if.if_flags & IFF_RUNNING) || joinPending || scanPending) {
        explicit_bzero(&join, sizeof(join));
        return !supported ? kIOReturnUnsupported : kIOReturnBusy;
    }
    if (roamPending)            // phase 4u: macOS's join wins over a roam
        leaveWCLNetwork("new join during a roam");
    if (ic->ic_state == IEEE80211_S_RUN || ic->ic_state == IEEE80211_S_AUTH || ic->ic_state == IEEE80211_S_ASSOC)
        leaveWCLNetwork("new join");
    ieee80211_disable_rsn(ic);
    ieee80211_disable_wep(ic);
    explicit_bzero(ic->ic_psk, sizeof(ic->ic_psk));
    AirportWCL::clearSAE(ic);
    clearWCLPMKSA();
    ic->ic_flags &= ~(IEEE80211_F_AUTO_JOIN | IEEE80211_F_PSK);
    ic->ic_wcl_enterprise = enterprise;

    if (personal || enterprise) {
        ieee80211_wpaparams wpa = {};
        wpa.i_enabled = 1;
        if (join.upperAuth & (APPLE80211_AUTHTYPE_WPA | APPLE80211_AUTHTYPE_WPA_PSK))
            wpa.i_protos |= IEEE80211_WPA_PROTO_WPA1;
        if (join.upperAuth & (APPLE80211_AUTHTYPE_WPA2 | APPLE80211_AUTHTYPE_WPA2_PSK |
                              APPLE80211_AUTHTYPE_SHA256_PSK | APPLE80211_AUTHTYPE_SHA256_8021X) ||
            wpa3Personal)
            wpa.i_protos |= IEEE80211_WPA_PROTO_WPA2;
        // WPA3 asked for: WPA2-PSK from the same password where offered
        if ((join.upperAuth & (APPLE80211_AUTHTYPE_WPA_PSK | APPLE80211_AUTHTYPE_WPA2_PSK)) ||
            wpa3Personal)
            wpa.i_akms |= IEEE80211_WPA_AKM_PSK;
        if (join.upperAuth & (APPLE80211_AUTHTYPE_WPA | APPLE80211_AUTHTYPE_WPA2))
            wpa.i_akms |= IEEE80211_WPA_AKM_8021X;
        if (join.upperAuth & APPLE80211_AUTHTYPE_SHA256_PSK)
            wpa.i_akms |= IEEE80211_WPA_AKM_SHA256_PSK;
        if (join.upperAuth & APPLE80211_AUTHTYPE_SHA256_8021X)
            wpa.i_akms |= IEEE80211_WPA_AKM_SHA256_8021X;
        if (sae)
            wpa.i_akms |= IEEE80211_WPA_AKM_SAE;
        wpa.i_ciphers = IEEE80211_WPA_CIPHER_CCMP | IEEE80211_WPA_CIPHER_TKIP;
        if (join.rsnLength >= 8 && join.rsn[0] == IEEE80211_ELEMID_RSN &&
            join.rsn[4] == 0 && join.rsn[5] == 0x0f && join.rsn[6] == 0xac) {
            if (join.rsn[7] == 2) wpa.i_groupcipher = IEEE80211_WPA_CIPHER_TKIP;
            if (join.rsn[7] == 4) wpa.i_groupcipher = IEEE80211_WPA_CIPHER_CCMP;
        }
        int error = ieee80211_ioctl_setwpaparms(ic, &wpa);
        if (error && error != ENETRESET) {
            explicit_bzero(&join, sizeof(join));
            return kIOReturnBadArgument;
        }
        if (personal) {
            if (AirportWCL::isHexPSK(join)) {
                for (unsigned i = 0; i < sizeof(ic->ic_psk); ++i) {
                    auto nib = [](uint8_t c) -> uint8_t {
                        return c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10;
                    };
                    ic->ic_psk[i] = uint8_t(nib(join.key[2 * i]) << 4 | nib(join.key[2 * i + 1]));
                }
            } else if (AirportWCL::isPassphrase(join)) {
                char passphrase[64] = {};
                memcpy(passphrase, join.key, join.keyLength);
                pbkdf2_sha1(passphrase, join.ssid, join.ssidLength, 4096,
                            ic->ic_psk, sizeof(ic->ic_psk));
                explicit_bzero(passphrase, sizeof(passphrase));
            } else
                memcpy(ic->ic_psk, join.key, sizeof(ic->ic_psk));
            ic->ic_flags |= IEEE80211_F_PSK;
            XYLog("WCL join PSK key check %02x\n",
                  ieee80211_key_check(ic->ic_psk, sizeof(ic->ic_psk)));
            if (sae) {
                // SAE: the password for hunting-and-pecking, the PT for H2E
                memcpy(ic->ic_sae_password, join.key, join.keyLength);
                ic->ic_sae_password_len = join.keyLength;
                ic->ic_sae_pt_valid = ieee80211_sae_password_to_pt(ic->ic_sae_pt,
                    join.key, join.keyLength, join.ssid, join.ssidLength) == 0;
                XYLog("WCL join SAE: password set, H2E PT %s\n",
                      ic->ic_sae_pt_valid ? "derived" : "failed");
            }
        } else if (join.keyLength == IEEE80211_PMK_LEN) {
            bool cached = true;
            if (join.upperAuth & (APPLE80211_AUTHTYPE_WPA | APPLE80211_AUTHTYPE_WPA2))
                cached = ieee80211_pmksa_add(ic, IEEE80211_AKM_8021X, join.bssid, join.key, 0) != nullptr;
            if (cached && (join.upperAuth & APPLE80211_AUTHTYPE_SHA256_8021X))
                cached = ieee80211_pmksa_add(ic, IEEE80211_AKM_SHA256_8021X, join.bssid, join.key, 0) != nullptr;
            if (!cached) {
                clearWCLPMKSA();
                explicit_bzero(&join, sizeof(join));
                return kIOReturnNoMemory;
            }
        }
    } else if (auth == AirportWCL::LegacyAuth::Wep) {
        ieee80211_nwkey keys = {};
        keys.i_wepon = IEEE80211_NWKEY_WEP;
        keys.i_defkid = join.keyIndex + 1;
        keys.i_key[join.keyIndex].i_keylen = join.keyLength;
        keys.i_key[join.keyIndex].i_keydat = join.key;
        int error = ieee80211_ioctl_setnwkeys(ic, &keys);
        if (error && error != ENETRESET) {
            explicit_bzero(&join, sizeof(join));
            return kIOReturnBadArgument;
        }
    }
    ic->ic_des_esslen = join.ssidLength;
    memcpy(ic->ic_des_essid, join.ssid, sizeof(ic->ic_des_essid));
    // Phase 4g: a 6 GHz join (chanspec band 0x4000): its channel goes into
    // the join scan even off the PSC grid
    ic->ic_wcl_join_chan6g = (join.channelSpec & 0xc000) == 0x4000 ?
        uint8_t(join.channelSpec & 0xff) : 0;
    ic->ic_wcl_join_scans = 0;     // phase 4p: the channel alone first
    memcpy(ic->ic_des_bssid, join.bssid, 6);
    memcpy(joinBSSID, join.bssid, 6);
    ic->ic_flags |= IEEE80211_F_DESBSSID;
    ic->ic_wcl_join_requested = true;
    ic->ic_wcl_scan_requested = false;
    roamScanPending = false;            // phase 4u.1
    current_authtype_lower = join.lowerAuth;
    current_authtype_upper = join.upperAuth;
    explicit_bzero(&join, sizeof(join));
    wclBssValid = false;
    joinPending = true;
    assocNotified = firstBeaconNotified = portAuthorized = false;
    firstBeaconDeferredLogged = false;
    wclAssociatedBeacons = 0;
    wclJoinBeacons = 0;
    bzero(wclBeaconInfo, sizeof(wclBeaconInfo));
    disassocIsVoluntary = false;
    joinTimer->setTimeoutMS(30000);
    if (ic->ic_state == IEEE80211_S_SCAN && ic->ic_wcl_scan_idle) {
        // The stack waits for us between scans (ieee80211_end_scan).
        ic->ic_wcl_scan_idle = false;
        /*
         * Phase 4m: macOS joins the BSSID it picked from the scan it just
         * made; a real Mac then joins at once. If we heard that AP in the
         * last few seconds, choose it from what we have (ieee80211_end_scan)
         * instead of sweeping every channel first. Not found or not
         * matching: end_scan scans again, as before.
         */
        ieee80211_node *fn = ieee80211_find_node(ic, joinBSSID);
        uint64_t now = airport_up_time();
        // review S2: a node with a recorded failure is skipped by
        // node_choose_bss; those take the scan path, as before
        if (fn != NULL && fn->ni_age_ts != 0 && now - fn->ni_age_ts < 8000 &&
            fn->ni_fails == 0) {
            XYLog("WCL join: %s heard %llu ms ago, joining without a new scan\n",
                  ether_sprintf(joinBSSID), now - fn->ni_age_ts);
            ieee80211_end_scan(&ic->ic_if);
        } else
            ieee80211_next_scan(&ic->ic_if);
    } else if (ic->ic_state == IEEE80211_S_SCAN && ic->ic_wcl_join_chan6g != 0 &&
               !scanPending) {
        /*
         * Phase 4q: a sweep runs (the interface starts one when it comes
         * up, right before macOS's join): cancel it so the join scans its
         * 6 GHz channel (4p) now instead of in ~4 s.
         */
        IOReturn ar = fHalService->abortScanForJoin();
        XYLog("WCL join: 6 GHz join during a scan, scan %s (0x%x)\n",
              ar == kIOReturnSuccess ? "cancelled" : "left to finish", ar);
    }
    if (ic->ic_state != IEEE80211_S_SCAN && ic->ic_newstate(ic, IEEE80211_S_SCAN, -1)) {
        joinPending = false;
        joinTimer->cancelTimeout();
        ic->ic_wcl_join_requested = false;
        clearWCLPMKSA();
        ic->ic_wcl_enterprise = false;
        explicit_bzero(ic->ic_psk, sizeof(ic->ic_psk));
        AirportWCL::clearSAE(ic);
        return kIOReturnError;
    }
    return kIOReturnSuccess;
}

void AirportItlwmSkywalkInterface::resumeWCLJoin()
{
    if (!joinDeferred || wclStopping)
        return;
    AirportWCL::JoinRequest join = deferredJoin;
    explicit_bzero(&deferredJoin, sizeof(deferredJoin));
    joinDeferred = joinPending = false;
    joinTimer->cancelTimeout();
    IOReturn status = startWCLJoin(join);
    explicit_bzero(&join, sizeof(join));
    if (status != kIOReturnSuccess) {
        joinPending = true;
        finishWCLJoin(1, 0, status);
    }
}

void AirportItlwmSkywalkInterface::finishWCLJoin(uint16_t status, uint16_t reason, IOReturn driverStatus)
{
    if (!joinPending)
        return;
    XYLog("WCL join %s after %llu ms (status %u reason %u)\n",
          status ? "failed" : "done", airport_up_time() - wclJoinStartMs,
          status, reason);
    AirportWCL::ConnectionEvent event = {};
    event.status = status;
    event.reason = reason;
    memcpy(event.peers[0].bssid, joinBSSID, 6);
    event.peers[0].driverStatus = driverStatus;
    joinPending = false;
    joinDeferred = false;
    explicit_bzero(&deferredJoin, sizeof(deferredJoin));
    joinTimer->cancelTimeout();
    instance->postMessage(this, AirportWCL::ConnectComplete, &event, sizeof(event), true);
    if (status) {
        portAuthorized = false;
        updateWCLLinkQuality(true);
        ieee80211com *ic = fHalService->get80211Controller();
        ic->ic_wcl_join_requested = false;
        clearWCLPMKSA();
        ic->ic_wcl_enterprise = false;
        explicit_bzero(ic->ic_psk, sizeof(ic->ic_psk));
        AirportWCL::clearSAE(ic);
    }
}

void AirportItlwmSkywalkInterface::wclJoinTimeout(OSObject *owner, IOTimerEventSource *)
{
    auto self = OSDynamicCast(AirportItlwmSkywalkInterface, owner);
    if (self && !self->wclStopping && self->roamPending) {
        self->finishWCLRoam(false, "timeout");     // phase 4u
        return;
    }
    if (self && !self->wclStopping) {
        self->finishWCLJoin(1, 1004, kIOReturnTimeout);
        self->leaveWCLNetwork("join timeout");
    }
}

IOReturn AirportItlwmSkywalkInterface::leaveWCLNetwork(const char *why)
{
    ieee80211com *ic = fHalService->get80211Controller();
    bool abandonedRoam = roamPending;   // phase 4u: macOS's leave or join ends a roam
    abortWCLRoam(kIOReturnAborted, why);
    roamScanPending = false;            // 4u.1 review
    roamScanIntervalMs = 0;
    XYLog("WCL leave (%s): state %d joinPending %d assoc %d firstBeacon %d bssValid %d "
        "join beacons %u assoc beacons %u port %d\n", why, ic->ic_state, joinPending,
        assocNotified, firstBeaconNotified, wclBssValid, wclJoinBeacons,
        wclAssociatedBeacons, portAuthorized);
    /*
     * Phase 4i: tell the AP we are leaving, as mac80211 does on every
     * disconnect. net80211's RUN -> SCAN sends nothing, so the AP kept our
     * session; with PMF (WPA3, all of 6 GHz) it then answered the next
     * association with status 30 and SA-queried the stale one first: the
     * "first join fails" pattern. Sent here, before RSN is turned off below,
     * so in RUN it goes out protected with the PTK (ieee80211_get_txkey()
     * needs IEEE80211_F_RSNON); the HAL lets it leave the chip before the
     * station entry goes.
     */
    /*
     * Review M3: ic_state changes only when the HAL's newstate task ends,
     * so a second leave in that window (macOS: disassociate, then join)
     * still sees RUN with RSN already off: no second deauth then (a
     * protected frame would get a group key). M5: data TX stops first, so
     * no class-3 frame follows the deauth.
     */
    timeout_del(&ic->ic_assoc_to);      /* review S1 */
    if (ic->ic_opmode == IEEE80211_M_STA && ic->ic_bss != NULL &&
        !ic->ic_leave_pending &&
        (ic->ic_state == IEEE80211_S_RUN || ic->ic_state == IEEE80211_S_ASSOC) &&
        ((ic->ic_flags & IEEE80211_F_RSNON) ||
         !(ic->ic_bss->ni_flags & IEEE80211_NODE_TXMGMTPROT))) {
        ic->ic_xflags |= IEEE80211_F_TX_MGMT_ONLY;
        ic->ic_leave_pending = 1;
        int rv = IEEE80211_SEND_MGMT(ic, ic->ic_bss,
            IEEE80211_FC0_SUBTYPE_DEAUTH, IEEE80211_REASON_AUTH_LEAVE);
        XYLog("WCL leave: deauth to %s (%s) -> %d, %d management frames still "
            "queued\n", ether_sprintf(ic->ic_bss->ni_macaddr),
            (ic->ic_bss->ni_flags & IEEE80211_NODE_TXMGMTPROT) ?
            "protected" : "not protected", rv, mq_len(&ic->ic_mgtq));
    }
    portAuthorized = false;
    updateWCLLinkQuality(true);
    joinPending = false;
    joinDeferred = false;
    explicit_bzero(&deferredJoin, sizeof(deferredJoin));
    joinTimer->cancelTimeout();
    ic->ic_wcl_join_requested = false;
    wclAssociatedBeacons = 0;
    wclBssValid = false;
    disassocIsVoluntary = true;
    ic->ic_deauth_reason = IEEE80211_REASON_AUTH_LEAVE;
    if (ic->ic_state > IEEE80211_S_SCAN)
        ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
    ieee80211_disable_rsn(ic);
    ieee80211_disable_wep(ic);
    explicit_bzero(ic->ic_psk, sizeof(ic->ic_psk));
    AirportWCL::clearSAE(ic);
    clearWCLPMKSA();
    ic->ic_wcl_enterprise = false;
    ic->ic_flags &= ~(IEEE80211_F_PSK | IEEE80211_F_DESBSSID);
    ic->ic_des_esslen = 0;
    bzero(ic->ic_des_essid, sizeof(ic->ic_des_essid));
    if (abandonedRoam)
        syncLinkAfterRoam();    // phase 4u
    return kIOReturnSuccess;
}

// Phase 4s (AirportItlwm::systemWillShutdown, on the command gate): leave
// as macOS's disassociate does, so the AP drops our session now.
bool AirportItlwmSkywalkInterface::leaveForShutdown()
{
    ieee80211com *ic = fHalService ? fHalService->get80211Controller() : NULL;
    if (wclStopping || ic == NULL || ic->ic_opmode != IEEE80211_M_STA ||
        ic->ic_state != IEEE80211_S_RUN)
        return false;
    // review: true only if the deauth was queued (leaveWCLNetwork skips it
    // when a leave is pending or RSN is already off)
    bool pendingBefore = ic->ic_leave_pending != 0;
    leaveWCLNetwork("system shutdown");
    return !pendingBefore && ic->ic_leave_pending != 0;
}

IOReturn AirportItlwmSkywalkInterface::abortWCLJoin()
{
    leaveWCLNetwork("join abort");
    instance->postMessage(this, AirportWCL::JoinAbortComplete, nullptr, 0, true);
    return kIOReturnSuccess;
}

void AirportItlwmSkywalkInterface::notifyWCLFirstBeacon(const char *source)
{
    if (!joinPending || !assocNotified || firstBeaconNotified || !wclBssValid)
        return;
    /*
     * Phase 4n: the association event goes up from recv_assoc_resp, but
     * ic_state becomes RUN only when the HAL's newstate task ends (~30 ms of
     * BSS_INFO/STA_REC commands). The link-up below makes WCL fetch
     * APPLE80211_IOC_WCL_EXTENDED_BSS_INFO at once, which answers NotReady
     * outside RUN; WCL then leaves with "Update Bss fail" (hardware log,
     * Nov 16: a beacon 1 ms before RUN). Wait for RUN: the next beacon, at
     * most a beacon interval later, sends it.
     */
    if (fHalService->get80211Controller()->ic_state != IEEE80211_S_RUN) {
        if (!firstBeaconDeferredLogged) {
            firstBeaconDeferredLogged = true;
            XYLog("WCL first beacon (%s) before RUN (state %d): waiting for the next one\n",
                source, fHalService->get80211Controller()->ic_state);
        }
        return;
    }
    AirportWCL::FirstBeaconEvent event = {};
    memcpy(event.peer.bssid, joinBSSID, 6);
    firstBeaconNotified = true;
    AirportWCL::LinkStatusEvent link = {};
    memcpy(link.bssid, joinBSSID, sizeof(link.bssid));
    link.up = 1;
    link.reason = 255;
    wclLinkIndicated = true;
    XYLog("WCL first beacon (%s), %u join beacons, port %s\n", source,
        wclJoinBeacons, portAuthorized ? "authorized" : "not yet authorized");
    instance->postMessage(this, AirportWCL::LinkStatus, &link, sizeof(link), true);
    instance->postMessage(this, AirportWCL::FirstBeacon, &event, sizeof(event), true);
    if (portAuthorized)
        finishWCLJoin(0, 0, kIOReturnSuccess);
}

/*
 * The port is authorized but no beacon from the BSS has arrived since the
 * association. Publish the BSS from the beacon cached at scan time so the
 * join can complete instead of hitting WCL's 10 s association timeout.
 */
void AirportItlwmSkywalkInterface::synthesizeWCLFirstBeacon()
{
    ieee80211com *ic = fHalService->get80211Controller();
    ieee80211_node *ni = ic->ic_bss;

    if (!joinPending || !assocNotified || firstBeaconNotified || !ni)
        return;
    if (!IEEE80211_ADDR_EQ(ni->ni_bssid, joinBSSID))
        return;
    if (!wclBssValid && ni->ni_rsnie_tlv && ni->ni_rsnie_tlv_len > 0)
        publishWCLBeacon(ni, ni->ni_rsnie_tlv, ni->ni_rsnie_tlv_len);
    if (!wclBssValid) {
        XYLog("WCL first beacon: no cached BSS (ies %u)\n", ni->ni_rsnie_tlv_len);
        return;
    }
    notifyWCLFirstBeacon("cached scan beacon");
}

/*
 * Phase 4u: roaming between the APs of the joined network (mesh nodes).
 * A real Mac's Broadcom firmware roams by itself and tells WCL in a fixed
 * order (AppleBCMWLANCore: roam scan start 137, reassoc 73, link up 216 with
 * the new BSSID, roam completion 80); WCLNetManager::linkUp then reads the
 * new BSS (updateBss), and WCLRoamManager keeps its statistics. Here the
 * driver decides like a Mac with default settings (the user's choice):
 * only on a weak link (averaged signal, phase 4t, at or below -72 dBm) and
 * only to an AP of the same network at least 8 dB stronger, heard in the
 * last 30 s (macOS's own associated scans keep the list fresh); not in the
 * first minute of a link, at most one try a minute, and an AP that failed
 * is left alone for 5 minutes. No fast transition on the user's network,
 * so a roam is a full join (SAE, association, 4-way) with the password the
 * join gave: about 1.5-2 s without data, link kept up for macOS.
 * -mtk7927noroam turns it off.
 */
static constexpr uint64_t kRoamSettleMs = 60000;
static constexpr uint64_t kRoamRetryMs = 60000;
static constexpr uint64_t kRoamBlockMs = 300000;
static constexpr uint64_t kRoamHeardMs = 30000;
static constexpr uint64_t kRoamScanMs = 15000;     // a Mac's low-RSSI roam scans: 30 s
static constexpr uint32_t kRoamTimeoutMs = 10000;       // 6 GHz: its channel alone
static constexpr uint32_t kRoamSweepTimeoutMs = 15000;  // otherwise a full sweep first

void AirportItlwmSkywalkInterface::checkWCLRoam()
{
    static int disabled = -1;
    if (disabled < 0) {
        char v[8];
        disabled = PE_parse_boot_argn("-mtk7927noroam", v, sizeof(v)) ? 1 : 0;
    }
    ieee80211com *ic = fHalService->get80211Controller();
    if (disabled || wclStopping || roamPending || joinPending || scanPending ||
        !portAuthorized || ic->ic_opmode != IEEE80211_M_STA ||
        ic->ic_state != IEEE80211_S_RUN || ic->ic_bss == NULL ||
        ic->ic_wcl_enterprise || !(ic->ic_flags & IEEE80211_F_PSK) ||
        !(ic->ic_flags & IEEE80211_F_RSNON))
        return;
    uint64_t now = airport_up_time();
    // review: a completion the HAL drops never ends roamScanPending
    if (roamScanPending && now - roamLastScanMs > 20000)
        roamScanPending = false;
    if (now - linkUpMs < kRoamSettleMs || now - roamLastTryMs < kRoamRetryMs)
        return;
    ieee80211_node *bss = ic->ic_bss;
    int cur = int(bss->ni_rssi) - 100;      // dBm, averaged (phase 4t)
    if (bss->ni_rssi == 0 || cur > AirportWCL::kRoamTriggerDbm) {
        roamConfirm.armed = false;
        roamScanIntervalMs = 0;
        return;
    }
    ieee80211_node *best = NULL, *ni;
    int bestRssi = -128;
    RB_FOREACH(ni, ieee80211_tree, &ic->ic_tree) {
        if (ni == bss || IEEE80211_ADDR_EQ(ni->ni_macaddr, bss->ni_macaddr) ||
            ni->ni_esslen != bss->ni_esslen ||
            memcmp(ni->ni_essid, bss->ni_essid, bss->ni_esslen) != 0 ||
            !(ni->ni_rsnakms & bss->ni_rsnakms) || ni->ni_fails != 0 ||
            ni->ni_age_ts == 0 || now - ni->ni_age_ts > kRoamHeardMs ||
            ni->ni_rssi == 0 || ni->ni_chan == NULL ||
            ni->ni_chan == IEEE80211_CHAN_ANYC)
            continue;
        if (now < roamBlockUntilMs && IEEE80211_ADDR_EQ(ni->ni_macaddr, roamBlockBSSID))
            continue;
        int r = int(ni->ni_rssi) - 100;
        if (r > bestRssi) {
            bestRssi = r;
            best = ni;
        }
    }
    bool wanted = best != NULL && AirportWCL::roamWanted(cur, bestRssi);
    bool go = false;
    if (!wanted)
        roamConfirm.armed = false;
    else
        go = AirportWCL::roamConfirmed(roamConfirm, best->ni_macaddr, best->ni_age_ts);
    if (go || (wanted && roamConfirm.armed && roamLastLogMs != roamConfirm.sampleMs) ||
        now - roamLastLogMs >= 30000) {
        roamLastLogMs = wanted ? roamConfirm.sampleMs : now;
        XYLog("WCL roam check: %s at %d dBm (average), best other AP %s at %d dBm%s\n",
              ether_sprintf(bss->ni_macaddr), cur,
              best ? ether_sprintf(best->ni_macaddr) : "none", best ? bestRssi : 0,
              go ? ": roaming" : wanted ? ": waiting for a second reading" : "");
    }
    if (wanted)
        roamScanIntervalMs = 0;     // something better heard: scan again soon
    if (go && roamScanPending) {    // review: not on top of our running scan
        go = false;
        roamConfirm.armed = true;   // the confirmed reading still counts
        roamConfirm.sampleMs = 0;
    }
    if (go)
        startWCLRoam(best);
    else if (!roamScanPending &&
             now - roamLastScanMs >= (roamScanIntervalMs ? roamScanIntervalMs : kRoamScanMs))
        startWCLRoamScan();
}

/*
 * Phase 4u (hardware, Nov 16): on the far Deco no other AP was ever heard
 * fresh enough: macOS skips its own roam scans here ("SKIPPING RoamScan;
 * Env:0 isDualBand:0") and its other scans are minutes apart, and the
 * firmware filters other APs' beacons in RUN. A Mac's firmware roam-scans
 * itself on a weak link (WCL's roam profile below -75 dBm: every 30 s).
 * Here every 15 s while the link is weak: the channels where APs of this
 * network were heard and our own, through the associated-scan path macOS's
 * scans use (a 6 GHz channel of our own does not leave the home channel).
 */
void AirportItlwmSkywalkInterface::startWCLRoamScan()
{
    ieee80211com *ic = fHalService->get80211Controller();
    roamLastScanMs = airport_up_time();
    if (roamScanPending || scanPending || (ic->ic_flags & IEEE80211_F_BGSCAN))
        return;
    // review: back off (15, 30, 60 s) while the scans find nothing better
    roamScanIntervalMs = roamScanIntervalMs == 0 ? kRoamScanMs :
        (roamScanIntervalMs * 2 > 4 * kRoamScanMs ? 4 * kRoamScanMs : roamScanIntervalMs * 2);
    ieee80211_node *bss = ic->ic_bss, *ni;
    uint8_t bitmap[sizeof(ic->ic_wcl_scan_channels)] = {};
    uint8_t six[sizeof(ic->ic_wcl_scan_channels6g)] = {};
    unsigned n6 = 0, n = 0;
    // review: a bitmap by 6 GHz channel number, as WCL.hpp builds macOS's
    // requests and mt7927_hal_scan reads it
    auto add6 = [&](unsigned num) {
        if (AirportWCL::set6gChannel(six, sizeof(six), num)) {
            n6++;
            n++;
        }
    };
    auto add = [&](const ieee80211_channel *c) {
        if (c == NULL || c == IEEE80211_CHAN_ANYC)
            return;
        if (IEEE80211_IS_CHAN_6GHZ(c)) {
            add6(unsigned(ieee80211_chan2number(ic, c)));
        } else {
            unsigned idx = unsigned(c - ic->ic_channels);
            if (idx / 8 < sizeof(bitmap) && !(bitmap[idx / 8] & (1U << (idx % 8)))) {
                bitmap[idx / 8] |= uint8_t(1U << (idx % 8));
                n++;
            }
        }
    };
    add(bss->ni_chan);
    RB_FOREACH(ni, ieee80211_tree, &ic->ic_tree) {
        if (n >= 8)
            break;
        if (ni != bss && ni->ni_esslen == bss->ni_esslen &&
            memcmp(ni->ni_essid, bss->ni_essid, bss->ni_esslen) == 0)
            add(ni->ni_chan);
    }
    // review: every 4th roam scan wider, for an AP never heard or aged out:
    // on 6 GHz the preferred scanning channels (5, 21, ... 229), else the
    // channels of our band
    bool wide = (++roamScanCount % 4) == 0;
    if (wide && IEEE80211_IS_CHAN_6GHZ(bss->ni_chan)) {
        for (unsigned psc = 5; psc <= 229; psc += 16)
            add6(psc);
    } else if (wide) {
        bool two = IEEE80211_IS_CHAN_2GHZ(bss->ni_chan);
        for (ieee80211_channel *c = &ic->ic_channels[1];
             c <= &ic->ic_channels[IEEE80211_CHAN_MAX]; c++)
            if (c->ic_flags != 0 && !IEEE80211_IS_CHAN_6GHZ(c) &&
                bool(IEEE80211_IS_CHAN_2GHZ(c)) == two)
                add(c);
    }
    memcpy(ic->ic_wcl_scan_channels, bitmap, sizeof(bitmap));
    memcpy(ic->ic_wcl_scan_channels6g, six, sizeof(six));
    ic->ic_wcl_scan_requested = true;
    ic->ic_wcl_scan_restricted = true;
    ic->ic_wcl_scan_active = false;
    ic->ic_wcl_scan_ssid_length = 0;
    roamScanPending = true;
    ieee80211_begin_cache_bgscan(&ic->ic_if);
    bool started = (ic->ic_flags & IEEE80211_F_BGSCAN) != 0;
    if (!started) {
        roamScanPending = false;
        ic->ic_wcl_scan_requested = false;
        ic->ic_wcl_scan_restricted = false;
    }
    XYLog("WCL roam scan: %u channel(s)%s%s%s, next in %llu s\n", n, n6 ? ", 6 GHz" : "",
          wide ? " (wide)" : "", started ? "" : ": not started", roamScanIntervalMs / 1000);
}

bool AirportItlwmSkywalkInterface::startWCLRoam(ieee80211_node *target)
{
    ieee80211com *ic = fHalService->get80211Controller();
    uint64_t now = airport_up_time();
    roamLastTryMs = now;
    uint8_t to[6];
    memcpy(to, target->ni_macaddr, 6);
    uint8_t chan = uint8_t(ieee80211_chan2ieee(ic, target->ni_chan));
    bool sixGHz = IEEE80211_IS_CHAN_6GHZ(target->ni_chan);
    memcpy(roamFromBSSID, joinBSSID, 6);

    AirportWCL::RoamScanStartEvent start = {};
    start.reason = AirportWCL::kRoamReasonLowRSSI;
    instance->postMessage(this, AirportWCL::RoamScanStart, &start, sizeof(start), true);
    roamPending = true;
    roamStartMs = now;

    // Leave the old AP as leaveWCLNetwork does (phase 4i): protected deauth
    // while RSN is on, no data after it; the HAL lets it leave the chip
    // before the station entry goes.
    timeout_del(&ic->ic_assoc_to);
    int rv = -1;
    if (!ic->ic_leave_pending) {
        ic->ic_xflags |= IEEE80211_F_TX_MGMT_ONLY;
        ic->ic_leave_pending = 1;
        rv = IEEE80211_SEND_MGMT(ic, ic->ic_bss, IEEE80211_FC0_SUBTYPE_DEAUTH,
                                 IEEE80211_REASON_AUTH_LEAVE);
    }
    ic->ic_deauth_reason = IEEE80211_REASON_AUTH_LEAVE;
    XYLog("WCL roam: from %s, deauth -> %d; to %s on channel %u%s\n",
          ether_sprintf(roamFromBSSID), rv, ether_sprintf(to), chan,
          sixGHz ? " (6 GHz)" : "");
    // Aim the join at the target; the network's credentials (PSK, SAE
    // password and PT: the same SSID) stay as the join set them.
    memcpy(ic->ic_des_bssid, to, 6);
    memcpy(joinBSSID, to, 6);
    ic->ic_flags |= IEEE80211_F_DESBSSID;
    ic->ic_wcl_join_chan6g = sixGHz ? chan : 0;    // 4p/4r: its channel alone first
    ic->ic_wcl_join_scans = 0;
    ic->ic_wcl_join_requested = true;
    ic->ic_wcl_scan_requested = false;
    // review: the old AP's BSS and beacon information stay readable until
    // the new one's beacons replace them (assocNotified again at
    // association). portAuthorized stays set: the held link down never
    // reaches handleWCLLink, so link-quality reports go on through the roam.
    assocNotified = firstBeaconNotified = false;
    joinTimer->setTimeoutMS(sixGHz ? kRoamTimeoutMs : kRoamSweepTimeoutMs);
    if (ic->ic_newstate(ic, IEEE80211_S_SCAN, -1) != 0) {
        finishWCLRoam(false, "could not start");
        return false;
    }
    return true;
}

void AirportItlwmSkywalkInterface::finishWCLRoam(bool ok, const char *why)
{
    if (!roamPending)
        return;
    // review: WCL reads the BSS (IOC 0x1b1, wclBssInfo) right after the
    // link-up and leaves on a failure or keeps the old AP: it must be the
    // new AP's by then
    if (ok && !publishRoamBss()) {
        ok = false;
        why = "no BSS information for the new AP";
    }
    roamPending = false;
    joinTimer->cancelTimeout();
    uint64_t now = airport_up_time();
    XYLog("WCL roam %s to %s after %llu ms (%s)\n", ok ? "done" : "failed",
          ether_sprintf(joinBSSID), now - roamStartMs, why);
    if (ok) {
        assocNotified = firstBeaconNotified = true;
        linkUpMs = now;
        AirportWCL::ReassocEvent reassoc = {};
        instance->postMessage(this, AirportWCL::Reassoc, &reassoc, sizeof(reassoc), true);
        AirportWCL::LinkStatusEvent link = {};
        memcpy(link.bssid, joinBSSID, 6);
        link.up = 1;
        link.reason = 255;      // as the first link-up (notifyWCLFirstBeacon)
        wclLinkIndicated = true;
        instance->postMessage(this, AirportWCL::LinkStatus, &link, sizeof(link), true);
    } else {
        memcpy(roamBlockBSSID, joinBSSID, 6);
        roamBlockUntilMs = now + kRoamBlockMs;
        memcpy(joinBSSID, roamFromBSSID, 6);    // review: the link down names the old AP
    }
    AirportWCL::RoamStatus status = {};
    status.status = ok ? 0 : uint32_t(kIOReturnTimeout);
    status.reason = AirportWCL::kRoamReasonLowRSSI;
    instance->postMessage(this, AirportWCL::RoamDone, &status, sizeof(status), true);
    if (!ok) {
        // Not on any AP now: a real disconnect, so macOS joins again
        leaveWCLNetwork("roam failed");
        syncLinkAfterRoam();
    }
    updateWCLLinkQuality(true);
}

// The new AP's BSS for WCL: from its beacons since the association (they
// refresh wclBssInfo once assocNotified is set), else from the scan entry,
// as synthesizeWCLFirstBeacon does.
bool AirportItlwmSkywalkInterface::publishRoamBss()
{
    ieee80211com *ic = fHalService->get80211Controller();
    auto stored = [this]() {
        return wclBssValid && memcmp(wclBssInfo + offsetof(AirportWCL::BeaconMetadata, bssid),
                                     joinBSSID, 6) == 0;
    };
    if (stored())
        return true;
    ieee80211_node *ni = ic->ic_bss;
    if (ni == NULL || !IEEE80211_ADDR_EQ(ni->ni_bssid, joinBSSID) ||
        ni->ni_rsnie_tlv == NULL || ni->ni_rsnie_tlv_len == 0)
        return false;
    bool was = assocNotified;
    assocNotified = true;           // publishWCLBeacon stores it only then
    publishWCLBeacon(ni, ni->ni_rsnie_tlv, ni->ni_rsnie_tlv_len);
    assocNotified = was;
    return stored();
}

// A roam ended from outside (macOS's leave or join, the driver stopping):
// WCL got 137, so it gets the completion too.
void AirportItlwmSkywalkInterface::abortWCLRoam(IOReturn reason, const char *why)
{
    if (!roamPending)
        return;
    roamPending = false;
    joinTimer->cancelTimeout();
    AirportWCL::RoamStatus status = {};
    status.status = uint32_t(reason);
    status.reason = AirportWCL::kRoamReasonLowRSSI;
    instance->postMessage(this, AirportWCL::RoamDone, &status, sizeof(status), true);
    XYLog("WCL roam to %s abandoned (%s)\n", ether_sprintf(joinBSSID), why);
    memcpy(joinBSSID, roamFromBSSID, 6);
}

/*
 * A roam that did not end on the new AP: the link down that
 * AirportItlwm::setLinkStatus held back during it is passed on now, so the
 * controller's link state is down again (otherwise the next join's link-up
 * would look like no change and never reach WCL) and WCL hears the
 * disconnect (handleWCLLink).
 */
void AirportItlwmSkywalkInterface::syncLinkAfterRoam()
{
    if (!wclStopping)
        instance->setLinkStatus(kIONetworkLinkValid, NULL);
}

void AirportItlwmSkywalkInterface::handleWCLLink(bool up)
{
    if (wclStopping)
        return;
    portAuthorized = up;
    if (roamPending) {          // phase 4u: macOS keeps the link during a roam
        if (up)
            finishWCLRoam(true, "port authorized");
        return;
    }
    if (up)
        linkUpMs = airport_up_time();
    if (!up && wclLinkIndicated) {
        AirportWCL::LinkStatusEvent event = {};
        memcpy(event.bssid, joinBSSID, sizeof(event.bssid));
        event.reason = 255;
        wclLinkIndicated = false;
        wclBssValid = false;
        instance->postMessage(this, AirportWCL::LinkStatus, &event, sizeof(event), true);
    }
    if (up && joinPending && firstBeaconNotified)
        finishWCLJoin(0, 0, kIOReturnSuccess);
    else if (up && joinPending)
        synthesizeWCLFirstBeacon();
    updateWCLLinkQuality(true);
}

void AirportItlwmSkywalkInterface::handleWCLEvent(int code, void *data)
{
    if (wclStopping)
        return;
    // Firmware initialization runs on systq, outside the native PostOffice gate.
    // Serialize only lifecycle notifications; never run synchronous WCL ioctls here.
    if ((code == IEEE80211_EVT_DRIVER_RESET_BEGIN || code == IEEE80211_EVT_DRIVER_READY ||
         code == IEEE80211_EVT_DRIVER_STOPPED) && !instance->getWorkQueue()->inGate()) {
        _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(12),
                                reinterpret_cast<void *>(uintptr_t(code)));
        return;
    }
    ieee80211com *ic = fHalService->get80211Controller();
    switch (code) {
        case IEEE80211_EVT_COUNTRY_CODE_UPDATE:
            deferWCLCountryUpdate();
            break;
        case IEEE80211_EVT_DRIVER_RESET_BEGIN: {
            portAuthorized = false;
            updateWCLLinkQuality(true);
            if (ic->ic_wcl_mac_reconfig) {
                break;
            }
            uint32_t reset = 0; // Native resetInterfacesBegin.
            instance->postMessage(this, AirportWCL::ResetInterface, &reset, sizeof(reset), true);
            break;
        }
        case IEEE80211_EVT_DRIVER_READY:
        case IEEE80211_EVT_DRIVER_STOPPED: {
            bool ready = code == IEEE80211_EVT_DRIVER_READY;
            if (!ready) {
                roamScanPending = false;    // 4u.1 review
                if (roamPending) {      // phase 4u (review: 80 too, timer off)
                    abortWCLRoam(kIOReturnOffline, "driver stopped");
                    syncLinkAfterRoam();
                }
                finishWCLScan(ic->ic_wcl_mac_reconfig ? kIOReturnAborted : kIOReturnOffline);
                finishWCLJoin(1, 0, kIOReturnOffline);
                portAuthorized = false;
                updateWCLLinkQuality(true);
                ic->ic_wcl_join_requested = false;
                clearWCLPMKSA();
                ic->ic_wcl_enterprise = false;
                explicit_bzero(ic->ic_psk, sizeof(ic->ic_psk));
                AirportWCL::clearSAE(ic);
            }
            // An address application is requested by WCL itself, not a new
            // adapter reset. Replaying firmware-load events here rotates the
            // scan MAC again and recursively restarts the card.
            if (AirportWCL::consumeMacReconfiguration(ic->ic_wcl_mac_reconfig, ready)) {
                if (ready) {
                    startDeferredWCLScan();
                    resumeWCLJoin();
                }
                break;
            }
            if (ready) {
                uint32_t reset = 1; // Native resetInterfacesComplete, only after HAL success.
                instance->postMessage(this, AirportWCL::ResetInterface, &reset, sizeof(reset), true);
            }
            AirportWCL::DriverAvailability event = {};
            event.version = 3;
            event.available = ready;
            event.reason = ready ? 0xe0821803 : 0xe0821804;
            instance->postMessage(this, AirportWCL::DriverAvailable, &event, sizeof(event), true);
            if (ready) {
                startDeferredWCLScan();     // before a join: a fresh list to pick from
                resumeWCLJoin();
            }
            break;
        }
        case IEEE80211_EVT_BEACON_6G:
            if (data && (scanPending || joinPending || ic->ic_state == IEEE80211_S_SCAN))
                publishWCLBeacon6G(static_cast<const ieee80211_beacon6g_event *>(data));
            break;
        case IEEE80211_EVT_BEACON: {
            auto beacon = static_cast<ieee80211_beacon_event *>(data);
            if (!beacon)
                break;
            // Retain the actual associated beacon, including its advancing TSF.
            // WCL polls BEACON_INFO to distinguish fresh reception from a stale BSS.
            if (assocNotified && (joinPending || portAuthorized || roamPending) &&
                IEEE80211_ADDR_EQ(beacon->node->ni_bssid, joinBSSID) &&
                beacon->frame && beacon->frame_length >= 36 &&
                beacon->frame_length <= 0x800 &&
                (beacon->frame[0] & 0xfc) == IEEE80211_FC0_SUBTYPE_BEACON) {
                uint32_t length = uint32_t(beacon->frame_length);
                bzero(wclBeaconInfo, sizeof(wclBeaconInfo));
                memcpy(wclBeaconInfo, &length, sizeof(length));
                memcpy(wclBeaconInfo + 4, beacon->frame, length);
                ++wclAssociatedBeacons;
                ++wclLqmBeacons;
                // WCL has no legacy LQMData instance at createLQMData().
                // Send the snapshot consumed by WCL instead of legacy 227/229.
                if (portAuthorized && (wclLqmBeacons % 8 == 0)) {
#if __IO80211_TARGET == __MAC_15_2
                    apple80211_rssi_data rssi = {};
                    if (getRSSI(&rssi) == kIOReturnSuccess) {
                        AirportWCL::SequoiaLqmUpdate update = {};
                        update.rssiValid = 1;
                        update.rssi = rssi.aggregate_rssi;
                        instance->postMessage(this, AirportWCL::LqmUpdate,
                            &update, sizeof(update), true);
                    }
#else
                    AirportWCL::LqmBeaconUpdate update;
                    if (AirportWCL::makeBeaconUpdate(
                            wclLqmBeacons - wclLqmReportedBeacons, update)) {
                        instance->postMessage(this, AirportWCL::LqmUpdate,
                            &update, sizeof(update), true);
                        wclLqmReportedBeacons = wclLqmBeacons;
                    }
#endif
                    updateWCLLinkQuality();
                }
            }
            if (scanPending || joinPending || ic->ic_state == IEEE80211_S_SCAN ||
                ((portAuthorized || (roamPending && assocNotified)) &&  // phase 4u
                 IEEE80211_ADDR_EQ(beacon->node->ni_bssid, joinBSSID)))
                publishWCLBeacon(beacon->node, beacon->ies, beacon->length);
            if (joinPending && IEEE80211_ADDR_EQ(beacon->node->ni_bssid, joinBSSID))
                ++wclJoinBeacons;
            if (joinPending && assocNotified && !firstBeaconNotified &&
                IEEE80211_ADDR_EQ(beacon->node->ni_bssid, joinBSSID))
                notifyWCLFirstBeacon("beacon");
            break;
        }
        case IEEE80211_EVT_ROAM_TICK:       // phase 4u: about every 2 s in RUN
            checkWCLRoam();
            break;
        case IEEE80211_EVT_SCAN_DONE:
            if (roamScanPending) {          // phase 4u: our roam scan ended
                roamScanPending = false;
                if (!scanPending) {
                    ic->ic_wcl_scan_requested = false;
                    ic->ic_wcl_scan_restricted = false;
                }
            }
            // not the scan this request is waiting for (Ersiter does the same)
            if (scanPending && (scanDeferred || ic->ic_wcl_scan_restart))
                break;
            if (scanPending) {
                if (scanSkipCompletion)
                    scanSkipCompletion = false;
                else {
                    scanCompleted = true;
                    scanSource->setTimeoutMS(0);
                }
            }
            break;
        case IEEE80211_EVT_STA_ASSOC_DONE:
            // phase 4u (review): associated with the new AP: its beacons
            // now refresh the BSS and beacon information WCL reads
            if (roamPending && !ic->ic_assoc_status)
                assocNotified = true;
            if (joinPending && !assocNotified) {
                AirportWCL::AssociationEvent event = {};
                event.status = ic->ic_assoc_status;
                memcpy(event.bssid, joinBSSID, 6);
                event.driverStatus = event.status ? kIOReturnError : kIOReturnSuccess;
                assocNotified = !event.status;
                instance->postMessage(this, AirportWCL::AssocComplete, &event, sizeof(event), true);
                if (event.status)
                    finishWCLJoin(event.status, 0, kIOReturnError);
            }
            break;
        case IEEE80211_EVT_STA_DEAUTH: {
            if (roamPending) {      // phase 4u: the join to the new AP retries
                XYLog("WCL roam: deauth (reason %u) while roaming, not reported\n",
                      ic->ic_deauth_reason);
                break;
            }
            portAuthorized = false;
            updateWCLLinkQuality(true);
            AirportWCL::DeauthEvent event = {};
            event.reason = ic->ic_deauth_reason;
            if (ic->ic_bss)
                memcpy(event.bssid, ic->ic_bss->ni_bssid, 6);
            instance->postMessage(this, AirportWCL::Deauth, &event, sizeof(event), true);
            finishWCLJoin(1, event.reason, kIOReturnOffline);
            break;
        }
        default: break;
    }
}

IOReturn AirportItlwmSkywalkInterface::getWCL_VALID_CHANNEL_COUNT(unsigned long *count)
{
    if (!count)
        return kIOReturnBadArgument;
    *count = 0;
    ieee80211com *ic = fHalService->get80211Controller();
    for (unsigned i = 1; i < IEEE80211_CHAN_MAX; ++i)
        if (isset(ic->ic_chan_active, i))
            ++*count;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::setWCL_LINK_STATE_UPDATE(apple80211_wcl_update_link_state *data)
{
    if (!data)
        return kIOReturnBadArgument;
#if __IO80211_TARGET == __MAC_15_2
    const auto bytes = reinterpret_cast<const uint8_t *>(data);
    if (bytes[6]) {
        if (bytes[8])
            setCurrentApAddress(reinterpret_cast<ether_addr *>(data));
        if (bytes[7])
            setLinkState(kIO80211NetworkLinkUp, 0, false, 0);
    } else {
        uint32_t debounce = AirportWCL::read32(bytes + 12);
        setCurrentApAddress(nullptr);
        setLinkState(kIO80211NetworkLinkDown, 0, debounce != 0, debounce);
    }
    IOReturn status = kIOReturnSuccess;
#else
    IOReturn status = IO80211InfraInterface::setWCL_LINK_STATE_UPDATE(data);
#endif
    if (status == kIOReturnSuccess)
        updateWCLLinkQuality(true);
    return status;
}

IOReturn AirportItlwmSkywalkInterface::getWCL_BSS_INFO(apple80211_beacon_msg *data)
{
    if (!data)
        return kIOReturnBadArgument;
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(5), data);
}

IOReturn AirportItlwmSkywalkInterface::getWCL_EXTENDED_BSS_INFO(apple80211_extended_bss_info *data)
{
    if (!data)
        return kIOReturnBadArgument;
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(6), data);
}

IOReturn AirportItlwmSkywalkInterface::copyWCLExtendedBss(void *data)
{
    ieee80211com *ic = fHalService->get80211Controller();
    if (!data || !ic->ic_bss || ic->ic_state != IEEE80211_S_RUN) {
        /* phase 4n: WCL leaves the network on this ("Update Bss fail") */
        XYLog("WCL extended BSS info asked in state %d: not ready\n", ic->ic_state);
        return kIOReturnNotReady;
    }
    static_assert(sizeof(apple80211_rate_set_data) == 0xbc, "Extended BSS rates size");
    static_assert(sizeof(apple80211_mcs_index_set_data) == 0x10, "Extended BSS MCS size");
    auto bytes = static_cast<uint8_t *>(data);
#if __IO80211_TARGET == __MAC_15_2
    bzero(bytes, 0x1e0);
#else
    bzero(bytes, 0x214);
#endif
    IOReturn status = getRATE_SET(reinterpret_cast<apple80211_rate_set_data *>(bytes));
    if (status)
        return status;
    status = getMCS_INDEX_SET(reinterpret_cast<apple80211_mcs_index_set_data *>(bytes + 0xbc));
    if (status)
        return status;
    apple80211_vht_mcs_index_set_data vht = {};
    vht.version = APPLE80211_VERSION;
    vht.mcs_map = 0xffff;
    if (ic->ic_bss->ni_flags & IEEE80211_NODE_VHT)
        vht.mcs_map = ic->ic_bss->ni_vht_mcsinfo.tx_mcs_map;
    memcpy(bytes + 0xcc, &vht, sizeof(vht));
    // Native updateMCSSet uses version + a 16-bit HE MCS/NSS map (8 bytes).
    uint32_t heVersion = APPLE80211_VERSION;
    uint16_t heMap = 0xffff;
    if (ic->ic_bss->ni_flags & IEEE80211_NODE_HE) {
        bool wide = ic->ic_bss->ni_chw == IEEE80211_CHAN_WIDTH_160;
        heMap = htole16(ieee80211_he_mcs_intersection(
            le16toh(wide ? ic->ic_he_mcs_nss_supp.rx_mcs_160 : ic->ic_he_mcs_nss_supp.rx_mcs_80),
            le16toh(wide ? ic->ic_bss->ni_he_mcs_nss_supp.tx_mcs_160 : ic->ic_bss->ni_he_mcs_nss_supp.tx_mcs_80)));
    }
    memcpy(bytes + 0xd4, &heVersion, sizeof(heVersion));
    memcpy(bytes + 0xd8, &heMap, sizeof(heMap));
    if (ic->ic_flags & IEEE80211_F_RSNON)
#if __IO80211_TARGET == __MAC_15_2
        ieee80211_add_rsn(bytes + 0xdd, ic, ic->ic_bss);
#else
        ieee80211_add_rsn(bytes + 0x113, ic, ic->ic_bss);
#endif
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::setWCL_UPDATE_FAST_LANE(apple80211_fastlane *data)
{
    if (!data)
        return kIOReturnBadArgument;
    const auto bytes = reinterpret_cast<const uint8_t *>(data);
    return (bytes[0] || bytes[1]) ? kIOReturnUnsupported : kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::getWCL_LOW_LATENCY_INFO(apple80211_low_latency_info *data)
{
    if (!data)
        return kIOReturnBadArgument;
    // No low-latency or P2P session is implemented by this adapter.
    bzero(data, 4);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::getWCL_CHANNELS_INFO(apple80211ChannelInfo *data)
{
    if (!data)
        return kIOReturnBadArgument;
    auto info = reinterpret_cast<AirportWCL::ChannelInfo *>(data);
    bzero(info, sizeof(*info));
    ieee80211com *ic = fHalService->get80211Controller();
    for (unsigned i = 1; i < IEEE80211_CHAN_MAX && info->count < 400; ++i) {
        if (!isset(ic->ic_chan_active, i))
            continue;
        const ieee80211_channel *channel = &ic->ic_channels[i];
        if (IEEE80211_IS_CHAN_6GHZ(channel))   // phase 4g: listed below
            continue;
        auto &entry = info->channels[info->count++];
        entry.channel = i;
        entry.channelSpec = uint16_t(i | (IEEE80211_IS_CHAN_5GHZ(channel) ? 0xd000 : 0x1000));
        if (channel->ic_flags & IEEE80211_CHAN_DFS)
            entry.flags |= 2;
        if (channel->ic_flags & IEEE80211_CHAN_PASSIVE)
            entry.flags |= 4;
    }
    /* Phase 4e.3: the 6 GHz channels the driver scans (passive: NO_IR) */
    if (ic->ic_6ghz_channels) {
        for (unsigned c6 = 1; c6 <= 233 && info->count < 400; c6 += 4) {
            auto &entry = info->channels[info->count++];
            entry.channel = uint8_t(c6);
            entry.channelSpec = uint16_t(c6 | 0x5000);
            entry.flags |= 4;
        }
        info->supports6GHz = 1;
    }
    apple80211_country_code_data country = {};
    if (instance->getCOUNTRY_CODE(static_cast<OSObject *>(this), &country) == kIOReturnSuccess)
        memcpy(info->country, country.cc, 3);
    return info->count ? kIOReturnSuccess : kIOReturnNotReady;
}

IOReturn AirportItlwmSkywalkInterface::getCHANNELS_INFO(apple80211_channels_info *data)
{
    if (!data)
        return kIOReturnBadArgument;
    if (!_fCommandGate)
        return kIOReturnNotReady;
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(13), data);
}

IOReturn AirportItlwmSkywalkInterface::copyWCLChannels(void *data)
{
    auto info = static_cast<AirportWCL::NativeChannelInfo *>(data);
    bzero(info, sizeof(*info));
    ieee80211com *ic = fHalService->get80211Controller();
    for (unsigned i = 1; i <= IEEE80211_CHAN_MAX; ++i) {
        const ieee80211_channel *channel = &ic->ic_channels[i];
        if (!isset(ic->ic_chan_active, i) || !channel->ic_freq ||
            IEEE80211_IS_CHAN_6GHZ(channel))  // phase 4g: appended below
            continue;
        AirportWCL::appendChannel(*info, i, IEEE80211_IS_CHAN_5GHZ(channel),
            channel->ic_flags & IEEE80211_CHAN_DFS,
            channel->ic_flags & IEEE80211_CHAN_PASSIVE,
            IEEE80211_IS_CHAN_HT40(channel) || IEEE80211_IS_CHAN_VHT40(channel),
            IEEE80211_IS_CHAN_VHT80(channel));
    }
    // 6 GHz (driver scans it; net80211 has no table entries for it)
    if (ic->ic_6ghz_channels)
        for (unsigned ch = 1; ch <= 233; ch += 4)
            AirportWCL::append6GHzChannel(*info, ch);
    apple80211_country_code_data country = {};
    if (instance->getCOUNTRY_CODE(static_cast<OSObject *>(this), &country) == kIOReturnSuccess)
        memcpy(info->country, country.cc, sizeof(country.cc));
    return info->count ? kIOReturnSuccess : kIOReturnNotReady;
}

IOReturn AirportItlwmSkywalkInterface::getWCL_TRAFFIC_COUNTERS(apple80211_wcl_traffic_counters *data)
{
    if (!data)
        return kIOReturnBadArgument;
    if (!_fCommandGate)
        return kIOReturnNotReady;
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(14), data);
}

IOReturn AirportItlwmSkywalkInterface::copyWCLTrafficCounters(void *data)
{
    ieee80211com *ic = fHalService->get80211Controller();
    uint64_t timestamp;
    absolutetime_to_nanoseconds(mach_absolute_time(), &timestamp);
    const auto counters = AirportWCL::makeTrafficCounters(
        ic->ic_wcl_tx_packets, ic->ic_wcl_rx_packets, timestamp);
    memcpy(data, &counters, sizeof(counters));
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::setWCL_SET_SCAN_HOME_AWAY_TIME(scanHomeAndAwayTime *data)
{
    if (!data)
        return kIOReturnBadArgument;
    if (!_fCommandGate)
        return kIOReturnNotReady;
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(15), data);
}
#endif

#ifdef AIRPORT_WCL
IOReturn AirportItlwmSkywalkInterface::getBEACON_INFO(apple80211_beacon_info_t *data)
{
    if (!_fCommandGate || !data)
        return kIOReturnNotReady;
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(7), data);
}
#endif
