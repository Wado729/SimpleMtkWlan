//
//  WCL.hpp
//  AirportItlwm
//
//  Created by laobamac on 2026/10/1.
//  Copyright © 2026 laobamac. All rights reserved.
//

#ifndef AirportWCL_hpp
#define AirportWCL_hpp

#include <stdint.h>
#include <stddef.h>
#include <string.h>

namespace AirportWCL {

enum class MacUpdate { Invalid, Unchanged, Busy, Change };
inline MacUpdate planMacUpdate(const uint8_t *current, const uint8_t *requested,
                               size_t length, bool initializing) {
    if (!current || !requested || length != 6 || (requested[0] & 1))
        return MacUpdate::Invalid;
    uint8_t bits = 0;
    for (unsigned i = 0; i < 6; ++i) bits |= requested[i];
    if (!bits) return MacUpdate::Invalid;
    if (memcmp(current, requested, 6) == 0) return MacUpdate::Unchanged;
    return initializing ? MacUpdate::Busy : MacUpdate::Change;
}

// Returns true when this is an internal MAC operation, not an adapter reset.
inline bool consumeMacReconfiguration(bool &pending, bool ready) {
    if (!pending) return false;
    if (ready) pending = false;
    return true;
}

struct HardwareAddress {
    uint32_t version;
    uint8_t address[6];
    uint8_t padding[2];
};
static_assert(sizeof(HardwareAddress) == 12, "HW_ADDR native wire size");
static_assert(offsetof(HardwareAddress, address) == 4, "HW_ADDR native address offset");
inline bool copyHardwareAddress(const uint8_t *address, HardwareAddress &out) {
    out = {};
    if (planMacUpdate(address, address, 6, false) == MacUpdate::Invalid) return false;
    out.version = 1;
    memcpy(out.address, address, 6);
    return true;
}

enum BeaconFlags : uint32_t {
    SSIDPresent = 1U << 1,
    RSSIValid = 1U << 14
};

enum Message : uint32_t {
    ResetInterface = 49,
    DriverAvailable = 55,
    ScanResult = 201,
    Deauth = 203,
    AssocComplete = 211,
    FirstBeacon = 212,
    ConnectComplete = 213,
    JoinAbortComplete = 214,
    LinkStatus = 216,
    LqmUpdate = 39,
    ScanDone = 237,
    // Phase 4u: a driver-side roam, as AppleBCMWLANCore reports one
    // (handleRoamScanStartEvent, handleReassocEvent, postRoamCompletionStatus;
    // WCLRoamManager's callback table takes these ids and sizes)
    Reassoc = 73,
    RoamDone = 80,
    RoamScanStart = 137
};

// Phase 4u: payloads (sizes checked by WCLRoamManager's handlers)
struct RoamScanStartEvent {
    uint32_t status;            // 0, or an IOReturn
    uint32_t reason;            // 0xe0820c00 | roam reason (1: low RSSI)
    uint16_t count;
    uint16_t reserved;
};
static_assert(sizeof(RoamScanStartEvent) == 0xc, "RoamScanStartEvent size");

struct ReassocEvent {
    uint32_t status;            // 0: success
    uint32_t reason;
};
static_assert(sizeof(ReassocEvent) == 0x8, "ReassocEvent size");

// apple80211_message_roam_status: with status 0 WCLRoamManager::roamDone
// builds the from/to details itself (buildRoamCompletionStatus)
struct RoamStatus {
    uint32_t status;
    uint32_t reason;
    uint64_t startTime;
    uint64_t endTime;
    uint8_t reserved[0xa8 - 0x18];
};
static_assert(sizeof(RoamStatus) == 0xa8, "RoamStatus size");
static constexpr uint32_t kRoamReasonLowRSSI = 0xe0820c01;

// Phase 4u.1: one 6 GHz channel into a scan request's bitmap by channel
// number (byte num / 8, bit num % 8), as macOS's requests are parsed below
// and mt7927_hal_scan reads it. True if newly set (host-tested in tests/roam).
inline bool set6gChannel(uint8_t *bitmap, size_t length, unsigned num)
{
    if (num == 0 || num > 233 || num / 8 >= length || (bitmap[num / 8] & (1U << (num % 8))))
        return false;
    bitmap[num / 8] |= uint8_t(1U << (num % 8));
    return true;
}

// Phase 4w: the roam decision, per band of the current BSS, from a Mac's
// roam profile (host-tested in tests/roam): IO80211's profile 0 as Sequoia
// 15.8.1 logged it for this driver (printRoamingBracket, before the
// APPLE80211_IOC_WCL_ROAM_PROFILE_CONFIG it failed to set), the bracket that
// covers a weak link:
//   Band:0 Index 1 RSSI[-75,-128] Scan(2,90,30,2,180,..) C2g(12,..)  2.4 GHz
//   Band:1 Index 1 RSSI[-75,-128] Scan(2,90,30,2,180,..) C5g(12,..)  5 GHz
//   Band:2 Index 0 RSSI[-70,-128] Scan(2,90,30,2,180,..) C6g(12,..)  6 GHz
// RSSI[trigger, lower]; Scan(nfscan, fullscan_period, init_scan_period,
// backoff_multiplier, max_scan_period). C2g/C5g/C6g are per CANDIDATE band
// (roam delta, boost threshold, boost); every delta in these weak-link
// brackets is 12 (and AppleBCMWLAN hands the firmware one roam_delta), so
// one 12 dB here. The boost (6 GHz: +70 dB at -65 dBm or better) is left
// out: it only matters for a candidate of the SSID on another band, so we
// move up to 5/6 GHz more conservatively than a Mac. Not here either: the
// 2.4/5 GHz brackets above -75 dBm (lazy, scans every 180-1200 s).
// This is IO80211's default profile 0. airportd on AC power asks for faster
// scans (6 GHz: 20 s to 90 s, full scan 120 s), but that path is not taken
// while our driver returns Unsupported to WCL_ROAM_PROFILE_CONFIG; we keep
// the conservative default.
enum RoamBand { kRoamBand2g, kRoamBand5g, kRoamBand6g };
struct RoamProfile {
    int triggerDbm;         // roam scans and roams at or below this
    int deltaDb;            // to a candidate at least this much stronger
    uint32_t initScanMs;    // first roam-scan interval,
    uint32_t backoff;       // times this after each scan,
    uint32_t maxScanMs;     // up to this
    uint32_t fullScanMs;    // a wide roam scan at least this often
};
inline RoamProfile roamProfile(RoamBand band)
{
    RoamProfile p = { band == kRoamBand6g ? -70 : -75, 12, 30000, 2, 180000, 90000 };
    return p;
}
// Review: the scan cadence starts over only once the average is clearly
// above the trigger, not on every tick of one hovering at it.
static constexpr int kRoamResetHysteresisDb = 3;
inline bool roamScanReset(const RoamProfile &p, int currentDbm)
{
    return currentDbm >= p.triggerDbm + kRoamResetHysteresisDb;
}
inline bool roamWanted(const RoamProfile &p, int currentDbm, int candidateDbm)
{
    return currentDbm <= p.triggerDbm && candidateDbm >= currentDbm + p.deltaDb;
}
// The interval to the roam scan after one that waited intervalMs (0: first).
inline uint64_t nextRoamScanMs(const RoamProfile &p, uint64_t intervalMs)
{
    if (intervalMs == 0)
        return p.initScanMs;
    return intervalMs * p.backoff > p.maxScanMs ? p.maxScanMs : intervalMs * p.backoff;
}
// Review: a roam scan is wide (an AP never heard or aged out) first after
// the cadence starts over (lastWideMs 0), then once per fullscan_period
// (the profile's nfscan is 2: its first two scans are full; ours one).
inline bool roamScanWide(const RoamProfile &p, uint64_t lastWideMs, uint64_t nowMs)
{
    return lastWideMs == 0 || nowMs - lastWideMs >= p.fullScanMs;
}

// A candidate's signal is one reading from macOS's last scan (review): go
// only when a second, newer reading of the same AP still qualifies.
// 4w: quickScans counts the early roam scans (kRoamConfirmScanMs in
// WCL.cpp) for that second reading; at most kRoamConfirmQuickScans per AP
// armed, after which the profile's cadence goes on.
struct RoamConfirm {
    uint8_t bssid[6];
    uint64_t sampleMs;
    bool armed;
    uint8_t quickScans;
};
static constexpr uint8_t kRoamConfirmQuickScans = 2;
inline bool roamConfirmed(RoamConfirm &c, const uint8_t *bssid, uint64_t sampleMs)
{
    if (c.armed && memcmp(c.bssid, bssid, 6) == 0 && sampleMs != c.sampleMs) {
        c.armed = false;
        return true;
    }
    // review: a new episode only (not armed); candidates that alternate as
    // the best keep the count, so the early scans stay capped
    if (!c.armed)
        c.quickScans = 0;
    memcpy(c.bssid, bssid, 6);
    c.sampleMs = sampleMs;
    c.armed = true;
    return false;
}

// Phase 4x (C8): which AP this tick confirms. Another AP best this tick no
// longer re-arms while the armed one still qualifies (two candidates taking
// turns as the best one re-armed each other, and neither got its second
// reading): true to confirm the armed AP instead of the best one.
inline bool roamKeepArmed(const RoamConfirm &c, const uint8_t *bestBssid, bool armedQualifies)
{
    return c.armed && armedQualifies && memcmp(c.bssid, bestBssid, 6) != 0;
}

struct SequoiaLqmUpdate {
    uint8_t rssiValid;
    uint8_t reserved0[3];
    int32_t rssi;
    uint8_t reserved1[0x150 - 8];
};
static_assert(sizeof(SequoiaLqmUpdate) == 0x150, "Sequoia LQM size");
static_assert(offsetof(SequoiaLqmUpdate, rssi) == 4, "Sequoia LQM RSSI offset");

// WCLNetManager::handleLqmUpdate consumes this 0x1dc snapshot.
// Only beacon reception is valid; unavailable radio measurements stay invalid.
struct LqmBeaconUpdate {
    uint8_t prefix[0x28];
    uint32_t receivedDelta;
    uint32_t scheduledDelta;
    uint8_t beaconValid;
    uint8_t reserved[0x1d8 - 0x31];
    uint8_t snapshotValid;
    uint8_t countersValid;
    uint8_t tail[2];
};
static_assert(sizeof(LqmBeaconUpdate) == 0x1dc, "WCL LQM update size");
static_assert(offsetof(LqmBeaconUpdate, receivedDelta) == 0x28, "WCL beacon delta offset");
static_assert(offsetof(LqmBeaconUpdate, beaconValid) == 0x30, "WCL beacon valid offset");
static_assert(offsetof(LqmBeaconUpdate, snapshotValid) == 0x1d8, "WCL snapshot valid offset");
inline bool makeBeaconUpdate(uint32_t receivedDelta, LqmBeaconUpdate &out)
{
    out = {};
    if (!receivedDelta)
        return false;
    out.receivedDelta = receivedDelta;
    out.beaconValid = out.snapshotValid = out.countersValid = 1;
    return true;
}

struct DriverAvailability {
    uint32_t version;
    uint32_t reserved0;
    uint32_t available;
    uint32_t reserved1;
    uint32_t reason;
    uint32_t subReason;
    uint8_t reserved2[0xf8 - 24];
};

static_assert(sizeof(DriverAvailability) == 0xf8, "DriverAvailability size");

struct BeaconMetadata {
    uint32_t ieLength;
    uint16_t channelSpec;
    uint8_t ssid[32];
    uint8_t ssidLength;
    uint8_t channel;
    uint8_t reserved0;
    uint8_t bssid[6];
    uint8_t reserved1;
    int32_t rssi;
    int16_t noise;
    int16_t snr;
    uint16_t interval;
    uint16_t capability;
#if !defined(__IO80211_TARGET) || __IO80211_TARGET != __MAC_15_2
    uint32_t reserved2;
#endif
    uint32_t flags;
};

struct AssociationEvent {
    uint16_t status;
    uint16_t reason;
    uint8_t mlo;
    uint8_t bssid[6];
    uint8_t reserved;
    uint32_t mloData[2];
    int32_t driverStatus;
    int32_t driverReason;
};

struct ConnectionPeer {
    uint8_t bssid[6];
    uint16_t reserved;
    int32_t driverStatus;
    int32_t driverReason;
};

struct FirstBeaconEvent {
    uint16_t status;
    uint16_t reason;
    ConnectionPeer peer;
};

struct ConnectionEvent {
    uint16_t status;
    uint16_t reason;
    ConnectionPeer peers[10];
};

struct LinkStatusEvent {
    uint8_t bssid[6];
    uint8_t up;
    uint8_t inSleep;
    uint32_t reason;
    uint32_t reserved;
};
static_assert(sizeof(LinkStatusEvent) == 16, "LinkStatusEvent size");
static_assert(offsetof(LinkStatusEvent, up) == 6, "LinkStatusEvent up offset");

struct DeauthEvent {
    int32_t driverStatus;
    int32_t driverReason;
    uint16_t reason;
    uint8_t bssid[6];
    uint8_t disassociation;
    uint8_t reserved[3];
};

struct __attribute__((packed)) ChannelEntry {
    uint16_t channelSpec;
    uint8_t reserved[4];
    uint8_t channel;
    uint8_t flags;
};

struct __attribute__((packed)) ChannelInfo {
    ChannelEntry channels[400];
    uint16_t count;
    uint8_t country[3];
    uint8_t supports6GHz;
};

#if defined(__IO80211_TARGET) && __IO80211_TARGET == __MAC_15_2
static_assert(sizeof(BeaconMetadata) == 0x40, "Sequoia BeaconMetadata size");
static_assert(offsetof(BeaconMetadata, flags) == 0x3c, "Sequoia BeaconMetadata flags");
#else
static_assert(sizeof(BeaconMetadata) == 0x44, "BeaconMetadata size");
static_assert(offsetof(BeaconMetadata, flags) == 0x40, "BeaconMetadata flags");
#endif
static_assert(offsetof(BeaconMetadata, bssid) == 0x29, "BeaconMetadata BSSID");
static_assert(offsetof(BeaconMetadata, rssi) == 0x30, "BeaconMetadata RSSI");
static_assert(sizeof(AssociationEvent) == 0x1c, "AssociationEvent size");
static_assert(sizeof(FirstBeaconEvent) == 0x14, "FirstBeaconEvent size");
static_assert(sizeof(ConnectionEvent) == 0xa4, "ConnectionEvent size");
static_assert(sizeof(DeauthEvent) == 0x14, "DeauthEvent size");
static_assert(sizeof(ChannelInfo) == 0xc86, "ChannelInfo size");

struct NativeChannelInfo {
    uint8_t reserved0[8];
    uint8_t country[4];
    uint16_t count;
    uint16_t channelSpec[400];
    uint8_t channel[400];
    uint8_t indoor[400];
    uint8_t dfs[400];
    uint8_t passive[400];
    uint8_t supports40MHz[400];
    uint8_t supports80MHz[400];
    uint8_t reserved1[2];
    uint32_t firmwareChannelSpec[400];
    uint32_t channelBitmap[400];
    uint8_t reserved2[400];
    /*
     * Phase 4e.3: IO80211 works out each channel's band itself and only
     * reads this byte to override it: zero gives 5 GHz for any channel above
     * 14, non-zero gives 6 GHz.  Without it every 6 GHz channel we publish
     * is taken for 5 GHz.  (Found in Ersiter's Eric-AirportItlwm, GPL-2.)
     */
    uint8_t sixGHz[400];
    uint8_t reserved3[0x2720 - 0x1c30];
};
static_assert(sizeof(NativeChannelInfo) == 0x2720, "CHANNELS_INFO native size");
static_assert(offsetof(NativeChannelInfo, country) == 8, "CHANNELS_INFO country");
static_assert(offsetof(NativeChannelInfo, count) == 0xc, "CHANNELS_INFO count");
static_assert(offsetof(NativeChannelInfo, channelSpec) == 0xe, "CHANNELS_INFO chanspec");
static_assert(offsetof(NativeChannelInfo, channel) == 0x32e, "CHANNELS_INFO channel");
static_assert(offsetof(NativeChannelInfo, indoor) == 0x4be, "CHANNELS_INFO indoor");
static_assert(offsetof(NativeChannelInfo, dfs) == 0x64e, "CHANNELS_INFO DFS");
static_assert(offsetof(NativeChannelInfo, passive) == 0x7de, "CHANNELS_INFO passive");
static_assert(offsetof(NativeChannelInfo, supports40MHz) == 0x96e, "CHANNELS_INFO 40 MHz");
static_assert(offsetof(NativeChannelInfo, supports80MHz) == 0xafe, "CHANNELS_INFO 80 MHz");
static_assert(offsetof(NativeChannelInfo, firmwareChannelSpec) == 0xc90, "CHANNELS_INFO firmware chanspec");
static_assert(offsetof(NativeChannelInfo, channelBitmap) == 0x12d0, "CHANNELS_INFO bitmap");
static_assert(offsetof(NativeChannelInfo, sixGHz) == 0x1aa0, "CHANNELS_INFO 6 GHz flag");

inline bool appendChannel(NativeChannelInfo &info, unsigned channel, bool fiveGHz,
                          bool dfs, bool passive, bool supports40MHz, bool supports80MHz)
{
    if (!channel || channel > 255 || info.count >= 400)
        return false;
    unsigned index = info.count++;
    uint16_t spec = uint16_t(channel | (fiveGHz ? 0xd000 : 0x1000));
    info.channelSpec[index] = spec;
    info.firmwareChannelSpec[index] = spec;
    info.channel[index] = channel;
    info.dfs[index] = dfs;
    info.passive[index] = passive;
    info.supports40MHz[index] = supports40MHz;
    info.supports80MHz[index] = supports80MHz;
    info.channelBitmap[index] = 3U | (fiveGHz ? 4U : 0U) |
        (dfs ? 8U : 0U) | (passive ? 32U : 0U);
    return true;
}

// A 6 GHz channel: chanspec band 6G (WL_CHANSPEC_BAND_6G 0x4000 in
// Broadcom's bcmwifi_channels.h) with 20 MHz (0x1000), the encoding the
// 2.4 (0x1000) and 5 GHz (0xd000) entries already use; passive (6 GHz is
// NO_IR until a beacon). The channel bitmap's 6 GHz bit is not known.
inline bool append6GHzChannel(NativeChannelInfo &info, unsigned channel)
{
    if (!channel || channel > 233 || info.count >= 400)
        return false;
    unsigned index = info.count++;
    uint16_t spec = uint16_t(channel | 0x5000);
    info.channelSpec[index] = spec;
    info.firmwareChannelSpec[index] = spec;
    info.channel[index] = uint8_t(channel);
    info.passive[index] = 1;
    info.supports40MHz[index] = 1;
    info.supports80MHz[index] = 1;
    info.sixGHz[index] = 1;
    /* valid HW|SW, passive, WL_CHAN_BAND_6G (0x200, Broadcom wlioctl_defs.h) */
    info.channelBitmap[index] = 3U | 32U | 0x200U;
    return true;
}

struct TrafficCounters {
    uint64_t realtimeInfraTx;
    uint64_t realtimeInfraRx;
    uint64_t infraTx;
    uint64_t infraRx;
    uint64_t realtimeAwdlTx;
    uint64_t realtimeNanTx;
    uint64_t timestampNanoseconds;
};
static_assert(sizeof(TrafficCounters) == 0x38, "WCL_TRAFFIC_COUNTERS native size");
static_assert(offsetof(TrafficCounters, timestampNanoseconds) == 0x30, "WCL traffic timestamp");

inline TrafficCounters makeTrafficCounters(const uint64_t *tx, const uint64_t *rx,
                                           uint64_t timestampNanoseconds)
{
    TrafficCounters out = {};
    out.realtimeInfraTx = tx[2] + tx[3];
    out.realtimeInfraRx = rx[2] + rx[3];
    for (unsigned ac = 0; ac < 4; ++ac) {
        out.infraTx += tx[ac];
        out.infraRx += rx[ac];
    }
    out.timestampNanoseconds = timestampNanoseconds;
    return out;
}

struct ScanTiming {
    uint32_t maxOutTU;
    bool fragmented;
};

inline ScanTiming scanTiming(uint32_t awayMilliseconds, bool associated,
                             bool supportsFragmentation)
{
    if (!associated)
        return {0, false};
    if (!awayMilliseconds)
        return {120, false};
    uint64_t requested = uint64_t(awayMilliseconds) * 1000 / 1024;
    uint32_t minimum = supportsFragmentation ? 44 : 110;
    uint32_t maxOut = requested < minimum ? minimum :
        requested > 120 ? 120 : uint32_t(requested);
    return {maxOut, maxOut < 110};
}

inline uint16_t read16(const uint8_t *p) {
    return uint16_t(p[0]) | uint16_t(p[1]) << 8;
}

inline uint32_t read32(const uint8_t *p) {
    return uint32_t(read16(p)) | uint32_t(read16(p + 2)) << 16;
}

inline bool validIEs(const uint8_t *data, size_t length) {
    if (!data || length > 2048)
        return false;
    while (length) {
        if (length < 2 || size_t(data[1]) + 2 > length)
            return false;
        size_t next = size_t(data[1]) + 2;
        data += next;
        length -= next;
    }
    return true;
}

// Forget the SAE password, H2E PT and PWE (with the PSK, phase 4f.2).
inline void clearSAE(ieee80211com *ic) {
    volatile uint8_t *v;
    v = ic->ic_sae_password; for (size_t i = 0; i < sizeof(ic->ic_sae_password); ++i) v[i] = 0;
    v = ic->ic_sae_pt; for (size_t i = 0; i < sizeof(ic->ic_sae_pt); ++i) v[i] = 0;
    v = ic->ic_sae_pwe; for (size_t i = 0; i < sizeof(ic->ic_sae_pwe); ++i) v[i] = 0;
    ic->ic_sae_password_len = 0;
    ic->ic_sae_pt_valid = ic->ic_sae_pwe_valid = 0;
    ic->ic_xflags &= ~IEEE80211_F_SAE_PWE;
    // and what the last join left in the BSS node (review of 4f.2)
    if (ic->ic_bss) {
        v = reinterpret_cast<volatile uint8_t *>(&ic->ic_bss->ni_sae);
        for (size_t i = 0; i < sizeof(ic->ic_bss->ni_sae); ++i) v[i] = 0;
        v = ic->ic_bss->ni_pmk; for (size_t i = 0; i < sizeof(ic->ic_bss->ni_pmk); ++i) v[i] = 0;
        v = reinterpret_cast<volatile uint8_t *>(&ic->ic_bss->ni_ptk);
        for (size_t i = 0; i < sizeof(ic->ic_bss->ni_ptk); ++i) v[i] = 0;
    }
}

// Length of the run of complete elements at the start (a truncated or
// malformed trailing element is dropped instead of the whole frame).
inline size_t validIEPrefix(const uint8_t *data, size_t length) {
    size_t used = 0;
    if (!data || length > 2048)
        return 0;
    while (length - used >= 2 && size_t(data[used + 1]) + 2 <= length - used)
        used += size_t(data[used + 1]) + 2;
    return used;
}

// What a network's RSN element asks for, for logging WPA3 networks: AKM and
// pairwise suite types (00-0f-ac only, one bit each), group cipher, RSN caps,
// and whether a Multi-Link element (Wi-Fi 7 MLO) is present.
struct RSNSummary {
    bool rsn;
    uint32_t akms;
    uint32_t pairwise;
    uint8_t group;
    uint16_t caps;
    bool mlo;
};

inline RSNSummary summarizeRSN(const uint8_t *ies, size_t length) {
    RSNSummary out = {};
    if (!validIEs(ies, length))
        return out;
    for (size_t offset = 0; offset < length; offset += size_t(ies[offset + 1]) + 2) {
        const uint8_t *ie = ies + offset;
        size_t size = size_t(ie[1]) + 2;
        if (ie[0] == 255 && size >= 3 && ie[2] == 107)
            out.mlo = true;
        if (ie[0] != 48 || size < 8 || read16(ie + 2) != 1)
            continue;
        out.rsn = true;
        if (ie[4] == 0 && ie[5] == 0x0f && ie[6] == 0xac)
            out.group = ie[7];
        size_t at = 8;
        for (int list = 0; list < 2; ++list) {
            if (size < at + 2)
                break;
            size_t n = read16(ie + at);
            at += 2;
            for (size_t i = 0; i < n && size >= at + 4; ++i, at += 4) {
                const uint8_t *s = ie + at;
                if (s[0] == 0 && s[1] == 0x0f && s[2] == 0xac && s[3] < 32)
                    (list ? out.akms : out.pairwise) |= 1u << s[3];
            }
        }
        if (size >= at + 2)
            out.caps = read16(ie + at);
    }
    return out;
}

inline bool scanUsesProbes(bool requested, bool activeRequest) {
    return requested ? activeRequest : true;
}

// Present the supported PSK option of a PSK/SAE transition network to WCL.
// This operates on the scan-message copy, never the received beacon or the
// net80211 RSN IE used to validate the four-way handshake. SAE-only, mandatory
// PMF and other AKM combinations must not be converted into WPA2 networks.
inline size_t selectWPA2TransitionMode(uint8_t *ies, size_t length) {
    if (!validIEs(ies, length))
        return length;
    for (size_t offset = 0; offset < length; ) {
        uint8_t *ie = ies + offset;
        size_t size = size_t(ie[1]) + 2;
        if (ie[0] != 48 || size < 10 || read16(ie + 2) != 1) {
            offset += size;
            continue;
        }
        size_t pairwiseCount = read16(ie + 8);
        if (!pairwiseCount || pairwiseCount > (size - 10) / 4) {
            offset += size;
            continue;
        }
        size_t countOffset = 10 + 4 * pairwiseCount;
        if (size - countOffset < 2) {
            offset += size;
            continue;
        }
        size_t count = read16(ie + countOffset);
        size_t suitesOffset = countOffset + 2;
        if (count < 2 || count > (size - suitesOffset) / 4) {
            offset += size;
            continue;
        }
        size_t tailOffset = suitesOffset + 4 * count;
        // PSK/SAE transition mode advertises PMF capable, but not required.
        if (size - tailOffset < 2 || (read16(ie + tailOffset) & 0xc0) != 0x80) {
            offset += size;
            continue;
        }
        bool psk = false, sae = false, other = false;
        for (size_t i = 0; i < count; ++i) {
            const uint8_t *suite = ie + suitesOffset + 4 * i;
            if (suite[0] != 0 || suite[1] != 0x0f || suite[2] != 0xac)
                other = true;
            else if (suite[3] == 2)
                psk = true;
            else if (suite[3] == 8)
                sae = true;
            else
                other = true;
        }
        if (!psk || !sae || other) {
            offset += size;
            continue;
        }
        const uint8_t pskSuite[] = {0, 0x0f, 0xac, 2};
        memcpy(ie + suitesOffset, pskSuite, sizeof(pskSuite));
        ie[countOffset] = 1;
        ie[countOffset + 1] = 0;
        size_t removed = 4 * (count - 1);
        // Keep RSN capabilities, PMKIDs, group-management cipher and all
        // following information elements byte-for-byte intact.
        memmove(ie + suitesOffset + 4, ie + tailOffset,
                length - offset - tailOffset);
        ie[1] -= removed;
        length -= removed;
        offset += size - removed;
    }
    return length;
}
inline bool probeChannel(bool active, bool passiveOnly, bool dfs) {
    return active && !passiveOnly && !dfs;
}

struct ScanRequest {
    uint32_t identifier;
    uint32_t type;
    uint8_t ssid[32];
    uint32_t ssidLength;
    uint8_t bssid[6];
    uint32_t channelCount;
    uint8_t channels[32];
    uint8_t channels6g[30];     // 6 GHz channels (flag 0x2000), 1-233
};

inline bool scanChannelSelected(const uint8_t *channels, bool restricted, unsigned channel) {
    return !restricted || (channel < 256 && (channels[channel / 8] & (1U << (channel % 8))));
}

inline bool decodeScan(const void *buffer, size_t length, ScanRequest &out) {
    if (!buffer || length < 0x58)
        return false;
    const uint8_t *p = static_cast<const uint8_t *>(buffer);
    uint32_t count = read32(p + 0x54), ssidLength = read32(p + 0x1c);
    uint32_t type = read32(p + 0x40);
    if (count > 400 || ssidLength > 32 || type < 1 || type > 4 ||
        length < 0x58 + size_t(count) * 12)
        return false;
    out = {};
    out.identifier = read32(p);
    out.type = type;
    out.ssidLength = ssidLength;
    out.channelCount = count;
    memcpy(out.ssid, p + 0x20, ssidLength);
    memcpy(out.bssid, p + 0x14, 6);
    // Native entries are apple80211_channel: version, channel, flags (12 bytes).
    for (uint32_t i = 0; i < count; ++i) {
        const uint8_t *entry = p + 0x58 + size_t(i) * 12;
        uint32_t channel = read32(entry + 4), flags = read32(entry + 8);
        // 6 GHz channel numbers overlap 2.4/5 GHz ones: kept apart.
        if (flags & 0x2000) {
            if (channel && channel <= 233)
                out.channels6g[channel / 8] |= 1U << (channel % 8);
            continue;
        }
        if (!channel || channel > 196)
            continue;
        if (((flags & 0x8) && channel > 14) || ((flags & 0x10) && channel <= 14))
            continue;
        out.channels[channel / 8] |= 1U << (channel % 8);
    }
    return true;
}

struct JoinRequest {
    uint32_t lowerAuth;
    uint32_t upperAuth;
    uint32_t ssidLength;
    uint8_t ssid[32];
    uint32_t keyLength;
    uint32_t keyCipher;
    uint16_t keyIndex;
    uint8_t key[64];    // 63-character passphrases with the WPA3 capability
    uint8_t bssid[6];
    uint16_t channelSpec;
    uint16_t rsnLength;
    uint8_t rsn[257];
};

inline bool validCipherKey(uint32_t cipher, uint32_t length, uint16_t flags,
                           uint16_t index, uint32_t rscLength) {
    // Native WCL accepts PMK/MSK for enterprise, not legacy PTK/GTK.
    (void)flags; // PTK/GTK selectors do not apply to PMK material.
    (void)index;
    return (cipher == 6 || cipher == 7 || cipher == 9) && length == 32 && rscLength <= 8;
}

inline bool validRSNOverride(const uint8_t *ie, size_t length) {
    if (!ie || length > 257) return false;
    if (!length) return true;
    if (length < 4 || size_t(ie[1]) + 2 != length) return false;
    if (ie[0] == 48) return ie[2] == 1 && ie[3] == 0;
    return length >= 8 && ie[0] == 221 && ie[2] == 0 && ie[3] == 0x50 &&
        ie[4] == 0xf2 && ie[5] == 1 && ie[6] == 1 && ie[7] == 0;
}

// A WPA passphrase (8-63 printable characters) instead of the 32-byte PMK
// that macOS normally derives itself. macOS sends it so (key type 10, up to
// 64 bytes from the key field into its padding) to a card that says it does
// SAE, for WPA2 joins too (AirPort_RTW89, AirPort-RTW).
inline bool isPassphrase(const JoinRequest &j) {
    if (j.keyLength < 8 || j.keyLength > 63 ||
        (j.keyLength == 32 && (j.keyCipher == 6 || j.keyCipher == 7)))
        return false;
    for (uint32_t i = 0; i < j.keyLength; ++i)
        if (j.key[i] < 0x20 || j.key[i] > 0x7e)
            return false;
    return true;
}

enum class LegacyAuth { Invalid, Open, Wep, Personal, Enterprise };
inline const char *legacyAuthName(LegacyAuth auth) {
    switch (auth) {
        case LegacyAuth::Open: return "open";
        case LegacyAuth::Wep: return "WEP";
        case LegacyAuth::Personal: return "personal";
        case LegacyAuth::Enterprise: return "enterprise";
        default: return "invalid";
    }
}

// A raw PSK given as 64 hex digits instead of a passphrase.
inline bool isHexPSK(const JoinRequest &j) {
    if (j.keyLength != 64)
        return false;
    for (uint32_t i = 0; i < 64; ++i) {
        uint8_t c = j.key[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            return false;
    }
    return true;
}

inline LegacyAuth classifyLegacyAuth(const JoinRequest &j) {
    // Values from apple80211_authtype/cipher_type, used by the WCL association request.
    if (!validRSNOverride(j.rsn, j.rsnLength)) return LegacyAuth::Invalid;
    if (j.lowerAuth != 1) return LegacyAuth::Invalid;
    if (!j.upperAuth) {
        if (!j.keyLength) return LegacyAuth::Open;
        if (j.keyIndex < 4 && ((j.keyLength == 5 && j.keyCipher == 1) ||
                              (j.keyLength == 13 && j.keyCipher == 2)))
            return LegacyAuth::Wep;
        return LegacyAuth::Invalid;
    }
    const uint32_t personal = (1u << 1) | (1u << 3) | (1u << 10);
    const uint32_t enterprise = (1u << 0) | (1u << 2) | (1u << 11);
    if (j.upperAuth & ~(personal | enterprise)) return LegacyAuth::Invalid;
    if ((j.upperAuth & personal) && (j.upperAuth & enterprise)) return LegacyAuth::Invalid;
    if (j.upperAuth & personal)
        return (j.keyLength == 32 && (j.keyCipher == 6 || j.keyCipher == 7)) || isPassphrase(j) ||
            isHexPSK(j) ? LegacyAuth::Personal : LegacyAuth::Invalid;
    if (j.upperAuth & enterprise)
        return (!j.keyLength || (j.keyLength == 32 && (j.keyCipher == 6 || j.keyCipher == 7))) ?
            LegacyAuth::Enterprise : LegacyAuth::Invalid;
    return LegacyAuth::Invalid;
}

inline bool decodeJoin(const void *buffer, size_t length, JoinRequest &out) {
    if (!buffer || length < 0x218)
        return false;
    const uint8_t *p = static_cast<const uint8_t *>(buffer);
    uint32_t count = read32(p + 0x214), ssidLength = read32(p + 0x1c);
    uint32_t keyLength = read32(p + 0x44);
    uint16_t rsnLength = read16(p + 0xd4);
    if (!count || count > 10 || !ssidLength || ssidLength > 32 ||
        keyLength > 64 || rsnLength > 257 || length < 0x218 + size_t(count) * 18)
        return false;
    if (p[0x21c] & 1)
        return false;
    uint8_t addressBits = 0;
    for (unsigned i = 0; i < 6; ++i)
        addressBits |= p[0x21c + i];
    if (!addressBits)
        return false;
    out = {};
    out.lowerAuth = read32(p + 0x10);
    out.upperAuth = read32(p + 0x14);
    out.ssidLength = ssidLength;
    memcpy(out.ssid, p + 0x20, ssidLength);
    out.keyLength = keyLength;
    out.keyCipher = read32(p + 0x48);
    out.keyIndex = read16(p + 0x4e);
    memcpy(out.key, p + 0x50, keyLength);
    memcpy(out.bssid, p + 0x21c, 6);
    out.channelSpec = read16(p + 0x228);
    out.rsnLength = rsnLength;
    memcpy(out.rsn, p + 0xd6, rsnLength);
    return true;
}

}
#endif
