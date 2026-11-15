//
//  MtkLog.cpp
//  SimpleMtkWlan
//

#include "MtkLog.hpp"
#include <IOKit/IOLib.h>
#include <libkern/libkern.h>
#include <libkern/OSAtomic.h>
#include <kern/clock.h>

/*
 * Persistent debug log. Early boot messages are lost from the unified log
 * (no uuidtext for OpenCore-injected kexts, small msgbuf), so every message
 * is also kept in a ring buffer and published as the "MtkDebugLog" property
 * on the PCI provider, where it survives a failed probe/start.
 */
#define MTK_DBG_BUF_SIZE (128 * 1024)
static char gMtkDbgBuf[MTK_DBG_BUF_SIZE];
static size_t gMtkDbgLen;
static volatile SInt32 gMtkDbgLock;
static IOService *gMtkDbgNub;

static void mtkDbgLock()
{
    while (!OSCompareAndSwap(0, 1, &gMtkDbgLock)) {}
}

static void mtkDbgUnlock()
{
    OSCompareAndSwap(1, 0, &gMtkDbgLock);
}

extern "C" void mtk_dbg_log(const char *fmt, ...)
{
    char line[512];
    uint64_t ns;
    va_list ap;
    int prefix;
    size_t len;

    absolutetime_to_nanoseconds(mach_absolute_time(), &ns);
    prefix = snprintf(line, sizeof(line), "[%llu.%03llu] ",
        ns / 1000000000ULL, (ns / 1000000ULL) % 1000ULL);
    va_start(ap, fmt);
    vsnprintf(line + prefix, sizeof(line) - prefix, fmt, ap);
    va_end(ap);

    len = strnlen(line, sizeof(line));
    mtkDbgLock();
    if (gMtkDbgLen + len >= MTK_DBG_BUF_SIZE) {
        size_t drop = MTK_DBG_BUF_SIZE / 2;
        memmove(gMtkDbgBuf, gMtkDbgBuf + drop, gMtkDbgLen - drop);
        gMtkDbgLen -= drop;
    }
    memcpy(gMtkDbgBuf + gMtkDbgLen, line, len);
    gMtkDbgLen += len;
    gMtkDbgBuf[gMtkDbgLen] = 0;
    mtkDbgUnlock();
}

/*
 * Phase 4i: the ring above covers only minutes, so the log before each
 * disconnect (RUN left) is also copied here: the last MTK_DROP_SLOT bytes,
 * published as "MtkDropLog". The newest 4 disconnects macOS did not ask for
 * and, apart (review S7: they must not push those out), the newest 2 it did.
 */
#define MTK_DROP_SLOT  (16 * 1024)
#define MTK_DROP_INVOL 4
#define MTK_DROP_VOL   2
#define MTK_DROP_SLOTS (MTK_DROP_INVOL + MTK_DROP_VOL)
static char gMtkDropBuf[MTK_DROP_SLOTS][MTK_DROP_SLOT];
static size_t gMtkDropLen[MTK_DROP_SLOTS];
static unsigned gMtkDropCount, gMtkDropInvol, gMtkDropVol;

void mtk_dbg_snapshot(const char *why, bool voluntary)
{
    unsigned slot;
    size_t hdr, take, from;
    char *dst;
    uint64_t ns;

    absolutetime_to_nanoseconds(mach_absolute_time(), &ns);
    mtkDbgLock();
    if (voluntary)
        slot = MTK_DROP_INVOL + gMtkDropVol++ % MTK_DROP_VOL;
    else
        slot = gMtkDropInvol++ % MTK_DROP_INVOL;
    dst = gMtkDropBuf[slot];
    hdr = (size_t)snprintf(dst, 160, "===== disconnect #%u at [%llu.%03llu]: %s =====\n",
        gMtkDropCount + 1, ns / 1000000000ULL, (ns / 1000000ULL) % 1000ULL, why);
    if (hdr >= 160)
        hdr = 159;
    take = gMtkDbgLen;
    if (take > MTK_DROP_SLOT - hdr - 1)
        take = MTK_DROP_SLOT - hdr - 1;
    from = gMtkDbgLen - take;
    /* start at a line */
    while (from < gMtkDbgLen && from > 0 && gMtkDbgBuf[from - 1] != '\n') {
        from++;
        take--;
    }
    memcpy(dst + hdr, gMtkDbgBuf + from, take);
    gMtkDropLen[slot] = hdr + take;
    dst[gMtkDropLen[slot]] = 0;
    gMtkDropCount++;
    mtkDbgUnlock();
}

static void mtk_drop_publish(IOService *nub)
{
    const size_t size = MTK_DROP_SLOTS * MTK_DROP_SLOT + 1;
    char *copy;
    size_t len = 0;
    unsigned i, n, first;

    if (gMtkDropCount == 0)
        return;
    copy = (char *)IOMalloc(size);
    if (copy == NULL)
        return;
    mtkDbgLock();
    /* not asked for first, oldest to newest; then macOS's own leaves */
    n = gMtkDropInvol < MTK_DROP_INVOL ? gMtkDropInvol : MTK_DROP_INVOL;
    first = gMtkDropInvol - n;
    for (i = 0; i < n; i++) {
        unsigned slot = (first + i) % MTK_DROP_INVOL;
        memcpy(copy + len, gMtkDropBuf[slot], gMtkDropLen[slot]);
        len += gMtkDropLen[slot];
    }
    n = gMtkDropVol < MTK_DROP_VOL ? gMtkDropVol : MTK_DROP_VOL;
    first = gMtkDropVol - n;
    for (i = 0; i < n; i++) {
        unsigned slot = MTK_DROP_INVOL + (first + i) % MTK_DROP_VOL;
        memcpy(copy + len, gMtkDropBuf[slot], gMtkDropLen[slot]);
        len += gMtkDropLen[slot];
    }
    mtkDbgUnlock();
    copy[len] = 0;
    OSString *str = OSString::withCString(copy);
    IOFree(copy, size);
    if (str != NULL) {
        nub->setProperty("MtkDropLog", str);
        str->release();
    }
}

void mtk_dbg_publish()
{
    IOService *nub = gMtkDbgNub;
    char *copy;
    size_t len;

    if (nub == NULL)
        return;
    copy = (char *)IOMalloc(MTK_DBG_BUF_SIZE);
    if (copy == NULL)
        return;
    mtkDbgLock();
    len = gMtkDbgLen;
    memcpy(copy, gMtkDbgBuf, len);
    mtkDbgUnlock();
    copy[len] = 0;
    OSString *str = OSString::withCString(copy);
    IOFree(copy, MTK_DBG_BUF_SIZE);
    if (str != NULL) {
        nub->setProperty("MtkDebugLog", str);
        str->release();
    }
    mtk_drop_publish(nub);
}

void mtk_dbg_set_nub(IOService *nub)
{
    gMtkDbgNub = nub;
}
