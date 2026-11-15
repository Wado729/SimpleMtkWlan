#!/bin/bash
# Syntax-only compile of the kext sources on any host with clang (Linux too), with
# build-macos.sh's kernel flags and MacKernelSDK headers (AirportMtkWlan, Sequoia).
# No args: every source the AirportMtkWlan build compiles.
here="$(cd "$(dirname "$0")/.." && pwd)"; sdkhdr=$here/MacKernelSDK/Headers
incs=(-I "$sdkhdr")
for d in mtk80211/openbsd mtk80211 include; do incs+=(-isystem "$here/$d"); done
while IFS= read -r d; do incs+=(-I "$d"); done < <(find "$here/SimpleMtkWlan" "$here/include" "$here/mtk80211" -type d)
incs+=(-I "$here/AirportMtkWlan")
flags=(-target x86_64-apple-macos10.12 -x c++ -std=gnu++14 -mkernel -fapple-kext -fno-rtti -fno-exceptions -fno-builtin -fno-common -nostdlib -nostdinc
 -fno-use-cxa-atexit -DKERNEL -DIEEE80211_STA_ONLY -D__PRIVATE_SPI__ -DAIRPORT -DAIRPORT_WCL -D__IO80211_TARGET=__MAC_15_2 -DIO80211FAMILY_V2
 '-DSMTW_VERSION="x"' '-DGIT_COMMIT="x"' '-DITLWM_VERSION="x"' -include "$here/SimpleMtkWlan/PrivateSPI.pch"
 -Wno-deprecated-register -Wno-everything -Werror=return-type -fsyntax-only)
if [ $# -eq 0 ]; then
	cd "$here" || exit 1
	set -- include/FwBinary.cpp include/HAL/MtkHalService.cpp mtk80211/compat.cpp mtk80211/zutil.c \
		mtk80211/openbsd/crypto/*.c mtk80211/openbsd/net80211/*.c mtk80211/openbsd/net80211/*.cpp \
		mtk80211/openbsd/sys/arp.c mtk80211/openbsd/sys/_ifq.cpp mtk80211/openbsd/sys/_mbuf.cpp \
		mtk80211/openbsd/sys/_task.cpp SimpleMtkWlan/hal_mwx/MtkMwx.cpp SimpleMtkWlan/MtkLog.cpp \
		AirportMtkWlan/*.cpp AirportMtkWlan/WCL/*.cpp
fi
log=$(mktemp)
rc=0
for f in "$@"; do clang++ "${flags[@]}" "${incs[@]}" "$here/$f" 2>"$log" || { echo "FAIL $f"; grep -E "error" "$log" | head -15; rc=1; continue; }; echo "OK $f"; done
rm -f "$log"
exit $rc
