#!/bin/bash
# Downloads the MediaTek MT7927 Wi-Fi firmware from linux-firmware, checks it against
# known SHA-256 sums, and installs it where AirportMT7927Wlan.kext looks for it.
#   sudo ./tools/install-mt7927-firmware.sh
# Existing different files are kept as *.bak. Nothing is installed unless both files match.
set -euo pipefail
dest=/Library/Firmware/mediatek/mt7927
names=(WIFI_MT6639_PATCH_MCU_2_1_hdr.bin WIFI_RAM_CODE_MT6639_2_1.bin)
sums=(7a5aacf68ed8526c1d94ba962f84046496b3909562decf8bb690cfbd8de5b65e
      e841f5ed4fe547ff2f15275a2f330bb19a253db92e3e59cbdfd8581d72b2582d)
bases=(https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/plain
       https://gitlab.com/kernel-firmware/linux-firmware/-/raw/main)
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
as_user=()
[[ -n "${SUDO_USER:-}" && "$SUDO_USER" != root ]] && as_user=(sudo -u "$SUDO_USER")
dl=$(${as_user[@]+"${as_user[@]}"} mktemp -d)       # downloads, as the user
tmp=$(mktemp -d); chmod 700 "$tmp"                    # verified copies, root only
trap 'rm -rf "$tmp"; ${as_user[@]+"${as_user[@]}"} rm -rf "$dl"' EXIT
sha() { shasum -a 256 "$1" | awk '{print $1}'; }

for i in 0 1; do
	f=${names[$i]}; ok=0
	for b in "${bases[@]}"; do
		rm -f "$tmp/$f"
		if ${as_user[@]+"${as_user[@]}"} curl -q -fsSL --retry 2 -o "$dl/$f" "$b/mediatek/mt7927/$f" \
		   && cp "$dl/$f" "$tmp/$f" && [[ "$(sha "$tmp/$f")" == "${sums[$i]}" ]]; then
			ok=1; break
		fi
		echo "  $b: download failed or checksum mismatch, trying the next source"
	done
	[[ $ok -eq 1 ]] || { echo "STOP: could not get a verified $f; nothing installed"; exit 1; }
	echo "verified $f"
done
licsum=a90d3f66704d85889945fec5525ea77622549da83aced1aac99828383f8f1805
for b in "${bases[@]}"; do
	if ${as_user[@]+"${as_user[@]}"} curl -q -fsSL -o "$dl/LICENCE.mediatek" "$b/LICENSES/LICENCE.mediatek" \
	   && cp "$dl/LICENCE.mediatek" "$tmp/LICENCE.mediatek" && [[ "$(sha "$tmp/LICENCE.mediatek")" == "$licsum" ]]; then break; fi
	rm -f "$tmp/LICENCE.mediatek"
done

for d in /Library/Firmware /Library/Firmware/mediatek "$dest"; do
	mkdir -p "$d"; chown root:wheel "$d"; chmod 755 "$d"
done
for f in "${names[@]}" LICENCE.mediatek; do
	[[ -f "$tmp/$f" ]] || continue
	if [[ -f "$dest/$f" ]]; then
		if cmp -s "$tmp/$f" "$dest/$f"; then echo "$f already installed"; continue; fi
		mv -f "$dest/$f" "$dest/$f.bak"; echo "kept the old $f as $f.bak"
	fi
	cp "$tmp/$f" "$dest/$f"; chown root:wheel "$dest/$f"; chmod 644 "$dest/$f"
done
ls -l "$dest"
echo "Done. The kext loads the firmware once the Data volume is mounted (or at the next boot)."
