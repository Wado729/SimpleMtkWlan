#!/usr/bin/env python3
"""PTK derivation (ieee80211_derive_ptk) against an independent reference.

The driver's ieee80211_prf / ieee80211_kdf / ieee80211_derive_ptk, compiled
from ieee80211_crypto.c, against Python's hmac per IEEE Std 802.11-2020:
12.7.1.2 PRF-512 (HMAC-SHA1, label with its NUL) for AKM 2 (PSK), and
12.7.1.6.2 KDF-SHA256-384 (label without NUL, length in bits mixed in) for
AKM 6 (PSK-SHA256) and AKM 8 (SAE), as hostap's sha256_prf. Phase 4f.2:
the KDF took 23 bytes / 512 bits, so AKM 6 and 8 handshakes failed.
"""
import hashlib, hmac, os, pathlib, re, struct, subprocess, sys, tempfile
root = pathlib.Path(__file__).resolve().parents[2]
ob = root / "mtk80211" / "openbsd"
d = pathlib.Path(tempfile.mkdtemp(prefix="mtk-ptk-"))
for sub in ("sys", "crypto", "net80211"):
    (d / "inc" / sub).mkdir(parents=True)
(d / "inc/sys/types.h").write_text("""#pragma once
#include_next <sys/types.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
typedef uint8_t u_int8_t; typedef uint16_t u_int16_t; typedef uint32_t u_int32_t; typedef uint64_t u_int64_t;
static inline void explicit_bzero_shim(void *p, size_t n){ volatile unsigned char *q=(volatile unsigned char*)p; while(n--) *q++=0; }
#define explicit_bzero explicit_bzero_shim
""")
(d / "inc/sys/_endian.h").write_text("#pragma once\n#include <sys/types.h>\n#include <endian.h>\n#define _OSSwapInt64(x) __builtin_bswap64(x)\n#define _OSSwapInt32(x) __builtin_bswap32(x)\n")
for h in ("param", "systm", "endian"):
    (d / f"inc/sys/{h}.h").write_text("#pragma once\n#include <sys/types.h>\n")
(d / "inc/crypto/types.h").write_text("#pragma once\n#include <sys/types.h>\ntypedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;\n")
for h in ("sha2.h", "hmac.h", "md5.h", "sha1.h"):
    (d / "inc/crypto" / h).write_text((ob / "crypto" / h).read_text())
crypto = (ob / "net80211" / "ieee80211_crypto.c").read_text()
hdr = (ob / "net80211" / "ieee80211.h").read_text()
ch = (ob / "net80211" / "ieee80211_crypto.h").read_text()
ptk = re.search(r"struct ieee80211_ptk \{.*?\} __packed;", hdr, re.S).group(0).replace("__packed", "__attribute__((packed))")
akm = re.search(r"enum ieee80211_akm \{.*?\};", ch, re.S).group(0)
sha = re.search(r"static __inline int\nieee80211_is_sha256_akm\(.*?\n\}", ch, re.S).group(0).replace("__inline", "inline")
funcs = "".join(re.search(r"\nvoid\n" + n + r"\(.*?\n\}\n", crypto, re.S).group(0)
                for n in ("ieee80211_prf", "ieee80211_kdf", "ieee80211_derive_ptk"))
(d / "ptk.cpp").write_text(f"""#include <sys/types.h>
#include <crypto/md5.h>
#include <crypto/sha1.h>
#include <crypto/sha2.h>
#include <crypto/hmac.h>
#define IEEE80211_ADDR_LEN 6
#define IEEE80211_PMK_LEN 32
#define EAPOL_KEY_NONCE_LEN 32
#define XYLog(...)
#define NBBY 8
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif
{ptk}
{akm}
{sha}
{funcs}
static void hex(const char *s, uint8_t *o, size_t n) {{ for (size_t i = 0; i < n; i++) sscanf(s + 2 * i, "%2hhx", &o[i]); }}
int main(int argc, char **argv) {{
	uint8_t pmk[32], aa[6], spa[6], an[32], sn[32];
	struct ieee80211_ptk p;
	memset(&p, 0, sizeof p);
	hex(argv[2], pmk, 32); hex(argv[3], aa, 6); hex(argv[4], spa, 6); hex(argv[5], an, 32); hex(argv[6], sn, 32);
	ieee80211_derive_ptk((enum ieee80211_akm)atoi(argv[1]), pmk, aa, spa, an, sn, &p);
	for (size_t i = 0; i < sizeof p; i++) printf("%02x", ((uint8_t *)&p)[i]);
	printf("\\n");
	return 0;
}}
""")
flags = ["-std=c++14", "-O1", "-w", "-fsanitize=address,undefined", "-I", str(d / "inc")]
objs = []
for s in [d / "ptk.cpp"] + [ob / "crypto" / f for f in ("sha2.c", "hmac.c", "md5.c", "sha1.c")]:
    o = d / (s.name + ".o")
    subprocess.run(["clang++", "-x", "c++", "-c", *flags, str(s), "-o", str(o)], check=True)
    objs.append(str(o))
exe = d / "ptk"
subprocess.run(["clang++", "-fsanitize=address,undefined", *objs, "-o", str(exe)], check=True)

def kdf_sha256(k, label, ctx, bits):
    out, i = b"", 1
    while len(out) * 8 < bits:
        out += hmac.new(k, struct.pack("<H", i) + label + ctx + struct.pack("<H", bits), hashlib.sha256).digest()
        i += 1
    return out[:bits // 8]

def prf_sha1(k, label, ctx, bits):
    out, i = b"", 0
    while len(out) * 8 < bits:
        out += hmac.new(k, label + b"\0" + ctx + bytes([i]), hashlib.sha1).digest()
        i += 1
    return out[:bits // 8]

AKM = {"PSK": 0x02, "PSK-SHA256": 0x08, "SAE": 0x10}   # enum ieee80211_akm values
m = re.search(r"IEEE80211_AKM_PSK\s*=\s*(0x[0-9a-f]+)", (ob / "net80211" / "ieee80211_crypto.h").read_text())
AKM["PSK"] = int(m.group(1), 16)
fails = 0
for trial in range(4):
    pmk, aa, spa, an, sn = os.urandom(32), os.urandom(6), os.urandom(6), os.urandom(32), os.urandom(32)
    ctx = min(aa, spa) + max(aa, spa) + min(an, sn) + max(an, sn)
    for name, a in AKM.items():
        got = bytes.fromhex(subprocess.run([str(exe), str(a), pmk.hex(), aa.hex(), spa.hex(), an.hex(), sn.hex()],
                                           capture_output=True, text=True, check=True).stdout.strip())
        if name == "PSK":
            want, n = prf_sha1(pmk, b"Pairwise key expansion", ctx, 512), 64
        else:
            want, n = kdf_sha256(pmk, b"Pairwise key expansion", ctx, 384), 48
        ok = got[:n] == want
        if trial == 0 or not ok:
            print(f"{name:12s} PTK ({n * 8} bits) {'PASS' if ok else 'FAIL'}")
        fails += not ok
print("ALL PASS" if not fails else f"FAILED: {fails}")
sys.exit(fails != 0)
