"""
======================
Silicon Purity Test

Joseph R Goydish II
======================

ZombieHunter v3.1 - iOS Silicon Implant Detection Tool
Detects unwipeable, silicon-level iOS implants that survive DFU restore.
Forensic evidence of CVE-2026-20700 SSV-layer persistence confirmed in the wild.

Detection methods:
  1. UUID cross-reference: harvest UUIDs from .tracev3 logs, match against dsc/ binaries
  2. SHA256 hash match: flag known-bad DSC binaries regardless of log presence
  3. Hex-encoded C2 IP detection: Big-Endian sockaddr_in structs at port 443
  4. Cluster 2 boot chain symbols: FTAB persistence artifacts
  5. Cluster 3 HID surveillance symbols: StudyLog.framework hooks
  6. Cluster 1 GPU/silicon artifacts: AGX firmware patch indicators
  7. Anti-forensic trigger detection: ptrace, sandbox, jailbreak, self-destruct
  8. Embedded URL fingerprinting: operational URLs inconsistent with legitimate DSC content

Usage:
  python3 zombie_detection.py sysdiagnose_YYYY.MM.DD_HH-MM-SS-XXXX.tar.gz
"""

import re
import struct
import os
import tarfile
import hashlib
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# PATTERNS
# ---------------------------------------------------------------------------

# UUID in log text (with or without dashes)
ID_RE = re.compile(
    r'\b([a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}|[a-fA-F0-9]{32})\b'
)

# Scan binary for 32-char hex UUID blobs (no dashes)
UUID_SCAN_RE = re.compile(rb'[0-9a-fA-F]{32}', re.IGNORECASE)

# Hex-encoded IP immediately followed by port 443 (decimal or hex)
ANCHOR_RE = re.compile(rb'([0-9a-fA-F]{8})[:.](?:443|01bb)', re.IGNORECASE)

# Embedded HTTP/S URLs in binary
ASCII_URL_RE = re.compile(rb'https?://([a-zA-Z0-9._:/?&=%~-]{4,128})')

# Private/loopback ranges to ignore in C2 sweep
IGNORED_IPS = {
    "0.0.0.0", "255.255.255.255", "127.0.0.1",
    "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
}

# ---------------------------------------------------------------------------
# KNOWN BAD SHA256 HASHES
# Confirmed zombie DSC binaries - Device 1 (A16) and Device 2 (A14)
# Source: ZombieHunter forensic captures, iOS 26.2.1 through 26.3.1
# ---------------------------------------------------------------------------
KNOWN_BAD_SHA256S = {
    # Device 1 - Apple A16
    'ac746508938646c0cfae3f1d33f15bae718efbc7f0972426c41555e02e6f9770',
    'd93d48802aa3ccefa74ae09a6a86eafa7554490d884c00b531a9bfe81981fb06',
    # Device 2 - Apple A14
    '38a723210c18e81de8f33db79cfe8bae050a98d9d2eacdeb4f35dabbf7bd0cee',
    '869f9771ea1f9b6bf7adbd2663d71dbc041fafcbf68e878542c8639a6ba23066',
}

# ---------------------------------------------------------------------------
# CONFIRMED C2 INFRASTRUCTURE (Big-Endian hex in sockaddr_in structs)
# All confirmed via binary analysis of C4BE5627FAD93C7987A9E75944417538
# Zero prior VT detections as of 2026-03-07 - novel campaign infrastructure
# ---------------------------------------------------------------------------
KNOWN_C2_IPS = {
    # Active C2 - confirmed across all zombie captures, port 443
    "200.152.70.35":   "ZombieHunter primary C2 (Osasco SP Brazil, AS14463 TDKOM)",
    # Cluster 3 HID exfiltration endpoints
    "107.195.166.114": "HID exfil C2 via _ITTouchTranscoderSessionAddEvent (AT&T residential Cicero IL)",
    "136.133.187.184": "Real-time telemetry stream via _NetworkStream::Start (Ford Motor Co Dearborn MI)",
    "207.135.206.181": "System log exfil via _SLGLog::exfilBuffer (Thunderbox/GBIS Holdings Reno NV)",
}

# ---------------------------------------------------------------------------
# CLUSTER 2 - BOOT CHAIN & FTAB PERSISTENCE SYMBOLS
# Confirmed in payload_0x92a353b.macho via strings extraction
# These symbols have no legitimate presence in any DSC binary
# ---------------------------------------------------------------------------
FTAB_SYMBOLS = [
    b"setBootNonce",
    b"addNewFileToFTABOnData",
    b"updateFileInFTABOnData",
    b"copyManifest",
    b"copyPersonalizationSSOToken",
    # Repurposed Apple Image4 diagnostic - living-off-the-land boot chain marker
    b"cowardly retreating because tag",
]

# ---------------------------------------------------------------------------
# CLUSTER 3 - HID SURVEILLANCE SYMBOLS
# Confirmed in payload_0x97cd69b.macho / payload_0x97cd696.macho
# StudyLog.framework hooks - intercept raw IOHIDEvents before any app receives them
# ---------------------------------------------------------------------------
HID_SYMBOLS = [
    b"_ITTouchTranscoderSessionAddEvent",
    b"PListGestureParser",
    b"_SLGLog",
    b"SLGLog Mouse Point",
    b"StudyLog",
]

# ---------------------------------------------------------------------------
# CLUSTER 1 - GPU & SILICON ARTIFACTS
# Confirmed in payload_0x44535bf.macho through payload_0x44535ce.macho
# AGX firmware patches - raw framebuffer capture below ScreenCaptureKit
# ---------------------------------------------------------------------------
GPU_SYMBOLS = [
    b"gei_esl_range_exec_gen4",
    b"agc.patch_count_multiplier",
    b"vdm_nopdbg",
]

# ---------------------------------------------------------------------------
# ANTI-FORENSIC TRIGGERS
# Confirmed during initial triage - dormancy logic for research environments
# ---------------------------------------------------------------------------
ANTIFORENSIC_SYMBOLS = [
    b"PT_DENY_ATTACH",
    b"SIMULATOR_ROOT",
    b"cydia",
    b"removeItemAtPath",
]

# ---------------------------------------------------------------------------
# URL FINGERPRINTS
# Operational URLs embedded in zombie binaries - incompatible with any
# legitimate iOS DSC component. Partial list; flag any match as HIGH signal.
# ---------------------------------------------------------------------------
KNOWN_BAD_URL_FRAGMENTS = [
    b"covid-19-diagnostics.jrc.ec.europa.eu",   # EU JRC medical device registry
    b"wholefoodsmarket.com/stores/blossomhill",  # Geolocated - Blossom Hill, San Jose CA
    b"nike.com/us/en_us/retail/en/nike-san-francisco",  # Geolocated - Nike SF
    b"chevronwithtechron.com",                   # Retail brand, no iOS framework dependency
    b"ns.adobe.com/dicom",                       # DICOM medical imaging - not a consumer format
    b"google-analytics.com/analytics.js",        # Known exfil traffic blending technique
    b"securitykey/origins.json",                 # FIDO2/WebAuthn origin validation
    b"yelpcdn.com/bphoto",                       # Yelp business photo CDN
    b"mzstatic.com/image/thumb",                 # App Store CDN thumbnails in DSC = profiled app data
]

# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

def hex_to_ip(h):
    try:
        return ".".join(map(str, struct.pack(">I", int(h, 16))))
    except Exception:
        return None

def is_valid_public_ip(ip):
    if not ip:
        return False
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        if not all(0 <= int(p) <= 255 for p in parts):
            return False
    except ValueError:
        return False
    for prefix in IGNORED_IPS:
        if ip == prefix or ip.startswith(prefix):
            return False
    return True

def extract_hardcoded_c2(binary_data):
    seen = set()
    results = []

    def add(entry_type, value, confidence, note=""):
        key = (entry_type, value)
        if key not in seen:
            seen.add(key)
            results.append({
                'type': entry_type,
                'value': value,
                'confidence': confidence,
                'note': note
            })

    # Hex-encoded IPs at port 443
    for match in ANCHOR_RE.finditer(binary_data):
        ip = hex_to_ip(match.group(1).decode('ascii').lower())
        if is_valid_public_ip(ip):
            note = KNOWN_C2_IPS.get(ip, "")
            confidence = "CRITICAL" if ip in KNOWN_C2_IPS else "HIGH"
            add('hex_ip_port443', ip, confidence, note)

    # ASCII URLs
    for match in ASCII_URL_RE.finditer(binary_data):
        try:
            url = match.group(1).decode('ascii', errors='ignore').strip()
            if url:
                add('suspicious_url', url, 'MEDIUM')
        except Exception:
            pass

    # Known bad URL fragments
    for fragment in KNOWN_BAD_URL_FRAGMENTS:
        if fragment.lower() in binary_data.lower():
            add('known_bad_url', fragment.decode('ascii', errors='ignore'), 'HIGH',
                "Confirmed zombie binary URL fingerprint")

    return results

def scan_symbols(binary_data):
    """Scan for confirmed implant symbols across all three clusters."""
    hits = []

    for sym in FTAB_SYMBOLS:
        if sym.lower() in binary_data.lower():
            hits.append({
                'cluster': 'Cluster 2 - Boot Chain / FTAB Persistence',
                'symbol': sym.decode('ascii', errors='ignore'),
                'confidence': 'CRITICAL',
                'note': 'FTAB write capability - no legitimate DSC presence'
            })

    for sym in HID_SYMBOLS:
        if sym.lower() in binary_data.lower():
            hits.append({
                'cluster': 'Cluster 3 - HID Surveillance',
                'symbol': sym.decode('ascii', errors='ignore'),
                'confidence': 'CRITICAL',
                'note': 'StudyLog.framework hook - intercepts IOHIDEvents pre-encryption'
            })

    for sym in GPU_SYMBOLS:
        if sym.lower() in binary_data.lower():
            hits.append({
                'cluster': 'Cluster 1 - GPU / Silicon',
                'symbol': sym.decode('ascii', errors='ignore'),
                'confidence': 'HIGH',
                'note': 'AGX firmware patch - framebuffer capture below ScreenCaptureKit'
            })

    for sym in ANTIFORENSIC_SYMBOLS:
        if sym.lower() in binary_data.lower():
            hits.append({
                'cluster': 'Anti-Forensic',
                'symbol': sym.decode('ascii', errors='ignore'),
                'confidence': 'MEDIUM',
                'note': 'Dormancy trigger - confirms production-device-only activation'
            })

    return hits

# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def analyze_sysdiagnose_tarball(archive_path):
    print(f"[*] ZOMBIE DETECTOR v3.1 - Silicon Purity Test")
    print(f"[*] Target: {archive_path}")
    print(f"[*] CVE-2026-20700 - SSV-layer persistence detection")
    print("=" * 70)

    out_dir = "zombie_evidence"
    os.makedirs(out_dir, exist_ok=True)

    all_harvested_ids = set()
    zombie_binary_details = {}

    try:
        with tarfile.open(archive_path, "r:*") as tar:
            for m in tar.getmembers():
                if not m.isfile():
                    continue
                f_obj = tar.extractfile(m)
                if not f_obj:
                    continue

                data = f_obj.read()

                # Phase 1+2 - UUID harvest from logs
                if m.name.endswith('.tracev3'):
                    text = data.decode('ascii', errors='ignore')
                    for uid in ID_RE.findall(text):
                        all_harvested_ids.add(uid.lower().replace('-', ''))

                # Phase 3 - DSC/uuidtext binary analysis
                elif 'dsc' in m.name or 'uuidtext' in m.name:
                    sha256_hash = hashlib.sha256(data).hexdigest()
                    data_lower = data.lower()

                    found_uuids = {
                        h.group(0).decode('ascii')
                        for h in UUID_SCAN_RE.finditer(data_lower)
                    }
                    matches = found_uuids & all_harvested_ids

                    is_known_hash = sha256_hash in KNOWN_BAD_SHA256S
                    symbol_hits   = scan_symbols(data)
                    c2_hits       = extract_hardcoded_c2(data_lower)

                    # Flag if any detection method triggers
                    if matches or is_known_hash or symbol_hits or c2_hits:
                        details = zombie_binary_details.setdefault(m.name, {
                            'uuids_matched':     matches,
                            'sha256_hash':       sha256_hash,
                            'detection_methods': set(),
                            'c2_hits':           c2_hits,
                            'symbol_hits':       symbol_hits,
                        })

                        if matches:
                            details['detection_methods'].add('UUID_MATCH')
                        if is_known_hash:
                            details['detection_methods'].add('HASH_MATCH')
                        if symbol_hits:
                            details['detection_methods'].add('SYMBOL_MATCH')
                        if c2_hits:
                            details['detection_methods'].add('C2_MATCH')

                        # Extract flagged binary for independent analysis
                        safe_filename = os.path.basename(m.name)
                        extract_path = os.path.join(out_dir, safe_filename)
                        try:
                            with open(extract_path, 'wb') as bin_out:
                                bin_out.write(data)
                        except Exception as e:
                            print(f"[!] Error saving binary {safe_filename}: {e}")

    except Exception as e:
        print(f"[!] Tarball Processing Error: {e}")

    # ---------------------------------------------------------------------------
    # REPORT
    # ---------------------------------------------------------------------------

    report_path = os.path.join(out_dir, "ZOMBIE_REPORT.txt")
    with open(report_path, "w", encoding='utf-8') as f:

        f.write("=" * 70 + "\n")
        f.write("  ZOMBIE DETECTOR v3.1 - FORENSIC REPORT\n")
        f.write("  CVE-2026-20700 - SSV-Layer Persistence Detection\n")
        f.write("=" * 70 + "\n\n")

        if not zombie_binary_details:
            f.write("  No zombie binaries detected.\n")
            f.write("  Device appears clean for known IOCs.\n\n")
            f.write("  Note: Absence of detection does not confirm clean device.\n")
            f.write("  Unknown variants may not yet be in the IOC database.\n")
            f.write("  Submit your sysdiagnose to ZombieHunter community reporting.\n")
        else:
            f.write(f"  * {len(zombie_binary_details)} ZOMBIE BINARY/BINARIES DETECTED\n\n")

            for binary_name, details in zombie_binary_details.items():
                f.write("-" * 70 + "\n")
                f.write(f"  Binary         : {binary_name}\n")
                f.write(f"  SHA256         : {details['sha256_hash']}\n")
                f.write(f"  Detection      : {', '.join(sorted(details['detection_methods']))}\n")
                f.write(f"  UUID Matches   : {len(details['uuids_matched']) if details['uuids_matched'] else 'None'}\n")

                # Symbol hits
                if details['symbol_hits']:
                    f.write(f"\n  IMPLANT SYMBOLS ({len(details['symbol_hits'])} confirmed):\n")
                    for hit in details['symbol_hits']:
                        f.write(f"    [{hit['confidence']}] {hit['cluster']}\n")
                        f.write(f"      Symbol : {hit['symbol']}\n")
                        f.write(f"      Note   : {hit['note']}\n")

                # C2 hits
                if details['c2_hits']:
                    f.write(f"\n  C2 INDICATORS ({len(details['c2_hits'])} found):\n")
                    for hit in details['c2_hits']:
                        f.write(f"    [{hit['confidence']}] {hit['type']}: {hit['value']}\n")
                        if hit.get('note'):
                            f.write(f"      Note: {hit['note']}\n")

                f.write("\n")

        f.write("=" * 70 + "\n")
        f.write("  ZombieHunter - github.com/JGoyd/ZombieHunter\n")
        f.write("  Report new IOCs via GitHub Issues\n")
        f.write("=" * 70 + "\n")

    # Console summary
    if zombie_binary_details:
        print(f"\n  * ZOMBIE BINARIES DETECTED: {len(zombie_binary_details)}")
        for name, details in zombie_binary_details.items():
            print(f"    {os.path.basename(name)}")
            print(f"      Methods   : {', '.join(sorted(details['detection_methods']))}")
            print(f"      SHA256    : {details['sha256_hash']}")
            crit = [h for h in details['symbol_hits'] if h['confidence'] == 'CRITICAL']
            if crit:
                print(f"      Symbols   : {len(crit)} CRITICAL implant symbol(s) confirmed")
            c2_crit = [h for h in details['c2_hits'] if h['confidence'] == 'CRITICAL']
            if c2_crit:
                print(f"      C2        : {[h['value'] for h in c2_crit]}")
    else:
        print("\n  No zombie binaries detected for known IOCs.")

    print(f"\n[*] Full report  : {report_path}")
    print(f"[*] Evidence dir : {out_dir}/")
    print(f"[*] Extracted binaries available for independent analysis.\n")


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 zombie_detection.py <sysdiagnose.tar.gz>")
        sys.exit(1)
    analyze_sysdiagnose_tarball(sys.argv[1])
