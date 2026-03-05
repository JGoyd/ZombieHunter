======================
Silicon Purity Test

Joseph R Goydish II
======================


import re
import struct
import csv
import os
import tarfile
import sys
from urllib.parse import urlparse # Added for more robust URL filtering

# --- Patterns ---

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

# Private/loopback ranges to ignore
IGNORED_IPS = {
    "0.0.0.0", "255.255.255.255", "127.0.0.1",
    "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
}

# --- Helpers ---

def hex_to_ip(h):
    try:
        return ".".join(map(str, struct.pack(">I", int(h, 16))))
    except:
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

# Domains and hostnames to be filtered out from URLs
IGNORED_URL_DOMAINS = {
    'apple.com', 'icloud.com', 'me.com', 'mac.com',
    'cdn-apple.com', 'apps.apple.com', 'itunes.apple.com',
    'mzstatic.com', 'aaplimg.com', 'appleid.apple.com',
    'www.apple.com', 'support.apple.com', 'developer.apple.com', 'itunes.com',
    'schema.org', 'hl7.org', 'w3.org', 'schemas.microsoft.com',
    'schemas.openxmlformats.org', 'purl.org', 'purl.oclc.org',
    'ns.adobe.com', 'ns.apple.com',
    # Explicitly added from previous output and user request:
    'edge.apple', # For croissant.edge.apple
    'apple.news', # For apple.news/familysetup
    'digitalhub.com', # For idmsa-uat.digitalhub.com
    'unitsofmeasure.org',
    'crl.comodo.net',
    'partner.barrons.com', # barrons.com for /apple/web_access, etc.
    'digicert.com',
    'radio.itunes.apple.com',
    'gateway.icloud.com',
    'tether.edge.apple',
    'radio-activity.itunes.apple.com',
    'snomed.info',
    'ncimeta.nci.nih.gov',
    'tools.ietf.org',
    'smarthealth.cards',
    'www.ama-assn.org',
    'www.whocc.no',
    'www.google.com',
    'openusd.org',
    'open.fda.gov',
    'r3.o.lencr.org',
    'x1.c.lencr.org',
    'ocsp.digicert.com',
    'us-pst.exp.fastly-masque.net',
    'r3.i.lencr.org',
    'crl.comodoca.com',
    'acsegateway.icloud.com',
    'idmsa-uat.digitalhub.com',
    'accounts.barrons.com',
    'nema.org',
    'developers.google.com',
    'www.nlm.nih.gov',
    'q1.us-pst.gh-g.v1.akaquill.net',
    'ocsp.comodoca.com',
    'www.instapaper.com',
    'pinboard.in',
    'wordpress.com',
    'trello.com',
    'vp25q03ad-app037.iad.apple.com',
    'www.showtime.com',
    'www.hulu.com',
    'en.wikipedia.org',
    'www.cgal.org',
    'ml-explore.github.io',
    'github.com',
    'login.live.com',
    'outlook.office.com',
    'login.microsoftonline.com',
    'mdm.example.com',
    'eas.outlook.com',
    'outlook.office365.com',
    'www.britannica.com',
    'www.investopedia.com',
    'www.beatsbydre.com',
    'covid-19-diagnostics.jrc.ec.europa.eu',
    'ec.europa.eu',
    'spor.ema.europa.eu',
    'fhir.org',
    'commonmark.org',
    'jwxkwap.miit.gov.cn',
    'migrate.google',
    'raptor-dr.apple.com',
    'starbucks.com',
    'passman.apple.com',
    'docs.oasis-open.org'
}

IGNORED_URL_EXACT_MATCHES = {
    'localhost', '127.0.0.1', 'example.com', 'pcmdestination.example',
    # Explicitly added from previous output and user request:
    'user:password',
    '%s:%s',
    '%s:%u',
    'host.com%',
    'autodiscover.%',
    'localhost:%li%',
    'jwxkwap.miit.gov.cn/eauthenticityquerydetails?type=1&r=%',
    '17.253.144.13', # specific IP that is not a C2
    'networkquality/.well-known/nq',
    'macvmlschemauri'
}

# Regex for common format strings in URLs
# Updated to match specific format specifiers including %ld, %lu
FORMAT_STRING_RE = re.compile(r'%(?:s|d|f|@|ld|lu)', re.IGNORECASE)

def is_ignored_url(url_value):
    try:
        url_lower = url_value.lower()

        # Check for exact matches (host or full URL part) directly against the raw URL string
        if url_lower in IGNORED_URL_EXACT_MATCHES:
            return True

        # Check for format strings
        if FORMAT_STRING_RE.search(url_lower):
            return True

        # To robustly parse the domain, ensure the URL has a scheme
        parsed_url = urlparse(url_lower if '://' in url_lower else 'http://' + url_lower)
        host = parsed_url.netloc.lower()

        if not host: # If host still couldn't be parsed (e.g., 'user:password' would result in host='')
            return False

        for domain in IGNORED_URL_DOMAINS:
            if host == domain or host.endswith('.' + domain): # Handle subdomains as well
                return True
        return False
    except Exception:
        return False

def extract_hardcoded_c2(binary_data):
    """
    Scan a zombie binary for embedded C2 indicators.
    Returns list of dicts with type, value, confidence.
    """
    seen = set()
    results = []

    def add(entry_type, value, confidence):
        key = (entry_type, value)
        if key not in seen:
            seen.add(key)
            results.append({'type': entry_type, 'value': value, 'confidence': confidence})

    # HIGH confidence: hex-encoded IP paired with HTTPS port — almost certainly intentional
    for match in ANCHOR_RE.finditer(binary_data):
        ip = hex_to_ip(match.group(1).decode('ascii').lower())
        if is_valid_public_ip(ip):
            add('hex_ip_port443', ip, 'HIGH')

    # MEDIUM confidence: embedded URLs (catches domain-based C2 too)
    for match in ASCII_URL_RE.finditer(binary_data):
        try:
            url = match.group(1).decode('ascii', errors='ignore').strip()
            if url and not is_ignored_url(url): # Apply the new, enhanced filtering here
                add('suspicious_url', url, 'MEDIUM') # Changed type label to suspicious_url
        except:
            pass

    return results

# --- Main ---

def analyze_sysdiagnose_tarball(archive_path):
    print(f"[*] ZOMBIE DETECTOR v3.0")
    print(f"[*] Target: {archive_path}")
    print()

    if not os.path.exists(archive_path):
        print(f"[!] File not found: {archive_path}")
        return

    out_dir = "zombie_evidence"
    os.makedirs(out_dir, exist_ok=True)

    all_harvested_ids = set()   # 32-char hex, lowercase, no dashes
    id_to_log_map = {}          # uuid32 -> tracev3 filename
    # tracev3_cache = {}          # filename -> raw bytes (for phase 3) # Removed
    zombie_uuids = set()        # confirmed zombie uuid32s
    zombie_to_binary = {}       # uuid32 -> dsc/uuidtext filename
    binary_c2 = {}              # binary filename -> [c2 hit dicts]

    # -------------------------------------------------------------------------
    # SINGLE PASS: harvest UUIDs from tracev3, detect zombies in dsc/uuidtext,
    # and immediately scan confirmed zombie binaries for hardcoded C2
    # -------------------------------------------------------------------------
    print("[*] Phase 1+2: Single-pass tar scan...")

    try:
        with tarfile.open(archive_path, "r:*") as tar:
            for m in tar.getmembers():
                if not m.isfile():
                    continue
                f_obj = tar.extractfile(m)
                if not f_obj:
                    continue
                data = f_obj.read()

                if m.name.endswith('.tracev3'):
                    text = data.decode('ascii', errors='ignore')
                    for uid in ID_RE.findall(text):
                        norm = uid.lower().replace('-', '')
                        all_harvested_ids.add(norm)
                        id_to_log_map[norm] = m.name
                    # tracev3_cache[m.name] = data # Removed

                elif 'dsc' in m.name or 'uuidtext' in m.name:
                    data_lower = data.lower()

                    found_in_binary = {
                        hit.group(0).decode('ascii')
                        for hit in UUID_SCAN_RE.finditer(data_lower)
                    }
                    matches = found_in_binary & all_harvested_ids

                    if matches:
                        for uid in matches:
                            zombie_uuids.add(uid)
                            zombie_to_binary[uid] = m.name

                        print(f"  [!] ZOMBIE BINARY: {m.name}")
                        print(f"      Matched UUIDs: {len(matches)}")

                        c2_hits = extract_hardcoded_c2(data_lower)
                        binary_c2[m.name] = c2_hits

                        if c2_hits: # Now 'c2_hits' is already filtered
                            num_c2_ips = len([hit for hit in c2_hits if hit['type'] == 'hex_ip_port443'])
                            num_suspicious_urls = len([hit for hit in c2_hits if hit['type'] == 'suspicious_url'])
                            print(f"      Hardcoded C2 indicators found: {num_c2_ips} (IPs) / {num_suspicious_urls} (Suspicious URLs) (filtered)") # Updated console print
                            for hit in c2_hits:
                                if hit['type'] == 'hex_ip_port443':
                                    print(f"        [{hit['confidence']}] C2 indicator: {hit['value']}")
                                elif hit['type'] == 'suspicious_url': # Now checking for 'suspicious_url'
                                    print(f"        [{hit['confidence']}] Suspicious URL: {hit['value']}") # Updated label
                        else:
                            print(f"      No relevant hardcoded C2 or suspicious URLs found in binary (after filtering)") # Updated text

                        out_bin = os.path.join(out_dir, f"ZOMBIE_{os.path.basename(m.name)}.bin")
                        if not os.path.exists(out_bin):
                            with open(out_bin, 'wb') as df:
                                df.write(data_lower)

    except Exception as e:
        print(f"[!] Error during scan: {e}")
        raise

    print()
    print(f"[*] {len(all_harvested_ids)} UUIDs harvested from logs")
    print(f"[*] {len(zombie_uuids)} zombie UUIDs confirmed")
    print()

    if not zombie_uuids:
        print("[+] No zombies detected — device clean")
        return

    print("=" * 70)
    print("  ZOMBIE CONFIRMED")
    print("=" * 70)
    print()

    # -------------------------------------------------------------------------
    # PHASE 3 (SECONDARY): tracev3 proximity scan for runtime connections
    # Removed as per user request
    # -------------------------------------------------------------------------
    # print("[*] Phase 3: Tracev3 proximity scan (secondary/runtime evidence)...")

    # zombie_flows = []
    # PROXIMITY_WINDOW = 512

    # for tname, content in tracev3_cache.items():
    #     content_lower = content.lower()

    #     for uid in zombie_uuids:
    #         uid_bytes = uid.encode()
    #         for uuid_match in re.finditer(re.escape(uid_bytes), content_lower):
    #             start = max(0, uuid_match.start() - PROXIMITY_WINDOW)
    #             end = min(len(content_lower), uuid_match.end() + PROXIMITY_WINDOW)
    #             chunk = content_lower[start:end]

    #             for anchor in ANCHOR_RE.finditer(chunk):
    #                 ip = hex_to_ip(anchor.group(1).decode('ascii').lower())
    #                 if is_valid_public_ip(ip):
    #                     zombie_flows.append({
    #                         'zombie_binary': zombie_to_binary.get(uid, 'UNKNOWN'),
    #                         'zombie_uuid': uid,
    #                         'destination_ip': ip,
    #                         'source': 'tracev3_runtime',
    #                         'trace_log': tname
    #                     })

    # print(f"[*] {len(zombie_flows)} runtime connections mapped from logs") # Removed
    # print()

    # -------------------------------------------------------------------------
    # PHASE 4: Write reports
    # -------------------------------------------------------------------------
    print("[*] Phase 4: Writing evidence...")

    report_path = os.path.join(out_dir, "ZOMBIE_REPORT.txt")
    with open(report_path, "w", encoding='utf-8') as f:
        f.write("=" * 70 + "\n")
        f.write("  ZOMBIE DETECTOR v3.0 — FORENSIC REPORT\n")
        f.write("=" * 70 + "\n\n")

        f.write(">>> PRIMARY: HARDCODED C2 AND SUSPICIOUS URLS IN ZOMBIE BINARIES <<<\n")
        f.write("-" * 70 + "\n\n")

        any_relevant_c2 = False
        for binary_name, hits in binary_c2.items():
            uuids_in_binary = [u for u, b in zombie_to_binary.items() if b == binary_name]
            f.write(f"Binary: {binary_name}\n")
            f.write(f"Zombie UUIDs matched: {len(uuids_in_binary)}\n")

            # Filter hits for reporting based on user's request
            filtered_hex_ip_hits = [hit for hit in hits if hit['type'] == 'hex_ip_port443']
            filtered_suspicious_urls = [hit for hit in hits if hit['type'] == 'suspicious_url'] # Now using 'suspicious_url' type

            if filtered_hex_ip_hits or filtered_suspicious_urls:
                any_relevant_c2 = True

                f.write(f"  C2 Indicators (hex_ip_port443):\n") # Changed title
                if filtered_hex_ip_hits:
                    for hit in filtered_hex_ip_hits:
                        f.write(f"    [{hit['confidence']}] C2 indicator: {hit['value']}\n") # Changed type label
                else:
                    f.write("    None found.\n")

                f.write(f"  Suspicious URLs:\n") # Simplified title
                if filtered_suspicious_urls:
                    for hit in filtered_suspicious_urls:
                        f.write(f"    [{hit['confidence']}] Suspicious URL: {hit['value']}\n") # Changed type label
                else:
                    f.write("    None found.\n")
            else:
                f.write("  No relevant C2 indicators (hex_ip_port443) or suspicious URLs found in this binary.\n") # Updated text
            f.write("\n")

        if not any_relevant_c2:
            f.write("No relevant C2 indicators (hex_ip_port443) or suspicious URLs found in any zombie binary.\n") # Updated text
            f.write("(Other IP types and ignored URLs are not prioritized in this report.)\n\n") # Updated explanation

        # Removed SECONDARY: RUNTIME CONNECTIONS (tracev3 logs) section as per user request
        # f.write("\n>>> SECONDARY: RUNTIME CONNECTIONS (tracev3 logs) <<<\n")
        # f.write("-" * 70 + "\n\n")

        # if zombie_flows:
        #     seen_flows = set()
        #     for flow in zombie_flows:
        #         key = (flow['zombie_binary'], flow['destination_ip'])
        #         if key not in seen_flows:
        #             seen_flows.add(key)
        #             f.write(f"  Binary: {flow['zombie_binary']}\n")
        #             f.write(f"  IP:     {flow['destination_ip']}\n")
        #             f.write(f"  Log:    {flow['trace_log']}\n\n")
        # else:
        #     f.write("  No runtime connections mapped from logs.\n\n")

        f.write("\n>>> ZOMBIE UUID LIST <<<\n")
        f.write("-" * 70 + "\n\n")
        for uid in sorted(zombie_uuids):
            f.write(f"  UUID:   {uid}\n")
            f.write(f"  Binary: {zombie_to_binary.get(uid, 'N/A')}\n")
            f.write(f"  Log:    {id_to_log_map.get(uid, 'N/A')}\n\n")

    # Removed CSV file generation blocks as per user request
    # c2_rows and zombie_flows are still populated for potential future use or debugging if needed elsewhere

    print("=" * 70)
    print("  ZOMBIE DETECTION COMPLETE")
    print("=" * 70)
    print(f"  Zombie binaries:          {len(binary_c2)}")
    print(f"  Zombie UUIDs:             {len(zombie_uuids)}")
    
    total_c2_ips_for_summary = 0
    total_suspicious_urls_for_summary = 0
    for binary_name, hits in binary_c2.items():
        total_c2_ips_for_summary += len([hit for hit in hits if hit['type'] == 'hex_ip_port443'])
        total_suspicious_urls_for_summary += len([hit for hit in hits if hit['type'] == 'suspicious_url'])

    print(f"  Hardcoded C2 indicators (IPs): {total_c2_ips_for_summary}")
    print(f"  Suspicious URLs:         {total_suspicious_urls_for_summary}")
    # print(f"  Runtime connections:       {len(zombie_flows)}") # Removed
    print()
    print(f"  Evidence written to: {out_dir}/")
    print(f"    ZOMBIE_REPORT.txt        — full forensic report (filtered as requested)")
    print(f"    ZOMBIE_*.bin             — extracted zombie binaries")
    # Removed CSV file printing references as well
    print("=" * 70)


def main():
    if len(sys.argv) != 2:
        print("Usage: python zombie_detector.py <sysdiagnose.tar.gz>")
        return 1
    analyze_sysdiagnose_tarball(sys.argv[1])
    return 0

if __name__ == "__main__":
    sys.exit(main())
