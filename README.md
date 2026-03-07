# ZombieHunter
### iOS Silicon Detector

### Stepped-On Silicon | Dirty iPhones Pass the Purity Test

> Detects unwipeable, silicon-level iOS implants that survive DFU restore.
> Forensic evidence of CVE-2026-20700 SSV-layer persistence confirmed in the wild.

---

## CVE-2026-20700 — Confirmed Post-DFU Persistence

> *"A memory corruption issue was addressed with improved state management.
> An attacker with memory write capability may be able to execute arbitrary code.
> Apple is aware of a report that this issue may have been exploited in an
> extremely sophisticated attack against specific targeted individuals on versions
> of iOS before iOS 26."*
> [Apple Security Advisory](https://support.apple.com/en-us/126346)



- **CVE:** CVE-2026-20700 
- **Patched:** iOS 26.3, February 11, 2026 

The zombie DSC binary was confirmed present after a **full DFU restore** with no
backup, no iCloud, and no Wi-Fi. The `dsc/` path maps to the **Signed System
Volume (SSV)**: the hardware root-of-trust-sealed, read-only partition at
`/System/Library/Caches/com.apple.dyld/`. Presence here survives every
remediation path available to a device owner: OTA update, DFU restore, factory
reset.

> **There is no fix. A confirmed zombie device is permanently compromised at the silicon level.**

---


## Verified Forensic Findings — 2 Independent Devices

Five zombie binary detections across two devices, three iOS versions, and both
major Apple chipset generations. Every capture resolves to the same C2 endpoint.
Both devices were fully DFU restored... no backup, no iCloud, no Wi-Fi. And the
implant **survived**. Per-device unique UUIDs confirm targeted implant generation;
the shared C2 confirms a single active campaign.

**Detection path:** `/system_logs.logarchive/dsc/[32-char UUID]`

### Device 1 — A16: iOS 26.2.1 → 26.3

| Date | Build | Zombie binary | UUIDs | C2 |
|---|---|---|---|---|
| 2026-02-07 | `23C71` (iOS 26.2.1) | `dsc/5D958D9D5B053C2796AE2A93B895337C` | 3 | `200.152.70.35:443` |
| 2026-03-03 | `23D127` (iOS 26.3) | `dsc/168CADF663A7397F9E9D2CE113F33C6C` | 2 | `200.152.70.35:443` |
| 2026-03-06 | `23D8133` (iOS 26.3.1) | `dsc/37552E3873EC310782BB3D424E169A66` | TBD | `200.152.70.35:443` |

UUID rotated post-update. C2 did not. Post-DFU restore on 26.3 confirmed survival.

### Device 2 — A14: iOS 26.3 → 26.3.1

| Date | Build | Zombie binary | Detection | UUIDs | Primary C2 |
|---|---|---|---|---|---|
| 2026-03-03 | `23D127` (iOS 26.3) | `dsc/C4BE5627FAD93C7987A9E75944417538` | UUID | 1 | `200.152.70.35:443` |
| 2026-03-05 | `23D8133` (iOS 26.3.1) | `dsc/C4BE5627FAD93C7987A9E75944417538` | HASH + UUID | 3 | `200.152.70.35:443` |
| 2026-03-05 | `23D8133` (iOS 26.3.1) | `dsc/1B623819BDF93618A76B785FF68F1F6B` | UUID | 3 | `200.152.70.35:443` |

**26.3.1 did not remove the implant. It added a second one.**



---

### Confirmed Zombie Binary Hashes (SHA256)

| Hash | Device | Chipset |
|---|---|---|
| `d93d48802aa3ccefa74ae09a6a86eafa7554490d884c00b531a9bfe81981fb06` | Device 1 | Apple A16 |
| `ac746508938646c0cfae3f1d33f15bae718efbc7f0972426c41555e02e6f9770` | Device 1 | Apple A16 |
| `38a723210c18e81de8f33db79cfe8bae050a98d9d2eacdeb4f35dabbf7bd0cee` | Device 2 | Apple A14 |
| `869f9771ea1f9b6bf7adbd2663d71dbc041fafcbf68e878542c8639a6ba23066` | Device 2 | Apple A14 |

These hashes are seeded into `KNOWN_BAD_SHA256S` in `zombie_detection.py` and
will trigger a `HASH_MATCH` detection even if the implant has gone silent in the
unified logging system.

---




## Embedded URLs — Implant Capability Fingerprint

Static analysis of the extracted zombie binaries surfaces hundreds of embedded URLs.
Most are XML/XMP namespace strings — W3C, Adobe, IPTC, Apple — the type legitimately
compiled into any iOS media framework. The volume of this familiar-looking noise is
not accidental: a first-pass scanner sees something that resembles an image metadata
library and moves on. The operational URLs are buried inside it.

A partial sample from the extracted binaries reveals a capability fingerprint
incompatible with any legitimate iOS system component:

| URL | Signal |
|---|---|
| `covid-19-diagnostics.jrc.ec.europa.eu/devices` | EU Joint Research Centre medical device regulatory database. Not a namespace, not a CDN — a hardcoded path to a specific EU government registry with no iOS framework dependency. |
| `www.wholefoodsmarket.com/stores/blossomhill` | Geolocated store page: Blossom Hill, South San Jose, CA. Neighborhood-level retail URL in a system binary. |
| `www.nike.com/us/en_us/retail/en/nike-san-francisco` | Geolocated Nike retail store, San Francisco, CA. |
| `www.chevronwithtechron.com` | Retail brand URL. No iOS framework dependency. |
| `is[3-5].mzstatic.com/image/thumb/[hash]/258x258.png` | Apple App Store CDN thumbnails — three separate paths. Runtime-fetched icon content has no place compiled into a system binary; indicates the implant processed or profiled installed app data. |
| `s3-media[1-3].fl.yelpcdn.com/bphoto/[hash]/o.jpg` | Yelp business photo CDN — three separate paths. Suggests active monitoring of location-discovery app activity on the device. |
| `www.gstatic.com/securitykey/origins.json` | Google FIDO2/WebAuthn security key origin validation. Presence suggests awareness of — or capability against — hardware-key-protected authentication. |
| `www.google-analytics.com/analytics.js` | Known technique for blending exfiltration traffic with legitimate analytics requests. |
| `www.microsoft.com/en-us/microsoft-365/microsoft-teams/` | Hardcoded Teams product URL, not a schema namespace. No legitimate DSC dependency. |
| `ns.adobe.com/dicom/` | DICOM — the medical imaging standard for MRI, CT, and X-ray. Not a consumer iOS format. Co-occurrence with EU medical regulatory infrastructure is a consistent signal. |

The Bay Area retail cluster... Whole Foods Blossom Hill, Nike SF, Chevron — combined
with Yelp photo CDN paths and App Store icon thumbnails represents a **geographic and
behavioral fingerprint**. These are not schema strings; they are runtime-content URLs
that only appear in a binary if the implant harvested device data (Maps, Safari,
Wallet) or was operating against a pre-profiled target. The EU COVID Diagnostics JRC URL alongside DICOM
capability points toward a specific professional context: healthcare, medical device
regulation, or public health infrastructure.

---


## C4 Binary Analysis | Full Reverse Engineering

The `C4BE5627FAD93C7987A9E75944417538` module (Device 2, A14, iOS 26.3) was
subjected to full static and dynamic reverse engineering. It is a 165.7 MB
multi-stage dropper concealed behind an `hcsd` CoreSymbolication file
signature. Ten Mach-O payloads were carved across three functional clusters:

- **GPU & Silicon** — AGX firmware patches achieving raw framebuffer capture
  below `ScreenCaptureKit` protections and all user-space privacy indicators
- **Boot Chain & FTAB** — FTAB injection and boot nonce manipulation for
  persistence that survives DFU restore and factory reset
- **HID Surveillance** — `StudyLog.framework` hooks intercepting every touch,
  gesture, and keystroke before application-layer encryption is applied

Five hardcoded endpoints were recovered from the binary's `.data` segment,
all encoded in Big-Endian hex within raw `sockaddr_in` structures — bypassing
every string-based detection method:

| IP Address | Role |
|---|---|
| `107.195.166.114` | Primary C2 — HID exfiltration via `_ITTouchTranscoderSessionAddEvent` |
| `136.133.187.184` | Real-time telemetry stream |
| `207.135.206.181` | System log exfiltration |
| `246.48.148.156` | Internal IPC — Class E reserved |
| `244.25.215.0` | Early boot hardware loopback — Class E reserved, active before iOS network stack initializes |

Captured HID data is encrypted with AES-256-GCM using hardware-derived
runtime keys before transmission. Keys are not stored in the binary and
are not recoverable through static analysis.

→ [`C4_Binary_Analysis/README.md`](https://github.com/JGoyd/ZombieHunter/tree/main/C4%20Binary%20Analysis)

---

## What ZombieHunter Detects

ZombieHunter detects the zombie exploit exemplifying the CVE-2026-20700 bypass: a
rogue `dyld_shared_cache` slice that survives patching and full DFU restore by
persisting at the SSV layer. The implant masquerades as a legitimate shared
library while maintaining active C2 connectivity, invisible to the user and
beyond the reach of any standard remediation.

| Phase | Action |
|---|---|
| **1+2** | Single-pass tar scan: harvest UUIDs from `.tracev3` logs, cross-reference against `dsc/` and `uuidtext/` binaries |
| **3** | Hash check: compare every DSC binary SHA256 against known-bad hash list, flag regardless of log presence |
| **4** | Write filtered forensic report, extract zombie binaries for independent analysis |

---

## Usage

**Generate sysdiagnose on device:**
```
VolUp + VolDown + Power (hold 1.5 sec) → Settings → Privacy & Security → Analytics & Improvements → Analytics Data
```

**Run ZombieHunter:**
```bash
python3 zombie_detector.py sysdiagnose_YYYY.MM.DD_HH-MM-SS-XXXX.tar.gz
```

**Output:**
```
zombie_evidence/
├── ZOMBIE_REPORT.txt        — forensic report with detection method and C2 indicators
└── ZOMBIE_[UUID].bin        — raw extracted DSC binary for independent analysis
```

The extracted binary can be loaded directly into IDA Pro, Ghidra, or Binary Ninja
for static analysis, or submitted to a sandboxed environment for dynamic analysis.

---

## Disclosure Timeline

```
2026-02-17  →  Apple PSIRT (product-security@apple.com)   Automated response only (ref: OE0104868731498)
2026-02-20  →  CISA / US-CERT                             Delayed response then deferred to Apple
2026-02-25  →  Public disclosure with reproducible PoC
```

---

## Repository

```
├── zombie_detector.py         # Forensic detection tool
├── README.md                  # CVE-2026-20700 exploitation evidence
└── C4_Binary_Analysis/
    ├── README.md              # Full reverse engineering report: C4BE5627FAD93C7987A9E75944417538
    └── Carved_Binaries/       # 10 extracted Mach-O payloads
```

---

## Threat Assessment

```
✓  Zombie dyld slice confirmed on 2 independent devices across 4 iOS builds
✓  Cross-chipset confirmation: A16 and A14 both affected
✓  Exploit survives full DFU restore, no backup, no iCloud, no Wi-Fi
✓  Persistence maps to SSV, hardware root-of-trust layer
✓  SSV seal bypass confirmed, beyond any standard remediation
✓  iOS 26.3.1 did not remediate, implant expanded to 2 simultaneous zombie binaries
✓  Binary UUID rotates per OS version, C2 endpoint unchanged across all builds
✓  Hash-based detection confirms presence even when implant evades log-based detection
✓  Same C2 endpoint (200.152.70.35:443) confirmed across all captures, active campaign
✓  Rogue DSC binaries extracted for independent static/dynamic analysis
```

---

## Community Reporting

**Got a detection? Found new IOCs?** Open an Issue with your script output.

Please include your iOS build string, `ZOMBIE_REPORT.txt` contents, and any new
C2 IPs or UUID patterns observed.
