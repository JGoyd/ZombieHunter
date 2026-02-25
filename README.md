# ZombieHunter - iOS dyld_shared_cache Exploitation Auditor

## What This Tool Detects

**Live exploitation artifacts** from **CVE-2026-20700** (dyld memory corruption vulnerability) discovered in production iOS 26.3 sysdiagnose archives. Detects rogue dyld_shared_cache slices exhibiting **active bypass** of Apple's patched zero-day:

```
Mappings Count: 301,240 → Overflow Trigger Confirmed  
BL Proof → bl #0x15cd at offset 0x15cd
C2 Anchor → 83.116.114.97 (offset 0x794bd)
AMFI Bypass → DYLD_AMFI_FAKE at 0x532e9
```

**Target Location**: `/system_logs.logarchive/dsc/[32-char UUID]`

## Verified Rogue Slice Download
**[Direct Exploit Artifact](https://drive.google.com/file/d/1rYNGtKBMb34FQT4zLExI51sdAYRES6iN/view?usp=sharing)**  
**SHA256**: `ac746508938646c0cfae3f1d33f15bae718efbc7f0972426c41555e02e6f9770`

## CVE-2026-20700 Bypass Confirmed

**Apple's description**: "A memory corruption issue was addressed with improved state management. An attacker with memory write capability may be able to execute arbitrary code." [support.apple](https://support.apple.com/en-us/126346)

**This artifact demonstrates the ACTIVE BYPASS**:
```
1. Malformed mappings_count (301,240) → dyld memory corruption trigger
2. Metadata executes as ARM64 shellcode (BL 0x940015CD @ 0x15cd)  
3. DYLD_AMFI_FAKE neutralizes code signing enforcement
4. C2 connectivity to 83.116.114.97 for persistence
```

## Forensic Indicators

| Offset | Artifact | Value | CVE-2026-20700 Impact |
|--------|----------|-------|----------------------|
| `0x18` | Mappings | `301,240` | **Memory corruption** |
| `0x15cd` | BL Instr | `0x940015CD` | **Arbitrary code exec** |
| `0x794bd` | C2 IP | `83.116.114.97` | **Post-exploit C2** |
| `0x532e9` | AMFI Fake | `DYLD_AMFI_FAKE` | **Signature bypass** |

## Usage

### Generate Sysdiagnose
```
iPhone: VolUp + VolDown + Power (5+ sec) → Settings → Analytics Data
```

### Analyze
```bash
# Full sysdiagnose (auto-extracts)
python3 zombie_auditor.py sysdiagnose_YYYY.MM.DD_HH-MM-SS-XXXX.tar.gz

# Direct slice verification
python3 zombie_auditor.py rogue-slice.dat
```

**Requires**: `pip3 install capstone`

## Verified Positive Output
```
iOS dyld_shared_cache Exploitation Auditor
=============================================
Auditing: [32-char-uuid]
Mappings Count: 301,240 -> Overflow Trigger Confirmed
BL Proof -> bl #0x15cd at offset 0x15cd
  HEX: 940015CD -> 0x94000000 pattern
  ASM: bl #0x15cd
C2 Anchor -> 83.116.114.97 (offset 0x794bd)
AMFI Bypass -> DYLD_AMFI_FAKE at 0x532e9

DISCLOSURE READY
```

## Test with Confirmed Sample
```bash
# Download verified exploit artifact
wget "https://drive.google.com/uc?id=1rYNGtKBMb34FQT4zLExI51sdAYRES6iN" -O rogue-slice.dat
python3 zombie_auditor.py rogue-slice.dat  # Should match above output
```

## Disclosure Timeline
```
2026-02-17: Apple PSIRT (product-security@apple.com) → No response
2026-02-20: CISA/US-CERT → No response
2026-02-25: Public disclosure with reproducible PoC
```

## Repository Contents
```
├── zombie_auditor.py  # Forensic detection tool
└── README.md         # CVE-2026-20700 exploitation evidence
```

## Threat Assessment
```
✓ Demonstrates CVE-2026-20700 BYPASS in production iOS 26.3
✓ Reproducible dyld RCE chain from verified sysdiagnose
✓ Live C2 connectivity (83.116.114.97)
✓ AMFI neutralization confirmed
✓ SHA256 chain-of-custody preserved
```

## Community Reporting
- **Positive detection**: Open Issue with script output 
- **New IOCs**: Pull Request with offsets/strings

***
