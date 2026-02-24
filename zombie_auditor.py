#!/usr/bin/env python3
import struct, os, glob, tarfile, json, tempfile, argparse, sys
from pathlib import Path

def load_c2_config(config_path='c2_actors.json'):
    default = {
        "116.68.105.103": "Rogers Proxy", 
        "109.105.110.73": "Rostelecom Command",
        "109.97.120.73": "DigitalOcean Terminus"
    }
    try:
        with open(config_path) as f:
            return json.load(f)
    except:
        return default

def audit_single_binary(file_path, anchors, DART_OVERFLOW):
    print(f"\n--- {os.path.basename(file_path)} ---")
    hits = 0
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            
            # DART Overflow check
            if struct.pack('<I', DART_OVERFLOW) in data:
                print("[✓] DART Overflow Seed")
                hits += 1
            
            # C2 Anchor scan
            print("[C2 SCAN]")
            for ip, role in anchors.items():
                ip_bytes = bytes(map(int, ip.split('.')))
                if ip_bytes in data:
                    print(f"  [✓] {ip} ({role})")
                    hits += 1
                else:
                    print(f"  [✗] {ip}")
            
        return hits
        
    except Exception as e:
        print(f"[ERROR] {e}")
        return 0

def find_dsc_binaries(root_path):
    """Aggressive search for ANY binary in ANY dsc/ folder"""
    binaries = []
    
    # Pattern 1: system_logs.logarchive/dsc/* (your structure)
    pattern1 = os.path.join(root_path, "**", "system_logs.logarchive", "dsc", "*")
    binaries.extend(glob.glob(pattern1, recursive=True))
    
    # Pattern 2: os_logarchive/DSC/* (alternate)
    pattern2 = os.path.join(root_path, "**", "os_logarchive", "DSC", "*")
    binaries.extend(glob.glob(pattern2, recursive=True))
    
    # Pattern 3: ANY dsc/ folder containing binaries (universal)
    pattern3 = os.path.join(root_path, "**", "dsc", "*")
    binaries.extend(glob.glob(pattern3, recursive=True))
    
    # Filter to likely binaries (not .txt, .log, etc.)
    binary_files = [f for f in binaries if not f.lower().endswith(('.txt', '.log', '.plist', '.json'))]
    
    return list(set(binary_files))  # Dedupe

def extract_and_scan_tar(tar_path, anchors, DART_OVERFLOW):
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            print(f"[INFO] Extracting {os.path.basename(tar_path)}...")
            with tarfile.open(tar_path, 'r:gz') as tar:
                tar.extractall(temp_dir)
            
            # Find your DSC binaries
            binaries = find_dsc_binaries(temp_dir)
            
            if not binaries:
                print("[WARNING] No binaries found in dsc/ folders. Listing logarchive contents...")
                # Debug: show all logarchive paths
                logarchives = glob.glob(os.path.join(temp_dir, "**", "logarchive", "*"), recursive=True)
                for la in logarchives[:10]:  # Top 10
                    print(f"  Found: {la}")
                return 0
            
            print(f"[INFO] Found {len(binaries)} potential DSC binaries")
            
            total_hits = 0
            for binary_file in binaries:
                hits = audit_single_binary(binary_file, anchors, DART_OVERFLOW)
                total_hits += hits
            
            print(f"\n=== SUMMARY ===\n{total_hits} total hits across {len(binaries)} binaries")
            return total_hits
            
    except FileNotFoundError:
        print(f"[ERROR] File not found: {tar_path}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="iOS DSC Binary Auditor")
    parser.add_argument("sysdiagnose", help="Path to your sysdiagnose tar.gz")
    parser.add_argument("--config", default="c2_actors.json", help="Optional C2 config")
    args = parser.parse_args()
    
    anchors = load_c2_config(args.config)
    DART_OVERFLOW = 1685283688
    
    print("🚨 iOS DSC Binary Forensic Auditor 🚨")
    print(f"Target: {args.sysdiagnose}\n")
    
    if os.path.isdir(args.sysdiagnose):
        binaries = find_dsc_binaries(args.sysdiagnose)
        total_hits = sum(audit_single_binary(f, anchors, DART_OVERFLOW) for f in binaries)
    else:
        total_hits = extract_and_scan_tar(args.sysdiagnose, anchors, DART_OVERFLOW)
    
    print(f"\n✅ Complete: {total_hits} hits")

if __name__ == "__main__":
    main()
