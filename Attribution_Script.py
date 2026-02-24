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

def audit_single_dsc(file_path, anchors, DART_OVERFLOW):
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

def extract_and_scan_tar(tar_path, anchors, DART_OVERFLOW):
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            print(f"[INFO] Extracting {os.path.basename(tar_path)}...")
            with tarfile.open(tar_path, 'r:gz') as tar:
                tar.extractall(temp_dir)
            
            # Primary DSC path
            dsc_pattern = os.path.join(temp_dir, "**", "os_logarchive", "**", "DSC", "**", "*.dsc")
            dsc_files = glob.glob(dsc_pattern, recursive=True)
            
            # Fallback paths
            if not dsc_files:
                print("[INFO] Primary path empty, scanning all .dsc files...")
                dsc_files = glob.glob(os.path.join(temp_dir, "**", "*.dsc"), recursive=True)
            
            print(f"[INFO] Found {len(dsc_files)} DSC files")
            
            total_hits = 0
            for dsc_file in dsc_files:
                hits = audit_single_dsc(dsc_file, anchors, DART_OVERFLOW)
                total_hits += hits
            
            print(f"\n=== SUMMARY ===\n{total_hits} total hits across {len(dsc_files)} files")
            return total_hits
            
    except FileNotFoundError:
        print(f"[ERROR] File not found: {tar_path}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="iOS DSC Zombie Cache Auditor")
    parser.add_argument("sysdiagnose", help="Path to your sysdiagnose tar.gz")
    parser.add_argument("--config", default="c2_actors.json", help="Optional C2 config")
    args = parser.parse_args()
    
    anchors = load_c2_config(args.config)
    DART_OVERFLOW = 1685283688
    
    print("🚨 Personal iOS Zombie Cache Auditor 🚨")
    print(f"Target: {args.sysdiagnose}\n")
    
    if os.path.isdir(args.sysdiagnose):
        dsc_files = glob.glob(os.path.join(args.sysdiagnose, "**", "os_logarchive", "**", "DSC", "**", "*.dsc"), recursive=True)
        total_hits = sum(audit_single_dsc(f, anchors, DART_OVERFLOW) for f in dsc_files)
    else:
        total_hits = extract_and_scan_tar(args.sysdiagnose, anchors, DART_OVERFLOW)
    
    print(f"\n✅ Complete: {total_hits} hits")

if __name__ == "__main__":
    main()
