import struct, os, glob, tarfile, json, tempfile
from pathlib import Path

def load_c2_config(config_path='c2_actors.json'):
    default = {"116.68.105.103": "Rogers", "109.105.110.73": "Rostelecom", "109.97.120.73": "DO-Terminus"}
    try:
        with open(config_path) as f:
            return json.load(f)
    except:
        return default

def audit_single_dsc(file_path, anchors):
    DART_OVERFLOW = 1685283688
    print(f"\n--- {os.path.basename(file_path)} ---")
    
    try:
        with open(file_path, 'rb') as f:
            # Full file scan (no offsets)
            data = f.read()
            
            # DART check
            if struct.pack('<I', DART_OVERFLOW) in data:
                print("[✓] DART Overflow")
            
            # C2 scan
            print("[C2 SCAN]")
            for ip, role in anchors.items():
                ip_bytes = bytes(map(int, ip.split('.')))
                if ip_bytes in data:
                    print(f"  [✓] {ip} ({role})")
                    
    except Exception as e:
        print(f"[ERROR] {e}")

def universal_audit(input_path):
    anchors = load_c2_config()
    
    # Handle tar.gz OR directory
    if input_path.endswith('.tar.gz'):
        with tempfile.TemporaryDirectory() as temp_dir:
            with tarfile.open(input_path, 'r:gz') as tar:
                tar.extractall(temp_dir)
            scan_path = temp_dir
    else:
        scan_path = input_path
    
    # Find & audit all DSC files
    dsc_files = glob.glob(os.path.join(scan_path, "**", "os_logarchive", "**", "DSC", "*.dsc"), recursive=True)
    print(f"Scanning {len(dsc_files)} DSC files...")
    
    total_hits = 0
    for dsc in dsc_files:
        hits = audit_single_dsc(dsc, anchors)
        total_hits += hits
    
    print(f"\nSUMMARY: {total_hits} hits across {len(dsc_files)} files")

# Usage
universal_audit("sysdiagnose_2026.02.23_20-30-00.tar.gz")
