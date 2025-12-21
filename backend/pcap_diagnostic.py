import struct
import sys

def diagnose_pcap(filename):
    try:
        with open(filename, 'rb') as f:
            magic = f.read(4)
            print(f"[1] Magic bytes: {magic.hex()}")
            
            if magic == b'\xa1\xb2\xc3\xd4':
                print("    ✓ Valid PCAP (little-endian)")
                endian = '<'
            elif magic == b'\xd4\xc3\xb2\xa1':
                print("    ✓ Valid PCAP (big-endian)")
                endian = '>'
            else:
                print("    ✗ INVALID PCAP FORMAT")
                return
            
            g_hdr = f.read(20)
            if len(g_hdr) < 20:
                print("    ✗ Truncated header")
                return
            
            major, minor, tz_offset, ts_acc, snaplen, link_type = struct.unpack(f'{endian}HHIIII', g_hdr)
            print(f"[2] Version: {major}.{minor}")
            print(f"[3] Snaplen: {snaplen} bytes")
            print(f"[4] Link type: {link_type} (1=Ethernet)")
            
            packet_count = 0
            ips_seen = set()
            packet_sizes = []
            flows = {}
            
            while True:
                pkt_hdr = f.read(16)
                if len(pkt_hdr) < 16:
                    break
                
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f'{endian}IIII', pkt_hdr)
                pkt_data = f.read(incl_len)
                
                if len(pkt_data) < 34:
                    packet_count += 1
                    continue
                
                try:
                    src_ip = '.'.join(map(str, pkt_data[26:30]))
                    dst_ip = '.'.join(map(str, pkt_data[30:34]))
                    
                    ips_seen.add(src_ip)
                    ips_seen.add(dst_ip)
                    packet_sizes.append(orig_len)
                    
                    flow_key = f"{src_ip} → {dst_ip}"
                    if flow_key not in flows:
                        flows[flow_key] = 0
                    flows[flow_key] += 1
                    
                except:
                    pass
                
                packet_count += 1
                
                if packet_count >= 200:  
                    break
            
            print(f"\n[5] Packets analyzed: {packet_count}")
            print(f"[6] Unique IPs: {len(ips_seen)}")
            if ips_seen:
                print(f"    IPs found: {sorted(list(ips_seen))[:15]}")
            
            print(f"\n[7] Top flows:")
            for flow, count in sorted(flows.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"    {flow}: {count} packets")
            
            if packet_sizes:
                print(f"\n[8] Packet sizes:")
                print(f"    Min: {min(packet_sizes)} bytes")
                print(f"    Max: {max(packet_sizes)} bytes")
                print(f"    Avg: {sum(packet_sizes)/len(packet_sizes):.0f} bytes")
                mode_size = max(set(packet_sizes), key=packet_sizes.count)
                print(f"    Mode (most common): {mode_size} bytes")
            
            print(f"\n[9] TOR Pattern Analysis:")
            if packet_sizes:
                tor_size_packets = sum(1 for s in packet_sizes if 500 <= s <= 1500)
                print(f"    Packets 500-1500 bytes (TOR-like): {tor_size_packets}/{len(packet_sizes)} ({tor_size_packets*100//len(packet_sizes)}%)")
            
            tor_exits = ['185.220', '45.142', '45.76', '107.189', '198.51', '203.0.113']
            tor_ips = [ip for ip in ips_seen for pattern in tor_exits if ip.startswith(pattern)]
            print(f"    Known TOR exit IPs: {tor_ips if tor_ips else 'NONE'}")
            
            private_ips = [ip for ip in ips_seen if ip.startswith(('10.', '172.', '192.168'))]
            print(f"    Private IPs (10.*, 172.*, 192.168.*): {private_ips}")
            
            print(f"\n[10] DIAGNOSIS:")
            issues = 0
            
            if not private_ips:
                print("    ⚠ No private IPs found - PCAP might be from network backbone")
                issues += 1
            
            if not tor_ips:
                print("    ⚠ No known TOR exits - traffic doesn't go TO TOR exit nodes")
                issues += 1
            
            if packet_sizes and sum(1 for s in packet_sizes if 500 <= s <= 1500) == 0:
                print("    ⚠ No 500-1500 byte packets - doesn't look like TOR cells")
                issues += 1
            
            if issues == 0:
                print("    ✓✓✓ This PCAP SHOULD be detected as TOR!")
            elif issues == 1:
                print("    ~ Partial TOR characteristics, might be detected with tweaked thresholds")
            else:
                print("    ✗ This PCAP doesn't contain TOR-like traffic patterns")
                print(f"\n    SOLUTION: Use a real TOR PCAP or generate one with:")
                print(f"    $ python generate-tor-pcap.py")
                print(f"    $ python api_backend.py")
                print(f"    Then upload 'demo.pcap' to the web interface")
                
    except FileNotFoundError:
        print(f"✗ File not found: {filename}")
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    filename = sys.argv[1] if len(sys.argv) > 1 else 'sample.pcap'
    diagnose_pcap(filename)