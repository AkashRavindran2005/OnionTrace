import struct
import random
from datetime import datetime

def create_guaranteed_tor_pcap(filename='demo.pcap'):
    pcap_magic = b'\xa1\xb2\xc3\xd4'  
    pcap_header = struct.pack('<IIIII', 2, 4, 0, 65535, 1)
    
    packets_data = []
    base_timestamp = 1700000000
    
    
    flows = [
        ('192.168.1.100', '185.220.100.45'),    
        ('10.0.0.50', '45.142.182.100'),        
        ('172.16.0.10', '203.0.113.50'),        
    ]
    
    for flow_num, (src_ip, dst_ip) in enumerate(flows):
        print(f"  Flow {flow_num+1}: {src_ip} → {dst_ip}")
        
        for burst_num in range(3):
            burst_time = base_timestamp + flow_num * 1000 + burst_num * 100
            
            for pkt_num in range(20):
                ts_sec = burst_time
                ts_usec = pkt_num * 50000  
                if pkt_num % 5 == 0:
                    size = 1024
                else:
                    size = 512 + random.randint(-2, 2)
                
                eth_header = b'\x00' * 14
                
                src_bytes = bytes([int(x) for x in src_ip.split('.')])
                dst_bytes = bytes([int(x) for x in dst_ip.split('.')])
                ip_header = (
                    b'\x45\x00' +  
                    struct.pack('>H', size) +  
                    b'\x00\x00' +
                    b'\x40\x00' +
                    b'\x40' +  
                    b'\x06' +  
                    b'\x00\x00' + 
                    src_bytes + dst_bytes
                )
                
                tcp_header = b'\x00' * 20
                
                payload_size = size - len(eth_header) - len(ip_header) - len(tcp_header)
                payload = b'\x00' * max(0, payload_size)
                
                full_packet = eth_header + ip_header + tcp_header + payload
                
                pkt_header = struct.pack(
                    '<IIII',
                    ts_sec, ts_usec,
                    len(full_packet),  
                    len(full_packet)   
                )
                
                packets_data.append(pkt_header + full_packet)
    
    with open(filename, 'wb') as f:
        f.write(pcap_magic + pcap_header)
        for pkt in packets_data:
            f.write(pkt)
    
    print(f"\n✓ Created {filename}")
    print(f"  - {len(packets_data)} packets")
    print(f"  - File size: {len(pcap_magic + pcap_header + b''.join(packets_data)) / 1024:.1f} KB")
    print(f"\nThis PCAP contains:")
    print(f"  ✓ Private IPs (192.168.1.100, 10.0.0.50, 172.16.0.10)")
    print(f"  ✓ Known TOR exit IPs (185.220.100.45, 45.142.182.100)")
    print(f"  ✓ 512-byte packets (TOR cell size)")
    print(f"  ✓ Regular burst patterns")
    print(f"\n→ This WILL be detected by OnionTrace!")

if __name__ == '__main__':
    create_guaranteed_tor_pcap('demo.pcap')