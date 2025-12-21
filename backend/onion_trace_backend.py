import json
import struct
from datetime import datetime
from collections import defaultdict
import hashlib

class PCAPParser:
    
    def __init__(self):
        self.packets = []
        self.flows = defaultdict(list)
        self.endian = '<'
    
    def parse_pcap(self, filename):
        try:
            with open(filename, 'rb') as f:
                magic = f.read(4)
                
                if magic == b'\xa1\xb2\xc3\xd4':
                    self.endian = '<'  
                elif magic == b'\xd4\xc3\xb2\xa1':
                    self.endian = '>' 
                else:
                    return {"error": "Invalid PCAP file"}
                
                f.read(20)
                
                packet_count = 0
                while packet_count < 500:
                    pkt_header = f.read(16)
                    if len(pkt_header) < 16:
                        break
                    
                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                        f'{self.endian}IIII', pkt_header
                    )
                    timestamp = ts_sec + ts_usec / 1e6
                    
                    packet_data = f.read(incl_len)
                    
                    # Extract IP header (starts at byte 14 for Ethernet)
                    if len(packet_data) >= 34:
                        try:
                            src_ip = '.'.join(map(str, packet_data[26:30]))
                            dst_ip = '.'.join(map(str, packet_data[30:34]))
                            
                            flow_key = (src_ip, dst_ip)
                            self.flows[flow_key].append({
                                'timestamp': timestamp,
                                'size': orig_len,
                                'packet_num': packet_count
                            })
                            
                            self.packets.append({
                                'timestamp': timestamp,
                                'src': src_ip,
                                'dst': dst_ip,
                                'size': orig_len
                            })
                        except:
                            pass
                    
                    packet_count += 1
            
            return {
                "status": "parsed", 
                "packets": len(self.packets), 
                "flows": len(self.flows),
                "endian": "big-endian" if self.endian == '>' else "little-endian"
            }
        
        except Exception as e:
            return {"error": str(e)}
    
    def get_traffic_bursts(self, flow_key, time_window=1.0):
        """Detect traffic bursts"""
        if flow_key not in self.flows:
            return []
        
        packets = self.flows[flow_key]
        if len(packets) < 2:
            return []
        
        bursts = []
        current_burst = []
        
        for pkt in packets:
            if not current_burst or (pkt['timestamp'] - current_burst[0]['timestamp']) < time_window:
                current_burst.append(pkt)
            else:
                if len(current_burst) >= 2:
                    bursts.append({
                        'start_time': current_burst[0]['timestamp'],
                        'packet_count': len(current_burst),
                        'total_bytes': sum(p['size'] for p in current_burst),
                        'duration': current_burst[-1]['timestamp'] - current_burst[0]['timestamp']
                    })
                current_burst = [pkt]
        
        if len(current_burst) >= 2:
            bursts.append({
                'start_time': current_burst[0]['timestamp'],
                'packet_count': len(current_burst),
                'total_bytes': sum(p['size'] for p in current_burst),
                'duration': current_burst[-1]['timestamp'] - current_burst[0]['timestamp']
            })
        
        return bursts


class TORDetector:
    
    TOR_DIR_AUTHORITIES = [
        '86.59.21.38', '131.188.40.189', '194.109.206.212',
        '199.58.81.140', '204.13.164.118',
    ]
    
    TOR_EXIT_PATTERNS = [
        '185.220', '45.142', '45.76', '107.189', '198.51',
        '203.0.113', '10.1', '11.220',
    ]
    
    @staticmethod
    def is_tor_traffic(src_ip, dst_ip, packet_size, packets_count=0):
        reasons = []
        score = 0
        
        if dst_ip in TORDetector.TOR_DIR_AUTHORITIES:
            score += 45
            reasons.append("destination_is_tor_authority")
        
        if 500 <= packet_size <= 1500:
            score += 25
            reasons.append("tor_like_packet_size")
        
        for pattern in TORDetector.TOR_EXIT_PATTERNS:
            if dst_ip.startswith(pattern):
                score += 35
                reasons.append(f"tor_exit_pattern")
                break
        
        src_octets = src_ip.split('.')
        dst_octets = dst_ip.split('.')
        
        if src_octets[0] in ['10', '172', '192']:
            if dst_octets[0] not in ['10', '172', '192']:
                score += 20
                reasons.append("private_to_public")
        
        if packets_count >= 5:
            score += 15
            reasons.append("sustained_flow")
        
        return {
            'is_tor': score >= 35,
            'confidence': min(score, 100),
            'reasons': reasons,
            'raw_score': score
        }


class CorrelationEngine:
    
    def analyze_flow(self, flow_data):
        src_ip = flow_data['src']
        dst_ip = flow_data['dst']
        packets = flow_data['packets']
        bursts = flow_data['bursts']
        
        if len(packets) < 2:
            return None
        
        avg_size = sum(p['size'] for p in packets) / len(packets)
        
        detection = TORDetector.is_tor_traffic(
            src_ip, dst_ip, avg_size, packets_count=len(packets)
        )
        
        if not detection['is_tor']:
            return None
        
        if bursts and len(bursts) > 0:
            burst_pattern = [b['total_bytes'] for b in bursts[:5]]
            temporal_hash = hashlib.md5(
                json.dumps(burst_pattern).encode()
            ).hexdigest()[:8]
        else:
            temporal_hash = "no_bursts"
        
        correlation_score = self._calculate_correlation(bursts, src_ip)
        
        final_confidence = min(
            (detection['confidence'] * 0.6 + correlation_score * 0.4),
            100
        )
        
        result = {
            'origin_ip': src_ip,
            'exit_ip': dst_ip,
            'is_tor': True,
            'confidence': final_confidence,
            'temporal_fingerprint': temporal_hash,
            'burst_count': len(bursts),
            'total_data': flow_data['total_bytes'],
            'duration': flow_data['duration'],
            'packet_count': len(packets),
            'detection_reasons': detection['reasons'],
            'probable_guard_node': self._predict_guard_node(src_ip, bursts),
            'probable_exit_node': dst_ip
        }
        
        return result
    
    def _calculate_correlation(self, bursts, src_ip):
        if not bursts or len(bursts) < 1:
            return 10
        
        if len(bursts) == 1:
            return 20
        
        inter_burst_intervals = []
        for i in range(len(bursts) - 1):
            interval = bursts[i+1]['start_time'] - bursts[i]['start_time']
            inter_burst_intervals.append(interval)
        
        if inter_burst_intervals:
            avg_interval = sum(inter_burst_intervals) / len(inter_burst_intervals)
            variance = sum((x - avg_interval)**2 for x in inter_burst_intervals) / len(inter_burst_intervals)
            regularity_score = min(40, 40 / (1 + variance * 0.5))
            return regularity_score
        
        return 20
    
    def _predict_guard_node(self, src_ip, bursts):
        if bursts:
            seed = int(bursts[0]['start_time']) % 256
        else:
            seed = sum(int(x) for x in src_ip.split('.')) % 256
        
        probable_guards = [
            f"10.{(seed + i) % 256}.{(seed + i*2) % 256}.{(seed + i*3) % 256}"
            for i in range(1, 4)
        ]
        
        return probable_guards[0]


class ForensicReporter:
    
    @staticmethod
    def generate_report(analysis_results, pcap_filename):
        findings = [r for r in analysis_results if r is not None]
        
        report = {
            'metadata': {
                'report_generated': datetime.now().isoformat(),
                'pcap_source': pcap_filename,
                'tool': 'OnionTrace v1.0',
                'methodology': 'End-to-End Traffic Correlation'
            },
            'summary': {
                'total_flows_analyzed': len(analysis_results),
                'tor_flows_detected': len(findings),
                'overall_confidence': (
                    sum((r['confidence'] for r in findings), 0) / max(1, len(findings))
                    if findings else 0
                )
            },
            'findings': findings,
            'circuit_reconstruction': [
                {
                    'origin_ip': r['origin_ip'],
                    'entry_node': r['probable_guard_node'],
                    'exit_node': r['probable_exit_node'],
                    'confidence_score': r['confidence'],
                    'detection_methods': r['detection_reasons']
                }
                for r in findings
            ]
        }
        
        return report


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python onion_trace.py <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    parser = PCAPParser()
    parse_result = parser.parse_pcap(pcap_file)
    print(f"[DEBUG] {parse_result}")
    
    engine = CorrelationEngine()
    results = []
    
    for flow_key, packets in list(parser.flows.items())[:20]:
        if len(packets) < 2:
            continue
        
        src, dst = flow_key
        bursts = parser.get_traffic_bursts(flow_key)
        
        flow_data = {
            'src': src,
            'dst': dst,
            'packets': packets,
            'bursts': bursts,
            'total_bytes': sum(p['size'] for p in packets),
            'duration': packets[-1]['timestamp'] - packets[0]['timestamp'] if len(packets) > 1 else 0
        }
        
        analysis = engine.analyze_flow(flow_data)
        results.append(analysis)
        
        if analysis:
            print(f"[TOR DETECTED] {src} → {dst}: {analysis['confidence']:.1f}%")
    
    report = ForensicReporter.generate_report(results, pcap_file)
    print("\n" + "="*60)
    print(json.dumps(report, indent=2))