"""
OnionTrace v2.0 - ML-Based TOR Detection
Random Forest Classifier trained on real TOR traffic
"""

import struct
import json
from collections import defaultdict
from datetime import datetime
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib
import os
from scapy.all import PcapReader, IP
import hashlib


class MLPCAPAnalyzer:
    """Extract features from PCAP files for ML classification"""

    def __init__(self):
        self.flows = defaultdict(list)
        self.model = None

    # ---------------- PCAP PARSING ----------------

    def parse_pcap(self, filename):
        """Parse PCAP using Scapy for robust IP extraction."""
        try:
            self.flows.clear()
            packet_count = 0

            with PcapReader(filename) as pcap:
                for pkt in pcap:
                    if packet_count >= 1000:
                        break
                    if IP not in pkt:
                        continue

                    ip = pkt[IP]
                    src_ip = ip.src
                    dst_ip = ip.dst
                    timestamp = float(pkt.time)
                    size = len(bytes(pkt))

                    flow_key = (src_ip, dst_ip)
                    self.flows[flow_key].append(
                        {
                            "timestamp": timestamp,
                            "size": size,
                            "packet_num": packet_count,
                        }
                    )
                    packet_count += 1

            return {"status": "parsed", "flows": len(self.flows)}
        except Exception as e:
            return {"error": str(e)}

    # ---------------- FEATURE EXTRACTION ----------------

    def extract_features(self, flow_key):
        """
        Extract ML features from a single flow.
        Returns a 1D numpy array of features for RandomForest.
        """
        if flow_key not in self.flows:
            return None

        packets = self.flows[flow_key]
        if len(packets) < 5:  # need minimum packets
            return None

        # Feature 1: packet size statistics
        sizes = [p["size"] for p in packets]
        mean_size = np.mean(sizes)
        std_size = np.std(sizes)
        min_size = np.min(sizes)
        max_size = np.max(sizes)

        # Feature 2: inter-packet arrival time (IAT)
        timestamps = [p["timestamp"] for p in packets]
        iats = np.diff(timestamps)
        mean_iat = np.mean(iats) if len(iats) > 0 else 0.0
        std_iat = np.std(iats) if len(iats) > 0 else 0.0

        # Feature 3: packet count and duration
        packet_count = len(packets)
        duration = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0.0

        # Feature 4: packet size distribution (TOR ≈ many ~512-byte cells)
        size_512_count = sum(1 for s in sizes if 500 <= s <= 514)
        size_512_ratio = size_512_count / len(sizes) if len(sizes) > 0 else 0.0

        # Feature 5: burst detection (rapid sequences of packets)
        burst_count = 0
        current_burst_size = 1
        burst_threshold = 0.1  # 100ms

        for iat in iats:
            if iat < burst_threshold:
                current_burst_size += 1
            else:
                if current_burst_size >= 3:
                    burst_count += 1
                current_burst_size = 1

        # Feature 6: flow direction pattern
        src_ip, dst_ip = flow_key
        src_octets = src_ip.split(".")
        dst_octets = dst_ip.split(".")

        # private → public = 1, other = 0
        is_private_to_public = (
            1
            if src_octets[0] in ["10", "172", "192"]
            and dst_octets[0] not in ["10", "172", "192"]
            else 0
        )

        # Feature 7: coefficient of variation (regularity)
        cv_iat = (std_iat / mean_iat) if mean_iat > 0 else 0.0
        cv_size = (std_size / mean_size) if mean_size > 0 else 1.0

        features = np.array(
            [
                mean_size,  # 0
                std_size,  # 1
                min_size,  # 2
                max_size,  # 3
                mean_iat,  # 4
                std_iat,  # 5
                packet_count,  # 6
                duration,  # 7
                size_512_ratio,  # 8
                burst_count,  # 9
                is_private_to_public,  # 10
                cv_iat,  # 11
                cv_size,  # 12
            ],
            dtype=float,
        )

        return features

    def extract_all_features(self):
        """Extract features for all flows in this PCAP."""
        X = []
        flow_keys = []

        for flow_key in self.flows.keys():
            features = self.extract_features(flow_key)
            if features is not None:
                X.append(features)
                flow_keys.append(flow_key)

        if not X:
            return None, []

        return np.array(X), flow_keys

    # ---------------- TEMPORAL FINGERPRINT ----------------

    def compute_temporal_fingerprint(self, packets, num_iat_bins=10, max_bursts=5):
        """Build a temporal fingerprint from IAT histogram + burst bytes."""
        timestamps = [p["timestamp"] for p in packets]
        sizes = [p["size"] for p in packets]

        if len(timestamps) < 2:
            return "no_fingerprint"

        timestamps = sorted(timestamps)
        iats = np.diff(timestamps)
        if len(iats) == 0:
            return "no_fingerprint"

        # IAT histogram (log-spaced bins 1ms–10s)
        bins = np.logspace(-3, 1, num_iat_bins + 1)
        hist, _ = np.histogram(iats, bins=bins)
        if hist.sum() == 0:
            return "no_fingerprint"
        hist = (hist / hist.sum()).tolist()

        # Simple burst bytes pattern
        burst_bytes = []
        current_bytes = sizes[0]
        for dt, sz in zip(iats, sizes[1:]):
            if dt < 0.1:
                current_bytes += sz
            else:
                burst_bytes.append(current_bytes)
                current_bytes = sz
        burst_bytes.append(current_bytes)
        burst_bytes = burst_bytes[:max_bursts]

        fp_struct = {"iat_hist": hist, "burst_bytes": burst_bytes}
        fp_json = json.dumps(fp_struct, sort_keys=True)
        fp_hash = hashlib.sha256(fp_json.encode()).hexdigest()[:12]
        return fp_hash

    # ---------------- MODEL LOADING & PREDICTION ----------------

    def load_model(self, model_path="tor_detector_model.pkl"):
        """Load pre-trained ML model."""
        if not os.path.exists(model_path):
            print(f"[WARNING] Model not found at {model_path}")
            return False

        try:
            self.model = joblib.load(model_path)
            print(f"[OK] Loaded model from {model_path}")
            return True
        except Exception as e:
            print(f"[ERROR] Failed to load model: {e}")
            return False

    def predict_tor(self, X):
        """
        Predict TOR probability using ML model.
        Returns 1D array of probabilities (0.0–1.0).
        """
        if self.model is None:
            return None

        try:
            proba = self.model.predict_proba(X)  # [[p0, p1], ...]
            tor_probabilities = proba[:, 1]
            return tor_probabilities
        except Exception as e:
            print(f"[ERROR] Prediction failed: {e}")
            return None

    # ---------------- MAIN ANALYSIS ----------------

    def analyze_pcap_ml(self, pcap_filename, threshold=0.5):
        """Complete ML-based analysis pipeline."""
        # Step 1: parse PCAP
        parse_result = self.parse_pcap(pcap_filename)
        if "error" in parse_result:
            return {"error": parse_result["error"]}

        print(f"[*] Parsed {parse_result['flows']} flows")

        # Step 2: load ML model
        if not self.load_model():
            return {"error": "ML model not available."}

        # Step 3: extract features
        X, flow_keys = self.extract_all_features()
        if X is None:
            return {"error": "No valid flows to analyze"}

        print(f"[*] Extracted features from {len(X)} flows")

        # Step 4: predict
        tor_probabilities = self.predict_tor(X)
        if tor_probabilities is None:
            return {"error": "Prediction failed"}

        # Step 5: build findings + graph
        findings = []
        nodes = {}
        links = {}

        for flow_key, prob in zip(flow_keys, tor_probabilities):
            src_ip, dst_ip = flow_key
            packets = self.flows.get(flow_key, [])

            # ----- REAL TIME EXTRACTION -----
            timestamps = [p["timestamp"] for p in packets]

            start_time = min(timestamps)
            end_time = max(timestamps)
            duration = end_time - start_time

            from datetime import datetime, timezone

            start_time_iso = datetime.fromtimestamp(
                start_time, tz=timezone.utc
            ).isoformat()

            end_time_iso = datetime.fromtimestamp(
                end_time, tz=timezone.utc
            ).isoformat()

            if prob >= threshold and len(packets) >= 2:
                temporal_fp = self.compute_temporal_fingerprint(packets)

                timestamps = [p["timestamp"] for p in packets]
                start_time = min(timestamps)
                end_time = max(timestamps)
                duration = end_time - start_time

                from datetime import datetime, timezone
                start_time_iso = datetime.fromtimestamp(
                    start_time, tz=timezone.utc
                ).isoformat()
                end_time_iso = datetime.fromtimestamp(
                    end_time, tz=timezone.utc
                ).isoformat()

                finding = {
                    "origin_ip": src_ip,
                    "exit_ip": dst_ip,
                    "is_tor": True,
                    "confidence": float(prob * 100.0),
                    "ml_probability": float(prob),
                    "temporal_fingerprint": temporal_fp,

                    # ✅ REAL TIME DATA
                    "start_time": start_time,
                    "end_time": end_time,
                    "duration": duration,
                    "start_time_iso": start_time_iso,
                    "end_time_iso": end_time_iso,

                    "detection_method": "RandomForest ML Model",
                }

                findings.append(finding)


                # build graph nodes
                if src_ip not in nodes:
                    nodes[src_ip] = {"id": src_ip, "type": "client"}
                if dst_ip not in nodes:
                    nodes[dst_ip] = {"id": dst_ip, "type": "tor"}

                # build graph links
                key = (src_ip, dst_ip)
                if key not in links:
                    links[key] = {
                        "source": src_ip,
                        "target": dst_ip,
                        "flows": 0,
                        "sum_conf": 0.0,
                    }
                links[key]["flows"] += 1
                links[key]["sum_conf"] += finding["confidence"]

        findings.sort(key=lambda x: x["confidence"], reverse=True)

        # finalize graph
        for key, link in links.items():
            link["avg_conf"] = link["sum_conf"] / link["flows"]
            del link["sum_conf"]

        graph = {
            "nodes": list(nodes.values()),
            "links": list(links.values()),
        }

        report = {
            "metadata": {
                "report_generated": datetime.now().isoformat(),
                "pcap_source": pcap_filename,
                "tool": "OnionTrace v2.0 (ML-Based)",
                "model": "Random Forest Classifier",
                "methodology": "ML Classification on Temporal + Size Features",
                "threshold": threshold,
            },
            "summary": {
                "total_flows_analyzed": len(flow_keys),
                "tor_flows_detected": len(findings),
                "overall_confidence": (
                    sum(f["confidence"] for f in findings) / len(findings)
                    if findings
                    else 0.0
                ),
            },
            "findings": findings,
            "graph": graph,
        }

        return report


# ============================================================================
# TRAINING SCRIPT (flow‑capped)
# ============================================================================


def train_model_from_dataset(
    tor_pcap_dir,
    non_tor_pcap_dir,
    output_path="tor_detector_model.pkl",
    max_flows_per_class=30000,
):
    """
    Train RandomForest model on labeled TOR vs non-TOR PCAPs,
    but cap the number of flows per class so training is fast and safe.
    """
    print("[*] Training TOR Detection ML Model with flow cap")
    print("[*] Max flows per class:", max_flows_per_class)

    from glob import glob

    X_train = []
    y_train = []

    def load_flows_from_dir(pcap_dir, label, max_flows):
        flows_collected = 0
        feature_list = []
        labels_list = []

        pcap_files = glob(os.path.join(pcap_dir, "*.pcap"))
        print(f"[*] Scanning {len(pcap_files)} PCAPs in {pcap_dir} (label={label})")

        for pcap_file in pcap_files:
            if flows_collected >= max_flows:
                break

            print(f"  -> {pcap_file}")
            analyzer = MLPCAPAnalyzer()
            parse_result = analyzer.parse_pcap(pcap_file)
            if "error" in parse_result:
                print(f"     [!] Skipping (parse error): {parse_result['error']}")
                continue

            X, _ = analyzer.extract_all_features()
            if X is None or len(X) == 0:
                print("     [!] No valid flows, skipping.")
                continue

            remaining = max_flows - flows_collected
            if len(X) > remaining:
                X = X[:remaining]

            feature_list.extend(X)
            labels_list.extend([label] * len(X))
            flows_collected += len(X)

            print(f"     [+] {len(X)} flows (total: {flows_collected}/{max_flows})")

        print(f"[*] Finished {pcap_dir}: {flows_collected} flows collected (label={label})")
        return feature_list, labels_list

    tor_features, tor_labels = load_flows_from_dir(
        tor_pcap_dir, label=1, max_flows=max_flows_per_class
    )
    non_tor_features, non_tor_labels = load_flows_from_dir(
        non_tor_pcap_dir, label=0, max_flows=max_flows_per_class
    )

    X_train.extend(tor_features)
    X_train.extend(non_tor_features)
    y_train.extend(tor_labels)
    y_train.extend(non_tor_labels)

    if not X_train:
        print("[ERROR] No training data loaded!")
        return False

    X_train = np.array(X_train)
    y_train = np.array(y_train)

    print("\n[*] Final training set:")
    print(f"    Total flows: {len(X_train)}")
    print(f"    TOR flows:   {sum(y_train)}")
    print(f"    Non-TOR:     {len(y_train) - sum(y_train)}")

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
    )

    print("\n[*] Training RandomForest...")
    model.fit(X_train, y_train)
    print("[OK] Training complete.")

    joblib.dump(model, output_path)
    print(f"[OK] Model saved to {output_path}")

    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

    y_pred = model.predict(X_train)

    print("\n[*] Training Metrics (on training data):")
    print(f"    Accuracy:  {accuracy_score(y_train, y_pred):.2%}")
    print(f"    Precision: {precision_score(y_train, y_pred):.2%}")
    print(f"    Recall:    {recall_score(y_train, y_pred):.2%}")
    print(f"    F1-Score:  {f1_score(y_train, y_pred):.2%}")

    feature_names = [
        "mean_size",
        "std_size",
        "min_size",
        "max_size",
        "mean_iat",
        "std_iat",
        "packet_count",
        "duration",
        "size_512_ratio",
        "burst_count",
        "is_private_to_public",
        "cv_iat",
        "cv_size",
    ]
    importances = model.feature_importances_
    print("\n[*] Top 5 Important Features:")
    for name, importance in sorted(
        zip(feature_names, importances), key=lambda x: x[1], reverse=True
    )[:5]:
        print(f"    {name}: {importance:.2%}")

    return True


# ============================================================================
# CLI
# ============================================================================

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python ml_detector.py analyze <pcap_file>")
        print(
            "  python ml_detector.py train <tor_dir> <non_tor_dir> [max_flows_per_class]"
        )
        sys.exit(1)

    if sys.argv[1] == "analyze":
        if len(sys.argv) < 3:
            print("Usage: python ml_detector.py analyze <pcap_file>")
            sys.exit(1)

        analyzer = MLPCAPAnalyzer()
        result = analyzer.analyze_pcap_ml(sys.argv[2])
        print(json.dumps(result, indent=2))

    elif sys.argv[1] == "train":
        if len(sys.argv) < 4:
            print(
                "Usage: python ml_detector.py train <tor_dir> <non_tor_dir> [max_flows_per_class]"
            )
            sys.exit(1)

        tor_dir = sys.argv[2]
        non_tor_dir = sys.argv[3]
        max_flows = int(sys.argv[4]) if len(sys.argv) >= 5 else 30000

        train_model_from_dataset(
            tor_dir, non_tor_dir, max_flows_per_class=max_flows
        )
