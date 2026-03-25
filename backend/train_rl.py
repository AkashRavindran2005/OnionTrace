"""
train_rl.py — OnionTrace RL Training Script
============================================
Reads PCAPs from the Tor/ directory, automatically classifies them as
Tor or non-Tor based on their filename, then trains the DQN reinforcement
learning agent and saves the model to rl_tor_agent.pt.

Tor indicators (filename contains):
    _tor_   |  tor<something>.pcap  |  Torrent

Non-Tor indicators (filename contains):
    _gate_  |  gateway  |  Gateway  |  SSL_Browsing

Usage:
    python train_rl.py [--episodes N] [--max-flows N] [--pcap-dir DIR]
"""

import os
import sys
import glob
import argparse
import json
import shutil
import tempfile
from datetime import datetime

# ── Argument parsing ─────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(description="Train OnionTrace RL Agent on PCAP dataset")
    parser.add_argument("--episodes",  type=int, default=1000,
                        help="Number of training episodes (default: 1000)")
    parser.add_argument("--max-flows", type=int, default=5000,
                        help="Max flows per class to load (default: 5000)")
    parser.add_argument("--pcap-dir",  type=str,
                        default=os.path.join(os.path.dirname(__file__), "Tor"),
                        help="Directory containing PCAP files (default: ./Tor)")
    parser.add_argument("--model-out", type=str, default="rl_tor_agent.pt",
                        help="Output model path (default: rl_tor_agent.pt)")
    return parser.parse_args()


# ── Filename-based labelling ──────────────────────────────────────────────────

TOR_KEYWORDS     = ["_tor_", "torFacebook", "torGoogle", "torTwitter",
                    "torVimeo", "torYoutube", "tor_p2p", "tor_spotify",
                    "Torrent"]
NON_TOR_KEYWORDS = ["_gate_", "gateway", "Gateway", "SSL_Browsing",
                    "spotifygateway", "aimchatgateway", "hangoutschatgateway",
                    "icqchatgateway", "skypechatgateway", "facebookchatgateway"]


def classify_pcap(filepath):
    """
    Return 'tor' | 'non_tor' | 'unknown' based on the filename heuristic.
    """
    fname = os.path.basename(filepath)

    for kw in TOR_KEYWORDS:
        if kw in fname:
            return "tor"

    for kw in NON_TOR_KEYWORDS:
        if kw in fname:
            return "non_tor"

    return "unknown"


def split_pcaps(pcap_dir):
    """
    Scan *pcap_dir* for *.pcap / *.pcapng files and split them into
    tor / non_tor / unknown lists.
    """
    all_files = (
        glob.glob(os.path.join(pcap_dir, "*.pcap")) +
        glob.glob(os.path.join(pcap_dir, "*.pcapng"))
    )

    tor_files     = []
    non_tor_files = []
    unknown_files = []

    for fp in sorted(all_files):
        label = classify_pcap(fp)
        if label == "tor":
            tor_files.append(fp)
        elif label == "non_tor":
            non_tor_files.append(fp)
        else:
            unknown_files.append(fp)

    return tor_files, non_tor_files, unknown_files


# ── Symlink / copy helper ─────────────────────────────────────────────────────

def make_temp_dir_with_links(files, tmpdir_name):
    """
    Create a temporary subdirectory and hard-link (or copy on failure)
    the given files into it. Returns the temp dir path.
    """
    tmp = os.path.join(tempfile.gettempdir(), tmpdir_name)
    os.makedirs(tmp, exist_ok=True)
    # Clear previous run
    for f in glob.glob(os.path.join(tmp, "*.pcap")):
        os.remove(f)
    for f in glob.glob(os.path.join(tmp, "*.pcapng")):
        os.remove(f)

    for src in files:
        dst = os.path.join(tmp, os.path.basename(src))
        try:
            os.link(src, dst)
        except (OSError, AttributeError):
            shutil.copy2(src, dst)

    return tmp


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()

    print("=" * 65)
    print("  OnionTrace — RL Training Pipeline")
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 65)

    # ── 1. Discover & classify PCAPs ──────────────────────────────────────
    pcap_dir = os.path.abspath(args.pcap_dir)
    print(f"\n[1] Scanning PCAP directory: {pcap_dir}")

    tor_files, non_tor_files, unknown_files = split_pcaps(pcap_dir)

    print(f"    Tor     : {len(tor_files)} files")
    for f in tor_files:
        print(f"      + {os.path.basename(f)}")

    print(f"    Non-Tor : {len(non_tor_files)} files")
    for f in non_tor_files:
        print(f"      - {os.path.basename(f)}")

    if unknown_files:
        print(f"    Unknown : {len(unknown_files)} files (will be skipped)")
        for f in unknown_files:
            print(f"      ? {os.path.basename(f)}")

    if not tor_files:
        print("\n[ERROR] No Tor PCAP files found! Check --pcap-dir.")
        sys.exit(1)

    if not non_tor_files:
        print("\n[ERROR] No non-Tor PCAP files found! Check --pcap-dir.")
        sys.exit(1)

    # ── 2. Stage files into temp directories that RLAnalyzer can read ─────
    print("\n[2] Staging files into temp directories...")
    tor_tmp     = make_temp_dir_with_links(tor_files,     "oniontrace_tor_train")
    non_tor_tmp = make_temp_dir_with_links(non_tor_files, "oniontrace_non_tor_train")
    print(f"    Tor     dir : {tor_tmp}")
    print(f"    Non-Tor dir : {non_tor_tmp}")

    # ── 3. Train ──────────────────────────────────────────────────────────
    print(f"\n[3] Starting RL training...")
    print(f"    Episodes   : {args.episodes}")
    print(f"    Max flows  : {args.max_flows} per class")
    print(f"    Model out  : {args.model_out}")
    print()

    from rl_agent import RLAnalyzer

    model_path = os.path.join(os.path.dirname(__file__), args.model_out)
    rl = RLAnalyzer(model_path=model_path)

    metrics = rl.train(
        tor_pcap_dir    = tor_tmp,
        non_tor_pcap_dir= non_tor_tmp,
        num_episodes    = args.episodes,
        max_flows_per_class = args.max_flows,
    )

    # ── 4. Summary ────────────────────────────────────────────────────────
    print("\n" + "=" * 65)
    print("  Training Complete — Summary")
    print("=" * 65)

    if "error" in metrics:
        print(f"  [ERROR] {metrics['error']}")
        sys.exit(1)

    print(f"  Episodes trained : {metrics.get('episodes_trained')}")
    print(f"  Final accuracy   : {metrics.get('final_accuracy', 0):.1f}%")
    print(f"  Final epsilon    : {metrics.get('final_epsilon', 0):.4f}")
    print(f"  Avg reward (last 50): {metrics.get('avg_reward_last_50', 0):.4f}")
    print(f"  Total flows used : {metrics.get('total_flows', 0)}"
          f"  ({metrics.get('tor_flows', 0)} Tor / {metrics.get('non_tor_flows', 0)} non-Tor)")
    print(f"  Model saved to   : {metrics.get('model_path')}")
    print(f"  Trained at       : {metrics.get('trained_at')}")

    # Save metrics JSON next to the model
    metrics_path = model_path.replace(".pt", "_metrics.json")
    with open(metrics_path, "w") as fh:
        json.dump(metrics, fh, indent=2)
    print(f"  Metrics JSON     : {metrics_path}")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    main()
