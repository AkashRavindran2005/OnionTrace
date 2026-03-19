"""
OnionTrace RL Agent — Deep Q-Network for Tor Traffic Classification

Models traffic analysis as a sequential decision problem:
  - The agent observes a sliding window of flow features
  - At each step it chooses: OBSERVE_MORE, CLASSIFY_TOR, CLASSIFY_NOT_TOR
  - Rewards encourage correct and early classification

Inspired by MDP-based Tor detection and DeepCorr research.
"""

import os
import json
import random
import math
from collections import deque, defaultdict
from datetime import datetime

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ACTIONS = {0: "OBSERVE_MORE", 1: "CLASSIFY_TOR", 2: "CLASSIFY_NOT_TOR"}
NUM_ACTIONS = len(ACTIONS)

# Feature indices (same 13 features as ml_detector.py)
FEATURE_NAMES = [
    "mean_size", "std_size", "min_size", "max_size",
    "mean_iat", "std_iat", "packet_count", "duration",
    "size_512_ratio", "burst_count", "is_private_to_public",
    "cv_iat", "cv_size",
]
NUM_FEATURES = len(FEATURE_NAMES)

DEFAULT_WINDOW_SIZE = 8       # number of time-steps the agent looks back
DEFAULT_MODEL_PATH = "rl_tor_agent.pt"


# ---------------------------------------------------------------------------
# Gym-style Environment
# ---------------------------------------------------------------------------

class TorFlowEnvironment:
    """
    Gym-compatible environment for sequential Tor flow classification.

    Each episode = one network flow (a list of packets).
    The agent receives progressively more data and decides when to classify.
    """

    def __init__(self, flows_data, labels, window_size=DEFAULT_WINDOW_SIZE):
        """
        Args:
            flows_data: list of dicts, each with 'packets' list
            labels: list of int (1=Tor, 0=non-Tor), parallel to flows_data
            window_size: how many incremental feature snapshots the agent sees
        """
        self.flows_data = flows_data
        self.labels = labels
        self.window_size = window_size

        self.current_flow_idx = 0
        self.current_step = 0
        self.state_buffer = None
        self.done = False
        self.true_label = None

    @property
    def observation_shape(self):
        return (self.window_size, NUM_FEATURES)

    def reset(self, flow_idx=None):
        """Reset to a new flow episode. Returns initial observation."""
        if flow_idx is not None:
            self.current_flow_idx = flow_idx
        else:
            self.current_flow_idx = random.randint(0, len(self.flows_data) - 1)

        self.current_step = 0
        self.done = False
        self.true_label = self.labels[self.current_flow_idx]

        # Pre-compute incremental feature snapshots for this flow
        self._precompute_snapshots()

        # Initialize state buffer with zeros
        self.state_buffer = np.zeros((self.window_size, NUM_FEATURES), dtype=np.float32)

        # Fill in the first snapshot
        if len(self._snapshots) > 0:
            self.state_buffer[-1] = self._snapshots[0]

        return self._get_observation()

    def step(self, action):
        """
        Execute action.
        Returns: (observation, reward, done, info)
        """
        if self.done:
            return self._get_observation(), 0.0, True, {}

        info = {"action_name": ACTIONS[action], "step": self.current_step}

        if action == 0:  # OBSERVE_MORE
            self.current_step += 1

            if self.current_step >= len(self._snapshots):
                # Ran out of data — force a penalty
                self.done = True
                reward = -0.5
                info["forced_end"] = True
            else:
                # Shift window and add new snapshot
                self.state_buffer = np.roll(self.state_buffer, -1, axis=0)
                self.state_buffer[-1] = self._snapshots[self.current_step]
                reward = -0.05  # small cost for waiting

        elif action in (1, 2):  # CLASSIFY_TOR or CLASSIFY_NOT_TOR
            predicted_label = 1 if action == 1 else 0
            correct = (predicted_label == self.true_label)

            if correct:
                reward = 1.0
                # Bonus for early classification
                progress = self.current_step / max(1, len(self._snapshots) - 1)
                early_bonus = 0.5 * (1.0 - progress)
                reward += early_bonus
            else:
                reward = -1.0

            self.done = True
            info["correct"] = correct
            info["predicted"] = predicted_label
            info["true_label"] = self.true_label

        return self._get_observation(), reward, self.done, info

    def _get_observation(self):
        return self.state_buffer.copy()

    def _precompute_snapshots(self):
        """
        Compute incremental feature snapshots from packets.
        Each snapshot i uses the first (i+1)*chunk_size packets.
        """
        flow = self.flows_data[self.current_flow_idx]
        packets = flow.get("packets", [])

        if len(packets) < 5:
            self._snapshots = [np.zeros(NUM_FEATURES, dtype=np.float32)]
            return

        # Divide packets into chunks — aim for ~20 snapshots
        num_snapshots = min(20, len(packets))
        chunk_size = max(1, len(packets) // num_snapshots)

        snapshots = []
        for end_idx in range(chunk_size, len(packets) + 1, chunk_size):
            subset = packets[:end_idx]
            features = self._extract_features_from_packets(subset, flow.get("src", "0.0.0.0"), flow.get("dst", "0.0.0.0"))
            snapshots.append(self._normalize_features(features))

        if not snapshots:
            snapshots = [np.zeros(NUM_FEATURES, dtype=np.float32)]

        self._snapshots = snapshots

    @staticmethod
    def _normalize_features(features):
        """
        Normalize features to roughly [-1, 1] range using domain-aware scaling.
        This is critical: raw packet sizes (~500) and IATs (~0.05) differ by 4 orders.
        """
        # Scale factors for each of the 13 features
        scale = np.array([
            1500.0,   # mean_size — max typical packet
            500.0,    # std_size
            1500.0,   # min_size
            1500.0,   # max_size
            1.0,      # mean_iat — seconds
            1.0,      # std_iat
            100.0,    # packet_count
            10.0,     # duration — seconds
            1.0,      # size_512_ratio — already 0–1
            10.0,     # burst_count
            1.0,      # is_private_to_public — already 0–1
            2.0,      # cv_iat
            2.0,      # cv_size
        ], dtype=np.float32)
        return np.clip(features / scale, -1.0, 1.0)

    @staticmethod
    def _extract_features_from_packets(packets, src_ip, dst_ip):
        """Extract the same 13 features used by the RF model."""
        sizes = [p["size"] for p in packets]
        timestamps = [p["timestamp"] for p in packets]

        mean_size = np.mean(sizes)
        std_size = np.std(sizes)
        min_size = np.min(sizes)
        max_size = np.max(sizes)

        iats = np.diff(timestamps) if len(timestamps) > 1 else np.array([0.0])
        mean_iat = np.mean(iats) if len(iats) > 0 else 0.0
        std_iat = np.std(iats) if len(iats) > 0 else 0.0

        packet_count = len(packets)
        duration = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0.0

        size_512_count = sum(1 for s in sizes if 500 <= s <= 514)
        size_512_ratio = size_512_count / len(sizes) if sizes else 0.0

        burst_count = 0
        current_burst = 1
        for iat in iats:
            if iat < 0.1:
                current_burst += 1
            else:
                if current_burst >= 3:
                    burst_count += 1
                current_burst = 1

        src_octets = src_ip.split(".")
        dst_octets = dst_ip.split(".")
        is_private_to_public = (
            1 if src_octets[0] in ["10", "172", "192"]
            and dst_octets[0] not in ["10", "172", "192"]
            else 0
        )

        cv_iat = (std_iat / mean_iat) if mean_iat > 0 else 0.0
        cv_size = (std_size / mean_size) if mean_size > 0 else 1.0

        return np.array([
            mean_size, std_size, min_size, max_size,
            mean_iat, std_iat, packet_count, duration,
            size_512_ratio, burst_count, is_private_to_public,
            cv_iat, cv_size,
        ], dtype=np.float32)


# ---------------------------------------------------------------------------
# DQN Neural Network
# ---------------------------------------------------------------------------

class DQNetwork(nn.Module):
    """Dueling DQN architecture for Tor flow classification."""

    def __init__(self, window_size=DEFAULT_WINDOW_SIZE, num_features=NUM_FEATURES,
                 num_actions=NUM_ACTIONS):
        super().__init__()

        input_size = window_size * num_features

        # Shared feature layers
        self.feature_net = nn.Sequential(
            nn.Linear(input_size, 256),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Dropout(0.1),
        )

        # Value stream
        self.value_stream = nn.Sequential(
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, 1),
        )

        # Advantage stream
        self.advantage_stream = nn.Sequential(
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, num_actions),
        )

    def forward(self, x):
        # Flatten the (batch, window, features) → (batch, window*features)
        x = x.view(x.size(0), -1)
        features = self.feature_net(x)
        value = self.value_stream(features)
        advantage = self.advantage_stream(features)
        # Dueling: Q = V + (A - mean(A))
        q_values = value + advantage - advantage.mean(dim=1, keepdim=True)
        return q_values


# ---------------------------------------------------------------------------
# Experience Replay Buffer
# ---------------------------------------------------------------------------

class ReplayBuffer:
    """Fixed-size buffer to store experience tuples."""

    def __init__(self, capacity=10000):
        self.buffer = deque(maxlen=capacity)

    def push(self, state, action, reward, next_state, done):
        self.buffer.append((state, action, reward, next_state, done))

    def sample(self, batch_size):
        batch = random.sample(self.buffer, min(batch_size, len(self.buffer)))
        states, actions, rewards, next_states, dones = zip(*batch)
        return (
            np.array(states),
            np.array(actions),
            np.array(rewards, dtype=np.float32),
            np.array(next_states),
            np.array(dones, dtype=np.float32),
        )

    def __len__(self):
        return len(self.buffer)


# ---------------------------------------------------------------------------
# DQN Agent
# ---------------------------------------------------------------------------

class DQNAgent:
    """Deep Q-Network agent for Tor traffic classification."""

    def __init__(self, window_size=DEFAULT_WINDOW_SIZE, lr=1e-3,
                 gamma=0.99, epsilon_start=1.0, epsilon_end=0.01,
                 epsilon_decay=500, buffer_capacity=10000,
                 batch_size=64, target_update_freq=10):

        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.window_size = window_size
        self.gamma = gamma
        self.batch_size = batch_size
        self.target_update_freq = target_update_freq

        # Epsilon-greedy parameters
        self.epsilon_start = epsilon_start
        self.epsilon_end = epsilon_end
        self.epsilon_decay = epsilon_decay
        self.steps_done = 0

        # Networks
        self.policy_net = DQNetwork(window_size).to(self.device)
        self.target_net = DQNetwork(window_size).to(self.device)
        self.target_net.load_state_dict(self.policy_net.state_dict())
        self.target_net.eval()

        self.optimizer = optim.Adam(self.policy_net.parameters(), lr=lr)
        self.replay_buffer = ReplayBuffer(buffer_capacity)

        # Training metrics
        self.training_rewards = []
        self.training_losses = []
        self.epsilon_history = []
        self.accuracy_history = []

    @property
    def epsilon(self):
        return self.epsilon_end + (self.epsilon_start - self.epsilon_end) * \
            math.exp(-1.0 * self.steps_done / self.epsilon_decay)

    def select_action(self, state, training=True):
        """Epsilon-greedy action selection."""
        if training and random.random() < self.epsilon:
            return random.randint(0, NUM_ACTIONS - 1)

        with torch.no_grad():
            state_t = torch.FloatTensor(state).unsqueeze(0).to(self.device)
            q_values = self.policy_net(state_t)
            return q_values.argmax(dim=1).item()

    def learn(self):
        """Sample from replay buffer and update the policy network."""
        if len(self.replay_buffer) < self.batch_size:
            return None

        states, actions, rewards, next_states, dones = self.replay_buffer.sample(self.batch_size)

        states_t = torch.FloatTensor(states).to(self.device)
        actions_t = torch.LongTensor(actions).unsqueeze(1).to(self.device)
        rewards_t = torch.FloatTensor(rewards).to(self.device)
        next_states_t = torch.FloatTensor(next_states).to(self.device)
        dones_t = torch.FloatTensor(dones).to(self.device)

        # Current Q-values
        current_q = self.policy_net(states_t).gather(1, actions_t).squeeze(1)

        # Double DQN: use policy net to select action, target net to evaluate
        with torch.no_grad():
            next_actions = self.policy_net(next_states_t).argmax(dim=1, keepdim=True)
            next_q = self.target_net(next_states_t).gather(1, next_actions).squeeze(1)
            target_q = rewards_t + self.gamma * next_q * (1.0 - dones_t)

        loss = nn.SmoothL1Loss()(current_q, target_q)

        self.optimizer.zero_grad()
        loss.backward()
        nn.utils.clip_grad_norm_(self.policy_net.parameters(), 1.0)
        self.optimizer.step()

        return loss.item()

    def update_target_network(self):
        self.target_net.load_state_dict(self.policy_net.state_dict())

    def save(self, path=DEFAULT_MODEL_PATH):
        torch.save({
            "policy_net": self.policy_net.state_dict(),
            "target_net": self.target_net.state_dict(),
            "optimizer": self.optimizer.state_dict(),
            "steps_done": self.steps_done,
            "training_rewards": self.training_rewards,
            "training_losses": self.training_losses,
            "epsilon_history": self.epsilon_history,
            "accuracy_history": self.accuracy_history,
        }, path)
        print(f"[OK] RL model saved to {path}")

    def load(self, path=DEFAULT_MODEL_PATH):
        if not os.path.exists(path):
            print(f"[WARNING] RL model not found at {path}")
            return False
        try:
            checkpoint = torch.load(path, map_location=self.device, weights_only=False)
            self.policy_net.load_state_dict(checkpoint["policy_net"])
            self.target_net.load_state_dict(checkpoint["target_net"])
            self.optimizer.load_state_dict(checkpoint["optimizer"])
            self.steps_done = checkpoint.get("steps_done", 0)
            self.training_rewards = checkpoint.get("training_rewards", [])
            self.training_losses = checkpoint.get("training_losses", [])
            self.epsilon_history = checkpoint.get("epsilon_history", [])
            self.accuracy_history = checkpoint.get("accuracy_history", [])
            print(f"[OK] RL model loaded from {path}")
            return True
        except Exception as e:
            print(f"[ERROR] Failed to load RL model: {e}")
            return False


# ---------------------------------------------------------------------------
# High-Level RL Analyzer
# ---------------------------------------------------------------------------

class RLAnalyzer:
    """
    High-level interface for training and using the RL agent.
    Integrates with the existing MLPCAPAnalyzer for PCAP parsing.
    """

    def __init__(self, window_size=DEFAULT_WINDOW_SIZE, model_path=DEFAULT_MODEL_PATH):
        self.window_size = window_size
        self.model_path = model_path
        self.agent = DQNAgent(window_size=window_size)

    def _pcap_to_flows(self, pcap_dir):
        """Parse all PCAPs in a directory into flow data."""
        from glob import glob
        from ml_detector import MLPCAPAnalyzer

        all_flows = []
        pcap_files = glob(os.path.join(pcap_dir, "*.pcap"))
        print(f"[*] Loading PCAPs from {pcap_dir}: {len(pcap_files)} files")

        for pcap_file in pcap_files:
            analyzer = MLPCAPAnalyzer()
            result = analyzer.parse_pcap(pcap_file)
            if "error" in result:
                print(f"  [!] Skipping {pcap_file}: {result['error']}")
                continue

            for flow_key, packets in analyzer.flows.items():
                if len(packets) >= 5:
                    src, dst = flow_key
                    all_flows.append({
                        "src": src,
                        "dst": dst,
                        "packets": packets,
                    })

            print(f"  [+] {pcap_file}: {len(analyzer.flows)} flows")

        return all_flows

    def train(self, tor_pcap_dir, non_tor_pcap_dir, num_episodes=500,
              max_flows_per_class=5000):
        """
        Train the DQN agent on labeled PCAP datasets.
        """
        print("[*] === RL Training Pipeline ===")
        print(f"[*] Episodes: {num_episodes}")

        # Load Tor flows
        tor_flows = self._pcap_to_flows(tor_pcap_dir)[:max_flows_per_class]
        tor_labels = [1] * len(tor_flows)

        # Load non-Tor flows
        non_tor_flows = self._pcap_to_flows(non_tor_pcap_dir)[:max_flows_per_class]
        non_tor_labels = [0] * len(non_tor_flows)

        all_flows = tor_flows + non_tor_flows
        all_labels = tor_labels + non_tor_labels

        if not all_flows:
            print("[ERROR] No training flows loaded!")
            return {"error": "No training data"}

        print(f"[*] Training set: {len(tor_flows)} Tor + {len(non_tor_flows)} non-Tor = {len(all_flows)} total")

        env = TorFlowEnvironment(all_flows, all_labels, window_size=self.window_size)

        episode_rewards = []
        episode_accuracies = []
        recent_correct = deque(maxlen=100)

        for episode in range(num_episodes):
            state = env.reset()
            total_reward = 0.0
            step_count = 0

            while not env.done:
                action = self.agent.select_action(state, training=True)
                next_state, reward, done, info = env.step(action)

                self.agent.replay_buffer.push(state, action, reward, next_state, done)
                self.agent.steps_done += 1

                loss = self.agent.learn()
                if loss is not None:
                    self.agent.training_losses.append(loss)

                state = next_state
                total_reward += reward
                step_count += 1

            # Track accuracy
            correct = info.get("correct", False)
            recent_correct.append(1 if correct else 0)

            episode_rewards.append(total_reward)
            self.agent.training_rewards.append(total_reward)
            self.agent.epsilon_history.append(self.agent.epsilon)

            # Update target network periodically
            if (episode + 1) % self.agent.target_update_freq == 0:
                self.agent.update_target_network()

            # Log progress
            if (episode + 1) % 50 == 0:
                avg_reward = np.mean(episode_rewards[-50:])
                accuracy = np.mean(list(recent_correct)) * 100
                self.agent.accuracy_history.append(accuracy)
                print(f"  Episode {episode+1}/{num_episodes} | "
                      f"Avg Reward: {avg_reward:.3f} | "
                      f"Accuracy: {accuracy:.1f}% | "
                      f"ε: {self.agent.epsilon:.3f} | "
                      f"Buffer: {len(self.agent.replay_buffer)}")

        # Save model
        self.agent.save(self.model_path)

        final_accuracy = np.mean(list(recent_correct)) * 100

        metrics = {
            "episodes_trained": num_episodes,
            "final_accuracy": float(final_accuracy),
            "final_epsilon": float(self.agent.epsilon),
            "avg_reward_last_50": float(np.mean(episode_rewards[-50:])),
            "total_flows": len(all_flows),
            "tor_flows": len(tor_flows),
            "non_tor_flows": len(non_tor_flows),
            "model_path": self.model_path,
            "trained_at": datetime.now().isoformat(),
        }

        print(f"\n[OK] Training complete!")
        print(f"    Final accuracy: {final_accuracy:.1f}%")
        print(f"    Model saved to: {self.model_path}")

        return metrics

    def analyze_pcap(self, pcap_filename, threshold=0.5):
        """
        Analyze a PCAP file using the trained RL agent.
        Returns a report in the same structure as ml_detector.
        """
        if not self.agent.load(self.model_path):
            return {"error": "RL model not available. Train the model first."}

        from ml_detector import MLPCAPAnalyzer
        from datetime import timezone

        analyzer = MLPCAPAnalyzer()
        parse_result = analyzer.parse_pcap(pcap_filename)
        if "error" in parse_result:
            return {"error": parse_result["error"]}

        print(f"[*] RL Analysis: {parse_result['flows']} flows found")

        findings = []
        nodes = {}
        links = {}
        decision_timelines = []

        for flow_key, packets in analyzer.flows.items():
            if len(packets) < 5:
                continue

            src_ip, dst_ip = flow_key
            flow_data = {"src": src_ip, "dst": dst_ip, "packets": packets}

            # Run the RL agent on this flow
            env = TorFlowEnvironment([flow_data], [0], window_size=self.window_size)
            state = env.reset(flow_idx=0)

            actions_taken = []
            q_value_history = []  # Q-values at each step for transparency
            step = 0

            while not env.done:
                # Get Q-values for transparency
                with torch.no_grad():
                    state_t = torch.FloatTensor(state).unsqueeze(0).to(self.agent.device)
                    q_vals = self.agent.policy_net(state_t)[0]
                    q_dict = {
                        "observe": round(float(q_vals[0].item()), 4),
                        "classify_tor": round(float(q_vals[1].item()), 4),
                        "classify_not_tor": round(float(q_vals[2].item()), 4),
                    }

                action = self.agent.select_action(state, training=False)
                next_state, reward, done, info = env.step(action)
                actions_taken.append({
                    "step": step,
                    "action": ACTIONS[action],
                    "action_id": action,
                    "q_values": q_dict,
                })
                q_value_history.append(q_dict)
                state = next_state
                step += 1

            # Determine classification from last action
            last_action = actions_taken[-1]["action_id"] if actions_taken else 2

            # Compute genuine confidence from Q-value margin (not softmax)
            if q_value_history:
                final_q = q_value_history[-1]
                q_tor = final_q["classify_tor"]
                q_not = final_q["classify_not_tor"]
                q_margin = q_tor - q_not  # positive = favors TOR
                # Convert margin to 0-100 confidence using sigmoid
                raw_confidence = 1.0 / (1.0 + math.exp(-q_margin * 2.0))
                confidence = round(raw_confidence * 100, 2)
            else:
                confidence = 0.0
                q_margin = 0.0

            if last_action == 1:  # CLASSIFY_TOR
                is_tor = True
            elif last_action == 2:  # CLASSIFY_NOT_TOR
                is_tor = False
            else:
                # Agent ran out of data — use Q-value margin to decide
                is_tor = q_margin > 0

            # Extract the raw feature snapshot at classification for transparency
            raw_features = {}
            if env._snapshots and len(env._snapshots) > 0:
                last_snap = env._snapshots[min(env.current_step, len(env._snapshots) - 1)]
                for fname, fval in zip(FEATURE_NAMES, last_snap):
                    raw_features[fname] = round(float(fval), 6)

            if is_tor and confidence >= threshold * 100:
                timestamps = [p["timestamp"] for p in packets]
                start_time = min(timestamps)
                end_time = max(timestamps)
                duration = end_time - start_time

                start_time_iso = datetime.fromtimestamp(start_time, tz=timezone.utc).isoformat()
                end_time_iso = datetime.fromtimestamp(end_time, tz=timezone.utc).isoformat()

                # Compute temporal fingerprint
                temporal_fp = analyzer.compute_temporal_fingerprint(packets)

                finding = {
                    "origin_ip": src_ip,
                    "exit_ip": dst_ip,
                    "is_tor": True,
                    "confidence": confidence,
                    "rl_confidence": confidence,
                    "q_value_margin": round(q_margin, 4),
                    "final_q_values": q_value_history[-1] if q_value_history else {},
                    "temporal_fingerprint": temporal_fp,
                    "start_time": start_time,
                    "end_time": end_time,
                    "duration": duration,
                    "start_time_iso": start_time_iso,
                    "end_time_iso": end_time_iso,
                    "detection_method": "DQN Reinforcement Learning",
                    "rl_steps_taken": len(actions_taken),
                    "rl_decision_timeline": actions_taken,
                    "feature_snapshot": raw_features,
                    "packet_count": len(packets),
                }
                findings.append(finding)

                # Build graph
                if src_ip not in nodes:
                    nodes[src_ip] = {"id": src_ip, "type": "client"}
                if dst_ip not in nodes:
                    nodes[dst_ip] = {"id": dst_ip, "type": "tor"}

                key = (src_ip, dst_ip)
                if key not in links:
                    links[key] = {"source": src_ip, "target": dst_ip, "flows": 0, "sum_conf": 0.0}
                links[key]["flows"] += 1
                links[key]["sum_conf"] += confidence

            decision_timelines.append({
                "flow": f"{src_ip} \u2192 {dst_ip}",
                "steps": len(actions_taken),
                "classified_as": "TOR" if is_tor else "NON-TOR",
                "confidence": confidence,
                "q_margin": round(q_margin, 4),
                "final_q_values": q_value_history[-1] if q_value_history else {},
                "q_history": q_value_history[-5:],  # last 5 steps for sparkline
                "packet_count": len(packets),
            })

        findings.sort(key=lambda x: x["confidence"], reverse=True)

        for key, link in links.items():
            link["avg_conf"] = link["sum_conf"] / link["flows"]
            del link["sum_conf"]

        graph = {"nodes": list(nodes.values()), "links": list(links.values())}

        report = {
            "metadata": {
                "report_generated": datetime.now().isoformat(),
                "pcap_source": pcap_filename,
                "tool": "OnionTrace v2.0 (RL-Based)",
                "model": "DQN (Dueling Double Deep Q-Network)",
                "methodology": "Reinforcement Learning — Sequential Flow Classification",
                "engine": "RL",
            },
            "summary": {
                "total_flows_analyzed": len(decision_timelines),
                "tor_flows_detected": len(findings),
                "overall_confidence": (
                    sum(f["confidence"] for f in findings) / len(findings)
                    if findings else 0.0
                ),
            },
            "findings": findings,
            "graph": graph,
            "rl_metrics": {
                "decision_timelines": decision_timelines[:50],
                "training_rewards": self.agent.training_rewards[-100:],
                "accuracy_history": self.agent.accuracy_history,
            },
        }

        return report

    def get_training_metrics(self):
        """Return training history metrics for visualization."""
        if not self.agent.load(self.model_path):
            return {"available": False}

        return {
            "available": True,
            "model_path": self.model_path,
            "total_episodes": len(self.agent.training_rewards),
            "reward_history": self.agent.training_rewards,
            "loss_history": self.agent.training_losses[-200:],
            "epsilon_history": self.agent.epsilon_history,
            "accuracy_history": self.agent.accuracy_history,
            "final_epsilon": float(self.agent.epsilon),
        }


# ---------------------------------------------------------------------------
# Synthetic Data Generator (for testing without real PCAPs)
# ---------------------------------------------------------------------------

def generate_synthetic_flows(num_flows=200, tor_ratio=0.5):
    """
    Generate synthetic flow data for testing the RL pipeline.
    Tor flows have distinctive patterns: regular IATs, 512-byte cells.
    """
    flows = []
    labels = []
    num_tor = int(num_flows * tor_ratio)

    for i in range(num_flows):
        is_tor = i < num_tor
        num_packets = random.randint(10, 100)

        packets = []
        t = random.uniform(1000000, 2000000)

        for j in range(num_packets):
            if is_tor:
                # Tor-like: regular IATs, cell-sized packets (~512 bytes)
                iat = random.gauss(0.05, 0.01)
                size = random.choice([512, 514, 510, 586, 590])
                if random.random() < 0.3:
                    size = random.randint(40, 1500)  # some noise
            else:
                # Non-Tor: irregular IATs, varied sizes
                iat = random.expovariate(2.0)
                size = random.randint(40, 1500)

            t += max(0.001, iat)
            packets.append({"timestamp": t, "size": size, "packet_num": j})

        src_ip = f"192.168.{random.randint(1,255)}.{random.randint(1,255)}" if is_tor else f"10.0.{random.randint(1,255)}.{random.randint(1,255)}"
        dst_ip = f"185.220.{random.randint(1,255)}.{random.randint(1,255)}" if is_tor else f"8.8.{random.randint(1,255)}.{random.randint(1,255)}"

        flows.append({"src": src_ip, "dst": dst_ip, "packets": packets})
        labels.append(1 if is_tor else 0)

    return flows, labels


def run_smoke_test():
    """Quick smoke test using synthetic data."""
    print("=" * 60)
    print("OnionTrace RL Agent — Smoke Test")
    print("=" * 60)

    print("\n[1] Generating synthetic flows...")
    flows, labels = generate_synthetic_flows(num_flows=200, tor_ratio=0.5)
    print(f"    Generated {len(flows)} flows ({sum(labels)} Tor, {len(labels)-sum(labels)} non-Tor)")

    print("\n[2] Creating environment & agent...")
    env = TorFlowEnvironment(flows, labels, window_size=DEFAULT_WINDOW_SIZE)
    agent = DQNAgent(window_size=DEFAULT_WINDOW_SIZE, epsilon_decay=150, lr=5e-4)

    print("\n[3] Training for 300 episodes...")
    num_episodes = 300
    recent_correct = deque(maxlen=50)

    for episode in range(num_episodes):
        state = env.reset()
        total_reward = 0.0

        while not env.done:
            action = agent.select_action(state, training=True)
            next_state, reward, done, info = env.step(action)
            agent.replay_buffer.push(state, action, reward, next_state, done)
            agent.steps_done += 1
            agent.learn()
            state = next_state
            total_reward += reward

        correct = info.get("correct", False)
        recent_correct.append(1 if correct else 0)

        if (episode + 1) % agent.target_update_freq == 0:
            agent.update_target_network()

        if (episode + 1) % 50 == 0:
            acc = np.mean(list(recent_correct)) * 100
            print(f"    Episode {episode+1}/{num_episodes} | Reward: {total_reward:.3f} | "
                  f"Accuracy: {acc:.1f}% | ε: {agent.epsilon:.3f}")

    agent.save(DEFAULT_MODEL_PATH)

    print("\n[4] Running inference on 20 test flows...")
    agent.load(DEFAULT_MODEL_PATH)
    correct_count = 0
    total_count = 20

    for i in range(total_count):
        idx = random.randint(0, len(flows) - 1)
        state = env.reset(flow_idx=idx)

        while not env.done:
            action = agent.select_action(state, training=False)
            state, _, done, info = env.step(action)

        if info.get("correct", False):
            correct_count += 1

    print(f"    Inference accuracy: {correct_count}/{total_count} = {correct_count/total_count*100:.1f}%")
    print("\n[OK] Smoke test complete!")
    print("=" * 60)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python rl_agent.py test                          — Run smoke test")
        print("  python rl_agent.py train <tor_dir> <non_tor_dir> — Train on PCAPs")
        print("  python rl_agent.py analyze <pcap_file>           — Analyze a PCAP")
        sys.exit(1)

    if sys.argv[1] == "test":
        run_smoke_test()

    elif sys.argv[1] == "train":
        if len(sys.argv) < 4:
            print("Usage: python rl_agent.py train <tor_dir> <non_tor_dir> [episodes]")
            sys.exit(1)
        tor_dir = sys.argv[2]
        non_tor_dir = sys.argv[3]
        episodes = int(sys.argv[4]) if len(sys.argv) >= 5 else 500

        rl = RLAnalyzer()
        metrics = rl.train(tor_dir, non_tor_dir, num_episodes=episodes)
        print(json.dumps(metrics, indent=2))

    elif sys.argv[1] == "analyze":
        if len(sys.argv) < 3:
            print("Usage: python rl_agent.py analyze <pcap_file>")
            sys.exit(1)
        rl = RLAnalyzer()
        result = rl.analyze_pcap(sys.argv[2])
        print(json.dumps(result, indent=2, default=str))
