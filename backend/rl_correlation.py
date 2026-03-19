"""
OnionTrace RL Correlation — RL-enhanced entry/exit flow matching.

Uses a lightweight DQN to learn whether pairs of flows
(entry-side and exit-side) are correlated based on temporal
and statistical similarity.

This is a drop-in enhancement for time_correlation.py.
"""

import os
import random
import math
from collections import deque
from datetime import datetime

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
import ipaddress

DEFAULT_CORR_MODEL_PATH = "rl_correlation_model.pt"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


def _flow_pair_features(entry, exit_flow):
    """
    Build a feature vector representing how similar two flows are.
    Returns a numpy array of shape (num_pair_features,).
    """
    features = []

    # 1. Temporal fingerprint match (binary)
    fp_e = entry.get("temporal_fingerprint", "")
    fp_x = exit_flow.get("temporal_fingerprint", "")
    features.append(1.0 if (fp_e and fp_x and fp_e == fp_x) else 0.0)

    # 2. Confidence scores (normalized 0–1)
    features.append(entry.get("confidence", 0.0) / 100.0)
    features.append(exit_flow.get("confidence", 0.0) / 100.0)

    # 3. Duration similarity (absolute difference, capped)
    dur_e = entry.get("duration", 0.0)
    dur_x = exit_flow.get("duration", 0.0)
    dur_diff = abs(dur_e - dur_x)
    features.append(min(dur_diff / 60.0, 1.0))  # normalize to 1 minute

    # 4. Start-time proximity (seconds between starts)
    st_e = entry.get("start_time", 0)
    st_x = exit_flow.get("start_time", 0)
    time_diff = abs(st_e - st_x)
    features.append(min(time_diff / 10.0, 1.0))  # normalize to 10 seconds

    # 5. Mean confidence of pair
    features.append(
        (entry.get("confidence", 0.0) + exit_flow.get("confidence", 0.0)) / 200.0
    )

    # 6. RL confidence if available
    features.append(entry.get("rl_confidence", 0.0) / 100.0)
    features.append(exit_flow.get("rl_confidence", 0.0) / 100.0)

    return np.array(features, dtype=np.float32)


NUM_PAIR_FEATURES = 8


# ---------------------------------------------------------------------------
# Correlation DQN
# ---------------------------------------------------------------------------

class CorrelationNet(nn.Module):
    def __init__(self, input_size=NUM_PAIR_FEATURES, num_actions=2):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_size, 64),
            nn.ReLU(),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, num_actions),
        )

    def forward(self, x):
        return self.net(x)


class CorrelationAgent:
    """Lightweight DQN agent for flow-pair correlation."""

    def __init__(self, lr=1e-3, gamma=0.95):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.net = CorrelationNet().to(self.device)
        self.target_net = CorrelationNet().to(self.device)
        self.target_net.load_state_dict(self.net.state_dict())
        self.optimizer = optim.Adam(self.net.parameters(), lr=lr)
        self.gamma = gamma
        self.buffer = deque(maxlen=5000)
        self.steps = 0
        self.epsilon = 1.0
        self.epsilon_min = 0.05
        self.epsilon_decay = 200

    def _get_epsilon(self):
        return self.epsilon_min + (1.0 - self.epsilon_min) * \
            math.exp(-1.0 * self.steps / self.epsilon_decay)

    def select_action(self, state, training=True):
        eps = self._get_epsilon() if training else 0.0
        if random.random() < eps:
            return random.randint(0, 1)
        with torch.no_grad():
            q = self.net(torch.FloatTensor(state).unsqueeze(0).to(self.device))
            return q.argmax(dim=1).item()

    def store(self, state, action, reward, next_state, done):
        self.buffer.append((state, action, reward, next_state, done))

    def learn(self, batch_size=32):
        if len(self.buffer) < batch_size:
            return
        batch = random.sample(self.buffer, batch_size)
        s, a, r, ns, d = zip(*batch)

        s_t = torch.FloatTensor(np.array(s)).to(self.device)
        a_t = torch.LongTensor(a).unsqueeze(1).to(self.device)
        r_t = torch.FloatTensor(r).to(self.device)
        ns_t = torch.FloatTensor(np.array(ns)).to(self.device)
        d_t = torch.FloatTensor(d).to(self.device)

        q = self.net(s_t).gather(1, a_t).squeeze(1)
        with torch.no_grad():
            target = r_t + self.gamma * self.target_net(ns_t).max(1)[0] * (1 - d_t)

        loss = nn.SmoothL1Loss()(q, target)
        self.optimizer.zero_grad()
        loss.backward()
        self.optimizer.step()
        self.steps += 1

        if self.steps % 20 == 0:
            self.target_net.load_state_dict(self.net.state_dict())

    def save(self, path=DEFAULT_CORR_MODEL_PATH):
        torch.save(self.net.state_dict(), path)

    def load(self, path=DEFAULT_CORR_MODEL_PATH):
        if not os.path.exists(path):
            return False
        self.net.load_state_dict(
            torch.load(path, map_location=self.device, weights_only=True)
        )
        self.target_net.load_state_dict(self.net.state_dict())
        return True


# ---------------------------------------------------------------------------
# Public API — drop-in replacement for correlate_flows()
# ---------------------------------------------------------------------------

def correlate_flows_rl(findings, model_path=DEFAULT_CORR_MODEL_PATH):
    """
    RL-enhanced correlation. Falls back to rule-based scoring if
    no trained model is available.
    """
    entry_flows = []
    exit_flows = []

    for f in findings:
        origin = f.get("origin_ip", "")
        exit_ip = f.get("exit_ip", "")
        if is_private_ip(origin):
            entry_flows.append(f)
        elif is_private_ip(exit_ip) and not is_private_ip(origin):
            exit_flows.append(f)

    agent = CorrelationAgent()
    has_model = agent.load(model_path)

    correlations = []

    for e in entry_flows:
        for x in exit_flows:
            pair_features = _flow_pair_features(e, x)

            if has_model:
                # RL-based decision
                action = agent.select_action(pair_features, training=False)
                with torch.no_grad():
                    q_vals = agent.net(
                        torch.FloatTensor(pair_features).unsqueeze(0).to(agent.device)
                    )
                    probs = torch.softmax(q_vals, dim=1)[0]
                    rl_confidence = float(probs[1].item())

                match = action == 1
                method = "RL"
            else:
                # Fallback: rule-based (same as time_correlation.py)
                fp_e = e.get("temporal_fingerprint", "")
                fp_x = x.get("temporal_fingerprint", "")
                match = bool(fp_e and fp_x and fp_e == fp_x)
                temporal_score = 0.9 if match else 0.3
                ml_conf = (e.get("confidence", 0) + x.get("confidence", 0)) / 200.0
                rl_confidence = round(0.6 * temporal_score + 0.4 * ml_conf, 3)
                method = "RuleBased"

            correlations.append({
                "entry_origin_ip": e.get("origin_ip"),
                "exit_destination_ip": x.get("exit_ip"),
                "entry_fingerprint": e.get("temporal_fingerprint", ""),
                "exit_fingerprint": x.get("temporal_fingerprint", ""),
                "temporal_match": match,
                "correlation_confidence": rl_confidence,
                "correlation_method": method,
            })

    return correlations
