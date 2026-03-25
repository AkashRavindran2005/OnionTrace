import React, { useState, useEffect, useRef, useCallback } from 'react';
import './App.css';
import {
  FaShieldAlt, FaUpload, FaHistory, FaFileDownload, FaSyncAlt,
  FaBrain, FaRobot, FaNetworkWired, FaChartLine, FaSearch,
  FaEye, FaCheckCircle, FaTimesCircle, FaCogs, FaInfoCircle,
  FaChevronDown, FaChevronUp, FaLock, FaFilter, FaDatabase,
  FaProjectDiagram, FaStream, FaExclamationTriangle, FaCircle,
  FaPlay, FaStop, FaWifi, FaTerminal,
} from 'react-icons/fa';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';

/* ─── Q Sparkline ─── */
function QSparkline({ qHistory }) {
  if (!qHistory || qHistory.length === 0) return null;
  const w = 90, h = 22, pad = 2;
  const torVals = qHistory.map(q => q.classify_tor);
  const notVals = qHistory.map(q => q.classify_not_tor);
  const all = [...torVals, ...notVals];
  const min = Math.min(...all) - 0.1, max = Math.max(...all) + 0.1, range = max - min || 1;
  const x = i => pad + (i / (qHistory.length - 1 || 1)) * (w - 2 * pad);
  const y = v => h - pad - ((v - min) / range) * (h - 2 * pad);
  const path = vals => vals.map((v, i) => `${i === 0 ? 'M' : 'L'}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(' ');
  return (
    <svg width={w} height={h} style={{ display: 'block' }}>
      <path d={path(torVals)} fill="none" stroke="var(--c-alert)" strokeWidth="1.5" />
      <path d={path(notVals)} fill="none" stroke="var(--c-ok)" strokeWidth="1.5" />
    </svg>
  );
}

/* ─── Collapsible ─── */
function Collapsible({ title, icon, children, defaultOpen = false, badge }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className={`collapsible${open ? ' open' : ''}`}>
      <button className="collapsible-hd" onClick={() => setOpen(!open)}>
        <span className="collapsible-title">{icon && <span className="c-icon">{icon}</span>}{title}</span>
        <span className="collapsible-meta">
          {badge && <span className="c-badge">{badge}</span>}
          {open ? <FaChevronUp size={11} /> : <FaChevronDown size={11} />}
        </span>
      </button>
      {open && <div className="collapsible-bd">{children}</div>}
    </div>
  );
}

/* ═══════════════════════════════
   LIVE CAPTURE COMPONENT
   ═══════════════════════════════ */
function LiveCapture() {
  const [interfaces, setInterfaces] = useState([]);
  const [selectedIface, setSelectedIface] = useState('');
  const [engine, setEngine] = useState('rf');
  const [running, setRunning] = useState(false);
  const [status, setStatus] = useState({ packets_captured: 0, flows_found: 0, tor_count: 0 });
  const [torFindings, setTorFindings] = useState([]);
  const [safeFlows, setSafeFlows] = useState([]);
  const [log, setLog] = useState([]); // terminal lines
  const [error, setError] = useState(null);
  const [connecting, setConnecting] = useState(false);
  const esRef = useRef(null);
  const logRef = useRef(null);

  // Fetch interfaces on mount
  useEffect(() => {
    fetch(`${API_URL}/api/capture/interfaces`)
      .then(r => r.json())
      .then(d => {
        setInterfaces(d.interfaces || []);
        if (d.interfaces?.length > 0) setSelectedIface(d.interfaces[0].name);
      })
      .catch(() => setError('Could not fetch interfaces. Ensure the backend is running as Administrator.'));
  }, []);

  const addLog = useCallback((line, type = 'info') => {
    const ts = new Date().toLocaleTimeString('en-GB', { hour12: false });
    setLog(prev => [...prev.slice(-199), { ts, line, type }]);
    setTimeout(() => {
      if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
    }, 20);
  }, []);

  const startCapture = async () => {
    setError(null); setTorFindings([]); setSafeFlows([]); setLog([]);
    setStatus({ packets_captured: 0, flows_found: 0, tor_count: 0 });
    setConnecting(true);

    try {
      const res = await fetch(`${API_URL}/api/capture/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interface: selectedIface || null, engine }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Start failed');
      setRunning(true);
      addLog(`▶ Capture started on "${data.interface}" using ${data.engine.toUpperCase()} engine`, 'ok');

      // Open SSE stream
      const es = new EventSource(`${API_URL}/api/capture/stream`);
      esRef.current = es;

      es.onmessage = (evt) => {
        let ev;
        try { ev = JSON.parse(evt.data); } catch { return; }

        if (ev.type === 'packet') {
          setStatus(s => ({ ...s, packets_captured: ev.count }));
          // Only log every 10th packet to avoid flooding
          if (ev.count % 10 === 0) {
            addLog(`PKT #${ev.count}  ${ev.src} → ${ev.dst}  [${ev.size}B  proto=${ev.proto}]`, 'pkt');
          }
        } else if (ev.type === 'tor_detected') {
          const f = ev.finding;
          setTorFindings(prev => [f, ...prev]);
          setStatus(s => ({ ...s, tor_count: s.tor_count + 1 }));
          addLog(`🚨 TOR DETECTED  ${f.origin_ip} → ${f.exit_ip}  conf=${f.confidence}%`, 'alert');
        } else if (ev.type === 'flow_safe') {
          setSafeFlows(prev => [ev, ...prev.slice(0, 49)]);
          setStatus(s => ({ ...s, flows_found: s.flows_found + 1 }));
          addLog(`  ✓ SAFE flow  ${ev.src} → ${ev.dst}  [${ev.packet_count} pkts]`, 'ok');
        } else if (ev.type === 'stopped') {
          addLog(`■ Capture stopped. Total packets: ${ev.packets}`, 'ok');
          setRunning(false);
          es.close();
        }
      };

      es.onerror = () => {
        if (running) addLog('SSE connection lost.', 'err');
        es.close();
        setRunning(false);
      };

    } catch (e) {
      setError(e.message);
      addLog(`ERROR: ${e.message}`, 'err');
    } finally {
      setConnecting(false);
    }
  };

  const stopCapture = async () => {
    try {
      await fetch(`${API_URL}/api/capture/stop`, { method: 'POST' });
      if (esRef.current) { esRef.current.close(); esRef.current = null; }
      setRunning(false);
      addLog('■ Capture stopped by user.', 'ok');
    } catch (e) {
      setError(e.message);
    }
  };

  return (
    <div className="live-wrapper">

      {/* ── Top bar ── */}
      <div className="live-topbar">
        <div className="live-topbar-left">
          <span className={`live-dot ${running ? 'live-dot--on' : ''}`} />
          <span className="live-title">LIVE PACKET CAPTURE</span>
          {running && <span className="live-running-tag">● RECORDING</span>}
        </div>
        <div className="live-topbar-right">
          {/* Interface selector */}
          <select
            className="live-select"
            value={selectedIface}
            onChange={e => setSelectedIface(e.target.value)}
            disabled={running}
          >
            <option value="">All interfaces</option>
            {interfaces.map(i => (
              <option key={i.name} value={i.name}>
                {i.description || i.name}
                {i.ips?.length > 0 ? ` (${i.ips[0]})` : ''}
              </option>
            ))}
          </select>
          {/* Engine selector */}
          <select className="live-select" value={engine} onChange={e => setEngine(e.target.value)} disabled={running}>
            <option value="rf">RandomForest</option>
            <option value="rl">DQN Agent</option>
          </select>
          {/* Start/Stop */}
          {!running
            ? <button className="btn-start" onClick={startCapture} disabled={connecting}>
                {connecting ? <><span className="spinner-sm" /> Connecting…</> : <><FaPlay size={11} /> Start Capture</>}
              </button>
            : <button className="btn-stop" onClick={stopCapture}>
                <FaStop size={11} /> Stop
              </button>}
        </div>
      </div>

      {error && <div className="live-error"><FaExclamationTriangle /> {error}</div>}

      {/* ── Stats strip ── */}
      <div className="live-stats">
        <div className="live-stat">
          <span className="live-stat-val" style={{ color: 'var(--c-accent)' }}>
            {status.packets_captured.toLocaleString()}
          </span>
          <span className="live-stat-label">Packets Captured</span>
        </div>
        <div className="live-stat-sep" />
        <div className="live-stat">
          <span className="live-stat-val">{status.flows_found}</span>
          <span className="live-stat-label">Flows Analyzed</span>
        </div>
        <div className="live-stat-sep" />
        <div className="live-stat">
          <span className="live-stat-val" style={{ color: torFindings.length > 0 ? 'var(--c-alert)' : 'var(--c-ok)' }}>
            {torFindings.length}
          </span>
          <span className="live-stat-label">Tor Detections</span>
        </div>
        <div className="live-stat-sep" />
        <div className="live-stat">
          <span className="live-stat-val">{engine.toUpperCase()}</span>
          <span className="live-stat-label">Engine</span>
        </div>
      </div>

      {/* ── Two columns: terminal + findings ── */}
      <div className="live-columns">

        {/* LEFT: Terminal log */}
        <div className="live-terminal">
          <div className="live-terminal-hd">
            <FaTerminal size={11} /> <span>Packet Stream</span>
            <button className="terminal-clear" onClick={() => setLog([])}>clear</button>
          </div>
          <div className="live-terminal-body" ref={logRef}>
            {log.length === 0 && (
              <span className="terminal-idle">
                {running ? 'Waiting for packets…' : '▌ Start capture to begin monitoring'}
              </span>
            )}
            {log.map((l, i) => (
              <div key={i} className={`terminal-line terminal-line--${l.type}`}>
                <span className="terminal-ts">{l.ts}</span>
                <span className="terminal-msg">{l.line}</span>
              </div>
            ))}
          </div>
        </div>

        {/* RIGHT: Detections */}
        <div className="live-detections">
          <div className="live-detections-hd">
            <FaExclamationTriangle size={11} />
            <span>Tor Detections</span>
            <span className="live-det-count">{torFindings.length}</span>
          </div>
          <div className="live-detections-body">
            {torFindings.length === 0 && (
              <div className="live-no-det">
                <FaCheckCircle style={{ color: 'var(--c-ok)', fontSize: 28 }} />
                <p>No Tor traffic detected yet</p>
                <span>{running ? 'Monitoring…' : 'Start a capture session'}</span>
              </div>
            )}
            {torFindings.map((f, i) => (
              <div key={i} className="live-finding-card">
                <div className="live-finding-top">
                  <span className="live-finding-alert">🚨 TOR</span>
                  <span className="live-finding-conf">{f.confidence}%</span>
                  <span className="live-finding-engine">{f.engine}</span>
                </div>
                <div className="live-finding-flow">
                  <code>{f.origin_ip}</code>
                  <span className="live-finding-arrow">→</span>
                  <code>{f.exit_ip}</code>
                </div>
                <div className="live-finding-meta">
                  {f.packet_count} packets · {f.duration}s ·{' '}
                  {f.start_time_iso ? new Date(f.start_time_iso).toLocaleTimeString() : '—'}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Bottom: How live capture works */}
      <div className="live-explainer">
        <FaInfoCircle style={{ color: 'var(--c-accent)', flexShrink: 0 }} />
        <div>
          <strong>How live capture works:</strong> Scapy's <code>AsyncSniffer</code> intercepts IP packets on the selected interface in real-time.
          Once a flow accumulates ≥15 packets, it's passed to the {engine === 'rl' ? 'DQN RL agent' : 'RandomForest classifier'} for instant classification.
          Tor flows appear as red alerts. Requires <strong>Npcap</strong> installed + running as Administrator.
        </div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════
   MAIN APP
   ═══════════════════════════════ */
export default function App() {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [error, setError] = useState(null);
  const [view, setView] = useState('home');
  const [history, setHistory] = useState([]);
  const [analysisMode, setAnalysisMode] = useState('rf');
  const [rlStatus, setRlStatus] = useState(null);

  useEffect(() => {
    fetch(`${API_URL}/api/rl/status`).then(r => r.ok ? r.json() : null).then(d => d && setRlStatus(d)).catch(() => {});
  }, []);

  const handleFileSelect = e => { setFile(e.target.files?.[0] || null); setError(null); };

  const handleAnalyze = async () => {
    if (!file) { setError('Select a PCAP file first.'); return; }
    setLoading(true); setError(null);
    const fd = new FormData(); fd.append('pcap', file);
    try {
      let rfResult = null, rlResult = null;
      if (analysisMode === 'rf' || analysisMode === 'both') {
        const r = await fetch(`${API_URL}/api/analyze`, { method: 'POST', body: fd });
        if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || 'RF failed');
        rfResult = await r.json();
      }
      if (analysisMode === 'rl' || analysisMode === 'both') {
        const fd2 = new FormData(); fd2.append('pcap', file);
        const r = await fetch(`${API_URL}/api/analyze/rl`, { method: 'POST', body: fd2 });
        if (r.ok) rlResult = await r.json();
        else if (analysisMode === 'rl') throw new Error((await r.json().catch(() => ({}))).error || 'RL failed');
      }
      const primary = rfResult || rlResult;
      if (!primary) throw new Error('No results');
      if (rlResult) primary.rl_data = rlResult.data;
      setAnalysisResult(primary);
      setView('results');
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  };

  const downloadReport = async () => {
    if (!analysisResult?.data?.findings) return;
    try {
      const r = await fetch(`${API_URL}/api/report/pdf`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ findings: analysisResult.data.findings, metadata: analysisResult.data.metadata || {}, graph: analysisResult.data.graph || {} }),
      });
      if (!r.ok) throw new Error('Report failed');
      const blob = await r.blob(), url = URL.createObjectURL(blob);
      const a = Object.assign(document.createElement('a'), { href: url, download: `OnionTrace_Report_${Date.now()}.pdf` });
      a.click(); URL.revokeObjectURL(url);
    } catch (e) { setError('Download failed: ' + e.message); }
  };

  const loadHistory = async () => {
    try {
      const r = await fetch(`${API_URL}/api/history`);
      setHistory((await r.json()).cases || []); setView('history');
    } catch (e) { setError(e.message); }
  };

  /* ══ HOME ══ */
  const renderHome = () => (
    <>
      {/* Hero */}
      <section className="hero">
        <div className="hero-scan" />
        <div className="hero-inner">
          <div className="hero-eyebrow"><span className="eyebrow-dot" />NETWORK FORENSICS TOOL</div>
          <h1 className="hero-h1">OnionTrace</h1>
          <p className="hero-tagline">Detecting Tor anonymity networks through encrypted traffic fingerprints</p>
          <div className="hero-chips">
            <span className="chip chip-blue"><FaBrain size={11}/> Random Forest</span>
            <span className="chip chip-purple"><FaRobot size={11}/> Deep Q-Network</span>
            <span className="chip chip-green"><FaLock size={11}/> No Decryption Needed</span>
            <span className="chip chip-amber"><FaDatabase size={11}/> ISCX Dataset · 95% Acc</span>
          </div>
        </div>
      </section>

      {/* What & Why */}
      <section className="sec">
        <div className="sec-label">background</div>
        <h2 className="sec-h2">What is this project?</h2>
        <div className="four-grid">
          {[
            { icon: '🧅', h: 'The Tor Network', b: 'Tor routes your traffic through 3+ encrypted relay nodes ("onions") to hide your identity. While privacy-focused, it is widely used in cybercrime, making detection critical for network forensics.' },
            { icon: '🔐', h: 'The Problem', b: 'You cannot read the packet contents — they\'re encrypted. Traditional Deep Packet Inspection fails. OnionTrace detects Tor purely from *statistical shapes* of packets — timing and sizes.' },
            { icon: '📊', h: 'Statistical Fingerprinting', b: 'Tor uses fixed 512-byte "cells", rhythmic inter-arrival times, and a specific burst pattern. These features exist in packet metadata even when content is encrypted.' },
            { icon: '📄', h: 'What You Provide', b: 'A .pcap file (Wireshark/tcpdump capture). OnionTrace groups it into flows, extracts 13 features per flow, and classifies each as Tor or non-Tor.' },
          ].map((c, i) => (
            <div className="four-card" key={i}>
              <div className="four-card-icon">{c.icon}</div>
              <h4>{c.h}</h4>
              <p>{c.b}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Pipeline */}
      <section className="sec">
        <div className="sec-label">methodology</div>
        <h2 className="sec-h2">Detection Pipeline</h2>
        <div className="pipeline-row">
          {[
            { n: '01', color: '#00d4ff', t: 'PCAP Upload', d: 'Raw network capture from Wireshark or tcpdump' },
            { n: '02', color: '#a8ff78', t: 'Flow Extraction', d: 'Group packets by (src IP, dst IP) — only flows with ≥5 pkts' },
            { n: '03', color: '#ffd43b', t: 'Feature Engineering', d: '13 statistical features: sizes, IATs, burst count, 512-byte ratio…' },
            { n: '04', color: '#f783ac', t: 'RF Classifier', d: '100 decision trees vote — instant one-shot classification' },
            { n: '05', color: '#cc5de8', t: 'DQN RL Agent', d: 'Observes feature windows sequentially, decides when to commit' },
            { n: '06', color: '#ff7043', t: 'Forensic Report', d: 'IP circuit diagram, confidence, PDF export' },
          ].map((s, i) => (
            <React.Fragment key={i}>
              <div className="pipe-step" style={{ '--pc': s.color }}>
                <div className="pipe-num">{s.n}</div>
                <div className="pipe-title">{s.t}</div>
                <div className="pipe-desc">{s.d}</div>
              </div>
              {i < 5 && <div className="pipe-arrow">→</div>}
            </React.Fragment>
          ))}
        </div>
      </section>

      {/* RL Architecture */}
      <section className="sec">
        <div className="sec-label">deep reinforcement learning</div>
        <h2 className="sec-h2">How the DQN Agent Works</h2>
        <p className="sec-sub">Unlike the RandomForest (one shot), the RL agent *observes over time* and decides the optimal moment to classify — just like a detective building a case.</p>
        <div className="arch-row">
          <div className="arch-box arch-box-env">
            <div className="arch-box-tag">ENVIRONMENT</div>
            <div className="arch-box-name">TorFlowEnvironment</div>
            <ul>
              <li>Sliding window: <b>8 × 13</b> feature matrix</li>
              <li>Each episode = one network flow</li>
              <li>Reward: +1 correct · +0.5 early · −1 wrong</li>
            </ul>
          </div>
          <div className="arch-conn">
            <div className="arch-conn-label">state</div>
            <div className="arch-conn-line">━━━━━▶</div>
          </div>
          <div className="arch-box arch-box-agent">
            <div className="arch-box-tag">AGENT</div>
            <div className="arch-box-name">Dueling Double DQN</div>
            <ul>
              <li>Layers: 256 → 128 → 64 neurons</li>
              <li>Value + Advantage streams</li>
              <li>ε-greedy exploration (trained)</li>
            </ul>
          </div>
          <div className="arch-conn">
            <div className="arch-conn-label">action</div>
            <div className="arch-conn-line">━━━━━▶</div>
          </div>
          <div className="arch-box arch-box-actions">
            <div className="arch-box-tag">ACTIONS</div>
            <div className="arch-box-name">3 Choices</div>
            <div className="action-pill action-obs">👁 OBSERVE MORE</div>
            <div className="action-pill action-tor">🧅 CLASSIFY TOR</div>
            <div className="action-pill action-ok">✓ CLASSIFY SAFE</div>
          </div>
        </div>
        {rlStatus?.rl_model_available && (
          <div className="model-trained-bar">
            <span className="mtb-item"><span className="mtb-val">1,000</span>Episodes Trained</span>
            <span className="mtb-sep">|</span>
            <span className="mtb-item mtb-highlight"><span className="mtb-val">95.0%</span>Final Accuracy</span>
            <span className="mtb-sep">|</span>
            <span className="mtb-item"><span className="mtb-val">0.051</span>Final Epsilon (ε)</span>
            <span className="mtb-sep">|</span>
            <span className="mtb-item"><span className="mtb-val">104</span>Training Flows</span>
            <span className="mtb-sep">|</span>
            <span className="mtb-item mtb-ok"><span className="mtb-val">● LIVE</span>Model Status</span>
          </div>
        )}
      </section>

      {/* 13 Features */}
      <section className="sec">
        <div className="sec-label">feature engineering</div>
        <h2 className="sec-h2">13 Extracted Features</h2>
        <p className="sec-sub">Computed from packet metadata only — no payload inspection required.</p>
        <div className="features-table">
          {[
            ['mean_size', 'Average packet size in bytes. Tor cells are fixed at ~512 bytes.'],
            ['std_size', 'Variation in packet sizes. Low variance = uniform Tor cell sizes.'],
            ['min_size', 'Minimum packet size — Tor uses small control cells.'],
            ['max_size', 'Maximum packet size in the flow.'],
            ['mean_iat', 'Average inter-arrival time between packets (seconds).'],
            ['std_iat', 'Timing variation. Tor has rhythmic, regular packet timing.'],
            ['packet_count', 'Total packets in the flow.'],
            ['duration', 'Flow duration from first to last packet (seconds).'],
            ['512_byte_ratio', 'Fraction of packets near 512 bytes — the Tor cell size.'],
            ['burst_count', 'Number of rapid bursts (IAT < 100ms).'],
            ['priv→pub', 'Whether source is a private IP and dest is public (1/0).'],
            ['cv_iat', 'Coefficient of variation of IATs: std_iat / mean_iat.'],
            ['cv_size', 'Coefficient of variation of packet sizes: std_size / mean_size.'],
          ].map(([name, desc]) => (
            <div className="feat-row" key={name}>
              <code className="feat-name">{name}</code>
              <span className="feat-desc">{desc}</span>
            </div>
          ))}
        </div>
      </section>

      {/* Upload */}
      <section className="sec" id="upload">
        <div className="sec-label">analyze pcap file</div>
        <h2 className="sec-h2">Upload & Detect</h2>
        <div className="upload-box">
          <div className="engine-row">
            {[
              { id: 'rf', icon: <FaBrain />, label: 'RandomForest', badge: 'ML · Fast', desc: '100 decision trees — instant one-shot prediction' },
              { id: 'rl', icon: <FaRobot />, label: 'DQN Agent', badge: 'RL · 95% Acc', desc: 'Sequential observer — learns when to decide', disabled: rlStatus && !rlStatus.rl_model_available },
              { id: 'both', icon: <><FaBrain size={14}/><FaRobot size={14}/></>, label: 'Both', badge: 'Compare', desc: 'Run both and compare results side-by-side', disabled: rlStatus && !rlStatus.rl_model_available },
            ].map(m => (
              <button key={m.id}
                className={`engine-btn ${analysisMode === m.id ? 'engine-btn--on' : ''} ${m.disabled ? 'engine-btn--off' : ''}`}
                onClick={() => !m.disabled && setAnalysisMode(m.id)}>
                <span className="engine-btn-icon">{m.icon}</span>
                <span className="engine-btn-label">{m.label}</span>
                <span className="engine-btn-badge">{m.badge}</span>
                <span className="engine-btn-desc">{m.desc}</span>
              </button>
            ))}
          </div>
          <label className={`dropzone ${file ? 'dropzone--file' : ''}`}>
            <input type="file" accept=".pcap,.pcapng" onChange={handleFileSelect} disabled={loading} style={{ display: 'none' }} />
            {file
              ? <div className="dz-file"><span className="dz-file-name">{file.name}</span><span className="dz-file-size">{(file.size / 1024).toFixed(1)} KB — ready</span></div>
              : <div className="dz-empty"><FaUpload size={28} /><span>Drop .pcap / .pcapng here</span><span className="dz-hint">or click to browse · max 50 MB</span></div>}
          </label>
          {error && <div className="err-bar"><FaExclamationTriangle /> {error}</div>}
          <button className="btn-analyze" onClick={handleAnalyze} disabled={!file || loading}>
            {loading ? <><span className="spinner" />Analyzing…</> : <><FaSearch /> Run {analysisMode === 'rl' ? 'RL' : analysisMode === 'both' ? 'Dual' : 'RF'} Analysis</>}
          </button>
        </div>
      </section>
    </>
  );

  /* ══ RESULTS ══ */
  const renderResults = () => {
    if (!analysisResult?.data) return null;
    const data = analysisResult.data, meta = data.metadata || {};
    const findings = data.findings || [], summary = data.summary || {};
    const graph = data.graph || { nodes: [], links: [] };
    const rlData = analysisResult.rl_data;
    const rlMetrics = rlData?.rl_metrics || data?.rl_metrics;
    const timelines = rlMetrics?.decision_timelines || [];
    const torCount = summary.tor_flows_detected ?? findings.length;
    const totalFlows = summary.total_flows_analyzed ?? 0;
    const avgConf = summary.overall_confidence ?? 0;
    const engine = meta.engine || 'ML';

    return (
      <div className="results">
        {/* Verdict */}
        <div className={`verdict-bar ${torCount > 0 ? 'verdict-bar--tor' : 'verdict-bar--clean'}`}>
          <div className="verdict-left">
            <div className="verdict-icon-wrap">{torCount > 0 ? <FaTimesCircle /> : <FaCheckCircle />}</div>
            <div>
              <div className="verdict-text">{torCount > 0 ? `${torCount} Tor Flow${torCount > 1 ? 's' : ''} Detected` : 'No Tor Traffic Detected'}</div>
              <div className="verdict-sub">
                {torCount > 0
                  ? `${totalFlows} flows analyzed · ${avgConf.toFixed(1)}% avg confidence · ${engine === 'RL' ? 'DQN Agent' : 'RandomForest'}`
                  : `All ${totalFlows} flows appear clean · ${engine === 'RL' ? 'DQN Agent' : 'RandomForest'} engine`}
              </div>
            </div>
          </div>
          {meta.case_id && <code className="case-id">CASE {meta.case_id}</code>}
        </div>

        {/* Info bar */}
        <div className="info-bar">
          <FaInfoCircle style={{ color: 'var(--c-accent)', flexShrink: 0 }} />
          <span>
            <b>Reading results:</b> Each "flow" is a unique (source IP → destination IP) conversation.
            Confidence ≥ 70% = high confidence Tor. The <em>Q-margin</em> is the RL agent's certainty: positive = leans Tor, negative = leans safe.
          </span>
        </div>

        {/* Engine comparison */}
        {rlData && (
          <Collapsible title="Engine Comparison — RF vs DQN" icon={<FaChartLine />} defaultOpen={true} badge="Side-by-side">
            <div className="compare-grid">
              <div className="compare-panel">
                <div className="compare-name"><FaBrain /> RandomForest</div>
                <p>Analyzes all 13 features simultaneously with 100 decision trees voting. Fast, batch, one-shot.</p>
                <div className="compare-nums">
                  <span><b>{data.summary?.tor_flows_detected ?? 0}</b> detections</span>
                  <span><b>{(data.summary?.overall_confidence ?? 0).toFixed(1)}%</b> avg conf</span>
                </div>
              </div>
              <div className="compare-vs">vs</div>
              <div className="compare-panel compare-panel-rl">
                <div className="compare-name"><FaRobot /> DQN Agent (RL)</div>
                <p>Watches packets arrive one window at a time. Decides when it's confident enough — trades speed for precision.</p>
                <div className="compare-nums">
                  <span><b>{rlData.summary?.tor_flows_detected ?? 0}</b> detections</span>
                  <span><b>{(rlData.summary?.overall_confidence ?? 0).toFixed(1)}%</b> avg conf</span>
                </div>
              </div>
            </div>
          </Collapsible>
        )}

        {/* Findings */}
        {findings.length > 0 && (
          <Collapsible title="Detected Tor Flows" icon={<FaNetworkWired />} defaultOpen={true} badge={`${findings.length} finding${findings.length > 1 ? 's' : ''}`}>
            {findings.map((f, idx) => (
              <div key={idx} className="finding">
                <div className="finding-top">
                  <span className="finding-num-badge">#{idx + 1}</span>
                  <span className="finding-method">{f.detection_method || 'ML Classifier'}</span>
                  <span className={`finding-conf ${f.confidence >= 80 ? 'fconf-high' : f.confidence >= 60 ? 'fconf-med' : 'fconf-low'}`}>
                    {f.confidence?.toFixed(1)}%
                  </span>
                </div>
                {/* Circuit diagram */}
                <div className="circuit">
                  <div className="circuit-node circuit-origin">
                    <span className="cn-label">Tor Client</span>
                    <code className="cn-ip">{f.origin_ip}</code>
                    <span className="cn-hint">Origin device</span>
                  </div>
                  <div className="circuit-path">
                    <div className="circuit-line" />
                    <span className="circuit-path-label">encrypted circuit</span>
                  </div>
                  <div className="circuit-node circuit-guard">
                    <span className="cn-label">Guard Relay</span>
                    <code className="cn-ip">🧅</code>
                    <span className="cn-hint">Entry node</span>
                  </div>
                  <div className="circuit-path">
                    <div className="circuit-line" />
                    <span className="circuit-path-label">exit connection</span>
                  </div>
                  <div className="circuit-node circuit-exit">
                    <span className="cn-label">Exit Node</span>
                    <code className="cn-ip">{f.exit_ip}</code>
                    <span className="cn-hint">Destination</span>
                  </div>
                </div>
                <div className="finding-meta-row">
                  {[
                    ['Duration', `${f.duration?.toFixed(2)}s`],
                    ['Packets', f.packet_count ?? '—'],
                    ['Start', f.start_time_iso ? new Date(f.start_time_iso).toLocaleString() : '—'],
                    ['Fingerprint', f.temporal_fingerprint || '—'],
                    f.rl_steps_taken != null ? ['RL Steps', f.rl_steps_taken] : null,
                    f.q_value_margin != null ? ['Q-Margin', `${f.q_value_margin > 0 ? '+' : ''}${f.q_value_margin?.toFixed(4)}`] : null,
                  ].filter(Boolean).map(([k, v]) => (
                    <div key={k} className="fmeta"><span className="fmeta-k">{k}</span><span className={`fmeta-v ${k === 'Q-Margin' ? (f.q_value_margin > 0 ? 'q-pos' : 'q-neg') : ''}`}>{v}</span></div>
                  ))}
                </div>
                {/* Q-value bars */}
                {f.final_q_values && (
                  <div className="q-panel">
                    <div className="q-panel-hd"><FaRobot size={10}/> RL Agent Q-Values</div>
                    {[
                      { key: 'observe', label: '👁 Observe', color: 'var(--c-accent)' },
                      { key: 'classify_tor', label: '🧅 Tor', color: 'var(--c-alert)' },
                      { key: 'classify_not_tor', label: '✓ Safe', color: 'var(--c-ok)' },
                    ].map(({ key, label, color }) => {
                      const val = f.final_q_values[key] ?? 0;
                      const allV = Object.values(f.final_q_values);
                      const mx = Math.max(...allV.map(Math.abs), 0.1);
                      const pct = Math.max(4, ((val + mx) / (2 * mx)) * 100);
                      return (
                        <div key={key} className="qbar-row">
                          <span className="qbar-label">{label}</span>
                          <div className="qbar-track"><div className="qbar-fill" style={{ width: `${pct}%`, background: color }} /></div>
                          <code className="qbar-val">{val.toFixed(4)}</code>
                        </div>
                      );
                    })}
                  </div>
                )}
                {/* Feature snapshot */}
                {f.feature_snapshot && Object.keys(f.feature_snapshot).length > 0 && (
                  <Collapsible title="Feature Snapshot" icon={<FaEye size={11}/>} badge="13 features">
                    <p className="feat-note">Normalized values at time of classification. Higher = stronger signal for that feature.</p>
                    <div className="feat-snap">
                      {Object.entries(f.feature_snapshot).map(([k, v]) => (
                        <div key={k} className="fs-cell">
                          <span className="fs-name">{k}</span>
                          <div className="fs-track"><div className="fs-fill" style={{ width: `${Math.min(Math.abs(v) * 100, 100)}%` }} /></div>
                          <code className="fs-val">{v.toFixed(4)}</code>
                        </div>
                      ))}
                    </div>
                  </Collapsible>
                )}
                {/* RL Decision timeline */}
                {f.rl_decision_timeline?.length > 0 && (
                  <Collapsible title="RL Agent Step-by-Step Reasoning" icon={<FaChartLine size={11}/>} badge={`${f.rl_decision_timeline.length} steps`}>
                    <p className="feat-note">Each step: 👁 = gather more data, 🧅 = decided Tor, ✓ = decided safe.</p>
                    <div className="timeline">
                      {f.rl_decision_timeline.map((s, si) => (
                        <div key={si} className={`tl-step ${s.action_id === 0 ? 'tl-obs' : s.action_id === 1 ? 'tl-tor' : 'tl-safe'}`}>
                          <span className="tl-n">Step {s.step}</span>
                          <span className="tl-icon">{s.action_id === 0 ? '👁' : s.action_id === 1 ? '🧅' : '✓'}</span>
                          <span className="tl-act">{s.action}</span>
                          {s.q_values && <span className="tl-q">Q(Tor)={s.q_values.classify_tor?.toFixed(3)} Q(¬Tor)={s.q_values.classify_not_tor?.toFixed(3)}</span>}
                        </div>
                      ))}
                    </div>
                  </Collapsible>
                )}
              </div>
            ))}
          </Collapsible>
        )}

        {/* RL Decision log */}
        {timelines.length > 0 && (
          <Collapsible title="RL Agent — All Flow Decisions" icon={<FaRobot />} badge={`${timelines.length} flows`}>
            <p className="feat-note">Full decision log. Q-margin: positive = leans Tor, negative = leans safe.</p>
            <div className="dt-wrap">
              <table className="dt">
                <thead><tr><th>Flow</th><th>Pkts</th><th>Steps</th><th>Verdict</th><th>Conf</th><th>Q-Margin</th><th>Q(Tor)</th><th>Q(¬Tor)</th><th>Trend</th></tr></thead>
                <tbody>
                  {timelines.slice(0, 30).map((t, i) => (
                    <tr key={i} className={t.classified_as === 'TOR' ? 'dt-tor' : ''}>
                      <td><code>{t.flow}</code></td>
                      <td>{t.packet_count ?? '—'}</td>
                      <td>{t.steps}</td>
                      <td><span className={`verdict-chip ${t.classified_as === 'TOR' ? 'vc-tor' : 'vc-safe'}`}>{t.classified_as === 'TOR' ? 'Tor' : 'Safe'}</span></td>
                      <td><b>{t.confidence?.toFixed(1)}%</b></td>
                      <td className={t.q_margin > 0 ? 'q-pos' : 'q-neg'}>{t.q_margin > 0 ? '+' : ''}{t.q_margin?.toFixed(3) ?? '—'}</td>
                      <td><code>{t.final_q_values?.classify_tor?.toFixed(3) ?? '—'}</code></td>
                      <td><code>{t.final_q_values?.classify_not_tor?.toFixed(3) ?? '—'}</code></td>
                      <td><QSparkline qHistory={t.q_history} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Collapsible>
        )}

        {/* Network map */}
        {graph.links?.length > 0 && (
          <Collapsible title="Network Flow Map" icon={<FaNetworkWired />} badge={`${graph.links.length} connection(s)`}>
            {graph.links.map((l, i) => (
              <div key={i} className="nmap-row">
                <div className="nmap-node nmap-src"><span className="nmap-tag">Client</span><code>{l.source}</code></div>
                <div className="nmap-mid"><div className="nmap-line" /><span className="nmap-meta">{l.flows} flow(s) · {l.avg_conf?.toFixed(1)}% conf</span><div className="nmap-arrow">▶</div></div>
                <div className="nmap-node nmap-exit"><span className="nmap-tag">Exit Node</span><code>{l.target}</code></div>
              </div>
            ))}
          </Collapsible>
        )}

        {findings.length === 0 && (
          <div className="no-findings"><FaCheckCircle style={{ color: 'var(--c-ok)', fontSize: 36 }} /><h3>No Tor Traffic Found</h3><p>{totalFlows} flows analyzed — all appear clean.</p></div>
        )}

        <div className="result-btns">
          <button onClick={downloadReport} className="btn-primary"><FaFileDownload /> Download PDF Report</button>
          <button onClick={() => { setAnalysisResult(null); setFile(null); setError(null); setView('home'); }} className="btn-sec"><FaSyncAlt /> Analyze Another</button>
        </div>
      </div>
    );
  };

  /* ══ HISTORY ══ */
  const renderHistory = () => (
    <div className="history">
      <div className="sec-label">case log</div>
      <h2 className="sec-h2">Case History</h2>
      {history.length === 0 && <div className="no-findings"><p>No cases logged yet.</p></div>}
      <div className="history-grid">
        {history.map(c => (
          <div key={c.case_id} className="h-card">
            <div className="h-card-top"><code className="h-case-id">#{c.case_id}</code><span className="h-ts">{new Date(c.timestamp).toLocaleString()}</span></div>
            <div className="h-file">{c.pcap_source}</div>
            <div className="h-stats"><span><b>{c.tor_flows_detected}</b> Tor flows</span><span><b>{c.overall_confidence?.toFixed(1)}%</b> confidence</span></div>
            {c.sample_flows?.length > 0 && (
              <div className="h-flows">
                {c.sample_flows.slice(0, 2).map((f, i) => (
                  <div key={i} className="h-flow"><code>{f.origin_ip}</code>→<code>{f.exit_ip}</code><span className="h-fc">{f.confidence?.toFixed(1)}%</span></div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
      <button className="btn-sec" onClick={() => setView('home')}><FaUpload /> Back</button>
    </div>
  );

  return (
    <div className="app">
      <header className="hdr">
        <div className="hdr-in">
          <div className="hdr-brand">
            <FaShieldAlt className="hdr-logo" />
            <span className="hdr-name">OnionTrace</span>
            <span className="hdr-ver">v2.0</span>
          </div>
          <nav className="hdr-nav">
            {[
              { id: 'home', label: 'Analyze', icon: <FaSearch size={12}/> },
              { id: 'live', label: 'Live Capture', icon: <FaWifi size={12}/>, hot: true },
              { id: 'history', label: 'History', icon: <FaHistory size={12}/>, fn: loadHistory },
            ].map(t => (
              <button key={t.id}
                className={`nav-btn ${view === t.id ? 'nav-btn--on' : ''}`}
                onClick={t.fn || (() => setView(t.id))}>
                {t.icon} {t.label}
                {t.hot && <span className="nav-live-dot" />}
              </button>
            ))}
            <div className={`rl-pill ${rlStatus?.rl_model_available ? 'rl-pill--ok' : 'rl-pill--off'}`}>
              <FaRobot size={10}/> {rlStatus?.rl_model_available ? 'RL Ready' : 'RL Off'}
            </div>
          </nav>
        </div>
      </header>

      <main className="main-content">
        {view === 'home' && renderHome()}
        {view === 'results' && analysisResult && renderResults()}
        {view === 'live' && <LiveCapture />}
        {view === 'history' && renderHistory()}
      </main>

      <footer className="ftr">
        <FaShieldAlt size={12}/> OnionTrace v2.0 &nbsp;·&nbsp; ML + RL Tor Detection &nbsp;·&nbsp; ISCX Tor/NonTor Dataset
      </footer>
    </div>
  );
}
