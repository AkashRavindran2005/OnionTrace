import React, { useState, useEffect, useCallback } from 'react';
import './App.css';
import {
  FaShieldAlt,
  FaUpload,
  FaHistory,
  FaFileDownload,
  FaSyncAlt,
  FaBrain,
  FaRobot,
  FaNetworkWired,
  FaChartLine,
  FaSearch,
  FaEye,
  FaCheckCircle,
  FaTimesCircle,
  FaCogs,
  FaInfoCircle,
  FaChevronDown,
  FaChevronUp,
} from 'react-icons/fa';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';

/* ────────────────────── tiny inline sparkline ────────────────────── */
function QSparkline({ qHistory }) {
  if (!qHistory || qHistory.length === 0) return null;
  const w = 120, h = 28, pad = 2;
  const torVals = qHistory.map(q => q.classify_tor);
  const notVals = qHistory.map(q => q.classify_not_tor);
  const all = [...torVals, ...notVals];
  const min = Math.min(...all) - 0.1;
  const max = Math.max(...all) + 0.1;
  const range = max - min || 1;
  const x = (i) => pad + (i / (qHistory.length - 1 || 1)) * (w - 2 * pad);
  const y = (v) => h - pad - ((v - min) / range) * (h - 2 * pad);
  const pathFor = (vals) => vals.map((v, i) => `${i === 0 ? 'M' : 'L'}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(' ');

  return (
    <svg width={w} height={h} className="q-sparkline">
      <path d={pathFor(torVals)} fill="none" stroke="var(--color-error)" strokeWidth="1.5" />
      <path d={pathFor(notVals)} fill="none" stroke="var(--color-success)" strokeWidth="1.5" />
    </svg>
  );
}

/* ────────────────────── collapsible panel ────────────────────── */
function Collapsible({ title, icon, children, defaultOpen = false, badge }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className={`collapsible ${open ? 'collapsible--open' : ''}`}>
      <button className="collapsible-header" onClick={() => setOpen(!open)}>
        <span className="collapsible-title">{icon}{title}</span>
        <span className="collapsible-right">
          {badge && <span className="collapsible-badge">{badge}</span>}
          {open ? <FaChevronUp size={12} /> : <FaChevronDown size={12} />}
        </span>
      </button>
      {open && <div className="collapsible-body">{children}</div>}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   Main App
   ═══════════════════════════════════════════════════════════════ */
export default function App() {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [error, setError] = useState(null);
  const [view, setView] = useState('upload');
  const [history, setHistory] = useState([]);
  const [analysisMode, setAnalysisMode] = useState('rf');
  const [rlStatus, setRlStatus] = useState(null);

  useEffect(() => { fetchRlStatus(); }, []);

  const fetchRlStatus = async () => {
    try {
      const res = await fetch(`${API_URL}/api/rl/status`);
      if (res.ok) setRlStatus(await res.json());
    } catch (_) { }
  };

  const handleFileSelect = (e) => { setFile(e.target.files?.[0] || null); setError(null); };

  /* ────────── analysis handler ────────── */
  const handleAnalyze = async () => {
    if (!file) { setError('Please select a PCAP file'); return; }
    setLoading(true); setError(null);
    const formData = new FormData();
    formData.append('pcap', file);

    try {
      let rfResult = null, rlResult = null;

      if (analysisMode === 'rf' || analysisMode === 'both') {
        const res = await fetch(`${API_URL}/api/analyze`, { method: 'POST', body: formData });
        if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'RF failed');
        rfResult = await res.json();
      }

      if (analysisMode === 'rl' || analysisMode === 'both') {
        const rlFD = new FormData(); rlFD.append('pcap', file);
        const res = await fetch(`${API_URL}/api/analyze/rl`, { method: 'POST', body: rlFD });
        if (!res.ok) {
          if (analysisMode === 'rl') throw new Error((await res.json().catch(() => ({}))).error || 'RL failed');
        } else { rlResult = await res.json(); }
      }

      const primary = rfResult || rlResult;
      if (!primary) throw new Error('No results');
      if (rlResult) primary.rl_data = rlResult.data;
      setAnalysisResult(primary);
      setView('results');
    } catch (err) { setError(err.message); }
    finally { setLoading(false); }
  };

  /* ────────── report download ────────── */
  const downloadReport = async () => {
    if (!analysisResult?.data?.findings) return;
    try {
      const res = await fetch(`${API_URL}/api/report/pdf`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ findings: analysisResult.data.findings, metadata: analysisResult.data.metadata || {}, graph: analysisResult.data.graph || {} }),
      });
      if (!res.ok) throw new Error('Report failed');
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url;
      a.download = `OnionTrace_Report_${Date.now()}.pdf`; a.click();
      window.URL.revokeObjectURL(url);
    } catch (err) { setError('Download failed: ' + err.message); }
  };

  const loadHistory = async () => {
    try {
      const res = await fetch(`${API_URL}/api/history`);
      if (!res.ok) throw new Error('History failed');
      setHistory((await res.json()).cases || []);
      setView('history');
    } catch (err) { setError(err.message); }
  };

  /* ═══════ UPLOAD VIEW ═══════ */
  const renderUploadView = () => (
    <div className="upload-section">
      <div className="upload-box">
        <h2><FaUpload className="section-icon" /> Upload PCAP File</h2>

        {/* Mode toggle */}
        <div className="mode-toggle">
          <span className="mode-label">Detection Engine</span>
          <div className="toggle-group">
            {[
              { id: 'rf', label: 'RF', icon: <FaBrain size={13} />, desc: 'RandomForest' },
              { id: 'rl', label: 'RL', icon: <FaRobot size={13} />, desc: 'DQN Agent' },
              { id: 'both', label: 'Both', icon: <><FaBrain size={11} /><span>+</span><FaRobot size={11} /></>, desc: 'Compare' },
            ].map(m => (
              <button key={m.id}
                className={`toggle-btn ${analysisMode === m.id ? 'toggle-btn--active' : ''}`}
                onClick={() => setAnalysisMode(m.id)}
                disabled={m.id !== 'rf' && rlStatus && !rlStatus.rl_model_available}
                title={m.desc}
              >{m.icon}<span className="toggle-text">{m.label}</span></button>
            ))}
          </div>
        </div>

        <input type="file" accept=".pcap,.pcapng" onChange={handleFileSelect}
          className="file-input" disabled={loading} />
        {file && <p className="file-name">📄 {file.name} ({(file.size / 1024).toFixed(1)} KB)</p>}

        <button onClick={handleAnalyze} disabled={!file || loading}
          className="btn-primary btn--lg btn--full-width">
          {loading ? <><span className="spinner" /> Analyzing…</> :
            <><FaSearch className="btn-icon" /> Start {analysisMode === 'rl' ? 'RL' : analysisMode === 'both' ? 'Dual' : 'RF'} Analysis</>}
        </button>
        {error && <p className="error">{error}</p>}
      </div>

      {/* "How it works" explainer */}
      <div className="info-section">
        <h3><FaInfoCircle className="section-icon" /> How OnionTrace Works</h3>

        <div className="explainer-cards">
          <div className="explainer-card">
            <div className="explainer-num">1</div>
            <div>
              <strong>PCAP Parsing</strong>
              <p>Reads raw packet captures and groups them into bidirectional network flows</p>
            </div>
          </div>
          <div className="explainer-card">
            <div className="explainer-num">2</div>
            <div>
              <strong>Feature Extraction</strong>
              <p>Computes 13 statistical features per flow: packet sizes, inter-arrival times (IATs), burst patterns, size ratios</p>
            </div>
          </div>
          <div className="explainer-card">
            <div className="explainer-num">3</div>
            <div>
              <strong>Classification</strong>
              <p><b>RF:</b> RandomForest classifier makes a one-shot prediction<br />
                <b>RL:</b> DQN agent observes features <em>sequentially</em> and chooses when to classify — learning the optimal accuracy/speed tradeoff</p>
            </div>
          </div>
          <div className="explainer-card">
            <div className="explainer-num">4</div>
            <div>
              <strong>Temporal Fingerprinting</strong>
              <p>Builds unique fingerprints from IAT patterns to correlate entry ↔ exit flows</p>
            </div>
          </div>
        </div>

        {/* RL Architecture */}
        <Collapsible title="RL Agent Architecture (DQN)" icon={<FaCogs className="section-icon" />} defaultOpen={false}
          badge="Deep Q-Network">
          <div className="arch-diagram">
            <div className="arch-row">
              <div className="arch-node arch-env">
                <span className="arch-label">Environment</span>
                <span className="arch-detail">TorFlowEnvironment</span>
                <span className="arch-sub">Sliding window of 8×13 features</span>
              </div>
              <div className="arch-arrow">→ state</div>
              <div className="arch-node arch-agent">
                <span className="arch-label">Agent</span>
                <span className="arch-detail">Dueling Double DQN</span>
                <span className="arch-sub">256→128→64 neurons, ε-greedy</span>
              </div>
              <div className="arch-arrow">→ action</div>
              <div className="arch-node arch-actions">
                <span className="arch-label">Actions</span>
                <div className="arch-action-list">
                  <span className="arch-action obs">👁 OBSERVE</span>
                  <span className="arch-action tor">🧅 TOR</span>
                  <span className="arch-action not">✓ NOT TOR</span>
                </div>
              </div>
            </div>
            <div className="arch-features">
              <span className="arch-feat-title">13 Features per Timestep:</span>
              <div className="arch-feat-grid">
                {['mean_size', 'std_size', 'min_size', 'max_size', 'mean_iat', 'std_iat',
                  'pkt_count', 'duration', '512_ratio', 'bursts', 'priv→pub', 'cv_iat', 'cv_size'
                ].map(f => <code key={f} className="arch-feat">{f}</code>)}
              </div>
            </div>
          </div>
        </Collapsible>
      </div>
    </div>
  );

  /* ═══════ RESULTS VIEW ═══════ */
  const renderResultsView = () => {
    if (!analysisResult?.data) return null;
    const data = analysisResult.data;
    const summary = data.summary || {};
    const findings = data.findings || [];
    const graph = data.graph || { nodes: [], links: [] };
    const meta = data.metadata || {};
    const rlData = analysisResult.rl_data || null;
    const rlMetrics = rlData?.rl_metrics || data?.rl_metrics || null;
    const timelines = rlMetrics?.decision_timelines || [];
    const torTimelines = timelines.filter(t => t.classified_as === 'TOR');
    const nonTorTimelines = timelines.filter(t => t.classified_as !== 'TOR');
    const engine = meta.engine || 'ML';

    return (
      <div className="results-section">

        {/* ── Summary Card ── */}
        <div className="summary-card">
          <div className="summary-header">
            <h2><FaShieldAlt className="section-icon" /> Analysis Complete</h2>
            <span className="engine-badge">{engine === 'RL' ? '🤖 RL Engine' : '🧠 RF Engine'}</span>
          </div>
          <div className="summary-stats">
            <div className="stat"><h4>{summary.total_flows_analyzed ?? '—'}</h4><p>Flows Analyzed</p></div>
            <div className="stat stat--highlight"><h4>{summary.tor_flows_detected ?? findings.length}</h4><p>TOR Detected</p></div>
            <div className="stat"><h4>{(summary.overall_confidence ?? 0).toFixed(1)}%</h4><p>Avg Confidence</p></div>
            {rlData && <div className="stat stat--rl"><h4>{rlData.summary?.tor_flows_detected ?? '—'}</h4><p>RL Detections</p></div>}
          </div>
          {meta.case_id && <p className="case-id">Case ID: {meta.case_id}</p>}
        </div>

        {/* ── RF vs RL Comparison ── */}
        {rlData && data.summary && (
          <Collapsible title="Engine Comparison: RF vs RL" icon={<FaChartLine className="section-icon" />}
            defaultOpen={true} badge="Side-by-Side">
            <div className="comparison-grid">
              <div className="comparison-card">
                <div className="comparison-icon"><FaBrain size={28} /></div>
                <h4>RandomForest</h4>
                <div className="comparison-metric"><span className="metric-val">{data.summary?.tor_flows_detected ?? 0}</span><span className="metric-label">detections</span></div>
                <div className="comparison-metric"><span className="metric-val">{(data.summary?.overall_confidence ?? 0).toFixed(1)}%</span><span className="metric-label">avg confidence</span></div>
                <p className="comparison-desc">One-shot classification: extracts features once and predicts immediately.</p>
              </div>
              <div className="comparison-vs">VS</div>
              <div className="comparison-card comparison-card--rl">
                <div className="comparison-icon"><FaRobot size={28} /></div>
                <h4>DQN Agent</h4>
                <div className="comparison-metric"><span className="metric-val">{rlData.summary?.tor_flows_detected ?? 0}</span><span className="metric-label">detections</span></div>
                <div className="comparison-metric"><span className="metric-val">{(rlData.summary?.overall_confidence ?? 0).toFixed(1)}%</span><span className="metric-label">avg confidence</span></div>
                <p className="comparison-desc">Sequential decision: observes packet windows and chooses the optimal moment to classify.</p>
              </div>
            </div>
          </Collapsible>
        )}

        {/* ── RL Decision Log (detailed) ── */}
        {timelines.length > 0 && (
          <Collapsible title="RL Agent Decision Log"
            icon={<FaRobot className="section-icon" />}
            defaultOpen={true}
            badge={`${timelines.length} flows`}>

            <div className="decision-legend">
              <span className="legend-item"><span className="legend-dot legend-dot--tor" /> Classified TOR</span>
              <span className="legend-item"><span className="legend-dot legend-dot--safe" /> Classified NOT-TOR</span>
              <span className="legend-item">Q-Margin: <code>Q(TOR) − Q(NOT_TOR)</code></span>
            </div>

            <div className="decision-table-wrap">
              <table className="decision-table">
                <thead>
                  <tr>
                    <th>Flow</th>
                    <th>Pkts</th>
                    <th>Steps</th>
                    <th>Verdict</th>
                    <th>Confidence</th>
                    <th>Q-Margin</th>
                    <th>Q(TOR)</th>
                    <th>Q(¬TOR)</th>
                    <th>Q Trend</th>
                  </tr>
                </thead>
                <tbody>
                  {timelines.slice(0, 30).map((t, i) => (
                    <tr key={i} className={t.classified_as === 'TOR' ? 'row--tor' : ''}>
                      <td><code>{t.flow}</code></td>
                      <td>{t.packet_count ?? '—'}</td>
                      <td>{t.steps}</td>
                      <td>
                        <span className={`verdict ${t.classified_as === 'TOR' ? 'verdict--tor' : 'verdict--safe'}`}>
                          {t.classified_as === 'TOR' ? <><FaTimesCircle size={11} /> TOR</> : <><FaCheckCircle size={11} /> Safe</>}
                        </span>
                      </td>
                      <td><strong>{t.confidence?.toFixed(1)}%</strong></td>
                      <td className={t.q_margin > 0 ? 'q-pos' : 'q-neg'}>
                        {t.q_margin > 0 ? '+' : ''}{t.q_margin?.toFixed(3) ?? '—'}
                      </td>
                      <td><code>{t.final_q_values?.classify_tor?.toFixed(3) ?? '—'}</code></td>
                      <td><code>{t.final_q_values?.classify_not_tor?.toFixed(3) ?? '—'}</code></td>
                      <td><QSparkline qHistory={t.q_history} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="decision-summary">
              <div className="decision-stat">
                <span className="decision-stat-val">{torTimelines.length}</span>
                <span className="decision-stat-label">Flagged TOR</span>
              </div>
              <div className="decision-stat">
                <span className="decision-stat-val">{nonTorTimelines.length}</span>
                <span className="decision-stat-label">Classified Safe</span>
              </div>
              <div className="decision-stat">
                <span className="decision-stat-val">
                  {(timelines.reduce((s, t) => s + t.steps, 0) / (timelines.length || 1)).toFixed(1)}
                </span>
                <span className="decision-stat-label">Avg Steps/Flow</span>
              </div>
            </div>
          </Collapsible>
        )}

        {/* ── Per-Finding Deep Dive ── */}
        {findings.length > 0 && (
          <Collapsible title="Detected TOR Flows — Deep Dive"
            icon={<FaNetworkWired className="section-icon" />}
            defaultOpen={true}
            badge={`${findings.length} finding(s)`}>

            {findings.map((f, idx) => (
              <div key={idx} className="finding-card">
                <div className="circuit-header">
                  <h4>Finding #{idx + 1}: {f.detection_method || 'ML'}</h4>
                  <span className="confidence-badge">{f.confidence?.toFixed(1)}%</span>
                </div>

                {/* Circuit diagram */}
                <div className="circuit-diagram">
                  <div className="node origin-node">
                    <span className="label">Origin</span>
                    <code>{f.origin_ip}</code>
                  </div>
                  <div className="arrow">→</div>
                  <div className="node guard-node">
                    <span className="label">Tor Guard</span>
                    <code>🧅</code>
                  </div>
                  <div className="arrow">→</div>
                  <div className="node exit-node">
                    <span className="label">Exit</span>
                    <code>{f.exit_ip}</code>
                  </div>
                </div>

                {/* Details grid */}
                <div className="finding-details">
                  <div className="detail-row">
                    <span className="label">Duration</span>
                    <span>{f.duration?.toFixed(2)}s</span>
                  </div>
                  <div className="detail-row">
                    <span className="label">Packets</span>
                    <span>{f.packet_count ?? '—'}</span>
                  </div>
                  <div className="detail-row">
                    <span className="label">Fingerprint</span>
                    <code>{f.temporal_fingerprint || 'N/A'}</code>
                  </div>
                  <div className="detail-row">
                    <span className="label">Start</span>
                    <span>{f.start_time_iso ? new Date(f.start_time_iso).toLocaleString() : '—'}</span>
                  </div>
                  {f.rl_steps_taken != null && (
                    <div className="detail-row">
                      <span className="label">RL Steps</span>
                      <span>{f.rl_steps_taken} observations</span>
                    </div>
                  )}
                  {f.q_value_margin != null && (
                    <div className="detail-row">
                      <span className="label">Q-Margin</span>
                      <span className={f.q_value_margin > 0 ? 'q-pos' : 'q-neg'}>
                        {f.q_value_margin > 0 ? '+' : ''}{f.q_value_margin.toFixed(4)}
                      </span>
                    </div>
                  )}
                </div>

                {/* Q-Values raw display */}
                {f.final_q_values && (
                  <div className="q-values-panel">
                    <span className="q-panel-title">Raw Q-Values at Classification:</span>
                    <div className="q-bar-group">
                      {[
                        { key: 'observe', label: '👁 Observe', color: 'var(--color-info)' },
                        { key: 'classify_tor', label: '🧅 TOR', color: 'var(--color-error)' },
                        { key: 'classify_not_tor', label: '✓ Safe', color: 'var(--color-success)' },
                      ].map(({ key, label, color }) => {
                        const val = f.final_q_values[key] ?? 0;
                        const allVals = Object.values(f.final_q_values);
                        const maxAbs = Math.max(...allVals.map(Math.abs), 0.1);
                        const pct = Math.max(5, ((val + maxAbs) / (2 * maxAbs)) * 100);
                        return (
                          <div key={key} className="q-bar-row">
                            <span className="q-bar-label">{label}</span>
                            <div className="q-bar-track">
                              <div className="q-bar-fill" style={{ width: `${pct}%`, background: color }} />
                            </div>
                            <code className="q-bar-val">{val.toFixed(4)}</code>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Feature snapshot */}
                {f.feature_snapshot && Object.keys(f.feature_snapshot).length > 0 && (
                  <Collapsible title="Feature Snapshot (Normalized)" icon={<FaEye size={12} />}
                    badge={`${Object.keys(f.feature_snapshot).length} features`}>
                    <div className="feature-grid">
                      {Object.entries(f.feature_snapshot).map(([k, v]) => (
                        <div key={k} className="feature-cell">
                          <span className="feature-name">{k}</span>
                          <div className="feature-bar-track">
                            <div className="feature-bar-fill"
                              style={{ width: `${Math.min(Math.abs(v) * 100, 100)}%` }} />
                          </div>
                          <code className="feature-val">{v.toFixed(4)}</code>
                        </div>
                      ))}
                    </div>
                  </Collapsible>
                )}

                {/* RL step-by-step timeline */}
                {f.rl_decision_timeline && f.rl_decision_timeline.length > 0 && (
                  <Collapsible title="Agent Decision Timeline" icon={<FaChartLine size={12} />}
                    badge={`${f.rl_decision_timeline.length} steps`}>
                    <div className="timeline-steps">
                      {f.rl_decision_timeline.map((s, si) => (
                        <div key={si} className={`timeline-step ${s.action_id === 0 ? 'step--observe' : s.action_id === 1 ? 'step--tor' : 'step--safe'}`}>
                          <span className="step-num">#{s.step}</span>
                          <span className="step-icon">{s.action_id === 0 ? '👁' : s.action_id === 1 ? '🧅' : '✓'}</span>
                          <span className="step-action">{s.action}</span>
                          {s.q_values && (
                            <span className="step-q" title={`Q(TOR)=${s.q_values.classify_tor} Q(¬TOR)=${s.q_values.classify_not_tor}`}>
                              Q: {s.q_values.classify_tor?.toFixed(2)} / {s.q_values.classify_not_tor?.toFixed(2)}
                            </span>
                          )}
                        </div>
                      ))}
                    </div>
                  </Collapsible>
                )}
              </div>
            ))}
          </Collapsible>
        )}

        {/* ── Network Map ── */}
        {graph.links && graph.links.length > 0 && (
          <Collapsible title="Network Map" icon={<FaNetworkWired className="section-icon" />}
            badge={`${graph.links.length} link(s)`}>
            <div className="network-links">
              {graph.links.map((l, i) => (
                <div key={i} className="link-row">
                  <code>{l.source}</code>
                  <span className="link-arrow">→</span>
                  <code>{l.target}</code>
                  <span className="link-meta">{l.flows} flow(s), {l.avg_conf?.toFixed(1)}% conf</span>
                </div>
              ))}
            </div>
          </Collapsible>
        )}

        {/* ── Actions ── */}
        <div className="actions">
          <button onClick={downloadReport} className="btn-primary btn-with-icon">
            <FaFileDownload className="btn-icon" /> Download Report (PDF)
          </button>
          <button onClick={() => { setAnalysisResult(null); setFile(null); setError(null); setView('upload'); }}
            className="btn-secondary btn-with-icon">
            <FaSyncAlt className="btn-icon" /> Analyze Another
          </button>
        </div>
      </div>
    );
  };

  /* ═══════ HISTORY VIEW ═══════ */
  const renderHistoryView = () => (
    <div className="history-section">
      <h2><FaHistory className="section-icon" /> Case History</h2>
      {history.length === 0 && <p className="no-results">No cases logged yet.</p>}
      {history.map(c => (
        <div key={c.case_id} className="history-card">
          <div className="history-header">
            <h4>Case #{c.case_id}</h4>
            <span className="timestamp">{new Date(c.timestamp).toLocaleString()}</span>
          </div>
          <div className="history-body">
            <div className="detail-row"><span className="label">PCAP:</span><span>{c.pcap_source}</span></div>
            <div className="detail-row"><span className="label">TOR Flows:</span><span>{c.tor_flows_detected}</span></div>
            <div className="detail-row"><span className="label">Avg Confidence:</span><span>{c.overall_confidence?.toFixed(1)}%</span></div>
          </div>
        </div>
      ))}
      <div className="actions">
        <button className="btn-secondary btn-with-icon" onClick={() => setView('upload')}>
          <FaUpload className="btn-icon" /> Back to Upload
        </button>
      </div>
    </div>
  );

  /* ═══════ RL Status Badge ═══════ */
  const rlBadge = rlStatus ? (
    <span className={`rl-status-badge ${rlStatus.rl_model_available ? 'rl-status--active' : 'rl-status--inactive'}`}>
      <FaRobot size={11} />
      {rlStatus.rl_model_available ? 'RL Ready' : 'RL Not Trained'}
    </span>
  ) : null;

  /* ═══════ RENDER ═══════ */
  return (
    <div className="app">
      <header className="header">
        <div className="header-top">
          <div className="title-wrap">
            <FaShieldAlt size={28} className="logo-icon" />
            <h1>OnionTrace</h1>
            {rlBadge}
          </div>
          <div className="header-actions">
            <button className={`btn-secondary btn--sm header-tab ${view === 'upload' ? 'header-tab--active' : ''}`}
              onClick={() => { setAnalysisResult(null); setView('upload'); }}>
              <FaUpload size={14} /> Upload
            </button>
            <button className={`btn-secondary btn--sm header-tab ${view === 'history' ? 'header-tab--active' : ''}`}
              onClick={loadHistory}>
              <FaHistory size={14} /> History
            </button>
          </div>
        </div>
        <p className="header-subtitle">ML + RL TOR Traffic Deanonymization · Temporal Fingerprinting · Forensic Reporting</p>
      </header>

      <main className="container">
        {view === 'upload' && !analysisResult && renderUploadView()}
        {view === 'results' && analysisResult && renderResultsView()}
        {view === 'history' && renderHistoryView()}
      </main>

      <footer className="footer">
        <p>OnionTrace v2.0 · ML + RL Tor Detection · Team Cybroskis</p>
      </footer>
    </div>
  );
}
