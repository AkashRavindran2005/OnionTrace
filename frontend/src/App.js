import React, { useState } from 'react';
import './App.css';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';

export default function App() {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [error, setError] = useState(null);
  const [view, setView] = useState('upload'); // 'upload' | 'results' | 'history'
  const [history, setHistory] = useState([]);

  const handleFileSelect = (e) => {
    setFile(e.target.files?.[0] || null);
    setError(null);
  };

  const handleAnalyze = async () => {
    if (!file) {
      setError('Please select a PCAP file');
      return;
    }

    setLoading(true);
    setError(null);

    const formData = new FormData();
    formData.append('pcap', file);

    try {
      const response = await fetch(`${API_URL}/api/analyze`, {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.error || 'Analysis failed');
      }

      const data = await response.json();
      setAnalysisResult(data);
      setView('results');
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const downloadReport = async () => {
    if (!analysisResult?.data?.findings) return;

    try {
      const response = await fetch(`${API_URL}/api/report/pdf`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          findings: analysisResult.data.findings,
          metadata: analysisResult.data.metadata || {},
          graph: analysisResult.data.graph || {},
        }),
      });

      if (!response.ok) throw new Error('Report generation failed');

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `OnionTrace_Report_${Date.now()}.pdf`;
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      setError('Failed to download report: ' + err.message);
    }
  };

  const loadHistory = async () => {
    try {
      const res = await fetch(`${API_URL}/api/history`);
      if (!res.ok) throw new Error('Failed to load history');
      const data = await res.json();
      setHistory(data.cases || []);
      setView('history');
    } catch (err) {
      setError(err.message);
    }
  };

  const renderUploadView = () => (
    <div className="upload-section">
      <div className="upload-box">
        <h2>Upload PCAP File</h2>
        <input
          type="file"
          accept=".pcap,.pcapng"
          onChange={handleFileSelect}
          className="file-input"
          disabled={loading}
        />
        {file && <p className="file-name">Selected: {file.name}</p>}
        <button
          onClick={handleAnalyze}
          disabled={!file || loading}
          className="btn-primary"
        >
          {loading ? 'Analyzing...' : 'Start Analysis'}
        </button>
        {error && <p className="error">{error}</p>}
      </div>

      <div className="info-section">
        <h3>How OnionTrace Works</h3>
        <ol>
          <li>
            <strong>Parses PCAP:</strong> Extracts packet/flow metadata.
          </li>
          <li>
            <strong>ML Classifier:</strong> RandomForest model trained on Tor/NonTor flows.
          </li>
          <li>
            <strong>Temporal Fingerprinting:</strong> Builds a fingerprint from inter-arrival times and burst patterns.
          </li>
          <li>
            <strong>Network Map:</strong> Aggregates Tor-suspect flows into a client → Tor endpoint map.
          </li>
          <li>
            <strong>Forensic Output:</strong> Generates a PDF report for case files.
          </li>
        </ol>
      </div>
    </div>
  );

  const renderResultsView = () => {
    const summary = analysisResult.data.summary || {};
    const findings = analysisResult.data.findings || [];
    const graph = analysisResult.data.graph || { nodes: [], links: [] };
    const meta = analysisResult.data.metadata || {};

    const torFlowsDetected = summary.tor_flows_detected ?? findings.length;
    const avgConf = summary.overall_confidence ?? 0;

    return (
      <div className="results-section">
        <div className="summary-card">
          <h2>Analysis Complete</h2>
          <div className="summary-stats">
            <div className="stat">
              <h4>{torFlowsDetected}</h4>
              <p>TOR Flows Detected</p>
            </div>
            <div className="stat">
              <h4>{avgConf.toFixed(1)}%</h4>
              <p>Avg Confidence</p>
            </div>
            <div className="stat">
              <h4>{findings.length}</h4>
              <p>Flow(s) Classified as TOR</p>
            </div>
          </div>
          {meta.case_id && (
            <p className="case-id">Case ID: {meta.case_id}</p>
          )}
        </div>

        {/* Network Map */}
        <div className="network-map">
          <h3>Network Map (Tor-Suspect Flows)</h3>
          {graph.links && graph.links.length > 0 ? (
            graph.links.map((link, idx) => (
              <div key={idx} className="link-row">
                <code>{link.source}</code>
                <span className="arrow">→</span>
                <code>{link.target}</code>
                <span className="meta">
                  {link.flows} flow(s), avg {link.avg_conf.toFixed(1)}% conf
                </span>
              </div>
            ))
          ) : (
            <p className="no-results">No Tor-suspect flows found for mapping.</p>
          )}
        </div>

        {/* Findings list */}
        <div className="findings-section">
          <h3>ML TOR Flow Findings</h3>
          {findings.length === 0 && (
            <p className="no-results">No TOR flows detected in this capture.</p>
          )}
          {findings.map((finding, idx) => (
            <div key={idx} className="finding-card">
              <div className="circuit-header">
                <h4>Flow #{idx + 1}</h4>
                <span className="confidence-badge">
                  {finding.confidence.toFixed(1)}%
                </span>
              </div>

              <div className="circuit-diagram">
                <div className="node origin-node">
                  <span className="label">Origin</span>
                  <code>{finding.origin_ip}</code>
                </div>
                <div className="arrow">→</div>
                <div className="node exit-node">
                  <span className="label">Exit / Peer</span>
                  <code>{finding.exit_ip}</code>
                </div>
              </div>

              <div className="finding-details">
                <div className="detail-row">
                  <span className="label">Temporal Fingerprint:</span>
                  <code>{finding.temporal_fingerprint}</code>
                </div>
                <div className="detail-row">
                  <span className="label">ML Probability:</span>
                  <span>{finding.ml_probability.toFixed(4)}</span>
                </div>
                <div className="detail-row">
                  <span className="label">Detection Method:</span>
                  <span>{finding.detection_method}</span>
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="actions">
          <button onClick={downloadReport} className="btn-primary">
            📥 Download Forensic Report (PDF)
          </button>
          <button
            onClick={() => {
              setAnalysisResult(null);
              setFile(null);
              setError(null);
              setView('upload');
            }}
            className="btn-secondary"
          >
            ↺ Analyze Another File
          </button>
        </div>
      </div>
    );
  };

  const renderHistoryView = () => (
    <div className="history-section">
      <h2>Case History</h2>
      {history.length === 0 && (
        <p className="no-results">No cases logged yet.</p>
      )}
      {history.map((c) => (
        <div key={c.case_id} className="history-card">
          <div className="history-header">
            <h4>Case #{c.case_id}</h4>
            <span className="timestamp">
              {new Date(c.timestamp).toLocaleString()}
            </span>
          </div>
          <div className="history-body">
            <div className="detail-row">
              <span className="label">PCAP:</span>
              <span>{c.pcap_source}</span>
            </div>
            <div className="detail-row">
              <span className="label">TOR Flows Detected:</span>
              <span>{c.tor_flows_detected}</span>
            </div>
            <div className="detail-row">
              <span className="label">Avg Confidence:</span>
              <span>{c.overall_confidence.toFixed(1)}%</span>
            </div>
          </div>
          {c.sample_flows && c.sample_flows.length > 0 && (
            <div className="history-samples">
              <span className="label">Sample Flows:</span>
              {c.sample_flows.map((f, idx) => (
                <div key={idx} className="sample-row">
                  <code>{f.origin_ip}</code>
                  <span className="arrow">→</span>
                  <code>{f.exit_ip}</code>
                  <span className="meta">
                    {f.confidence.toFixed(1)}% | FP: {f.temporal_fingerprint}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      ))}
      <div className="actions">
        <button
          className="btn-secondary"
          onClick={() => setView('upload')}
        >
          ← Back to Upload
        </button>
      </div>
    </div>
  );

  return (
    <div className="app">
      <header className="header">
        <h1>🧅 OnionTrace</h1>
        <p>
          ML-Based TOR Traffic Classification, Temporal Fingerprinting, Case History & Forensic Reporting
        </p>
        <div className="header-actions">
          <button
            className="btn-secondary small"
            onClick={() => {
              setAnalysisResult(null);
              setView('upload');
            }}
          >
            ⬆ Upload
          </button>
          <button
            className="btn-secondary small"
            onClick={loadHistory}
          >
            📚 Case History
          </button>
        </div>
      </header>

      <main className="container">
        {view === 'upload' && !analysisResult && renderUploadView()}
        {view === 'results' && analysisResult && renderResultsView()}
        {view === 'history' && renderHistoryView()}
      </main>

      <footer className="footer">
        <p>OnionTrace v2.0 | ML TOR Detection | Team Cybroskis</p>
      </footer>
    </div>
  );
}
