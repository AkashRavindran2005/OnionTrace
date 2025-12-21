import React, { useState } from 'react';
import './App.css';
import {
  FaShieldAlt,
  FaUpload,
  FaHistory,
  FaFileDownload,
  FaSyncAlt,
} from 'react-icons/fa';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';

export default function App() {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [error, setError] = useState(null);
  const [view, setView] = useState('upload'); // 'upload' | 'results' | 'history'
  const [history, setHistory] = useState([]);
  const [timeCorrelations, setTimeCorrelations] = useState([]);

  

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
      setTimeCorrelations(data.data?.time_correlations || []);
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
          className="btn-primary btn-with-icon"
        >
          {loading ? (
            'Analyzing…'
          ) : (
            <>
              <FaUpload className="btn-icon" />
              <span>Start Analysis</span>
            </>
          )}
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

<<<<<<< Updated upstream
        {/* Findings list */}
{/* Time-Based Correlation */}
       {/* Time-Based Correlation */}
=======
>>>>>>> Stashed changes
        <div className="findings-section">
          <h3>Time-Based Correlation (Entry ↔ Exit)</h3>

          {timeCorrelations.length === 0 ? (
            <p className="no-results">
              No correlatable entry–exit flows observed at this capture point.
            </p>
          ) : (
            timeCorrelations.map((c, idx) => {
              const entry = findings.find(
                f => f.origin_ip === c.entry_origin_ip
              );
              const exit = findings.find(
                f => f.exit_ip === c.exit_destination_ip
              );

              if (!entry || !exit) return null;

              return (
                <div key={idx} className="finding-card">
                  <div className="circuit-header">
                    <h4>Correlation #{idx + 1}</h4>
                    <span className="confidence-badge">
                      {(c.correlation_confidence * 100).toFixed(1)}%
                    </span>
                  </div>

                  {/* Timeline */}
                  <div className="timeline">
                    <div className="timeline-bar">
                      <div
                        className="timeline-segment"
                        title={`${entry.start_time_iso} → ${entry.end_time_iso}`}
                      />
                    </div>
                  </div>

                  <div className="circuit-diagram">
                    <div className="node origin-node">
                      <span className="label">Entry Origin</span>
                      <code>{c.entry_origin_ip}</code>
                    </div>
                    <div className="arrow">⇄</div>
                    <div className="node exit-node">
                      <span className="label">Exit Destination</span>
                      <code>{c.exit_destination_ip}</code>
                    </div>
                  </div>

                  <div className="finding-details">
                    <div className="detail-row">
                      <span className="label">Temporal Match:</span>
                      <span>{c.temporal_match ? 'Yes' : 'No'}</span>
                    </div>

                    <div className="detail-row">
                      <span className="label">Entry Start:</span>
                      <span>{new Date(entry.start_time_iso).toLocaleString()}</span>
                    </div>

                    <div className="detail-row">
                      <span className="label">Entry End:</span>
                      <span>{new Date(entry.end_time_iso).toLocaleString()}</span>
                    </div>

                    <div className="detail-row">
                      <span className="label">Entry Duration:</span>
                      <span>{entry.duration.toFixed(2)} seconds</span>
                    </div>

                    <div className="detail-row">
                      <span className="label">Entry Fingerprint:</span>
                      <code>{c.entry_fingerprint}</code>
                    </div>

                    <div className="detail-row">
                      <span className="label">Exit Fingerprint:</span>
                      <code>{c.exit_fingerprint}</code>
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>



        <div className="actions">
          <button onClick={downloadReport} className="btn-primary btn-with-icon">
            <FaFileDownload className="btn-icon" />
            <span>Download Forensic Report (PDF)</span>
          </button>
          <button
            onClick={() => {
              setAnalysisResult(null);
              setFile(null);
              setError(null);
              setView('upload');
            }}
            className="btn-secondary btn-with-icon"
          >
            <FaSyncAlt className="btn-icon" />
            <span>Analyze Another File</span>
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
      <div className="actions history-actions">
        <button
          className="btn-secondary btn-with-icon"
          onClick={() => setView('upload')}
        >
          <FaUpload className="btn-icon" />
          <span>Back to Upload</span>
        </button>
      </div>
    </div>
  );

  return (
    <div className="app">
      <header className="header">
        <div className="header-top">
          <div className="title-wrap">
            <FaShieldAlt className="logo-icon" />
            <h1>OnionTrace</h1>
          </div>
          <div className="header-actions">
            <button
              className="btn-secondary btn--sm btn-with-icon"
              onClick={() => {
                setAnalysisResult(null);
                setView('upload');
              }}
            >
              <FaUpload className="btn-icon" />
              <span>Upload</span>
            </button>
            <button
              className="btn-secondary btn--sm btn-with-icon"
              onClick={loadHistory}
            >
              <FaHistory className="btn-icon" />
              <span>Case History</span>
            </button>
          </div>
        </div>

        <p className="header-subtitle">
          ML-Based TOR Traffic Classification, Temporal Fingerprinting, Case History &amp; Forensic Reporting
        </p>
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
