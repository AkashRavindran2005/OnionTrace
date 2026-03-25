from flask import Flask, request, jsonify, send_file
from werkzeug.utils import secure_filename
from time_correlation import correlate_flows
from onion_trace_backend import PCAPParser, CorrelationEngine, ForensicReporter
from ml_detector import MLPCAPAnalyzer
from rl_agent import RLAnalyzer
from rl_correlation import correlate_flows_rl
import json
import os
import uuid
from datetime import datetime
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    Image,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from io import BytesIO
from flask_cors import CORS
import networkx as nx
from reportlab.graphics.shapes import Drawing
from reportlab.graphics import renderPM

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB
app.config["UPLOAD_FOLDER"] = "/tmp/pcap_uploads"

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
CORS(app)

CASE_LOG = "case_history.jsonl"


def append_case_history(filename, ml_report):
    case_id = str(uuid.uuid4())[:8]
    summary = ml_report.get("summary", {})
    entry = {
        "case_id": case_id,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "pcap_source": os.path.basename(filename),
        "tor_flows_detected": summary.get("tor_flows_detected", 0),
        "overall_confidence": summary.get("overall_confidence", 0.0),
        "sample_flows": [
            {
                "origin_ip": f["origin_ip"],
                "exit_ip": f["exit_ip"],
                "confidence": f["confidence"],
                "temporal_fingerprint": f.get("temporal_fingerprint", ""),
            }
            for f in ml_report.get("findings", [])[:3]
        ],
    }
    with open(CASE_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return case_id


def generate_network_graph_image(graph_data):
    try:
        G = nx.DiGraph()
        
        if graph_data and graph_data.get("links"):
            for link in graph_data["links"]:
                source = link.get("source", "Unknown")
                target = link.get("target", "Unknown")
                G.add_edge(source, target, weight=link.get("flows", 1), conf=link.get("avg_conf", 0))
        
        if G.number_of_nodes() == 0:
            return None
        
        pos = nx.spring_layout(G, k=2, iterations=50, seed=42)
        
        drawing = Drawing(6*inch, 4*inch)
        
        for edge in G.edges(data=True):
            src, tgt, data = edge
            x1, y1 = pos[src]
            x2, y2 = pos[tgt]
            
            x1 = 0.5*inch + x1 * 2.5*inch
            y1 = 2*inch - y1 * 1.8*inch
            x2 = 0.5*inch + x2 * 2.5*inch
            y2 = 2*inch - y2 * 1.8*inch
            
            from reportlab.graphics.shapes import Line
            line = Line(x1, y1, x2, y2, strokeColor=colors.HexColor("#208090"), strokeWidth=1.5)
            drawing.add(line)
            
            conf = data.get("conf", 0)
            mid_x = (x1 + x2) / 2
            mid_y = (y1 + y2) / 2
            from reportlab.graphics.shapes import String
            label = String(mid_x, mid_y, f"{conf:.0f}%", fontSize=7, fillColor=colors.HexColor("#208090"))
            drawing.add(label)
        
        from reportlab.graphics.shapes import Circle
        for node in G.nodes():
            x, y = pos[node]
            x = 0.5*inch + x * 2.5*inch
            y = 2*inch - y * 1.8*inch
            
            circle = Circle(x, y, 0.15*inch, fillColor=colors.HexColor("#32B8C6"), strokeColor=colors.HexColor("#1F2121"), strokeWidth=2)
            drawing.add(circle)
            
            from reportlab.graphics.shapes import String
            label_text = node.split('.')[-2:] if '.' in node else node[:8]
            label_text = '.'.join(label_text) if isinstance(label_text, list) else label_text
            label = String(x - 0.3*inch, y - 0.25*inch, label_text, fontSize=6, fillColor=colors.black)
            drawing.add(label)
        
        img_buffer = BytesIO()
        renderPM.drawToFile(drawing, img_buffer, fmt="PNG")
        img_buffer.seek(0)
        return img_buffer
        
    except Exception as e:
        print(f"Graph generation error: {e}")
        return None


@app.route("/health", methods=["GET"])
def health():
    model_exists = os.path.exists("tor_detector_model.pkl")
    return jsonify(
        {
            "status": "operational",
            "version": "2.0",
            "detection_method": "ML-Based (RandomForest)",
            "model_available": model_exists,
        }
    )


@app.route("/api/analyze", methods=["POST"])
def analyze_pcap():
    print("DEBUG files keys:", list(request.files.keys()))
    if "pcap" not in request.files:
        return jsonify({"error": "No PCAP file provided"}), 400

    file = request.files["pcap"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    try:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)

        analyzer = MLPCAPAnalyzer()
        ml_report = analyzer.analyze_pcap_ml(filepath)

        correlations = correlate_flows(ml_report["findings"])
        ml_report["time_correlations"] = correlations

        if os.path.exists(filepath):
            os.remove(filepath)

        if "error" in ml_report:
            return jsonify({"error": ml_report["error"]}), 400

        ml_report["metadata"]["tool"] = "OnionTrace v2.0"
        ml_report["metadata"]["engine"] = "ML"
        ml_report["metadata"][
            "detection_method"
        ] = "RandomForest on temporal + size features"

        case_id = append_case_history(filename, ml_report)
        ml_report["metadata"]["case_id"] = case_id

        return jsonify(
            {
                "success": True,
                "data": ml_report,
                "analysis_results": ml_report.get("findings", []),
            }
        )

    except Exception as e:
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
        except Exception:
            pass
        return jsonify({"error": str(e)}), 500


@app.route("/api/report/pdf", methods=["POST"])
def generate_pdf_report():
    """
    Generate professional forensic PDF report from ML findings.
    Frontend should send:
      {
        "findings": [...],
        "metadata": {...},
        "graph": { "nodes": [...], "links": [...] }
      }
    """
    try:
        data = request.get_json(force=True)
        findings = data.get("findings", [])
        meta = data.get("metadata", {})
        graph = data.get("graph", {})

        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.75*inch, bottomMargin=0.75*inch, leftMargin=0.75*inch, rightMargin=0.75*inch)
        story = []
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Heading1"],
            fontSize=28,
            textColor=colors.HexColor("#1F2121"),
            spaceAfter=6,
            spaceBefore=0,
            alignment=0,
            fontName="Helvetica-Bold",
        )

        subtitle_style = ParagraphStyle(
            "Subtitle",
            parent=styles["Normal"],
            fontSize=12,
            textColor=colors.HexColor("#208090"),
            spaceAfter=12,
            spaceBefore=0,
            alignment=0,
            fontName="Helvetica-Bold",
        )

        heading2_style = ParagraphStyle(
            "CustomHeading2",
            parent=styles["Heading2"],
            fontSize=14,
            textColor=colors.HexColor("#1F2121"),
            spaceAfter=8,
            spaceBefore=10,
            alignment=0,
            fontName="Helvetica-Bold",
            borderPadding=0,
        )

        meta_style = ParagraphStyle(
            "Meta",
            parent=styles["Normal"],
            fontSize=9,
            textColor=colors.HexColor("#5A5A5A"),
            spaceAfter=3,
            spaceBefore=0,
        )

        body_style = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontSize=10,
            textColor=colors.HexColor("#2A2A2A"),
            spaceAfter=6,
            spaceBefore=0,
            alignment=4,  
        )

        story.append(Spacer(1, 0.3*inch))
        story.append(Paragraph("OnionTrace v1.0", title_style))
        story.append(Paragraph("ML-Based TOR Traffic Detection Report", subtitle_style))
        story.append(Spacer(1, 0.2*inch))

        meta_data = [
            f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"<b>Report Type:</b> Forensic Analysis & Network Intelligence",
            f"<b>Detection Engine:</b> RandomForest ML Classifier",
            f"<b>Model Status:</b> Active &amp; Operational",
        ]
        if meta.get("case_id"):
            meta_data.insert(0, f"<b>Case ID:</b> {meta['case_id']}")

        for line in meta_data:
            story.append(Paragraph(line, meta_style))

        story.append(Spacer(1, 0.3*inch))

        story.append(Paragraph("Executive Summary", heading2_style))

        tor_detected = len(findings)
        avg_conf = (
            sum(f.get("confidence", 0) for f in findings) / max(1, len(findings))
            if findings
            else 0
        )

        summary_text = (
            f"This forensic analysis identified <b>{tor_detected} probable TOR flow(s)</b> within the provided network capture. "
            f"The RandomForest classifier, trained on the ISCX Tor/NonTor dataset with 13 temporal and statistical features, "
            f"achieved an average confidence score of <b>{avg_conf:.1f}%</b> across detected flows. "
            f"The analysis employs packet size distributions, inter-arrival times (IAT), burst patterns, and flow duration metrics "
            f"to distinguish Tor traffic from legitimate encrypted protocols without breaking encryption."
        )
        story.append(Paragraph(summary_text, body_style))
        story.append(Spacer(1, 0.15*inch))

        metrics_data = [
            ["Metric", "Value"],
            ["TOR Flows Detected", str(tor_detected)],
            ["Average Confidence", f"{avg_conf:.1f}%"],
            ["Unique Origin IPs", str(len(set(f.get("origin_ip") for f in findings)))],
            ["Unique Exit Nodes", str(len(set(f.get("exit_ip") for f in findings)))],
        ]

        metrics_table = Table(metrics_data, colWidths=[2.5*inch, 1.5*inch])
        metrics_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#208090")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                    ("TOPPADDING", (0, 0), (-1, 0), 8),
                    ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#CCCCCC")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F9F9F9")]),
                    ("FONTSIZE", (0, 1), (-1, -1), 9),
                ]
            )
        )
        story.append(metrics_table)
        story.append(Spacer(1, 0.2*inch))

        if graph and graph.get("links") and len(graph["links"]) > 0:
            story.append(Paragraph("Network Topology & Flow Mapping", heading2_style))
            
            link_rows = [
                ["Origin IP", "Destination/Exit Node", "Flows", "Avg Confidence", "Classification"]
            ]
            for link in graph["links"]:
                link_rows.append(
                    [
                        link.get("source", "N/A")[:15],
                        link.get("target", "N/A")[:15],
                        str(link.get("flows", 0)),
                        f"{link.get('avg_conf', 0):.1f}%",
                        "Tor-Suspect" if link.get("avg_conf", 0) > 70 else "Low-Probability",
                    ]
                )

            link_table = Table(link_rows, colWidths=[1.2*inch, 1.4*inch, 0.7*inch, 1.1*inch, 1.1*inch])
            link_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F2121")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, 0), 9),
                        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                        ("TOPPADDING", (0, 0), (-1, 0), 8),
                        ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#DDDDDD")),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#FAFAFA")]),
                        ("FONTSIZE", (0, 1), (-1, -1), 8),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ]
                )
            )
            story.append(link_table)
            story.append(Spacer(1, 0.15*inch))

        story.append(PageBreak())
        story.append(Paragraph("Detailed Flow Analysis", heading2_style))
        story.append(Spacer(1, 0.1*inch))

        if not findings:
            story.append(Paragraph("No TOR flows detected in this capture.", body_style))
        else:
            for i, finding in enumerate(findings, 1):
                flow_header = (
                    f"Flow #{i} &ndash; "
                    f"{finding.get('origin_ip', 'N/A')} → {finding.get('exit_ip', 'N/A')}"
                )
                flow_header_style = ParagraphStyle(
                    f"FlowHeader{i}",
                    parent=styles["Heading3"],
                    fontSize=11,
                    textColor=colors.HexColor("#208090"),
                    spaceAfter=6,
                    spaceBefore=8,
                    fontName="Helvetica-Bold",
                )
                story.append(Paragraph(flow_header, flow_header_style))

                flow_data = [
                    ["Field", "Value"],
                    ["Origin IP", finding.get("origin_ip", "N/A")],
                    ["Exit Node IP", finding.get("exit_ip", "N/A")],
                    ["ML Confidence", f"{finding.get('confidence', 0):.1f}%"],
                    ["ML Probability Score", f"{finding.get('ml_probability', 0.0):.4f}"],
                    ["Temporal Fingerprint", finding.get("temporal_fingerprint", "N/A")[:30] + ("..." if len(finding.get("temporal_fingerprint", "")) > 30 else "")],
                    ["Start Time", finding.get("start_time_iso", "N/A")],
                    ["End Time", finding.get("end_time_iso", "N/A")],
                    ["Duration", f"{finding.get('duration', 0):.2f}s"],
                    ["Detection Method", "RandomForest ML Classifier"],
                ]

                flow_table = Table(flow_data, colWidths=[1.8*inch, 3.7*inch])
                flow_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#32B8C6")),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                            ("ALIGN", (0, 0), (0, -1), "LEFT"),
                            ("ALIGN", (1, 0), (1, -1), "LEFT"),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, 0), 9),
                            ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
                            ("TOPPADDING", (0, 0), (-1, 0), 6),
                            ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#DDDDDD")),
                            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#FAFAFA")]),
                            ("FONTSIZE", (0, 1), (-1, -1), 8),
                            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                            ("LEFTPADDING", (0, 0), (-1, -1), 6),
                            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                        ]
                    )
                )
                story.append(flow_table)
                story.append(Spacer(1, 0.12*inch))

                if i % 2 == 0 and i < len(findings):
                    story.append(Spacer(1, 0.1*inch))

        story.append(PageBreak())
        story.append(Paragraph("Technical Methodology", heading2_style))
        story.append(Spacer(1, 0.1*inch))

        methodology_sections = [
            (
                "<b>1. ML Model Architecture</b>",
                "OnionTrace v1.0 employs a RandomForest classifier with 100 decision trees, trained on the ISCX Tor/NonTor dataset. "
                "The model achieves high accuracy by leveraging 13 engineered features that capture temporal and statistical properties of network flows. "
                "These features are immune to encryption, enabling traffic classification without payload inspection."
            ),
            (
                "<b>2. Feature Engineering</b>",
                "Key features include: (a) Packet Size Distribution (forward/backward), (b) Inter-Arrival Times (IAT) statistics, "
                "(c) Burst patterns and flow duration, (d) Protocol-level indicators, (e) Private-to-public IP transitions. "
                "Research by Rimmer et al. and Gu et al. demonstrates that Tor exhibits distinctive temporal signatures distinct from other encrypted protocols."
            ),
            (
                "<b>3. Training Data</b>",
                "The classifier was trained on labeled Tor and Non-Tor flows from the ISCX dataset, ensuring balanced representation "
                "and statistical robustness. Validation was performed using 5-fold cross-validation with stratification."
            ),
            (
                "<b>4. Confidence Scoring</b>",
                "Confidence scores reflect the probability of a flow belonging to the Tor class. Scores above 70% are flagged as high-confidence detections. "
                "Scores 50–70% are considered moderate-confidence, while scores below 50% indicate low-probability Tor activity."
            ),
            (
                "<b>5. Limitations &amp; Considerations</b>",
                "This analysis assumes typical Tor usage patterns. Exotic Tor configurations, pluggable transports, or novel obfuscation techniques may evade detection. "
                "Additionally, other privacy-preserving protocols (e.g., I2P, Freenet) may exhibit similar temporal signatures and could produce false positives."
            ),
        ]

        for heading, text in methodology_sections:
            story.append(Paragraph(heading, styles["Heading3"]))
            story.append(Paragraph(text, body_style))
            story.append(Spacer(1, 0.08*inch))

        story.append(PageBreak())
        story.append(Paragraph("Report Summary & Recommendations", heading2_style))
        story.append(Spacer(1, 0.1*inch))

        recommendations = [
            f"<b>Total Detected Flows:</b> {tor_detected} TOR-classified flow(s)",
            f"<b>Average Confidence:</b> {avg_conf:.1f}%",
            f"<b>High-Confidence Detections:</b> {len([f for f in findings if f.get('confidence', 0) > 70])} flow(s)",
            f"<b>Report Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"<b>Tool Version:</b> OnionTrace v2.0",
        ]

        for rec in recommendations:
            story.append(Paragraph(rec, body_style))

        story.append(Spacer(1, 0.2*inch))
        story.append(Paragraph("<b>Recommendations:</b>", styles["Heading3"]))
        
        recommendations_text = [
            "1. Investigate high-confidence flows (>80%) for potential unauthorized Tor usage.",
            "2. Cross-reference detected IPs with threat intelligence databases and logs.",
            "3. Consider network policy adjustments if Tor access is not approved.",
            "4. Monitor temporal patterns for recurring or anomalous behavior.",
            "5. Correlate findings with DNS queries and proxy logs for deeper forensic analysis.",
        ]

        for text in recommendations_text:
            story.append(Paragraph(text, body_style))

        story.append(Spacer(1, 0.3*inch))
        story.append(Paragraph("This report is confidential and for authorized forensic use only.", meta_style))

        doc.build(story)
        buffer.seek(0)

        return send_file(
            buffer,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"OnionTrace_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
        )

    except Exception as e:
        print(f"PDF Generation Error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/history", methods=["GET"])
def get_history():
    history = []
    if os.path.exists(CASE_LOG):
        with open(CASE_LOG, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    history.append(json.loads(line))
                except Exception:
                    continue
    history.reverse()
    return jsonify({"cases": history})


# ---------------------------------------------------------------------------
# RL Endpoints
# ---------------------------------------------------------------------------

@app.route("/api/analyze/rl", methods=["POST"])
def analyze_pcap_rl():
    """Analyze a PCAP using the DQN RL agent."""
    if "pcap" not in request.files:
        return jsonify({"error": "No PCAP file provided"}), 400

    file = request.files["pcap"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    filepath = None
    try:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)

        rl_analyzer = RLAnalyzer()
        rl_report = rl_analyzer.analyze_pcap(filepath)

        if "error" in rl_report:
            return jsonify({"error": rl_report["error"]}), 400

        # RL-enhanced correlation
        correlations = correlate_flows_rl(rl_report.get("findings", []))
        rl_report["time_correlations"] = correlations

        case_id = append_case_history(filename, rl_report)
        rl_report["metadata"]["case_id"] = case_id

        return jsonify({
            "success": True,
            "data": rl_report,
            "analysis_results": rl_report.get("findings", []),
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if filepath and os.path.exists(filepath):
            try:
                os.remove(filepath)
            except Exception:
                pass


@app.route("/api/rl/train", methods=["POST"])
def train_rl_model():
    """
    Trigger RL model training.
    Expects JSON: { "tor_dir": "...", "non_tor_dir": "...", "episodes": 500 }
    """
    try:
        data = request.get_json(force=True)
        tor_dir = data.get("tor_dir")
        non_tor_dir = data.get("non_tor_dir")
        episodes = data.get("episodes", 500)

        if not tor_dir or not non_tor_dir:
            return jsonify({"error": "tor_dir and non_tor_dir are required"}), 400

        if not os.path.isdir(tor_dir):
            return jsonify({"error": f"tor_dir not found: {tor_dir}"}), 400
        if not os.path.isdir(non_tor_dir):
            return jsonify({"error": f"non_tor_dir not found: {non_tor_dir}"}), 400

        rl_analyzer = RLAnalyzer()
        metrics = rl_analyzer.train(tor_dir, non_tor_dir, num_episodes=episodes)

        if "error" in metrics:
            return jsonify({"error": metrics["error"]}), 400

        return jsonify({"success": True, "metrics": metrics})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/rl/status", methods=["GET"])
def rl_status():
    """Returns RL model availability and training metrics."""
    rl_analyzer = RLAnalyzer()
    metrics = rl_analyzer.get_training_metrics()

    model_exists = os.path.exists("rl_tor_agent.pt")
    corr_model_exists = os.path.exists("rl_correlation_model.pt")

    return jsonify({
        "rl_model_available": model_exists,
        "rl_correlation_model_available": corr_model_exists,
        "metrics": metrics,
    })


# ---------------------------------------------------------------------------
# Live Packet Capture  (Scapy-based)
# ---------------------------------------------------------------------------

import threading
import time
import queue
from collections import defaultdict

class CaptureSession:
    """Thread-safe live capture state."""
    def __init__(self):
        self._lock = threading.Lock()
        self.running = False
        self.sniffer = None
        self.packets_captured = 0
        self.flows: dict = defaultdict(list)     # (src,dst) -> list of packets
        self.tor_findings: list = []
        self.classified_flows: set = set()       # already classified flow keys
        self.event_queue: queue.Queue = queue.Queue(maxsize=500)
        self.engine = 'rf'
        self.interface = None

    def reset(self):
        with self._lock:
            self.running = False
            self.sniffer = None
            self.packets_captured = 0
            self.flows.clear()
            self.tor_findings.clear()
            self.classified_flows.clear()
            self.engine = 'rf'
            self.interface = None
        # drain the queue
        while not self.event_queue.empty():
            try: self.event_queue.get_nowait()
            except queue.Empty: break

    def push_event(self, kind: str, payload: dict):
        msg = json.dumps({"type": kind, **payload})
        try:
            self.event_queue.put_nowait(msg)
        except queue.Full:
            pass

_capture = CaptureSession()


_global_rl_agent = None

def _is_private(ip_str):
    if ip_str.startswith("10.") or ip_str.startswith("192.168.") or ip_str == "127.0.0.1": 
        return True
    if ip_str.startswith("172."):
        try:
            second = int(ip_str.split(".")[1])
            if 16 <= second <= 31: return True
        except: pass
    return False

def _classify_flow(flow_key, packets, engine):
    """Classify a single flow. Returns a finding dict or None."""
    try:
        from ml_detector import MLPCAPAnalyzer
        from rl_agent import RLAnalyzer, TorFlowEnvironment
        import math
        import torch
        import numpy as np

        src, dst = flow_key
        flow_data = {"src": src, "dst": dst, "packets": packets}

        if engine == 'rl':
            global _global_rl_agent
            if _global_rl_agent is None:
                _global_rl_agent = RLAnalyzer()
                if not _global_rl_agent.agent.load():
                    return None
            
            rl = _global_rl_agent
            env = TorFlowEnvironment([flow_data], [0], window_size=8)
            state = env.reset(flow_idx=0)
            
            q_value_history = []
            while not env.done:
                with torch.no_grad():
                    state_t = torch.FloatTensor(state).unsqueeze(0).to(rl.agent.device)
                    q_vals = rl.agent.policy_net(state_t)[0]
                    q_dict = {
                        "observe": float(q_vals[0].item()),
                        "classify_tor": float(q_vals[1].item()),
                        "classify_not_tor": float(q_vals[2].item()),
                    }
                    q_value_history.append(q_dict)
                action = rl.agent.select_action(state, training=False)
                state, _, _, _ = env.step(action)
            
            last_action = action
            
            if q_value_history:
                final_q = q_value_history[-1]
                q_tor = final_q["classify_tor"]
                q_not = final_q["classify_not_tor"]
                q_margin = q_tor - q_not
                raw_confidence = 1.0 / (1.0 + math.exp(-q_margin * 1.5))  # Smooth sigmoid
                confidence = float(raw_confidence * 100)
            else:
                confidence = 0.0
                q_margin = 0.0

            if last_action == 1:
                is_tor = True
            elif last_action == 2:
                is_tor = False
            else:
                is_tor = q_margin > 0

            # Fallback for noise: only flag if confidence is notably high (90% for live capture)
            if not is_tor or confidence < 90.0:
                is_tor = False

        else:
            # RF path
            analyzer = MLPCAPAnalyzer()
            analyzer.flows[flow_key] = packets
            features = analyzer.extract_features(flow_key)
            if features is None:
                return None
            if not analyzer.load_model():
                return None
            proba = analyzer.model.predict_proba([features])[0]
            confidence = float(proba[1]) * 100
            is_tor = confidence >= 90.0

        # Ignore purely internal network traffic
        if _is_private(src) and _is_private(dst):
            is_tor = False

        # STRICT DEMO FILTER: Real Tor traffic MUST contain 512-byte cells.
        # If less than 20% of the transmission is near 512 bytes, it's definitively NOT Tor.
        sizes = [p["size"] for p in packets]
        num_tor_cells = sum(1 for s in sizes if 500 <= s <= 520)
        if (num_tor_cells / max(1, len(sizes))) < 0.2:
            is_tor = False

        if not is_tor:
            return None

        timestamps = [p["timestamp"] for p in packets]
        return {
            "origin_ip": src,
            "exit_ip": dst,
            "confidence": round(confidence, 2),
            "packet_count": len(packets),
            "duration": round(max(timestamps) - min(timestamps), 3) if len(timestamps) > 1 else 0,
            "start_time_iso": __import__('datetime').datetime.utcfromtimestamp(min(timestamps)).isoformat() + "Z",
            "engine": engine.upper(),
        }
    except Exception as e:
        print(f"[CAPTURE] classify error: {e}")
        return None


def _packet_handler(pkt):
    """Called for every captured packet, must be fast."""
    try:
        from scapy.layers.inet import IP, TCP
        # Tor is exclusively TCP. Ignore UDP/ICMP noise.
        if IP not in pkt or TCP not in pkt:
            return
        ip = pkt[IP]
        ts = float(pkt.time)
        size = len(bytes(pkt))
        flow_key = (ip.src, ip.dst)

        with _capture._lock:
            _capture.packets_captured += 1
            cnt = _capture.packets_captured
            _capture.flows[flow_key].append({"timestamp": ts, "size": size, "packet_num": cnt})
            pkt_list = list(_capture.flows[flow_key])
            already = flow_key in _capture.classified_flows

        # Push raw packet event every packet
        _capture.push_event("packet", {
            "count": cnt,
            "src": ip.src,
            "dst": ip.dst,
            "size": size,
            "proto": ip.proto,
        })

        # Classify once a flow has >=15 packets and hasn't been classified yet
        if len(pkt_list) >= 15 and not already:
            with _capture._lock:
                _capture.classified_flows.add(flow_key)

            def _classify_async():
                finding = _classify_flow(flow_key, pkt_list, _capture.engine)
                if finding:
                    with _capture._lock:
                        _capture.tor_findings.append(finding)
                    _capture.push_event("tor_detected", {"finding": finding})
                else:
                    _capture.push_event("flow_safe", {
                        "src": flow_key[0], "dst": flow_key[1],
                        "packet_count": len(pkt_list),
                    })

            threading.Thread(target=_classify_async, daemon=True).start()

    except Exception as e:
        print(f"[CAPTURE] packet handler error: {e}")


@app.route("/api/capture/interfaces", methods=["GET"])
def capture_interfaces():
    """Return available network interfaces."""
    try:
        from scapy.arch.windows import get_windows_if_list
        ifaces = get_windows_if_list()
        result = []
        for iface in ifaces:
            result.append({
                "name": iface.get("name", ""),
                "description": iface.get("description", iface.get("name", "")),
                "ips": iface.get("ips", []),
                "guid": iface.get("guid", ""),
            })
        return jsonify({"interfaces": result})
    except Exception:
        # Fallback: use scapy's simpler method
        try:
            from scapy.all import get_if_list
            ifaces = get_if_list()
            result = [{"name": i, "description": i, "ips": [], "guid": ""} for i in ifaces]
            return jsonify({"interfaces": result})
        except Exception as e:
            return jsonify({"interfaces": [], "error": str(e)})


@app.route("/api/capture/start", methods=["POST"])
def capture_start():
    """Start live packet capture."""
    global _capture
    if _capture.running:
        return jsonify({"error": "Capture already running"}), 400

    data = request.get_json(force=True) or {}
    interface = data.get("interface") or None   # None = Scapy default (all)
    engine = data.get("engine", "rf")

    _capture.reset()

    try:
        from scapy.all import AsyncSniffer
        _capture.engine = engine
        _capture.interface = interface
        _capture.running = True

        kwargs = {"prn": _packet_handler, "store": False, "filter": "ip"}
        if interface:
            kwargs["iface"] = interface

        sniffer = AsyncSniffer(**kwargs)
        sniffer.start()
        _capture.sniffer = sniffer

        return jsonify({
            "success": True,
            "interface": interface or "all",
            "engine": engine,
        })
    except Exception as e:
        _capture.running = False
        return jsonify({"error": str(e)}), 500


@app.route("/api/capture/stop", methods=["POST"])
def capture_stop():
    """Stop live packet capture."""
    global _capture
    if not _capture.running:
        return jsonify({"error": "No capture running"}), 400

    try:
        if _capture.sniffer:
            _capture.sniffer.stop()
        _capture.running = False
        _capture.push_event("stopped", {"packets": _capture.packets_captured})
        return jsonify({
            "success": True,
            "packets_captured": _capture.packets_captured,
            "flows_found": len(_capture.flows),
            "tor_count": len(_capture.tor_findings),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/capture/status", methods=["GET"])
def capture_status():
    """Return current capture state."""
    with _capture._lock:
        return jsonify({
            "running": _capture.running,
            "packets_captured": _capture.packets_captured,
            "flows_found": len(_capture.flows),
            "tor_count": len(_capture.tor_findings),
            "interface": _capture.interface or "all",
            "engine": _capture.engine,
            "findings": _capture.tor_findings[-10:],  # last 10
        })


@app.route("/api/capture/stream", methods=["GET"])
def capture_stream():
    """
    Server-Sent Events stream for live capture events.
    Frontend connects with EventSource('/api/capture/stream').
    """
    def generate():
        yield "data: {\"type\":\"connected\"}\n\n"
        while True:
            try:
                msg = _capture.event_queue.get(timeout=1.0)
                yield f"data: {msg}\n\n"
            except queue.Empty:
                # Send heartbeat so connection stays alive
                yield "data: {\"type\":\"heartbeat\"}\n\n"
                if not _capture.running:
                    break

    return app.response_class(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


if __name__ == "__main__":
    app.run(debug=True, port=5000)

