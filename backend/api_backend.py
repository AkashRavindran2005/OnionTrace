from flask import Flask, request, jsonify, send_file
from werkzeug.utils import secure_filename
from time_correlation import correlate_flows

# legacy imports (not used in v2.0 flow)
from onion_trace_backend import PCAPParser, CorrelationEngine, ForensicReporter
from ml_detector import MLPCAPAnalyzer
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
    """Append a single case entry to JSONL file and return case_id."""
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
    """Generate a network graph visualization as image bytes."""
    try:
        G = nx.DiGraph()
        
        # Add nodes and edges from graph_data
        if graph_data and graph_data.get("links"):
            for link in graph_data["links"]:
                source = link.get("source", "Unknown")
                target = link.get("target", "Unknown")
                G.add_edge(source, target, weight=link.get("flows", 1), conf=link.get("avg_conf", 0))
        
        if G.number_of_nodes() == 0:
            return None
        
        # Use spring layout for visualization
        pos = nx.spring_layout(G, k=2, iterations=50, seed=42)
        
        # Create drawing
        drawing = Drawing(6*inch, 4*inch)
        
        # Draw edges
        for edge in G.edges(data=True):
            src, tgt, data = edge
            x1, y1 = pos[src]
            x2, y2 = pos[tgt]
            
            # Scale to drawing coordinates
            x1 = 0.5*inch + x1 * 2.5*inch
            y1 = 2*inch - y1 * 1.8*inch
            x2 = 0.5*inch + x2 * 2.5*inch
            y2 = 2*inch - y2 * 1.8*inch
            
            from reportlab.graphics.shapes import Line
            line = Line(x1, y1, x2, y2, strokeColor=colors.HexColor("#208090"), strokeWidth=1.5)
            drawing.add(line)
            
            # Add label with confidence
            conf = data.get("conf", 0)
            mid_x = (x1 + x2) / 2
            mid_y = (y1 + y2) / 2
            from reportlab.graphics.shapes import String
            label = String(mid_x, mid_y, f"{conf:.0f}%", fontSize=7, fillColor=colors.HexColor("#208090"))
            drawing.add(label)
        
        # Draw nodes
        from reportlab.graphics.shapes import Circle
        for node in G.nodes():
            x, y = pos[node]
            x = 0.5*inch + x * 2.5*inch
            y = 2*inch - y * 1.8*inch
            
            circle = Circle(x, y, 0.15*inch, fillColor=colors.HexColor("#32B8C6"), strokeColor=colors.HexColor("#1F2121"), strokeWidth=2)
            drawing.add(circle)
            
            # Add IP label
            from reportlab.graphics.shapes import String
            label_text = node.split('.')[-2:] if '.' in node else node[:8]
            label_text = '.'.join(label_text) if isinstance(label_text, list) else label_text
            label = String(x - 0.3*inch, y - 0.25*inch, label_text, fontSize=6, fillColor=colors.black)
            drawing.add(label)
        
        # Convert to image
        img_buffer = BytesIO()
        renderPM.drawToFile(drawing, img_buffer, fmt="PNG")
        img_buffer.seek(0)
        return img_buffer
        
    except Exception as e:
        print(f"Graph generation error: {e}")
        return None


@app.route("/health", methods=["GET"])
def health():
    """Health check with version + model status."""
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
    """
    Endpoint: POST /api/analyze
    Body: multipart/form-data with file field 'pcap'
    Returns: JSON ML analysis results
    """
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

        # ============ ML v2.0 ANALYSIS ============
        analyzer = MLPCAPAnalyzer()
        ml_report = analyzer.analyze_pcap_ml(filepath)

        correlations = correlate_flows(ml_report["findings"])
        ml_report["time_correlations"] = correlations

        # remove temp file
        if os.path.exists(filepath):
            os.remove(filepath)

        if "error" in ml_report:
            return jsonify({"error": ml_report["error"]}), 400

        # enrich metadata
        ml_report["metadata"]["tool"] = "OnionTrace v2.0"
        ml_report["metadata"]["engine"] = "ML"
        ml_report["metadata"][
            "detection_method"
        ] = "RandomForest on temporal + size features"

        # append to case history
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
        # ensure cleanup
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

        # ========== CUSTOM STYLES ==========
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
            alignment=4,  # Justify
        )

        # ========== COVER SECTION ==========
        story.append(Spacer(1, 0.3*inch))
        story.append(Paragraph("OnionTrace v2.0", title_style))
        story.append(Paragraph("ML-Based TOR Traffic Detection Report", subtitle_style))
        story.append(Spacer(1, 0.2*inch))

        # Metadata section
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

        # ========== EXECUTIVE SUMMARY ==========
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

        # ========== KEY METRICS ==========
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

        # ========== NETWORK TOPOLOGY ==========
        if graph and graph.get("links") and len(graph["links"]) > 0:
            story.append(Paragraph("Network Topology & Flow Mapping", heading2_style))
            
            # Network graph
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

        # ========== DETAILED FINDINGS ==========
        story.append(PageBreak())
        story.append(Paragraph("Detailed Flow Analysis", heading2_style))
        story.append(Spacer(1, 0.1*inch))

        if not findings:
            story.append(Paragraph("No TOR flows detected in this capture.", body_style))
        else:
            for i, finding in enumerate(findings, 1):
                # Flow header
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

                # Flow details table
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

                # Page break every 2 flows for readability
                if i % 2 == 0 and i < len(findings):
                    story.append(Spacer(1, 0.1*inch))

        # ========== METHODOLOGY PAGE ==========
        story.append(PageBreak())
        story.append(Paragraph("Technical Methodology", heading2_style))
        story.append(Spacer(1, 0.1*inch))

        methodology_sections = [
            (
                "<b>1. ML Model Architecture</b>",
                "OnionTrace v2.0 employs a RandomForest classifier with 100 decision trees, trained on the ISCX Tor/NonTor dataset. "
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

        # ========== FOOTER PAGE ==========
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

        # ========== BUILD PDF ==========
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
    """Return list of past cases (newest first)."""
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


if __name__ == "__main__":
    app.run(debug=True, port=5000)
