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
from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from io import BytesIO
from flask_cors import CORS

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
    Generate forensic PDF report from ML findings.
    Frontend should send:
      {
        "findings": [...],
        "metadata": {...},   # optional
        "graph": { "nodes": [...], "links": [...] }  # optional
      }
    """
    try:
        data = request.get_json(force=True)
        findings = data.get("findings", [])
        meta = data.get("metadata", {})
        graph = data.get("graph", {})

        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        story = []
        styles = getSampleStyleSheet()

        # -------- Title --------
        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Heading1"],
            fontSize=24,
            textColor=colors.HexColor("#1F2121"),
            spaceAfter=30,
        )
        story.append(Paragraph("OnionTrace v2.0 Forensic Report", title_style))
        story.append(Spacer(1, 12))

        # -------- Metadata --------
        meta_style = ParagraphStyle(
            "Meta",
            parent=styles["Normal"],
            fontSize=10,
            textColor=colors.HexColor("#6C7C7D"),
        )
        story.append(
            Paragraph(
                f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
                meta_style,
            )
        )
        if meta.get("case_id"):
            story.append(
                Paragraph(f"<b>Case ID:</b> {meta['case_id']}", meta_style)
            )
        story.append(
            Paragraph(
                "<b>Tool:</b> OnionTrace v2.0 - ML-Based TOR Detection",
                meta_style,
            )
        )
        story.append(
            Paragraph(
                "<b>Detection Method:</b> RandomForest Classifier on TOR/NonTor flows",
                meta_style,
            )
        )
        story.append(Spacer(1, 20))

        # -------- Executive Summary --------
        story.append(Paragraph("Executive Summary", styles["Heading2"]))
        story.append(Spacer(1, 6))
        tor_detected = len(findings)
        avg_conf = (
            sum(f.get("confidence", 0) for f in findings) / max(1, len(findings))
            if findings
            else 0
        )
        story.append(
            Paragraph(
                f"This analysis detected <b>{tor_detected} probable TOR flow(s)</b> "
                f"in the provided capture. The ML model reports an average confidence of "
                f"<b>{avg_conf:.1f}%</b> for the identified flows.",
                styles["Normal"],
            )
        )
        story.append(Spacer(1, 20))

        # -------- Network Map Summary (from graph) --------
        if graph and graph.get("links"):
            story.append(Paragraph("Network Overview", styles["Heading2"]))
            story.append(Spacer(1, 6))
            link_rows = [
                ["Origin IP", "Tor/External IP", "Flows", "Avg Confidence (%)"]
            ]
            for link in graph["links"]:
                link_rows.append(
                    [
                        link.get("source", "N/A"),
                        link.get("target", "N/A"),
                        str(link.get("flows", 0)),
                        f"{link.get('avg_conf', 0):.1f}",
                    ]
                )
            table = Table(
                link_rows,
                colWidths=[1.6 * inch, 1.6 * inch, 1.1 * inch, 1.5 * inch],
            )
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#208090")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, 0), 11),
                        ("BOTTOMPADDING", (0, 0), (-1, 0), 10),
                        ("GRID", (0, 0), (-1, -1), 1, colors.black),
                        (
                            "ROWBACKGROUNDS",
                            (0, 1),
                            (-1, -1),
                            [colors.white, colors.HexColor("#F5F5F5")],
                        ),
                    ]
                )
            )
            story.append(table)
            story.append(Spacer(1, 20))

        # -------- Findings --------
        story.append(Paragraph("Detected TOR Flows", styles["Heading2"]))
        story.append(Spacer(1, 12))

        for i, finding in enumerate(findings, 1):
            story.append(Paragraph(f"<b>Flow #{i}</b>", styles["Heading3"]))

            data_table = [
                ["Field", "Value"],
                ["Origin IP", finding.get("origin_ip", "N/A")],
                ["Exit Node IP", finding.get("exit_ip", "N/A")],
                [
                    "Confidence (ML)",
                    f"{finding.get('confidence', 0):.1f}%",
                ],
                [
                    "ML Probability",
                    f"{finding.get('ml_probability', 0.0):.4f}",
                ],
                [
                    "Temporal Fingerprint",
                    finding.get("temporal_fingerprint", "N/A"),
                ],
                ["Detection Engine", finding.get("detection_method", "ML Model")],
            ]

            table = Table(data_table, colWidths=[2 * inch, 4 * inch])
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#208090")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, 0), 11),
                        ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                        ("GRID", (0, 0), (-1, -1), 1, colors.black),
                        (
                            "ROWBACKGROUNDS",
                            (0, 1),
                            (-1, -1),
                            [colors.white, colors.HexColor("#F5F5F5")],
                        ),
                    ]
                )
            )

            story.append(table)
            story.append(Spacer(1, 20))

        # -------- Methodology Page --------
        story.append(PageBreak())
        story.append(Paragraph("Methodology", styles["Heading2"]))
        story.append(Spacer(1, 12))
        story.append(
            Paragraph(
                "<b>Machine Learning-Based TOR Detection:</b><br/>"
                "OnionTrace v2.0 uses a RandomForest classifier trained on real "
                "TOR and NonTor flows from the ISCX Tor/NonTor dataset. The model "
                "uses 13 features per flow, including packet size statistics, "
                "inter-packet timing (IAT), burst patterns, flow duration, and "
                "private-to-public IP patterns. These features align with Tor "
                "traffic classification research that shows temporal and size "
                "features can distinguish Tor from other encrypted traffic without "
                "breaking encryption.",
                styles["Normal"],
            )
        )

        doc.build(story)
        buffer.seek(0)

        return send_file(
            buffer,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"OnionTrace_ML_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
        )

    except Exception as e:
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
