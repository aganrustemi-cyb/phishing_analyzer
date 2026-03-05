#!/usr/bin/env python3
"""
Flask Web UI for Phishing Email Analyzer
Wraps phishing_analyzer.py with a browser-based interface.
"""

import os
import io
import contextlib
import tempfile
from datetime import datetime, timezone

from flask import Flask, render_template, request, send_file, redirect, url_for
from werkzeug.utils import secure_filename

# Import analyzer functions and globals
import phishing_analyzer as pa

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB total (20 files x 5MB)

# Key IDs that the client sends as hidden form fields
API_KEY_IDS = ['vt_api_key', 'abuseipdb_key', 'groq_key', 'shodan_key']


def inject_keys_from_form():
    """Override analyzer globals with keys sent from the client's localStorage."""
    pa.VT_API_KEY    = request.form.get("vt_api_key", "")
    pa.ABUSEIPDB_KEY = request.form.get("abuseipdb_key", "")
    pa.GROQ_KEY      = request.form.get("groq_key", "")
    pa.SHODAN_KEY    = request.form.get("shodan_key", "")
    pa.refresh_headers()


def reset_findings():
    """Reset the global findings dict to empty state before each analysis."""
    pa.findings["email_meta"] = {}
    pa.findings["ips"] = []
    pa.findings["urls"] = []
    pa.findings["attachments"] = []
    pa.findings["mitre_techniques"] = []
    pa.findings["verdict"] = "CLEAN"
    pa.findings["confidence"] = 0


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/settings")
def settings():
    return render_template("settings.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    import copy

    files = request.files.getlist("eml_files")
    files = [f for f in files if f.filename]
    if not files:
        return redirect(url_for("index"))

    inject_keys_from_form()
    analysis_time = datetime.now(timezone.utc).isoformat()

    # Single file → original results page
    if len(files) == 1:
        return _analyze_single(files[0], analysis_time)

    # Batch → collect results per file
    all_results = []
    for file in files[:20]:  # cap at 20
        filename = secure_filename(file.filename)
        tmp_dir = tempfile.gettempdir()
        filepath = os.path.join(tmp_dir, filename)
        file.save(filepath)
        reset_findings()

        log_buffer = io.StringIO()
        report_file = None

        try:
            with contextlib.redirect_stdout(log_buffer):
                pa.parse_eml(filepath)
                pa.map_mitre()
                pa.determine_verdict()
                pa.generate_report()

            report_files = sorted(
                [f for f in os.listdir(".") if f.startswith("SOC_Report_") and f.endswith(".txt")],
                reverse=True
            )
            if report_files:
                report_file = report_files[0]
        except Exception as e:
            log_buffer.write(f"\n\nERROR: {e}")
        finally:
            try:
                os.remove(filepath)
            except OSError:
                pass

        report_text = ""
        if report_file and os.path.exists(report_file):
            with open(report_file, "r", errors="ignore") as f:
                report_text = f.read()

        all_results.append({
            "filename": filename,
            "findings": copy.deepcopy(pa.findings),
            "terminal_log": log_buffer.getvalue(),
            "report_text": report_text,
            "report_file": report_file,
        })

    return render_template(
        "batch_results.html",
        results=all_results,
        analysis_time=analysis_time,
    )


def _analyze_single(file, analysis_time):
    """Analyze a single .eml file and render the results page."""
    filename = secure_filename(file.filename)
    tmp_dir = tempfile.gettempdir()
    filepath = os.path.join(tmp_dir, filename)
    file.save(filepath)
    reset_findings()

    log_buffer = io.StringIO()
    report_file = None

    try:
        with contextlib.redirect_stdout(log_buffer):
            pa.parse_eml(filepath)
            pa.map_mitre()
            pa.determine_verdict()
            pa.generate_report()

        report_files = sorted(
            [f for f in os.listdir(".") if f.startswith("SOC_Report_") and f.endswith(".txt")],
            reverse=True
        )
        if report_files:
            report_file = report_files[0]
    except Exception as e:
        log_buffer.write(f"\n\nERROR: {e}")
    finally:
        try:
            os.remove(filepath)
        except OSError:
            pass

    terminal_log = log_buffer.getvalue()
    report_text = ""
    if report_file and os.path.exists(report_file):
        with open(report_file, "r", errors="ignore") as f:
            report_text = f.read()

    return render_template(
        "results.html",
        findings=pa.findings,
        terminal_log=terminal_log,
        report_text=report_text,
        report_file=report_file,
        filename=filename,
        analysis_time=analysis_time,
    )


@app.route("/download/<filename>")
def download(filename):
    safe = secure_filename(filename)
    if os.path.exists(safe):
        return send_file(safe, as_attachment=True)
    return "File not found", 404


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
