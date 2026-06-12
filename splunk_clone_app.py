from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO, emit
import datetime

from siem_engine import ingest_event, search_events, correlate_events
from scanner import run_full_scan

app = Flask(__name__)
app.config['SECRET_KEY'] = 'siem-secret'
socketio = SocketIO(app, cors_allowed_origins="*")

# -----------------------------
# SPLUNK-STYLE EVENT INGESTION
# -----------------------------
@app.route('/ingest', methods=['POST'])
def ingest():
    data = request.json

    ingest_event(
        source=data.get("source", "api"),
        severity=data.get("severity", "LOW"),
        category=data.get("category", "general"),
        message=data.get("message", ""),
        raw=data
    )

    socketio.emit("new_event", data)

    return jsonify({"status": "ingested"})


# -----------------------------
# SPLUNK-STYLE SEARCH (SPL BASIC)
# -----------------------------
@app.route('/search')
def search():
    query = request.args.get("q")
    severity = request.args.get("severity")
    category = request.args.get("category")

    results = search_events(query=query, severity=severity, category=category)

    return jsonify(results)


# -----------------------------
# REAL-TIME SCAN STREAM
# -----------------------------
@app.route('/run-scan', methods=['POST'])
def run_scan():
    results = run_full_scan()

    for category, items in results.items():
        for item in items:

            event = {
                "source": "aws-scanner",
                "severity": "HIGH" if "S3" in category or "Security" in category else "MEDIUM",
                "category": category,
                "message": item
            }

            ingest_event(**event)
            socketio.emit("new_event", event)

    return jsonify({"status": "scan_complete", "results": results})


# -----------------------------
# CORRELATION ENGINE (ALERTS)
# -----------------------------
@app.route('/alerts')
def alerts():
    return jsonify(correlate_events())


# -----------------------------
# SIMPLE SPLUNK UI
# -----------------------------
@app.route('/')
def index():
    return """
    <html>
    <head>
        <title>Splunk-Style SIEM</title>
    </head>
    <body style='background:#0b1220;color:white;font-family:Arial;'>
        <h1>🟢 Mini Splunk SIEM Clone</h1>

        <button onclick="runScan()">Run AWS Scan</button>
        <button onclick="getAlerts()">Get Alerts</button>

        <input id="query" placeholder="Search logs..." />
        <button onclick="search()">Search</button>

        <pre id="output"></pre>

        <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
        <script>
            const socket = io();

            socket.on("new_event", function(data) {
                document.getElementById("output").innerText += "\nNEW EVENT: " + JSON.stringify(data);
            });

            function runScan() {
                fetch('/run-scan', {method:'POST'})
                .then(r => r.json())
                .then(d => document.getElementById('output').innerText = JSON.stringify(d, null, 2));
            }

            function getAlerts() {
                fetch('/alerts')
                .then(r => r.json())
                .then(d => document.getElementById('output').innerText = JSON.stringify(d, null, 2));
            }

            function search() {
                const q = document.getElementById('query').value;
                fetch('/search?q=' + q)
                .then(r => r.json())
                .then(d => document.getElementById('output').innerText = JSON.stringify(d, null, 2));
            }
        </script>
    </body>
    </html>
    """


# -----------------------------
# START SERVER
# -----------------------------
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
