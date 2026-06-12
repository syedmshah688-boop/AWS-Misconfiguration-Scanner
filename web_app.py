from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO
import datetime

from scanner import run_full_scan
from siem_engine import ingest_event, search_events, correlate_events

app = Flask(__name__)
app.config['SECRET_KEY'] = 'web-siem'
socketio = SocketIO(app, cors_allowed_origins="*")

# -----------------------------
# WEB SIEM DASHBOARD (ENTRY)
# -----------------------------
@app.route('/')
def dashboard():
    return render_template('dashboard.html')


# -----------------------------
# RUN FULL SCAN (WEB BUTTON)
# -----------------------------
@app.route('/api/run-scan', methods=['POST'])
def run_scan():
    results = run_full_scan()

    events = []

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
            events.append(event)

    return jsonify({"status": "ok", "events": events})


# -----------------------------
# SEARCH API (WEB UI)
# -----------------------------
@app.route('/api/search')
def search():
    q = request.args.get('q')
    severity = request.args.get('severity')
    category = request.args.get('category')

    return jsonify(search_events(q, severity, category))


# -----------------------------
# ALERTS (CORRELATION)
# -----------------------------
@app.route('/api/alerts')
def alerts():
    return jsonify(correlate_events())


# -----------------------------
# SOCKET STREAM
# -----------------------------
@socketio.on('connect')
def connect():
    socketio.emit("status", {"message": "connected to SIEM stream"})


# -----------------------------
# RUN APP
# -----------------------------
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)