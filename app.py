from flask import Flask, render_template, jsonify
from scanner import run_full_scan
import datetime

app = Flask(__name__)

SCAN_HISTORY = []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    results = run_full_scan()

    # calculate simple risk score
    total_issues = sum(len(v) for v in results.values())
    risk_level = "LOW"

    if total_issues > 10:
        risk_level = "HIGH"
    elif total_issues > 5:
        risk_level = "MEDIUM"

    scan_data = {
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "results": results,
        "total_issues": total_issues,
        "risk_level": risk_level
    }

    SCAN_HISTORY.append(scan_data)

    return render_template(
        'index.html',
        results=results,
        risk_level=risk_level,
        total_issues=total_issues,
        history=SCAN_HISTORY
    )

@app.route('/api/scan')
def api_scan():
    return jsonify(run_full_scan())

@app.route('/api/history')
def history():
    return jsonify(SCAN_HISTORY)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)