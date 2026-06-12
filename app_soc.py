from flask import Flask, render_template, jsonify
from scanner import run_full_scan
import datetime

app = Flask(__name__)

SOC_LOGS = []

SEVERITY_WEIGHT = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1
}

CATEGORY_SEVERITY = {
    "S3": "HIGH",
    "IAM MFA": "MEDIUM",
    "IAM Keys": "HIGH",
    "Security Groups": "CRITICAL",
    "EC2": "MEDIUM",
    "Root Account": "CRITICAL",
    "Password Policy": "MEDIUM"
}


def build_soc_event(results):
    alerts = []
    score = 0

    for category, items in results.items():
        severity = CATEGORY_SEVERITY.get(category, "LOW")
        weight = SEVERITY_WEIGHT[severity]

        for item in items:
            alerts.append({
                "category": category,
                "message": item,
                "severity": severity
            })
            score += weight

    risk_level = "LOW"
    if score > 25:
        risk_level = "CRITICAL"
    elif score > 15:
        risk_level = "HIGH"
    elif score > 5:
        risk_level = "MEDIUM"

    return {
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "alerts": alerts,
        "score": score,
        "risk_level": risk_level
    }


@app.route("/")
def home():
    return render_template("soc.html")


@app.route("/scan", methods=["POST"])
def scan():
    results = run_full_scan()
    event = build_soc_event(results)
    SOC_LOGS.append(event)
    return render_template("soc.html", event=event, logs=SOC_LOGS)


@app.route("/api/scan")
def api_scan():
    results = run_full_scan()
    return jsonify(build_soc_event(results))


@app.route("/api/logs")
def api_logs():
    return jsonify(SOC_LOGS)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)