# ☁ AWS Misconfiguration Scanner (Flask Dashboard)

A production-style AWS security scanner that detects common cloud misconfigurations using Python + Flask.

---

## 🚀 Features

- Public S3 bucket detection
- IAM MFA missing detection
- Access key exposure scan
- Open security groups (0.0.0.0/0)
- Public EC2 instances
- IAM password policy validation
- Risk scoring dashboard
- Scan history tracking
- REST API endpoints

---

## 📸 Dashboard

Run the Flask app and open:
```
http://127.0.0.1:5000
```

---

## ⚙ Installation

```bash
pip install -r requirements.txt
```

---

## ▶ Run

```bash
python app.py
```

---

## 🔐 AWS Permissions Required

Use a read-only IAM user with:
- S3 read access
- IAM read access
- EC2 describe permissions

---

## 🧠 Architecture

Flask App → Scanner Engine → boto3 AWS API → Results Dashboard

---

## 📊 API Endpoints

- `/scan` → Run scan (UI)
- `/api/scan` → JSON scan results
- `/api/history` → Scan history

---

## ⚠ Disclaimer

This tool is for educational and security auditing purposes only. Do not use on unauthorized AWS accounts.
