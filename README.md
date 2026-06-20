
# 🔍 Law Enforcement PCAP Analysis Tool

A full-stack cybersecurity web application built for law enforcement agencies to analyze network packet capture files (.pcap, .pcapng, .cap) in real time.

## 🚀 Features
- 📋 **Overview Dashboard** — packet metrics, unique IPs, duration, and severity-ranked alerts
- 🔀 **Traffic Analysis** — top flows by volume, protocol distribution chart
- 🗄️ **Artifact Extraction** — auto-extracts domains, URLs, FTP/HTTP credentials
- 🌐 **Network Map** — interactive SVG connection graph of all hosts
- 📝 **Forensic Report** — executive summary, IOC tables, printable PDF

## 🛡️ Threat Detection
- Port scan detection
- C2 beacon pattern analysis
- DNS tunneling detection
- Data exfiltration alerts
- Tor / known C2 IP matching
- Cleartext credential extraction (FTP, HTTP Basic Auth)
- Suspicious port detection (4444, 1337, 31337)

## 🛠️ Tech Stack
- **Backend:** Python 3, Flask, Scapy, Flask-CORS
- **Frontend:** HTML5, CSS3, Vanilla JavaScript, SVG
- **Output:** REST API (/api/analyse), JSON responses

## ⚡ Quick Start
pip install flask flask-cors scapy
cd backend
python app.py

Then open frontend/static/index.html in your browser.

## 📌 Submitted for
APCSIP 2026 — Cybersecurity Internship Project
Submitted by: Sumit Kumar Mehta
