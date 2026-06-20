# Law Enforcement PCAP Analysis Tool

A full-stack forensic PCAP analysis tool for law enforcement use.

## Project Structure

```
pcap_tool/
├── backend/
│   └── app.py          ← Python Flask API
├── frontend/
│   └── static/
│       └── index.html  ← Full frontend (single file)
├── requirements.txt
└── README.md
```

## Quick Start

### 1. Install dependencies

```bash
pip install flask flask-cors scapy
```

### 2. Run the backend

```bash
cd backend
python app.py
```

Backend runs at: http://localhost:5000

### 3. Open the frontend

Open `frontend/static/index.html` in your browser.

> Or visit http://localhost:5000 directly — the Flask server also serves the frontend.

---

## Features

| Tab          | What it shows |
|--------------|---------------|
| Overview     | Packet/IP/duration metrics + severity-ranked alerts |
| Traffic      | Top flows by volume, protocol distribution bar |
| Artifacts    | Extracted domains, URLs, cleartext credentials |
| Network map  | Interactive SVG connection graph |
| Report       | Executive summary, IOCs, printable report |

## Detection capabilities

- Port scan detection (>100 unique ports from one host)
- Large data transfer / exfiltration alerts (>10 MB flows)
- Known Tor / C2 IP matching
- DNS beacon pattern detection (regular interval beaconing)
- Suspicious port detection (4444, 1337, 31337, etc.)
- FTP cleartext credential extraction
- HTTP Basic Auth credential extraction
- DNS domain extraction

## API Endpoints

| Method | Endpoint      | Description |
|--------|---------------|-------------|
| POST   | /api/analyse  | Upload and analyse a PCAP file |
| GET    | /api/demo     | Load demo capture data |

### Upload example (curl)

```bash
curl -X POST http://localhost:5000/api/analyse \
  -F "file=@/path/to/capture.pcap"
```

## Extending the tool

To add real PCAP parsing with more features, consider also installing:

```bash
pip install pyshark   # uses tshark under the hood (more protocol support)
pip install dpkt      # lightweight, fast alternative to scapy
```

## Notes

- The frontend works offline with built-in demo data if the backend is unreachable.
- For production use, add authentication and HTTPS.
- Large PCAP files (>500 MB) may be slow — consider pre-filtering with `tcpdump`.
