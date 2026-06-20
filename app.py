"""
Law Enforcement PCAP Analysis Tool - Backend
Requirements: pip install flask flask-cors scapy
Run: python app.py
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os, json, tempfile, hashlib
from collections import defaultdict, Counter
from datetime import datetime

app = Flask(__name__, static_folder="../frontend/static", static_url_path="/")
CORS(app)

# ── Try to import scapy ──────────────────────────────────────────────────────
try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw
    from scapy.layers.http import HTTPRequest, HTTPResponse
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False
    print("[WARN] scapy not installed. Install with: pip install scapy")


# ── Helpers ──────────────────────────────────────────────────────────────────

SUSPICIOUS_PORTS = {4444, 1337, 31337, 8888, 9999, 6666, 5555}
KNOWN_TOR_EXIT   = {"185.220.101.12", "185.220.100.253", "51.15.43.205"}
C2_INTERVALS_MAX = 35   # seconds – beacon regularity threshold

def human_bytes(n):
    for unit in ["B","KB","MB","GB"]:
        if n < 1024: return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"

def severity(score):
    if score >= 8: return "high"
    if score >= 4: return "med"
    return "low"


# ── Core analysis ─────────────────────────────────────────────────────────────

def analyse_pcap(path):
    if not SCAPY_OK:
        return demo_data()   # fallback when scapy missing

    packets = rdpcap(path)
    if not packets:
        return {"error": "Empty or unreadable PCAP file"}

    # ── Basic counters ────────────────────────────────────────────────────────
    total_bytes  = sum(len(p) for p in packets)
    start_ts     = float(packets[0].time)
    end_ts       = float(packets[-1].time)
    duration_s   = max(end_ts - start_ts, 1)

    ip_set       = set()
    proto_counts = Counter()
    flow_bytes   = defaultdict(int)   # (src,dst,proto) -> bytes
    flow_pkts    = defaultdict(int)
    dns_domains  = []
    http_urls    = []
    credentials  = []
    alerts       = []
    ftp_user     = None
    beacon_ts    = defaultdict(list)  # dst -> [timestamps]

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst
        ip_set.update([src, dst])
        ts  = float(pkt.time)

        # Protocol
        if pkt.haslayer(TCP):
            dport = pkt[TCP].dport
            sport = pkt[TCP].sport
            if dport == 443 or sport == 443:
                proto = "HTTPS"
            elif dport == 80 or sport == 80:
                proto = "HTTP"
            elif dport == 21 or sport == 21:
                proto = "FTP"
            elif dport == 22 or sport == 22:
                proto = "SSH"
            else:
                proto = "TCP"
        elif pkt.haslayer(UDP):
            dport = pkt[UDP].dport
            proto = "DNS" if dport == 53 else "UDP"
        elif pkt.haslayer(ICMP):
            proto = "ICMP"
        else:
            proto = "OTHER"

        proto_counts[proto] += 1
        key = (src, dst, proto)
        flow_bytes[key] += len(pkt)
        flow_pkts[key]  += 1

        # DNS extraction
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                if qname:
                    dns_domains.append({"domain": qname, "src": src, "ts": ts})
                    beacon_ts[dst].append(ts)
            except Exception:
                pass

        # HTTP extraction
        if pkt.haslayer(HTTPRequest):
            try:
                host   = pkt[HTTPRequest].Host.decode(errors="ignore")
                path   = pkt[HTTPRequest].Path.decode(errors="ignore")
                method = pkt[HTTPRequest].Method.decode(errors="ignore")
                http_urls.append({"url": f"http://{host}{path}", "src": src, "method": method})
            except Exception:
                pass

        # FTP credential sniff
        if pkt.haslayer(Raw) and (pkt.haslayer(TCP)) and (pkt[TCP].dport == 21 or pkt[TCP].sport == 21):
            try:
                raw = pkt[Raw].load.decode(errors="ignore").strip()
                if raw.upper().startswith("USER "):
                    ftp_user = raw[5:].strip()
                elif raw.upper().startswith("PASS ") and ftp_user:
                    credentials.append({"proto":"FTP","field":"Username","value":ftp_user,"src":src})
                    credentials.append({"proto":"FTP","field":"Password","value":raw[5:].strip(),"src":src})
                    ftp_user = None
            except Exception:
                pass

        # HTTP Basic Auth
        if pkt.haslayer(HTTPRequest):
            try:
                auth = pkt[HTTPRequest].Authorization
                if auth:
                    credentials.append({"proto":"HTTP","field":"Authorization","value":auth.decode(errors="ignore"),"src":src})
            except Exception:
                pass

    # ── Port scan detection ──────────────────────────────────────────────────
    dst_ports = defaultdict(set)
    for pkt in packets:
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            dst_ports[pkt[IP].src].add(pkt[TCP].dport)

    for src_ip, ports in dst_ports.items():
        if len(ports) > 100:
            alerts.append({
                "sev": "high", "type": "Port scan detected",
                "src": src_ip,
                "detail": f"{len(ports):,} ports probed in {duration_s:.0f}s",
                "time": "00:00:00"
            })

    # ── Large upload detection ───────────────────────────────────────────────
    for (src, dst, proto), nbytes in flow_bytes.items():
        if nbytes > 10 * 1024 * 1024 and proto in ("HTTPS","HTTP","TCP"):
            alerts.append({
                "sev": "med", "type": "Large data transfer",
                "src": src,
                "detail": f"{human_bytes(nbytes)} sent to {dst} via {proto}",
                "time": "00:00:00"
            })

    # ── Known Tor / C2 IP detection ──────────────────────────────────────────
    all_dsts = {dst for (_,dst,_) in flow_bytes}
    for ip in all_dsts & KNOWN_TOR_EXIT:
        alerts.append({
            "sev": "high", "type": "Known Tor/C2 IP contact",
            "src": "multiple", "detail": f"Traffic to {ip} (Tor exit node)",
            "time": "00:00:00"
        })

    # ── Suspicious port detection ────────────────────────────────────────────
    for pkt in packets:
        if pkt.haslayer(TCP):
            dp = pkt[TCP].dport
            if dp in SUSPICIOUS_PORTS:
                alerts.append({
                    "sev": "low", "type": f"Suspicious port {dp}",
                    "src": pkt[IP].src,
                    "detail": f"Connection to unusual port {dp}",
                    "time": "00:00:00"
                })
                break

    # ── Beacon detection (regular interval) ──────────────────────────────────
    for dst_ip, times in beacon_ts.items():
        if len(times) >= 5:
            times.sort()
            gaps = [times[i+1]-times[i] for i in range(len(times)-1)]
            avg  = sum(gaps) / len(gaps)
            variance = sum((g-avg)**2 for g in gaps) / len(gaps)
            if variance < 5 and avg < C2_INTERVALS_MAX:
                alerts.append({
                    "sev": "med", "type": "Beacon pattern detected",
                    "src": "multiple",
                    "detail": f"Regular {avg:.0f}s interval beaconing to {dst_ip}",
                    "time": "00:00:00"
                })

    # ── Top flows ────────────────────────────────────────────────────────────
    top_flows = sorted(flow_bytes.items(), key=lambda x: x[1], reverse=True)[:10]
    traffic   = [
        {
            "src":   k[0], "dst": k[1], "proto": k[2],
            "pkts":  flow_pkts[k],
            "bytes": human_bytes(v),
            "flag":  "clean"
        }
        for k, v in top_flows
    ]

    # ── Protocol distribution ─────────────────────────────────────────────────
    total_pkts = sum(proto_counts.values()) or 1
    protocols  = [
        {"name": p, "pct": round(c / total_pkts * 100)}
        for p, c in proto_counts.most_common(6)
    ]

    # ── Unique domains ────────────────────────────────────────────────────────
    seen_domains = {}
    for d in dns_domains:
        dom = d["domain"]
        if dom not in seen_domains:
            seen_domains[dom] = {"url": dom, "type": "Domain", "cat": "DNS query", "risk": "low"}
    urls = list(seen_domains.values())[:20]

    # ── Network nodes & edges ─────────────────────────────────────────────────
    unique_ips = list(ip_set)[:12]
    # Simple circular layout
    import math
    cx, cy, r = 340, 170, 130
    nodes = []
    for i, ip in enumerate(unique_ips):
        angle = 2 * math.pi * i / len(unique_ips)
        nodes.append({
            "id":    ip,
            "label": ip,
            "x":     round(cx + r * math.cos(angle)),
            "y":     round(cy + r * math.sin(angle)),
            "type":  "suspect" if ip in {k[0] for k,_ in top_flows[:3]} else "internal"
        })

    edges = []
    seen_edges = set()
    for (src, dst, proto), nbytes in list(flow_bytes.items())[:15]:
        ek = (src, dst)
        if ek not in seen_edges and src in ip_set and dst in ip_set:
            seen_edges.add(ek)
            edges.append({"from": src, "to": dst, "label": proto})

    # ── Duration string ───────────────────────────────────────────────────────
    m, s = divmod(int(duration_s), 60)
    h, m = divmod(m, 60)
    dur_str = f"{h}h {m}m {s}s" if h else f"{m}m {s}s"

    return {
        "filename": os.path.basename(path),
        "metrics": [
            {"label": "Total packets", "value": f"{len(packets):,}",   "sub": "Captured"},
            {"label": "Duration",      "value": dur_str,                "sub": "HH:MM:SS"},
            {"label": "Unique IPs",    "value": str(len(ip_set)),       "sub": "Hosts seen"},
            {"label": "Alerts",        "value": str(len(alerts)),       "sub": "Suspicious events"},
            {"label": "Bytes total",   "value": human_bytes(total_bytes),"sub": "Data volume"},
        ],
        "alerts":    alerts,
        "traffic":   traffic,
        "protocols": protocols,
        "urls":      urls,
        "credentials": credentials,
        "nodes":     nodes,
        "edges":     edges,
        "summary":   f"Analysed {os.path.basename(path)}: {len(packets):,} packets over {dur_str}, "
                     f"{len(ip_set)} unique IPs, {len(alerts)} alerts detected.",
        "findings":  [{"type": "warn" if a["sev"]=="med" else ("danger" if a["sev"]=="high" else "ok"),
                       "text": f"[{a['sev'].upper()}] {a['type']}: {a['detail']} (src: {a['src']})"}
                      for a in alerts],
        "iocs":      [{"type": a["type"], "value": a["src"], "conf": a["sev"].capitalize()} for a in alerts[:8]],
    }


def demo_data():
    """Fallback demo data when scapy is not installed."""
    return {
        "filename": "demo_capture.pcap",
        "metrics": [
            {"label":"Total packets","value":"18,432","sub":"Captured"},
            {"label":"Duration","value":"4m 12s","sub":"HH:MM:SS"},
            {"label":"Unique IPs","value":"47","sub":"Hosts seen"},
            {"label":"Alerts","value":"9","sub":"Suspicious events"},
            {"label":"Bytes total","value":"28.4 MB","sub":"Data volume"},
        ],
        "alerts": [
            {"sev":"high","type":"Port scan detected","src":"192.168.1.105","detail":"3,400 ports probed in 18s","time":"00:01:04"},
            {"sev":"high","type":"DNS tunneling","src":"10.0.0.88","detail":"Encoded data in TXT records → malware.cc","time":"00:02:31"},
            {"sev":"high","type":"Cleartext credentials","src":"192.168.1.105","detail":"FTP login captured","time":"00:00:48"},
            {"sev":"med","type":"C2 beacon pattern","src":"10.0.0.88","detail":"Regular 30s interval to 185.220.101.12","time":"00:02:00"},
            {"sev":"med","type":"Large data exfil","src":"10.0.0.55","detail":"42 MB HTTPS upload to unknown host","time":"00:03:10"},
            {"sev":"med","type":"Tor circuit","src":"10.0.0.88","detail":"Traffic to known Tor guard nodes","time":"00:01:55"},
            {"sev":"low","type":"Self-signed TLS cert","src":"185.220.101.12","detail":"CN=localhost, expired 2021","time":"00:01:58"},
            {"sev":"low","type":"Unusual port 4444","src":"192.168.1.200","detail":"Metasploit default listener","time":"00:03:44"},
            {"sev":"low","type":"ICMP flood","src":"192.168.1.105","detail":"1,200 ICMP echo in 3s","time":"00:00:55"},
        ],
        "traffic": [
            {"src":"192.168.1.105","dst":"192.168.1.1","proto":"TCP","pkts":3842,"bytes":"4.1 MB","flag":"scan"},
            {"src":"10.0.0.88","dst":"185.220.101.12","proto":"HTTPS","pkts":1204,"bytes":"2.8 MB","flag":"c2"},
            {"src":"10.0.0.55","dst":"104.21.44.82","proto":"HTTPS","pkts":890,"bytes":"42.0 MB","flag":"exfil"},
            {"src":"10.0.0.88","dst":"8.8.8.8","proto":"DNS","pkts":612,"bytes":"320 KB","flag":"tunnel"},
            {"src":"192.168.1.200","dst":"192.168.1.105","proto":"TCP","pkts":204,"bytes":"88 KB","flag":"suspicious"},
        ],
        "protocols": [
            {"name":"TCP","pct":52},{"name":"HTTPS","pct":28},
            {"name":"DNS","pct":10},{"name":"HTTP","pct":6},{"name":"ICMP","pct":4},
        ],
        "urls": [
            {"url":"malware.cc","type":"Domain","cat":"Malware C2","risk":"high"},
            {"url":"185.220.101.12","type":"IP","cat":"Known Tor exit node","risk":"high"},
            {"url":"104.21.44.82","type":"IP","cat":"Exfiltration target","risk":"med"},
            {"url":"updates.microsoft.com","type":"Domain","cat":"Legitimate software","risk":"low"},
        ],
        "credentials": [
            {"proto":"FTP","field":"Username","value":"admin","src":"192.168.1.105"},
            {"proto":"FTP","field":"Password","value":"p@ssw0rd123","src":"192.168.1.105"},
        ],
        "nodes": [
            {"id":"105","label":"192.168.1.105","x":140,"y":170,"type":"suspect"},
            {"id":"88","label":"10.0.0.88","x":310,"y":100,"type":"suspect"},
            {"id":"55","label":"10.0.0.55","x":420,"y":230,"type":"suspect"},
            {"id":"c2","label":"185.220.101.12","x":540,"y":80,"type":"external"},
            {"id":"dns","label":"8.8.8.8","x":560,"y":200,"type":"external"},
            {"id":"gw","label":"192.168.1.1","x":60,"y":80,"type":"internal"},
        ],
        "edges": [
            {"from":"105","to":"gw","label":"Port scan"},
            {"from":"88","to":"c2","label":"C2 beacon"},
            {"from":"55","to":"dns","label":"42 MB upload"},
        ],
        "summary": "Demo capture: 18,432 packets, 4m 12s, 9 alerts. Three suspect hosts detected with C2 beaconing, DNS tunneling, and data exfiltration.",
        "findings": [
            {"type":"danger","text":"Host 10.0.0.88 — C2 beacon pattern to 185.220.101.12 (Tor exit node) with DNS tunneling."},
            {"type":"danger","text":"Cleartext FTP credentials captured from 192.168.1.105."},
            {"type":"danger","text":"42 MB HTTPS upload from 10.0.0.55 — consistent with data exfiltration."},
            {"type":"warn","text":"Port scan from 192.168.1.105: 3,400 ports in 18 seconds (Nmap pattern)."},
            {"type":"ok","text":"Remaining 43 hosts show normal traffic patterns."},
        ],
        "iocs": [
            {"type":"IPv4 — C2","value":"185.220.101.12","conf":"High"},
            {"type":"IPv4 — Exfil","value":"104.21.44.82","conf":"High"},
            {"type":"Domain","value":"malware.cc","conf":"High"},
            {"type":"Port","value":"TCP/4444","conf":"Medium"},
        ],
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/api/analyse", methods=["POST"])
def analyse():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400

    suffix = os.path.splitext(f.filename)[1].lower()
    if suffix not in {".pcap", ".pcapng", ".cap"}:
        return jsonify({"error": "Only .pcap / .pcapng / .cap files accepted"}), 400

    fd, tmp_path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    try:
        f.save(tmp_path)
        result = analyse_pcap(tmp_path)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    return jsonify(result)


@app.route("/api/demo", methods=["GET"])
def demo():
    return jsonify(demo_data())


@app.route("/", methods=["GET"])
def index():
    return send_from_directory(app.static_folder, "index.html")


if __name__ == "__main__":
    print("=" * 55)
    print("  Law Enforcement PCAP Analysis Tool — Backend")
    print("  http://localhost:5000")
    print("  Install deps: pip install flask flask-cors scapy")
    print("=" * 55)
    app.run(debug=True, port=5000)
