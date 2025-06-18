# مشروع: أداة مراقبة وتحليل الشبكة المتقدمة - Network Sentinel
# التقنية: Python + Flask + Scapy + واجهة رسومية متقدمة (قيد التطوير)

import threading
import time
import json
import logging
import os
import smtplib
from email.mime.text import MIMEText
from flask import Flask, jsonify, request, send_file
from scapy.all import ARP, Ether, srp, sniff, IP, TCP, UDP, wrpcap
from uuid import uuid4
import socket

app = Flask(__name__)

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(message)s',
                    handlers=[logging.FileHandler("sentinel.log"), logging.StreamHandler()])

# إعدادات وتخزين داخلي
devices = {}
packets = []
snapshot_dir = "snapshots"
os.makedirs(snapshot_dir, exist_ok=True)

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL",
    3389: "RDP", 5900: "VNC"
}

ALERT_EMAIL = "admin@example.com"  # ضع بريد التنبيه هنا

# ====== الماسح المتقدم ======
class DeviceScanner:
    def __init__(self, interface='enp6s0', scan_interval=30):
        self.interface = interface
        self.interval = scan_interval
        self.running = False
        self.known_ips = set()

    def identify_services(self, ip):
        services = []
        for port in COMMON_PORTS:
            try:
                sock = socket.socket()
                sock.settimeout(0.5)
                sock.connect((ip, port))
                services.append(COMMON_PORTS[port])
                sock.close()
            except:
                continue
        return services

    def notify_new_device(self, device):
        try:
            msg = MIMEText(json.dumps(device, indent=2))
            msg["Subject"] = f"🛡️ Network Sentinel Alert: New device {device['ip']}"
            msg["From"] = "sentinel@localhost"
            msg["To"] = ALERT_EMAIL
            s = smtplib.SMTP("localhost")
            s.send_message(msg)
            s.quit()
        except Exception as e:
            logging.error(f"Email notification failed: {e}")

    def scan(self):
        logging.info("Scanning local network...")
        target_ip = "192.168.1.1/24"
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, iface=self.interface, verbose=0)[0]

        new_devices = {}
        for sent, received in result:
            ip = received.psrc
            mac = received.hwsrc
            hostname = "unknown"
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                pass

            services = self.identify_services(ip)

            device_data = {
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "services": services,
                "last_seen": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            }
            new_devices[ip] = device_data

            if ip not in self.known_ips:
                self.known_ips.add(ip)
                self.notify_new_device(device_data)

        global devices
        devices = new_devices
        logging.info(f"Discovered {len(devices)} active devices.")

    def start(self):
        self.running = True
        while self.running:
            self.scan()
            time.sleep(self.interval)

# ====== محلل الحزم ======
class PacketAnalyzer:
    def __init__(self, interface='enp6s0'):
        self.interface = interface
        self.captured_packets = []

    def packet_callback(self, packet):
        if IP in packet:
            pkt_info = {
                "id": str(uuid4()),
                "src": packet[IP].src,
                "dst": packet[IP].dst,
                "proto": self.proto_name(packet[IP].proto),
                "timestamp": time.strftime("%H:%M:%S", time.localtime()),
                "size": len(packet)
            }
            if TCP in packet:
                pkt_info.update({
                    "sport": packet[TCP].sport,
                    "dport": packet[TCP].dport,
                    "flags": str(packet[TCP].flags)
                })
            elif UDP in packet:
                pkt_info.update({
                    "sport": packet[UDP].sport,
                    "dport": packet[UDP].dport
                })

            packets.append(pkt_info)
            self.captured_packets.append(packet)

            if len(packets) > 200:
                packets.pop(0)
            if len(self.captured_packets) > 1000:
                self.captured_packets.pop(0)

    def proto_name(self, proto_num):
        return {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto_num, str(proto_num))

    def start(self):
        logging.info("Starting packet capture...")
        sniff(prn=self.packet_callback, iface=self.interface, store=False)

    def export_pcap(self, filename):
        path = os.path.join(snapshot_dir, filename)
        wrpcap(path, self.captured_packets)
        return path

# ====== API Endpoints ======
@app.route('/')
def dashboard():
    return send_file("dashboard.html")

@app.route('/api/devices')
def api_devices():
    return jsonify(list(devices.values()))

@app.route('/api/packets')
def api_packets():
    return jsonify(packets)

@app.route('/api/save', methods=['POST'])
def api_save():
    ts = int(time.time())
    json_path = os.path.join(snapshot_dir, f"snapshot_{ts}.json")
    with open(json_path, 'w') as f:
        json.dump({"devices": list(devices.values()), "packets": packets}, f, indent=2)
    return jsonify({"status": "saved", "file": json_path})

@app.route('/api/export-pcap', methods=['GET'])
def api_export_pcap():
    ts = int(time.time())
    filename = f"capture_{ts}.pcap"
    path = analyzer.export_pcap(filename)
    return send_file(path, as_attachment=True)

@app.route('/api/health')
def health():
    return jsonify({"status": "running", "devices": len(devices), "packets": len(packets)})

@app.route('/api/schedule-export')
def schedule_export():
    ts = int(time.time())
    json_path = os.path.join(snapshot_dir, f"auto_export_{ts}.json")
    with open(json_path, 'w') as f:
        json.dump({"devices": list(devices.values()), "packets": packets}, f, indent=2)
    return jsonify({"exported": True, "file": json_path})

# ====== بدء التشغيل ======
if __name__ == '__main__':
    logging.info("Launching Network Sentinel...")

    interface = 'enp6s0'  # غيّرها حسب جهازك

    scanner = DeviceScanner(interface=interface)
    threading.Thread(target=scanner.start, daemon=True).start()

    analyzer = PacketAnalyzer(interface=interface)
    threading.Thread(target=analyzer.start, daemon=True).start()

    app.run(host='0.0.0.0', port=5000, debug=False)
