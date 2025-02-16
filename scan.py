from flask import Flask, render_template, jsonify
import scapy.all as scapy
import subprocess
import threading
import time
import logging

app = Flask(__name__)

# إعداد نظام تسجيل الأحداث
logging.basicConfig(filename='network_monitor.log', level=logging.INFO, format='%(asctime)s - %(message)s')

devices = {}
requests_log = []

PROTOCOLS = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP'
}

def scan_network():
    global devices
    while True:
        # استخدام fping بدلاً من nmap
        result = subprocess.run(['fping', '-a', '-g', '192.168.8.0/24'], capture_output=True, text=True)
        devices_ips = result.stdout.splitlines()

        new_devices = {}
        for ip in devices_ips:
            new_devices[ip] = {'MAC': 'Unknown', 'Ports': [], 'OS': 'Unknown'}

        devices = new_devices
        print(f"Updated devices: {new_devices}")  # طباعة الأجهزة المحدثة
        logging.info(f"Updated device list: {devices}")
        time.sleep(5)  # تحديث كل 5 ثواني

def packet_sniffer(packet):
    global requests_log
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol_num = packet[scapy.IP].proto
        protocol_name = PROTOCOLS.get(protocol_num, f'Unknown ({protocol_num})')
        src_port = getattr(packet, 'sport', 'Unknown')
        dst_port = getattr(packet, 'dport', 'Unknown')

        if packet.haslayer(scapy.Raw):
            data = packet[scapy.Raw].load.decode(errors='ignore')
        else:
            data = "No Data"

        request_entry = {
            'source': src_ip,
            'destination': dst_ip,
            'source_port': src_port,
            'destination_port': dst_port,
            'protocol': f'{protocol_name} ({protocol_num})',
            'data': data
        }
        requests_log.append(request_entry)
        print(f"Captured request: {request_entry}")  # طباعة الطلبات الملتقطة
        logging.info(f"Captured request: {request_entry}")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/data')
def get_data():
    return jsonify(devices)

@app.route('/requests')
def get_requests():
    return jsonify(requests_log)

@app.route('/logs')
def get_logs():
    with open('network_monitor.log', 'r') as log_file:
        logs = log_file.readlines()
    return jsonify({'logs': logs})

if __name__ == '__main__':
    threading.Thread(target=scan_network, daemon=True).start()
    threading.Thread(target=lambda: scapy.sniff(prn=packet_sniffer, store=False), daemon=True).start()
    app.run(host='0.0.0.0', port=5000, debug=True)
